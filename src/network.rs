use super::*;
use async_trait::async_trait;
use futures::channel::{mpsc, oneshot};
use libp2p::core::either::EitherError;
use libp2p::core::upgrade::{ProtocolName, read_length_prefixed, write_length_prefixed};
use libp2p::{gossipsub, identity, kad, Multiaddr, PeerId};
use libp2p::identity::ed25519;
use libp2p::kad::record::store::MemoryStore;
use libp2p::kad::{GetProvidersOk, Kademlia, KademliaEvent, QueryId, QueryResult};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{
    ProtocolSupport, RequestId, RequestResponse, RequestResponseCodec, RequestResponseEvent,
    RequestResponseMessage, ResponseChannel,
};
use proconio::input;
use libp2p::swarm::{ConnectionHandlerUpgrErr, SwarmBuilder, SwarmEvent};
use libp2p::{NetworkBehaviour, Swarm};
use std::collections::{HashMap, HashSet};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::{env, fs, iter, thread, time};
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, Read};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use async_std::io;
use async_std::prelude::Stream;
use ethers::contract::Contract;
use ethers::prelude::{Http, Provider};
use ethers_signers::{LocalWallet, Signer};
use futures::{AsyncRead, AsyncWrite, SinkExt};
use libp2p::gossipsub::{IdentTopic, MessageId, Topic};
use libp2p::futures::AsyncWriteExt;
use libp2p::gossipsub::{Gossipsub, GossipsubEvent, GossipsubMessage, MessageAuthenticity, ValidationMode};
use libp2p::gossipsub::error::GossipsubHandlerError;
use libp2p::identify::{Identify, IdentifyConfig, IdentifyEvent, IdentifyInfo};
use libp2p_request_response::RequestResponseConfig;
use crate::{check_proof, ContractData, generate_key_Nth_group, GROUP_NUMBER};
use crate::types::file_request_value::FileRequestValue;
use crate::types::file_upload_value::FileUploadValue;
use crate::types::proof::Proof;

/// Creates the network components, namely:
///
/// - The network client to interact with the network layer from anywhere
///   within your application.
///
/// - The network event stream, e.g. for incoming requests.
///
/// - The network task driving the network itself.
pub async fn new(
    secret_key_seed: Option<u8>,
    group: Option<u64>,
    is_provider: bool
) -> Result<(Client, impl Stream<Item = Event>, EventLoop, PeerId, u64), Box<dyn Error>> {
    // Create a public/private key pair, either random or based on a seed.
    let id_keys = match secret_key_seed {
        Some(seed) => {
            let mut bytes = [0u8; 32];
            bytes[0] = seed;
            let secret_key = ed25519::SecretKey::from_bytes(&mut bytes).expect(
                "this returns `Err` only if the length is wrong; the length is correct; qed",
            );
            identity::Keypair::Ed25519(secret_key.into())
        }
        None => {
            match group {
                Some(group) => {
                    generate_key_Nth_group(group.try_into().unwrap())
                }
                None => {
                    identity::Keypair::generate_ed25519()
                }
            }
        },
    };

    let peer_id = id_keys.public().to_peer_id();

    println!("{:?}", peer_id);

    let bytes = peer_id.clone().to_bytes();

    let mut sum = 0u64;
    for num in bytes {
        sum += num as u64;
    }

    let group = sum % GROUP_NUMBER;
    println!("assigned to GROUP {}", group);

    let protocol_version:String = "beta".to_string();

    let identify = Identify::new(IdentifyConfig::new(protocol_version, id_keys.public().clone()));

    // To content-address message, we can take the hash of message and use it as an ID.
    let message_id_fn = |message: &GossipsubMessage| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        MessageId::from(s.finish().to_string())
    };

    //let topic = IdentTopic::new("testnet");

    // Set a custom gossipsub
    let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
        .validation_mode(ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
        .message_id_fn(message_id_fn) // content-address messages. No two messages of the
        // same content will be propagated.
        .max_transmit_size(6_000_000_000_000)
        .build()
        .expect("Valid config");
    // build a gossipsub network behaviour
    let mut gossipsub: gossipsub::Gossipsub =
        gossipsub::Gossipsub::new(MessageAuthenticity::Signed(id_keys.clone()), gossipsub_config)
            .expect("Correct configuration");

    gossipsub.subscribe(&IdentTopic::new("testnet")).unwrap();

    if is_provider {
        gossipsub.subscribe(&IdentTopic::new(format!("testnet-{}", group))).unwrap();
    }

    // Build the Swarm, connecting the lower layer transport logic with the
    // higher layer network behaviour logic.
    let mut swarm = SwarmBuilder::new(
        libp2p::development_transport(id_keys).await?,
        ComposedBehaviour {
            gossipsub,
            kademlia: Kademlia::new(peer_id, MemoryStore::new(peer_id)),
            identify,
            request_response: RequestResponse::new(
                FileExchangeCodec(),
                iter::once((FileExchangeProtocol(), ProtocolSupport::Full)),
                Default::default(),
            ),
        },
        peer_id.clone(),
    )
        .build();

    let (command_sender, command_receiver) = mpsc::channel(0);
    let (event_sender, event_receiver) = mpsc::channel(0);

    Ok((
        Client {
            sender: command_sender,
        },
        event_receiver,
        EventLoop::new(swarm, command_receiver, event_sender),
        peer_id,
        group,
    ))
}

#[derive(Clone)]
pub struct Client {
    sender: mpsc::Sender<Command>,
}

impl Client {
    /// Listen for incoming connections on the given address.
    pub async fn start_listening(
        &mut self,
        addr: Multiaddr,
    ) -> Result<(), Box<dyn Error + Send>> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::StartListening { addr, sender })
            .await
            .expect("Command receiver not to be dropped.");
        receiver.await.expect("Sender not to be dropped.")
    }

    /// Dial the given peer at the given address.
    pub async fn dial(
        &mut self,
        peer_id: PeerId,
        peer_addr: Multiaddr,
    ) -> Result<(), Box<dyn Error + Send>> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::Dial {
                peer_id,
                peer_addr,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped.");
        receiver.await.expect("Sender not to be dropped.")
    }

    /// Advertise the local node as the provider of the given file on the DHT.
    pub async fn start_providing(&mut self, file_name: String) {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::StartProviding { file_name, sender })
            .await
            .expect("Command receiver not to be dropped.");
        receiver.await.expect("Sender not to be dropped.");
    }

    /// Find the providers for the given file on the DHT.
    pub async fn get_providers(&mut self, file_name: String) -> HashSet<PeerId> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::GetProviders { file_name, sender })
            .await
            .expect("Command receiver not to be dropped.");
        receiver.await.expect("Sender not to be dropped.")
    }

    pub async fn get_peers(&mut self) -> HashSet<PeerId> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::GetPeers { sender })
            .await
            .expect("Command receiver not to be dropped.");
        receiver.await.expect("Sender not to be dropped.")
    }

    /// Request the content of the given file from the given peer.
    pub async fn request_file(
        &mut self,
        peer: PeerId,
        file_name: String,
    ) -> Result<Vec<u8>, Box<dyn Error + Send>> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::RequestFile {
                file_name,
                peer,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped.");
        receiver.await.expect("Sender not be dropped.")
    }

    /// Request the content of the given file from the given peer.
    pub async fn get_shards(
        &mut self,
        file_name: String,
    ) -> Vec<Result<Vec<u8>, Box<dyn Error + Send>>> {

        let mut senders = Vec::new();
        let mut receivers = Vec::new();

        for _ in 0..20 {
            let (sender, receiver) = oneshot::channel();
            senders.push(sender);
            receivers.push(receiver);
        }

        self.sender
            .send(Command::GetShards {
                file_name,
                senders,
            })
            .await
            .expect("Command receiver not to be dropped.");

        let mut res = Vec::new();

        for receiver in receivers.into_iter() {
            res.push(receiver.await.expect("Sender not be dropped."));
        }

        res
    }

    pub async fn get_shard(
        &mut self,
        file_name: String,
        group: u8,
    ) -> Result<Vec<u8>, Box<dyn Error + Send>> {
        println!("get shard, group: {}", group);
        let (sender, receiver) = oneshot::channel();

        self.sender
            .send(Command::GetShard {
                file_name,
                group,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped.");

        receiver.await.expect("Sender not be dropped.")
    }

    /// Respond with the provided file content to the given request.
    pub async fn respond_file(&mut self, file: Vec<u8>, channel: ResponseChannel<FileResponse>) {
        self.sender
            .send(Command::RespondFile { file, channel })
            .await
            .expect("Command receiver not to be dropped.");
    }

    pub async fn upload_file(&mut self, file: Vec<u8>, group: u8) {
        self.sender
            .send(Command::UploadFile {file, group})
            .await
            .expect("Command receiver not to be dropped")
    }

    pub async fn upload_shards(&mut self, shards: Vec<Vec<u8>>) {
        self.sender
            .send(Command::UploadShards {shards})
            .await
            .expect("Command receiver not to be dropped")
        /*
        self.sender
            .send(Command::UploadFile { file, group })
            .await
            .expect("Command receiver not to be dropped");*/
    }
}

pub struct EventLoop {
    swarm: Swarm<ComposedBehaviour>,
    //command_sender: mpsc::Sender<Command>,
    command_receiver: mpsc::Receiver<Command>,
    event_sender: mpsc::Sender<Event>,
    pending_dial: HashMap<PeerId, oneshot::Sender<Result<(), Box<dyn Error + Send>>>>,
    pending_start_providing: HashMap<QueryId, oneshot::Sender<()>>,
    pending_get_peers: HashMap<QueryId, oneshot::Sender<HashSet<PeerId>>>,
    pending_get_providers: HashMap<QueryId, oneshot::Sender<HashSet<PeerId>>>,
    pending_request_file:
    HashMap<RequestId, oneshot::Sender<Result<Vec<u8>, Box<dyn Error + Send>>>>,
}

impl EventLoop {
    fn new(
        swarm: Swarm<ComposedBehaviour>,
        //command_sender: mpsc::Sender<Command>,
        command_receiver: mpsc::Receiver<Command>,
        event_sender: mpsc::Sender<Event>,
    ) -> Self {
        Self {
            swarm,
            //command_sender,
            command_receiver,
            event_sender,
            pending_dial: Default::default(),
            pending_start_providing: Default::default(),
            pending_get_peers: Default::default(),
            pending_get_providers: Default::default(),
            pending_request_file: Default::default(),
        }
    }

    pub async fn run(mut self/*, mut client: Client*/, client: Client, group: u8) {
        let mut stdin = io::BufReader::new(io::stdin()).lines().fuse();

        let to_search: PeerId = identity::Keypair::generate_ed25519().public().into();

        loop {
            futures::select! {

                line = stdin.select_next_some() => {
                    let s: String = line.unwrap();

                    println!("入力: {}", s);

                    if s == "send" {
                        println!("input peer_id & file_name");
                        input!{
                            pid: String,
                            file_name: String
                        }
                        let peer_id = PeerId::from_str(pid.as_str()).unwrap();
                    }
                    if s == "peers" {
                        println!("show connected peers");
                        for connected_peer in self.swarm.connected_peers() {
                            println!("{:?}", connected_peer);
                        }
                    }
                    if s == "search" {
                        println!("search");
                        self.swarm.behaviour_mut().kademlia.get_closest_peers(to_search);
                    }
                }

                event = self.swarm.next() => self.handle_event(event.expect("Swarm stream to be infinite."), group).await  ,
                command = self.command_receiver.next() => match command {
                    Some(c) => self.handle_command(c).await,
                    // Command channel closed, thus shutting down the network event loop.
                    None=>  return,
                },
            }
        }
    }

    async fn handle_event(
        &mut self,
        event: SwarmEvent<
            ComposedEvent,
            EitherError<EitherError<EitherError<GossipsubHandlerError, ConnectionHandlerUpgrErr<std::io::Error>>, std::io::Error>, std::io::Error>,
        >,
        group: u8
    ) {
        match event {
            SwarmEvent::Behaviour(ComposedEvent::GossipSub(GossipsubEvent::Message {
                                                               propagation_source: peer_id,
                                                               message_id: id,
                                                               message,
                                                           })) => {
                println!("Got message: {} with id: {} from peer: {:?}", &message.data.len(), id, peer_id);

                let upload: FileUploadValue = serde_json::from_str(&String::from_utf8(message.data).unwrap()).unwrap();
                let received_message_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");

                let provider = Provider::<Http>::try_from("http://127.0.0.1:8545/").unwrap();
                let mut f = File::open("./contract.json").expect("no file found");
                let metadata = fs::metadata("./contract.json").expect("unable to read metadata");
                let mut buffer = vec![0; metadata.len() as usize];
                f.read(&mut buffer).expect("buffer overflow");
                let contract_data_str: &str = std::str::from_utf8(&buffer).unwrap();
                let contract_data: ContractData = serde_json::from_str(contract_data_str).unwrap();
                let contract = Contract::new(contract_data.contractAddress, contract_data.abi, provider);

                println!("root mae, {}", upload.file_name);
                let root = contract.method::<_, String>("merkleRootOf", upload.file_name.clone()).unwrap().call().await.unwrap();

                println!("root, {}", root);
                let proof: Proof = serde_json::from_str(&String::from_utf8(upload.proof).unwrap()).unwrap();

                let ok = check_proof(sha256::digest_bytes(&upload.file), &proof.proof, &root);
                if ok {
                    println!("OK");
                } else {
                    println!("No");
                }

                let check_hash_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");

                std::fs::write(format!("storage/{}.{}", upload.file_name, group), upload.file).unwrap();

                let save_file_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");

                std::fs::write("time", format!("received:{:?}, check hash:{:?}, save file:{:?}",
                                               received_message_at, check_hash_at, save_file_at)).unwrap();
                /*println!(
                    "Got message: {} with id: {} from peer: {:?}",
                    String::from_utf8_lossy(&message.data),
                    id,
                    peer_id
                )*/
            },

            SwarmEvent::Behaviour(ComposedEvent::Kademlia(
                                      KademliaEvent::OutboundQueryCompleted {
                                          id,
                                          result: QueryResult::StartProviding(_),
                                          ..
                                      },
                                  )) => {
                let sender: oneshot::Sender<()> = self
                    .pending_start_providing
                    .remove(&id)
                    .expect("Completed query to be previously pending.");
                let _ = sender.send(());
            }
            SwarmEvent::Behaviour(ComposedEvent::Kademlia(
                                      KademliaEvent::OutboundQueryCompleted {
                                          id,
                                          result: QueryResult::GetProviders(Ok(GetProvidersOk { providers, .. })),
                                          ..
                                      },
                                  )) => {
                let _ = self
                    .pending_get_providers
                    .remove(&id)
                    .expect("Completed query to be previously pending.")
                    .send(providers);
            }
            SwarmEvent::Behaviour(ComposedEvent::Kademlia(_)) => {}
            SwarmEvent::Behaviour(ComposedEvent::Identify(e)) => {

                if let IdentifyEvent::Received {
                    peer_id,
                    info:
                    IdentifyInfo {
                        listen_addrs,
                        protocols,
                        ..
                    },
                } = e
                {
                    if protocols
                        .iter()
                        .any(|p| p.as_bytes() == kad::protocol::DEFAULT_PROTO_NAME)
                    {
                        for addr in listen_addrs {
                            println!("Identify event received {:?}, {:?}", peer_id, addr);
                            self.swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(&peer_id, addr);
                        }
                    }
                }
            }
            SwarmEvent::Behaviour(ComposedEvent::RequestResponse(
                                      RequestResponseEvent::Message { message, .. },
                                  )) => match message {
                RequestResponseMessage::Request {
                    request, channel, ..
                } => {
                    self.event_sender
                        .send(Event::InboundRequest {
                            request: request.0,
                            channel,
                        })
                        .await
                        .expect("Event receiver not to be dropped.");
                }
                RequestResponseMessage::Response {
                    request_id,
                    response,
                } => {
                    let _ = self
                        .pending_request_file
                        .remove(&request_id)
                        .expect("Request to still be pending.")
                        .send(Ok(response.0));
                }
            },
            SwarmEvent::Behaviour(ComposedEvent::RequestResponse(
                                      RequestResponseEvent::OutboundFailure {
                                          request_id, error, ..
                                      },
                                  )) => {
                let _ = self
                    .pending_request_file
                    .remove(&request_id)
                    .expect("Request to still be pending.")
                    .send(Err(Box::new(error)));
            }
            SwarmEvent::Behaviour(ComposedEvent::RequestResponse(
                                      RequestResponseEvent::ResponseSent { .. },
                                  )) => {}
            SwarmEvent::NewListenAddr { address, .. } => {
                let local_peer_id = *self.swarm.local_peer_id();
                println!(
                    "Local node is listening on {:?}",
                    address.with(Protocol::P2p(local_peer_id.into()))
                );
            }
            SwarmEvent::IncomingConnection { .. } => {}
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                println!("connection established {:?}", peer_id);
                if endpoint.is_dialer() {
                    if let Some(sender) = self.pending_dial.remove(&peer_id) {
                        let _ = sender.send(Ok(()));
                    }
                }

                // TODO: ここでGetShard, Uploadタスクの実行はできるか
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                println!("Connection Closed with {:?}", peer_id);
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer_id) = peer_id {
                    if let Some(sender) = self.pending_dial.remove(&peer_id) {
                        let _ = sender.send(Err(Box::new(error)));
                    }
                }
            }
            SwarmEvent::IncomingConnectionError { .. } => {}
            SwarmEvent::Dialing(peer_id) => println!("Dialing {}", peer_id),
            e => {
                println!("{:?}", e);
                //panic!("{:?}", e)
            },
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            /*Command::AddKademlia {peer_id, addr, sender} => {
                self.swarm.behaviour_mut().kademlia.add_address(&peer_id,addr);
            },*/
            Command::StartListening { addr, sender } => {
                let _ = match self.swarm.listen_on(addr) {
                    Ok(_) => sender.send(Ok(())),
                    Err(e) => sender.send(Err(Box::new(e))),
                };
            }
            Command::Dial {
                peer_id,
                peer_addr,
                sender,
            } => {
                if self.pending_dial.contains_key(&peer_id) {
                    todo!("Already dialing peer.");
                } else {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, peer_addr.clone());
                    match self
                        .swarm
                        .dial(peer_addr.with(Protocol::P2p(peer_id.into())))
                    {
                        Ok(()) => {
                            self.pending_dial.insert(peer_id, sender);
                        }
                        Err(e) => {
                            let _ = sender.send(Err(Box::new(e)));
                        }
                    }
                }
            }
            Command::StartProviding { file_name, sender } => {
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .start_providing(file_name.into_bytes().into())
                    .expect("No store error.");
                self.pending_start_providing.insert(query_id, sender);
            }

            Command::GetPeers { sender } => {
                /*let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_providers(file_name.into_bytes().into());
                self.pending_get_providers.insert(query_id, sender);*/
            }

            Command::GetProviders { file_name, sender } => {
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_providers(file_name.into_bytes().into());
                self.pending_get_providers.insert(query_id, sender);
            }

            Command::GetShards {
                file_name,
                senders,
            } => {
                let to_search: PeerId = identity::Keypair::generate_ed25519().public().into();
                //self.swarm.behaviour_mut().kademlia.get_closest_peers(to_search);

                let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");

                let wallet = LocalWallet::from_str(&private_key).unwrap();

                let peers_iter = self.swarm.connected_peers();

                let mut peers = Vec::new();

                for peer in peers_iter {
                    peers.push(peer.clone());
                }

                let mut senders_iter = senders.into_iter();

                let mut cnt = 0;
                let mut requested = vec![false; GROUP_NUMBER as usize];

                let mut request_ids = Vec::new();

                println!("peers: {:?}", peers);

                for peer in peers {
                    if cnt >= 20 {
                        break;
                    }
                    let bytes = peer.to_bytes();
                    let mut sum = 0u64;
                    for num in bytes {
                        sum += num as u64;
                    }
                    let group = sum % GROUP_NUMBER;
                    if !requested[group as usize] {
                        let signature = wallet.sign_message(peer.to_string()).await.unwrap();
                        let request_value = FileRequestValue{
                            file: file_name.clone(),
                            address: wallet.address().to_string(),
                            signature: signature.to_string(),
                        };
                        let request_value_string = serde_json::to_string(&request_value).unwrap();

                        let request_id = self
                            .swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer, FileRequest(request_value_string.clone()));

                        request_ids.push(request_id);

                        requested[group as usize] = true;
                        cnt += 1;
                    }
                }

                cnt = 0;

                for sender in senders_iter {
                    self.pending_request_file.insert(request_ids[cnt], sender);
                    cnt += 1;
                }
            }

            Command::GetShard {
                file_name,
                group,
                sender,
            } => {
                let to_search: PeerId = identity::Keypair::generate_ed25519().public().into();
                //self.swarm.behaviour_mut().kademlia.get_closest_peers(to_search);

                let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");

                let wallet = LocalWallet::from_str(&private_key).unwrap();

                let peers_iter = self.swarm.connected_peers();

                let mut peers = Vec::new();

                for peer in peers_iter {
                    peers.push(peer.clone());
                }

                for peer in peers {
                    let bytes = peer.to_bytes();
                    let mut sum = 0u64;
                    for num in bytes {
                        sum += num as u64;
                    }
                    let group_ = sum % GROUP_NUMBER;
                    if group_ as u8 == group {
                        let signature = wallet.sign_message(peer.to_string()).await.unwrap();
                        let request_value = FileRequestValue{
                            file: file_name.clone(),
                            address: wallet.address().to_string(),
                            signature: signature.to_string(),
                        };
                        let request_value_string = serde_json::to_string(&request_value).unwrap();
                        let request_id = self
                            .swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer, FileRequest(request_value_string.clone()));

                        self.pending_request_file.insert(request_id, sender);
                        break;
                    }
                }
            }

            Command::RequestFile {
                file_name,
                peer,
                sender,
            } => {
                let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");

                let wallet = LocalWallet::from_str(&private_key).unwrap();
                let signature = wallet.sign_message(peer.to_string()).await.unwrap();

                let request_value = FileRequestValue{
                    file: file_name,
                    address: wallet.address().to_string(),
                    signature: signature.to_string(),
                };

                let request_value_string = serde_json::to_string(&request_value).unwrap();

                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer, FileRequest(request_value_string));
                self.pending_request_file.insert(request_id, sender);
            }
            Command::RespondFile { file, channel } => {
                self.swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, FileResponse(file))
                    .expect("Connection to peer to be still open.");
            }
            Command::UploadFile { file, group } => {
                let topic = IdentTopic::new(format!("testnet-{}", group));
                //let topic = IdentTopic::new("testnet");

                for peer_data in self.swarm
                    .behaviour_mut()
                    .gossipsub.all_peers() {
                    println!("{:?}, {:?}", peer_data.0, peer_data.1);
                }

                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), file)
                    .expect("publish file failed.");
            },
            Command::UploadShards {shards} => {
                for (i, shard) in shards.into_iter().enumerate() {
                    let topic = IdentTopic::new(format!("testnet-{}", i));

                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(topic, shard)
                        .expect("publish file failed.");
                }
            }
        }
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ComposedEvent")]
struct ComposedBehaviour {
    gossipsub: Gossipsub,
    request_response: RequestResponse<FileExchangeCodec>,
    identify: Identify,
    kademlia: Kademlia<MemoryStore>,
}

#[derive(Debug)]
enum ComposedEvent {
    GossipSub(GossipsubEvent),
    RequestResponse(RequestResponseEvent<FileRequest, FileResponse>),
    Identify(IdentifyEvent),
    Kademlia(KademliaEvent),
}

impl From<GossipsubEvent> for ComposedEvent {
    fn from(v: GossipsubEvent) -> Self {
        Self::GossipSub(v)
    }
}

impl From<IdentifyEvent> for ComposedEvent {
    fn from(event: IdentifyEvent) -> Self {
        ComposedEvent::Identify(event)
    }
}

impl From<RequestResponseEvent<FileRequest, FileResponse>> for ComposedEvent {
    fn from(event: RequestResponseEvent<FileRequest, FileResponse>) -> Self {
        ComposedEvent::RequestResponse(event)
    }
}

impl From<KademliaEvent> for ComposedEvent {
    fn from(event: KademliaEvent) -> Self {
        ComposedEvent::Kademlia(event)
    }
}

#[derive(Debug)]
enum Command {
    /*AddKademlia {
        peer_id: PeerId,
        addr: Multiaddr,
    },*/
    StartListening {
        addr: Multiaddr,
        sender: oneshot::Sender<Result<(), Box<dyn Error + Send>>>,
    },
    Dial {
        peer_id: PeerId,
        peer_addr: Multiaddr,
        sender: oneshot::Sender<Result<(), Box<dyn Error + Send>>>,
    },
    StartProviding {
        file_name: String,
        sender: oneshot::Sender<()>,
    },
    GetPeers {
        sender: oneshot::Sender<HashSet<PeerId>>,
    },
    GetProviders {
        file_name: String,
        sender: oneshot::Sender<HashSet<PeerId>>,
    },
    GetShards {
        file_name: String,
        senders: Vec<oneshot::Sender<Result<Vec<u8>, Box<dyn Error + Send>>>>,
    },
    GetShard {
        file_name: String,
        group: u8,
        sender: oneshot::Sender<Result<Vec<u8>, Box<dyn Error + Send>>>
    },
    RequestFile {
        file_name: String,
        peer: PeerId,
        sender: oneshot::Sender<Result<Vec<u8>, Box<dyn Error + Send>>>,
    },
    RespondFile {
        file: Vec<u8>,
        channel: ResponseChannel<FileResponse>,
    },
    UploadFile {
        file: Vec<u8>,
        group: u8,
    },
    UploadShards {
        shards: Vec<Vec<u8>>,
    }
}

#[derive(Debug)]
pub enum Event {
    InboundRequest {
        request: String,
        channel: ResponseChannel<FileResponse>,
    },
}

// Simple file exchange protocol
#[derive(Debug, Clone)]
struct FileExchangeProtocol();
#[derive(Clone)]
struct FileExchangeCodec();
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileRequest(String);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResponse(Vec<u8>);

impl ProtocolName for FileExchangeProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/file-exchange/1".as_bytes()
    }
}

#[async_trait]
impl RequestResponseCodec for FileExchangeCodec {
    type Protocol = FileExchangeProtocol;
    type Request = FileRequest;
    type Response = FileResponse;

    async fn read_request<T>(
        &mut self,
        _: &FileExchangeProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
        where
            T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 1_000_000_000).await?;

        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        Ok(FileRequest(String::from_utf8(vec).unwrap()))
    }

    async fn read_response<T>(
        &mut self,
        _: &FileExchangeProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
        where
            T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 1_000_000_000_000).await?;

        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        Ok(FileResponse(vec))
    }

    async fn write_request<T>(
        &mut self,
        _: &FileExchangeProtocol,
        io: &mut T,
        FileRequest(data): FileRequest,
    ) -> io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, data).await?;
        io.close().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &FileExchangeProtocol,
        io: &mut T,
        FileResponse(data): FileResponse,
    ) -> io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, data).await?;
        io.close().await?;

        Ok(())
    }
}

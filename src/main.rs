// Copyright 2021 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! # File sharing example
//!
//! Basic file sharing application with peers either providing or locating and
//! getting files by name.
//!
//! While obviously showcasing how to build a basic file sharing application,
//! the actual goal of this example is **to show how to integrate rust-libp2p
//! into a larger application**.
//!
//! ## Sample plot
//!
//! Assuming there are 3 nodes, A, B and C. A and B each provide a file while C
//! retrieves a file.
//!
//! Provider nodes A and B each provide a file, file FA and FB respectively.
//! They do so by advertising themselves as a provider for their file on a DHT
//! via [`libp2p-kad`]. The two, among other nodes of the network, are
//! interconnected via the DHT.
//!
//! Node C can locate the providers for file FA or FB on the DHT via
//! [`libp2p-kad`] without being connected to the specific node providing the
//! file, but any node of the DHT. Node C then connects to the corresponding
//! node and requests the file content of the file via
//! [`libp2p-request-response`].
//!
//! ## Architectural properties
//!
//! - Clean clonable async/await interface ([`Client`]) to interact with the
//!   network layer.
//!
//! - Single task driving the network layer, no locks required.
//!
//! ## Usage
//!
//! A two node setup with one node providing the file and one node requesting the file.
//!
//! 1. Run command below in one terminal.
//!
//!    ```
//!    cargo run --example file-sharing -- \
//!              --listen-address /ip4/127.0.0.1/tcp/40837 \
//!              --secret-key-seed 1 \
//!              provide \
//!              --path <path-to-your-file> \
//!              --name <name-for-others-to-find-your-file>
//!    ```
//!
//! 2. Run command below in another terminal.
//!
//!    ```
//!    cargo run --example file-sharing -- \
//!              --peer /ip4/127.0.0.1/tcp/40837/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X \
//!              get \
//!              --name <name-for-others-to-find-your-file>
//!    ```
//!
//! Note: The client does not need to be directly connected to the providing
//! peer, as long as both are connected to some node on the same DHT.
// PROVIDE
// cargo run -- --listen-address /ip4/127.0.0.1/tcp/40837 --secret-key-seed 1 provide
// cargo run -- --peer /ip4/127.0.0.1/tcp/40837/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X --listen-address /ip4/127.0.0.1/tcp/40840 --secret-key-seed 2 provide

// GET
// cargo run -- --peer /ip4/127.0.0.1/tcp/40837/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X --listen-address /ip4/127.0.0.1/tcp/40842 --secret-key-seed 3 get --name {file name here!}

use async_std::io;
use rand::seq::SliceRandom;
use async_std::task::spawn;
use clap::Parser;
use dotenv::dotenv;
use ethers::contract::Contract;
use ethers_core::abi::Abi;
use ethers_core::types::{Address, Signature};
use ethers::prelude::Provider;
use ethers::providers::Http;
use futures::prelude::*;
use libp2p::core::{identity, Multiaddr, PeerId};
use libp2p::multiaddr::Protocol;
use std::error::Error;
use std::env;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use proconio::input;
use std::str::FromStr;
use std::io::Read;
use std::iter::Map;
use futures::future::{BoxFuture, SelectOk};
use libp2p::identity::Keypair;
use rand::Rng;
use serde::Serialize;
use serde::Deserialize;
use crate::identity::ed25519;

#[derive(Serialize)]
#[derive(Deserialize)]
struct FileRequestValue {
    file: String,
    address: String,
    signature: String,
}

const GROUP_NUMBER: u64 = 40;

fn read_dir<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
    Ok(fs::read_dir(path)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if entry.file_type().ok()?.is_dir() {
                Some(entry.file_name().to_string_lossy().into_owned())
            } else {
                None
            }
        })
        .collect())
}

fn get_files<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
    Ok(fs::read_dir(path)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if entry.file_type().ok()?.is_file() {
                Some(entry.file_name().to_string_lossy().into_owned())
            } else {
                None
            }
        })
        .collect())
}

fn get_files_to_provide(s: &str, group_number: u64) {

    let _dirs = read_dir(s);

    let mut dirs = _dirs.unwrap();

    let mut files = Vec::<String>::new();

    println!("{:?}", dirs);

    for dir in dirs {
        files.push(format!("{}.{}", dir, group_number));
    }

    println!("{:?}", files);
}

fn get_file_as_byte_vec(filename: String) -> Vec<u8> {
    println!("{}", filename);
    let mut f = File::open(&filename).expect("no file found");
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

fn generate_key_Nth_group(n: u64) -> Keypair {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];

    loop {
        for i in 0..32 {
            bytes[i] = rng.gen();
        }

        let secret_key = ed25519::SecretKey::from_bytes(&mut bytes).expect(
            "this returns `Err` only if the length is wrong; the length is correct; qed",
        );

        let local_key = identity::Keypair::Ed25519(secret_key.into());

        let local_peer_id = local_key.clone().public().to_peer_id();
        let bytes = local_peer_id.to_bytes();

        let mut sum = 0u64;
        for num in bytes {
            sum += num as u64;
        }
        if sum % GROUP_NUMBER == n {
            return local_key;
        } else {
            continue ;
        }
    }

}

#[derive(Deserialize)]
struct ContractData {
    contractAddress: Address,
    abi: Abi,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    dotenv().ok();

    let opt = Opt::parse();

    /*
    let file_content = get_file_as_byte_vec("./bookshards/Go.pdf.shards/Go.pdf.shards.0".to_string());
    let s = unsafe {
        std::str::from_utf8_unchecked(&file_content)
    };*/

    let (mut network_client, mut network_events, network_event_loop,peerId, group) =
        network::new(opt.secret_key_seed, opt.group).await?;

    spawn(network_event_loop.run(network_client.clone()));

    //network_client.searchPeers();

    // In case a listen address was provided use it, otherwise listen on any
    // address.
    match opt.listen_address {
        Some(addr) => network_client
            .start_listening(addr)
            .await
            .expect("Listening not to fail."),
        None => network_client
            .start_listening("/ip4/0.0.0.0/tcp/0".parse()?)
            .await
            .expect("Listening not to fail."),
    };

    // In case the user provided an address of a peer on the CLI, dial it.
    if let Some(addr) = opt.peer {
        let peer_id = match addr.iter().last() {
            Some(Protocol::P2p(hash)) => PeerId::from_multihash(hash).expect("Valid hash."),
            _ => return Err("Expect peer multiaddr to contain peer ID.".into()),
        };
        network_client
            .dial(peer_id, addr)
            .await
            .expect("Dial to succeed");
    }

    // create contract instance for mumbai testnet
    let provider = Provider::<Http>::try_from("https://rpc-mumbai.maticvigil.com").unwrap();
    let mut f = File::open("./contract.json").expect("no file found");
    let metadata = fs::metadata("./contract.json").expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    let contract_data_str: &str = std::str::from_utf8(&buffer).unwrap();
    let contract_data: ContractData = serde_json::from_str(contract_data_str).unwrap();

    let contract = Contract::new(contract_data.contractAddress, contract_data.abi, provider);

    match opt.argument {
        // Providing a file.
        CliArgument::Provide { .. } => {

            let contents_to_provide = read_dir("./bookshards")?;

            for content in &contents_to_provide {
                network_client.start_providing(format!("{}.{}", content.clone(), group)).await;
            }

            loop {
                match network_events.next().await {
                    // Reply with the content of the file on incoming requests.
                    Some(network::Event::InboundRequest { request, channel }) => {
                        println!("request: {}", request);

                        let file_request_value: FileRequestValue = serde_json::from_str(&*request).unwrap();
                        let file = file_request_value.file;
                        let address = file_request_value.address;
                        let signature = Signature::from_str(&*file_request_value.signature).unwrap();

                        //println!("{:?}", title);

                        println!("file: {}", file);
                        println!("address: {}", address);
                        println!("signature: {}", signature);

                        let symbol = contract.method::<_, String>("symbol", ()).unwrap().call().await.unwrap();
                        println!("{:?}", symbol);

                        match signature.recover(peerId.to_string()) {
                            Ok(address) => {
                                // TODO: check Access Right.

                                println!("{}", file);
                                let has_ownership = contract.method::<_, bool>("hasOwnership", (address, file.clone())).unwrap().call().await.unwrap();

                                match has_ownership {
                                    true => {
                                        let file_content = get_file_as_byte_vec(format!("./bookshards/{}.shards/{}.shards.{}", &file, &file, group));
                                        network_client.respond_file(file_content, channel).await;
                                    },
                                    _ => {
                                        println!("No Ownership");
                                    }
                                }

                            }
                            _ => {
                                println!("No");
                            }
                        };
                    }
                    e => todo!("{:?}", e),
                }
            }
        }

        CliArgument::Get { name } => {
            // Locate all nodes providing the file.
            // TODO グループ番号の指定

            let mut v = (0..40).collect::<Vec<u8>>();
            let mut rng = rand::thread_rng();
            v.shuffle(&mut rng);

            println!("{:?}", v);


            let providers = network_client.get_providers(format!("{}.shards.{}", name.clone(), 25)).await;

            if providers.is_empty() {
                return Err(format!("Could not find provider for file {}.", name).into());
            }

            let requests = providers.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });

            let file = futures::future::select_ok(requests).await;

            let res = match file {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };

            println!("{}", res.len());

            /*
            let providers1 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[0])).await;
            let providers2 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[1])).await;
            let providers3 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[2])).await;
            let providers4 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[3])).await;
            let providers5 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[4])).await;
            let providers6 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[5])).await;
            let providers7 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[6])).await;
            let providers8 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[7])).await;
            let providers9 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[8])).await;
            let providers10 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[9])).await;
            let providers11 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[10])).await;
            let providers12 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[11])).await;
            let providers13 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[12])).await;
            let providers14 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[13])).await;
            let providers15 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[14])).await;
            let providers16 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[15])).await;
            let providers17 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[16])).await;
            let providers18 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[17])).await;
            let providers19 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[18])).await;
            let providers20 = network_client.clone().get_providers(format!("{}.shards.{}", name.clone(), v[19])).await;



            if providers1.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[0]).into());
            }
            if providers2.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[1]).into());
            }
            if providers3.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[2]).into());
            }
            if providers4.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[3]).into());
            }
            if providers5.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[4]).into());
            }
            if providers6.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[5]).into());
            }
            if providers7.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[6]).into());
            }
            if providers8.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[7]).into());
            }
            if providers9.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[8]).into());
            }
            if providers10.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[9]).into());
            }
            if providers11.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[10]).into());
            }
            if providers12.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[11]).into());
            }
            if providers13.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[12]).into());
            }
            if providers14.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[13]).into());
            }
            if providers15.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[14]).into());
            }
            if providers16.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[15]).into());
            }
            if providers17.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[16]).into());
            }
            if providers18.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[17]).into());
            }
            if providers19.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[18]).into());
            }
            if providers20.is_empty() {
                return Err(format!("Could not find provider for file {}.{}", name, v[19]).into());
            }

            // Request the content of the file from each node.
            let requests1 = providers1.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests2 = providers2.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests3 = providers3.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests4 = providers4.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests5 = providers5.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests6 = providers6.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests7 = providers7.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests8 = providers8.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests9 = providers9.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests10 = providers10.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests11 = providers11.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests12 = providers12.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests13 = providers13.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests14 = providers14.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests15 = providers15.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests16 = providers16.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests17 = providers17.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests18 = providers18.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests19 = providers19.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });
            let requests20 = providers20.into_iter().map(|p| {
                let mut network_client = network_client.clone();
                let name = name.clone();
                async move { network_client.request_file(p, format!("{}", name.clone())).await }.boxed()
            });




            let res1 = match futures::future::select_ok(requests1)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res2 = match futures::future::select_ok(requests2)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res3 = match futures::future::select_ok(requests3)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res4 = match futures::future::select_ok(requests4)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res5 = match futures::future::select_ok(requests5)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res6 = match futures::future::select_ok(requests6)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res7 = match futures::future::select_ok(requests7)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res8 = match futures::future::select_ok(requests8)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res9 = match futures::future::select_ok(requests9)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res10 = match futures::future::select_ok(requests10)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res11 = match futures::future::select_ok(requests11)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res12 = match futures::future::select_ok(requests12)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res13 = match futures::future::select_ok(requests13)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res14 = match futures::future::select_ok(requests14)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res15 = match futures::future::select_ok(requests15)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res16 = match futures::future::select_ok(requests16)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res17 = match futures::future::select_ok(requests17)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res18 = match futures::future::select_ok(requests18)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res19 = match futures::future::select_ok(requests19)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };
            let res20 = match futures::future::select_ok(requests20)
                .await {
                Err(why) => panic!("{:?}", why),
                Ok(file) => {
                    file.0
                },
            };

            println!("yay");*/
        }
    }

    Ok(())
}

#[derive(Parser, Debug)]
#[clap(name = "libp2p file sharing example")]
struct Opt {
    /// Fixed value to generate deterministic peer ID.
    #[clap(long)]
    secret_key_seed: Option<u8>,

    #[clap(long)]
    group: Option<u64>,

    #[clap(long)]
    peer: Option<Multiaddr>,

    #[clap(long)]
    listen_address: Option<Multiaddr>,

    #[clap(subcommand)]
    argument: CliArgument,
}

#[derive(Debug, Parser)]
enum CliArgument {
    Provide {
    },
    Get {
        #[clap(long)]
        name: String,
    },
}

/// The network module, encapsulating all network related logic.
mod network {
    use super::*;
    use async_trait::async_trait;
    use futures::channel::{mpsc, oneshot};
    use libp2p::core::either::EitherError;
    use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed, ProtocolName};
    use libp2p::{gossipsub, identity, kad};
    use libp2p::identity::ed25519;
    use libp2p::kad::record::store::MemoryStore;
    use libp2p::kad::{GetProvidersOk, Kademlia, KademliaEvent, QueryId, QueryResult};
    use libp2p::multiaddr::Protocol;
    use libp2p::request_response::{
        ProtocolSupport, RequestId, RequestResponse, RequestResponseCodec, RequestResponseEvent,
        RequestResponseMessage, ResponseChannel,
    };
    use libp2p::swarm::{ConnectionHandlerUpgrErr, SwarmBuilder, SwarmEvent};
    use libp2p::{NetworkBehaviour, Swarm};
    use std::collections::{HashMap, HashSet};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::{env, iter};
    use std::time::Duration;
    use ethers_signers::{LocalWallet, Signer};
    use libp2p::gossipsub::{IdentTopic, Topic};
    use libp2p::futures::AsyncWriteExt;
    use libp2p::gossipsub::{Gossipsub, GossipsubEvent, GossipsubMessage, MessageAuthenticity, ValidationMode};
    use libp2p::gossipsub::error::GossipsubHandlerError;
    use libp2p::identify::{Identify, IdentifyConfig, IdentifyEvent, IdentifyInfo};
    use libp2p_request_response::RequestResponseConfig;
    use crate::network::gossipsub::MessageId;


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
        group: Option<u64>
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

        let topic = IdentTopic::new("test-net");

        // Set a custom gossipsub
        let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
            .validation_mode(ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
            .message_id_fn(message_id_fn) // content-address messages. No two messages of the
            // same content will be propagated.
            .build()
            .expect("Valid config");
        // build a gossipsub network behaviour
        let mut gossipsub: gossipsub::Gossipsub =
            gossipsub::Gossipsub::new(MessageAuthenticity::Signed(id_keys.clone()), gossipsub_config)
                .expect("Correct configuration");

        // subscribes to our topic
        gossipsub.subscribe(&topic).unwrap();

        // Build the Swarm, connecting the lower layer transport logic with the
        // higher layer network behaviour logic.
        let swarm = SwarmBuilder::new(
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

        /// Respond with the provided file content to the given request.
        pub async fn respond_file(&mut self, file: Vec<u8>, channel: ResponseChannel<FileResponse>) {
            self.sender
                .send(Command::RespondFile { file, channel })
                .await
                .expect("Command receiver not to be dropped.");
        }
    }

    pub struct EventLoop {
        swarm: Swarm<ComposedBehaviour>,
        //command_sender: mpsc::Sender<Command>,
        command_receiver: mpsc::Receiver<Command>,
        event_sender: mpsc::Sender<Event>,
        pending_dial: HashMap<PeerId, oneshot::Sender<Result<(), Box<dyn Error + Send>>>>,
        pending_start_providing: HashMap<QueryId, oneshot::Sender<()>>,
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
                pending_get_providers: Default::default(),
                pending_request_file: Default::default(),
            }
        }

        pub async fn run(mut self/*, mut client: Client*/, client: Client) {
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
                            self.swarm.behaviour_mut().kademlia.get_closest_peers(to_search);
                        }
                    }

                    event = self.swarm.next() => self.handle_event(event.expect("Swarm stream to be infinite.")).await  ,
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
            >
        ) {
            match event {
                SwarmEvent::Behaviour(ComposedEvent::GossipSub(GossipsubEvent::Message {
                                                                   propagation_source: peer_id,
                                                                   message_id: id,
                                                                   message,
                                                               })) => println!(
                    "Got message: {} with id: {} from peer: {:?}",
                    String::from_utf8_lossy(&message.data),
                    id,
                    peer_id
                ),

                SwarmEvent::Behaviour(ComposedEvent::GossipSub(_)) => {}

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
                                println!("{:?}, {:?}", peer_id, addr);
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
                Command::GetProviders { file_name, sender } => {
                    let query_id = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .get_providers(file_name.into_bytes().into());
                    self.pending_get_providers.insert(query_id, sender);
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
                /*Command::SearchPeers {sender} => {
                    println!("search peer");
                    let to_search: PeerId = identity::Keypair::generate_ed25519().public().into();
                    self.swarm.behaviour_mut().kademlia.get_closest_peers(to_search);
                }*/
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
        GetProviders {
            file_name: String,
            sender: oneshot::Sender<HashSet<PeerId>>,
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
        /*SearchPeers {
            sender: oneshot::Sender<()>,
        }*/
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
            let vec = read_length_prefixed(io, 1_000_000).await?;

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
}

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use async_std::stream::Stream;
use ethers::contract::Contract;
use ethers::prelude::Middleware;
use ethers_core::types::Signature;
use libp2p::PeerId;
use regex::Regex;
use crate::libs::file::{get_file_as_byte_vec, get_files, read_dir};
use crate::network;
use crate::network::{Client, Event};
use crate::types::file_request_value::FileRequestValue;
use crate::types::file_response_value::FileResponseValue;

use futures::StreamExt;
use tokio::sync::Mutex;

pub async fn provide<T: Middleware+ 'static>(mut network_client: Arc<Mutex<Client>>, mut network_events: impl Stream<Item=Event> + std::marker::Unpin, peer_id: PeerId, contract: Contract<T>, group: u64) {
    let files_in_storage = get_files("./storage").unwrap();

    let re = Regex::new(r"^(.+).shards\.[0-9]+$").unwrap();

    let mut tmp_hash_set: HashSet<String> = HashSet::new();

    let contents = files_in_storage.iter().filter_map(|x| {
        let cap = re.captures(&x);
        return match cap {
            Some(ma) => {
                let str = ma.get(1).unwrap().as_str();

                if tmp_hash_set.contains(str) {
                    None
                } else {
                    tmp_hash_set.insert(str.to_string());
                    Some(ma.get(1).unwrap().as_str())
                }
            }
            _ => None,
        };
    }).collect::<Vec<&str>>();

    for content in contents {
        println!("{}", format!("{}.{}", content.clone(), group));
        network_client.lock().await.start_providing(format!("{}.{}", content.clone(), group)).await;
    }

    let contract = Arc::new(Mutex::new(contract));

    loop {
        match network_events.next().await {
            // Reply with the content of the file on incoming requests.
            Some(network::Event::InboundRequest { request, channel }) => {
                println!("request: {}", request);
                let contract = Arc::clone(&contract);
                let network_client = Arc::clone(&network_client);

                tokio::spawn(async move {
                    let file_request_value: FileRequestValue = serde_json::from_str(&*request).unwrap();
                    let file = file_request_value.file;
                    let address = file_request_value.address;
                    let signature = Signature::from_str(&*file_request_value.signature).unwrap();

                    //println!("{:?}", title);

                    println!("file: {}", file);
                    println!("address: {}", address);
                    println!("signature: {}", signature);

                    match signature.recover(peer_id.to_string()) {
                        Ok(address) => {
                            // TODO: check Access Right.

                            println!("{}", file);
                            let has_access_right = contract.lock().await.method::<_, bool>("hasAccessRight", (address, file.clone())).unwrap().call().await.unwrap();

                            match has_access_right {
                                true => {
                                    let mut file_content = get_file_as_byte_vec(format!("./storage/{}.shards.{}", &file, group));

                                    let mut file_proof = get_file_as_byte_vec(format!("./storage/{}.proofs.{}", &file, group));

                                    let response: FileResponseValue = FileResponseValue { file: file_content, proof: file_proof, group: group as u8 };

                                    let response_json_result = serde_json::to_string(&response).unwrap();
                                    let response_bytes = response_json_result.into_bytes();

                                    network_client.lock().await.respond_file(response_bytes, channel).await;
                                }
                                _ => {
                                    println!("No Ownership");
                                }
                            }
                        }
                        _ => {
                            println!("No");
                        }
                    };
                });
            }
            e => todo!("{:?}", e),
        }
    }
}
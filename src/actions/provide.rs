use std::str::FromStr;
use async_std::stream::Stream;
use ethers::contract::Contract;
use ethers::prelude::Middleware;
use ethers_core::types::Signature;
use libp2p::PeerId;
use crate::libs::file::{get_file_as_byte_vec, read_dir};
use crate::network;
use crate::network::{Client, Event};
use crate::types::file_request_value::FileRequestValue;
use crate::types::file_response_value::FileResponseValue;
use futures::StreamExt;

pub async fn provide<T: Middleware>(mut network_client: Client, mut network_events: impl Stream<Item=Event> + std::marker::Unpin, peer_id: PeerId, contract: Contract<T>, group: u64) {
    let contents_to_provide = read_dir("./bookshards").unwrap();

    for content in &contents_to_provide {
        println!("{}", format!("{}.{}", content.clone(), group));
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

                match signature.recover(peer_id.to_string()) {
                    Ok(address) => {
                        // TODO: check Access Right.

                        println!("{}", file);
                        let has_access_right = contract.method::<_, bool>("hasAccessRight", (address, file.clone())).unwrap().call().await.unwrap();

                        match has_access_right {
                            true => {
                                let mut file_content = get_file_as_byte_vec(format!("./bookshards/{}.shards/{}.shards.{}", &file, &file, group));

                                let mut file_proof = get_file_as_byte_vec(format!("./bookshards/{}.shards/{}.proofs.{}", &file, &file, group));

                                let response: FileResponseValue = FileResponseValue { file: file_content, proof: file_proof, group: group as u8 };

                                let response_json_result = serde_json::to_string(&response).unwrap();
                                let response_bytes = response_json_result.into_bytes();

                                network_client.respond_file(response_bytes, channel).await;
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
            }
            e => todo!("{:?}", e),
        }
    }
}
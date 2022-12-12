// PROVIDE
// cargo run -- --listen-address /ip4/127.0.0.1/tcp/40837 --secret-key-seed 1 provide
// cargo run -- --peer /ip4/127.0.0.1/tcp/40837/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X --listen-address /ip4/127.0.0.1/tcp/40840 --secret-key-seed 2 provide

// GET
// cargo run -- --peer /ip4/127.0.0.1/tcp/40837/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X --listen-address /ip4/127.0.0.1/tcp/40942 --secret-key-seed 99 get --name {file name here!}

// UPLOAD
// cargo run -- --peer /ip4/127.0.0.1/tcp/40837/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X --listen-address /ip4/127.0.0.1/tcp/45943 --secret-key-seed 199 upload --name {file name here!}

// AWS
// rpcを立ち上げる。hardhat node, hardhat run scripts/deploy も忘れず
// rpc-url = http://rpcのパブリックアドレス:8545
// bootstrap: cd d-book-repository; ./target/release/main --listen-address /ip4/0.0.0.0/tcp/40837 --secret-key-seed 1 --rpc-url ${rpc-url} provide
//
// cargo run -- --peer /ip4/127.0.0.1/tcp/40837/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X --listen-address /ip4/0.0.0.0/tcp/40942 --secret-key-seed 99 get --name 1MB_Sample

mod types;
mod libs;
mod network;
mod config;
mod command_options;
mod actions;

use crate::types::file_request_value::FileRequestValue;
use crate::types::file_response_value::FileResponseValue;
use crate::types::proof::Proof;
use crate::types::file_upload_value::FileUploadValue;
use std::collections::HashMap;
use async_std::io;
use rand::seq::SliceRandom;
use async_std::task::spawn;
use dotenv::dotenv;
use ethers::contract::Contract;
use ethers_core::abi::Abi;
use ethers_core::types::{Address, Signature};
use ethers::prelude::Provider;
use ethers::providers::Http;
use futures::prelude::*;
use libp2p::core::{identity, Multiaddr, PeerId};
use libp2p::multiaddr::Protocol;
use sha256;
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
use serde::Serialize;
use serde::Deserialize;
use crate::identity::ed25519;
use serde::ser::StdError;
use reed_solomon_erasure::galois_8::ReedSolomon;
use ethers_signers::{LocalWallet, Signer};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use network::Event;
use crate::libs::file::{get_file_as_byte_vec, read_dir};
use libs::generate_key_for_nth_group;
use config::GROUP_NUMBER;
use config::REQUIRED_SHARDS;
use libs::check_proof::check_proof;
use types::contract_data::ContractData;
use command_options::{Opt, CliArgument};
use clap::Parser;
use crate::actions::get::get;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    dotenv().ok();

    let opt = Opt::parse();

    let mut is_provider = false;

    if let CliArgument::Provide {} = opt.argument {
        is_provider = true;
    }

    let (mut network_client, mut network_events, network_event_loop, peer_id, group) =
        network::new(opt.secret_key_seed, opt.group, is_provider).await?;

    tokio::spawn(network_event_loop.run(network_client.clone(), group.clone() as u8));

    // In case a listen address was provided use it, otherwise listen on any
    // address.
    match opt.listen_address {
        Some(addr) => {
            network_client
                .start_listening(addr)
                .await
                .expect("Listening not to fail.");
        }
        None => {
            network_client
                .start_listening("/ip4/0.0.0.0/tcp/0".parse()?)
                .await
                .expect("Listening not to fail.");
        }
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

    let rpc_rul = match opt.rpc_url {
        Some(url) => url,
        None => "http://127.0.0.1:8545/".to_string()
    };

    println!("{}", rpc_rul);

    // create contract instance for mumbai testnet
    let provider = Provider::<Http>::try_from(rpc_rul).unwrap();
    let mut f = File::open("./contract.json").expect("no file found");
    let metadata = fs::metadata("./contract.json").expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    let contract_data_str: &str = std::str::from_utf8(&buffer).unwrap();
    let contract_data: ContractData = serde_json::from_str(contract_data_str).unwrap();

    let contract = Contract::new(contract_data.contract_address, contract_data.abi, provider);

    match opt.argument {
        // Providing a file.
        CliArgument::Provide { .. } => {
            let contents_to_provide = read_dir("./bookshards")?;

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

        CliArgument::Get { name } => {
            get(network_client, name, contract).await;
        }

        CliArgument::Upload { name } => {
            let start_find_peer = Instant::now();

            for group in 0..40 {
                let providers = network_client.get_providers(format!("{}.shards.{}", name.clone(), group)).await;
                if providers.len() == 0 {
                    println!("{} is not found", group);
                } else {
                    println!("{} is found", group);
                }
            }

            let find_peer_time = start_find_peer.elapsed().as_millis();
            //network_client.get_providers(format!("sample.txt.shards.{}", i)).await;

            let start_uploading = Instant::now();
            let mut shards = Vec::new();

            for num in 0..GROUP_NUMBER {
                let buffer = get_file_as_byte_vec(format!("./uploads/{}.shards/{}.shards.{}", name, name, num));
                let proof = get_file_as_byte_vec(format!("./uploads/{}.shards/{}.proofs.{}", name, name, num));

                let file_upload_value: FileUploadValue = FileUploadValue {
                    file_name: name.clone(),
                    file: buffer,
                    proof,
                };
                let data = String::into_bytes(serde_json::to_string(&file_upload_value).unwrap());
                //tokio::spawn(async move { network_client.upload_file(buffer, num as u8).await });
                shards.push(data);
            }
            //network_client.upload_shards(shards, ).await;

            //network_client.upload_file(get_file_as_byte_vec(name), 22).await;
            let start = SystemTime::now();
            let since_the_epoch = start
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
            println!("since_the_epoch");
            println!("start uploading at {:?}", since_the_epoch);
            network_client.upload_shards(shards).await;
            let uploading_time = start_uploading.elapsed().as_millis();

            println!("find peer {}", find_peer_time);
            loop {}
        }
    }

    Ok(())
}

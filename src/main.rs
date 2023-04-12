// PROVIDE
// cargo run --release -- --listen-address /ip4/127.0.0.1/tcp/40837 --group 0 provide
// cargo run -- --peer /ip4/127.0.0.1/tcp/40837/p2p/12D3KooWCxnyz1JxC9y1RniRQVFe2cLaLHsYNc2SnXbM7yq5JBbJ --listen-address /ip4/127.0.0.1/tcp/40840 --secret-key-seed 2 provide

// GET
// cargo run -- --peer /ip4/127.0.0.1/tcp/40837/p2p/12D3KooWCxnyz1JxC9y1RniRQVFe2cLaLHsYNc2SnXbM7yq5JBbJ --listen-address /ip4/127.0.0.1/tcp/40942 --secret-key-seed 250 get --name 1MB_Sample

// UPLOAD
// cargo run -- --peer /ip4/127.0.0.1/tcp/40837/p2p/12D3KooWCxnyz1JxC9y1RniRQVFe2cLaLHsYNc2SnXbM7yq5JBbJ --listen-address /ip4/127.0.0.1/tcp/45943 --secret-key-seed 199 upload --name {file name here!}

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
use crate::actions::provide::provide;
use crate::actions::upload::upload;

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

    let rpc_rul = match opt.rpc_url {
        Some(url) => url,
        None => "http://127.0.0.1:8545/".to_string()
    };

    println!("{}", rpc_rul);

    let mut f = File::open("./contract.json").expect("no file found");
    let metadata = fs::metadata("./contract.json").expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");
    // create contract instance for ethereum network
    let provider = Provider::<Http>::try_from(rpc_rul).unwrap();
    let contract_data_str: &str = std::str::from_utf8(&buffer).unwrap();
    let contract_data: ContractData = serde_json::from_str(contract_data_str).unwrap();
    let contract = Contract::new(contract_data.contract_address, contract_data.abi, provider);

    tokio::spawn(network_event_loop.run(network_client.clone(), group.clone() as u8, contract.clone()));

    // In case a listen address was provided use it, otherwise listen on any
    // address.
    match opt.listen_address {
        Some(addr) => {
            network_client.lock().await
                .start_listening(addr)
                .await
                .expect("Listening not to fail.");
        }
        None => {
            network_client.lock().await
                .start_listening("/ip4/0.0.0.0/tcp/0".parse()?)
                .await
                .expect("Listening not to fail.");
        }
    };

    // In case the user provided an address of a peer on the CLI, dial it.
    if let Some(addr) = opt.peer {
        let peer_id: PeerId = match addr.iter().last() {
            Some(Protocol::P2p(hash)) => PeerId::from_multihash(hash).expect("Valid hash."),
            _ => return Err("Expect peer multiaddr to contain peer ID.".into()),
        };
        network_client.lock().await
            .dial(peer_id, addr)
            .await
            .expect("Dial to succeed");
    }

    match opt.argument {
        CliArgument::Provide { .. } => {
            provide(network_client, network_events, peer_id, contract, group).await;
        }
        CliArgument::Get { name } => {
            get(network_client, name, contract).await;
        }
        CliArgument::Upload { name } => {
            upload(network_client, name).await;
        }
    }

    Ok(())
}

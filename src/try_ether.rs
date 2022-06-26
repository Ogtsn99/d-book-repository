use ethers::prelude::Provider;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;
use ethers::contract::Contract;
use ethers::providers::Http;
use ethers::types::Address;
use serde::Deserialize;
use ethers_core::abi::Abi;

#[derive(Deserialize)]
struct ContractData {
    contractAddress: Address,
    abi: Abi,
}


#[tokio::main]
async fn main() {
    let filename = "./contract.json".to_string();

    let provider = Provider::<Http>::try_from("https://rpc-mumbai.maticvigil.com").unwrap();

    let mut f = File::open(&filename).expect("no file found");
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    let contract_data_str: &str = std::str::from_utf8(&buffer).unwrap();
    let contract_data: ContractData = serde_json::from_str(contract_data_str).unwrap();
    println!("{}", contract_data.contractAddress);
    println!("{:?}", contract_data.abi);
    // コントラクト取得
    let contract = Contract::new(contract_data.contractAddress, contract_data.abi, provider);
    for method in contract.methods.iter() {
        println!("{:?}", method);
    }

    let symbol = contract.method::<_, String>("symbol", ()).unwrap().call().await.unwrap();
    println!("{:?}", symbol);
}
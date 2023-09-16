use std::fs::{File, metadata};
use std::{fs, io};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::str::FromStr;
use reqwest;
use serde::Deserialize;
use serde_json::{json, Value};
extern crate tiny_keccak;
use tiny_keccak::{Hasher, Keccak};
use ethers::types::U256;

extern crate rand;

use rand::{SeedableRng, Rng};
use rand::rngs::StdRng;

const RPC_ENDPOINT: &str = "http://127.0.0.1:8545/";

#[derive(Deserialize)]
#[allow(dead_code)] // To suppress the dead_code warning
struct RpcResponse {
    id: u64,
    jsonrpc: String,
    result: Value,
}

async fn get_ethereum_block_hash(block_number: u64) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    let params = json!([format!("{:#x}", block_number), false]); // Convert the block number to hex format and indicate we don't want full transaction details

    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getBlockByNumber",
        "params": params
    });

    let response: RpcResponse = client.post(RPC_ENDPOINT)
        .json(&payload)
        .send()
        .await?
        .json()
        .await?;

    let block_hash = response.result["hash"].as_str().unwrap_or_default().to_string();

    Ok(block_hash)
}

fn get_random_value(seed: [u8; 32]) -> u64 {
    let mut rng = StdRng::from_seed(seed);
    let random_value: u64 = rng.gen();
    println!("Random u64: {}", random_value);
    random_value
}

fn get_file_size(filename: &str) -> Result<u64, std::io::Error> {
    let meta = metadata(filename)?;
    Ok(meta.len())
}

fn get_bit_from_file(path: &str, x: usize) -> Result<bool, std::io::Error> {
    let mut file = File::open(path)?;

    // Calculate the byte position and the bit position within that byte
    let byte_pos = x / 8;
    let bit_pos = x % 8;

    // Seek to the desired byte position in the file
    file.seek(SeekFrom::Start(byte_pos as u64))?;

    // Read just the required byte
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte)?;

    // Check if the bit at the specified position is set
    let is_set = (byte[0] & (1 << bit_pos)) != 0;

    Ok(is_set)
}

pub fn get_files<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
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

fn keccak256(data: &[u8]) -> String {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut result = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut result);
    result.iter().map(|byte| format!("{:02x}", byte)).collect()
}

#[tokio::main]
async fn main() {
    let block_number = 7; // replace this with desired block number
    let result = match get_ethereum_block_hash(block_number).await {
        Ok(hash) => {
            println!("Block hash for block {}: {}", block_number, hash);
            Ok(hash)
        },
        Err(error) => {
            println!("Error fetching block hash: {}", error);
            Err(error)
        },
    };

    let block_hash_string = result.unwrap();
    println!("block_hash_string {}", block_hash_string);

    // Hexadecimal string to U256
    let block_hash = U256::from_str(&block_hash_string[2..]).expect("Failed to convert hex string to U256");
    println!("block_hash {:?}", block_hash);

    let mut bool_values: Vec<bool> = Vec::new();
    let files_in_storage = get_files("./storage").unwrap();
    for file in files_in_storage {
        let path = format!("storage/{}", file);
        // println!("{}", path);
        // println!("{}", get_file_size(&path).unwrap());
        let file_size_bits = U256::from(get_file_size(&path).unwrap() * 8);
        let position = block_hash % file_size_bits;
        let b = get_bit_from_file(&path, position.as_u64() as usize).expect("Failed to get bit from file");
        bool_values.push(b);
    }
    let bytes: Vec<u8> = bool_values.iter().map(|&b| if b { 1 } else { 0 }).collect();
    let proof = sha256::digest_bytes(&bytes);
    println!("sha256 hash: {:?}", proof);
    let hash = keccak256(&bytes);
    println!("Keccak256 hash: {:?}", hash);
}
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use libp2p::identity;
use libp2p::identity::{ed25519, Keypair};
use rand::Rng;
use serde::{Deserialize, Serialize};
use crate::config;

pub fn generate_key_nth_group(n: u64) -> Keypair {
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
        if sum % config::GROUP_NUMBER == n {
            return local_key;
        } else {
            continue ;
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct NodeInfo {
    group: u8,
    seed: u8,
    peer_id: String,
    private_key: String,
}

pub fn get_key_nth_group(n: u64) -> Keypair {
    let file = File::open("./id.json").unwrap();
    let reader = BufReader::new(file);
    let json_data: Vec<NodeInfo> = serde_json::from_reader(reader).unwrap();

    let mut bytes = [0u8; 32];
    let mut seed = 0;
    for data in json_data {
        if data.group == n as u8 {
            seed = data.seed;
            break;
        }
    }

    bytes[0] = seed;
    let secret_key = ed25519::SecretKey::from_bytes(&mut bytes).expect(
        "this returns `Err` only if the length is wrong; the length is correct; qed",
    );
    identity::Keypair::Ed25519(secret_key.into())
}

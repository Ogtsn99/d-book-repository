use ethers::prelude::Middleware;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use ethers::contract::Contract;
use futures::FutureExt;
use rand::prelude::SliceRandom;
use reed_solomon_erasure::galois_8::ReedSolomon;
use tokio::sync::Mutex;
use crate::config::{GROUP_NUMBER, REQUIRED_SHARDS};
use crate::libs::check_proof::check_proof;
use crate::network::Client;
use crate::types::file_response_value::FileResponseValue;
use crate::types::proof::Proof;

pub async fn get<T: Middleware>(mut network_client: Arc<Mutex<Client>>, name: String, contract: Contract<T>) {
    let start = Instant::now();
    let mut cand = (0..40).collect::<Vec<u8>>();

    let mut rng = rand::thread_rng();

    cand.shuffle(&mut rng);

    println!("{:?}", cand);

    for (i, group) in cand.iter().enumerate() {
        if i == 20 {
            break;
        }
        let providers = network_client.clone().lock().await.get_providers(format!("{}.shards.{}", name.clone(), group)).await;
        if providers.len() == 0 {
            println!("{} is not found", group);
        }
    }

    let find_peer_time = start.elapsed().as_millis();

    let mut shards: Vec<_> = vec![None; GROUP_NUMBER as usize];

    // ファイルダウンロード
    let start_downloading = Instant::now();
    let file_name = name.clone();

    let requests_ = async move { network_client.lock().await.get_shards(file_name).await }.boxed();

    let results = requests_.await;

    let mut proofs = HashMap::new();

    for result in results {
        let mut v = result.unwrap();

        let file_response_value: FileResponseValue = serde_json::from_str(&String::from_utf8(v).unwrap()).unwrap();

        let file = file_response_value.file;
        let proof_string = String::from_utf8(file_response_value.proof).unwrap();
        let proof: Proof = serde_json::from_str(&proof_string).unwrap();

        let group = file_response_value.group;
        //println!("group insert {}", group);
        proofs.insert(group, proof);
        //println!("{:?}", proofs.get(&group).unwrap().proof);

        println!("group: {}, size:{}", group, file.len());
        shards[group as usize] = Some(file);
    }

    let downloading_time = start_downloading.elapsed().as_millis();

    // ハッシュ値の確認
    let start_checking_hash = Instant::now();
    let root = contract.method::<_, String>("merkleRootOf", name.clone()).unwrap().call().await.unwrap();
    for (group, shard) in shards.iter().enumerate() {
        match shard {
            Some(x) => {
                println!("group get from {}", group);
                if !check_proof(sha256::digest_bytes(x), &proofs.get(&(group as u8)).unwrap().proof, &root) {
                    println!("Invalid hashes or proofs");
                }
            }
            None => {}
        }
    }

    let checking_hash_time = start_checking_hash.elapsed().as_millis();

    // 復元
    let r = ReedSolomon::new(REQUIRED_SHARDS as usize, (GROUP_NUMBER - REQUIRED_SHARDS) as usize).unwrap();
    let start_decoding = Instant::now();
    r.reconstruct_data(&mut shards).unwrap();

    let mut file = Vec::<u8>::new();

    for (i, shard) in shards.into_iter().enumerate() {
        if i == REQUIRED_SHARDS as usize {
            break;
        }
        file.append(&mut shard.unwrap());
    }

    let decoding_time = start_decoding.elapsed().as_millis();

    let start_saving = Instant::now();
    // 保存
    std::fs::write(format!("download/{}", name), file).unwrap();
    let saving_time = start_saving.elapsed().as_millis();

    println!("find peers {} ms", find_peer_time);
    println!("リクエストからダウンロードまで: {}", downloading_time);
    println!("ハッシュ確認: {}", checking_hash_time);
    println!("復元: {}", decoding_time);
    println!("保存: {}", saving_time);
    println!("合計: {}", start.elapsed().as_millis());
}
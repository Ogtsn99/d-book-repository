use std::process;
use crate::config::{GROUP_NUMBER, REQUIRED_SHARDS};
use crate::libs::file::get_file_as_byte_vec;
use crate::network::Client;
use crate::types::file_upload_value::FileUploadValue;
use crate::{config, libs};

use std::time::{Instant, SystemTime, UNIX_EPOCH};
use libs::erasure_coding;

pub async fn upload(mut network_client: Client, name: String,) {
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
    let mut file_upload_values: Vec<FileUploadValue> = Vec::new();

    let content_buffer = get_file_as_byte_vec(format!("{}", name));
    let (shards, proofs, root) = erasure_coding::create_shards_and_proofs(content_buffer,REQUIRED_SHARDS as usize, (GROUP_NUMBER - REQUIRED_SHARDS) as usize);

    //  TODO: ここでrootをスマコンに登録する？

    for i in 0_u64..GROUP_NUMBER {
        file_upload_values.push(FileUploadValue {
            file_name: name.clone(),
            file: shards[i as usize].clone(),
            proof: proofs[i as usize].clone().into_bytes(),
        });
    }

    let upload_items = file_upload_values.iter()
        .map(|file_upload_value|
            String::into_bytes(serde_json::to_string(&file_upload_value).unwrap())).collect();

    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    println!("since_the_epoch");
    println!("start uploading at {:?}", since_the_epoch);

    network_client.upload_shards(upload_items).await;
    let uploading_time = start_uploading.elapsed().as_millis();

    println!("find peer {}", find_peer_time);

    loop{}
}
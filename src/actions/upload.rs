use std::time::{Instant, SystemTime, UNIX_EPOCH};
use crate::config::GROUP_NUMBER;
use crate::libs::file::get_file_as_byte_vec;
use crate::network::Client;
use crate::types::file_upload_value::FileUploadValue;

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

    loop{}
}
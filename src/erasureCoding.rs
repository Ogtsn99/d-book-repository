
#[macro_use(shards)]
extern crate reed_solomon_erasure;

use std::{env, fs};
use std::fs::File;
use std::io::Read;
use std::mem::swap;
use std::time::Instant;
use reed_solomon_erasure::galois_8::ReedSolomon;
use sha256;
use serde::{Serialize, Deserialize};
use serde_json;

#[derive(Serialize)]
struct MerkleProof {
    proof: Vec<String>,
}

fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
    let mut f = File::open(&filename).expect("no file found");
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

fn calc_hash_from_two(s1: &String, s2: &String) -> String {
    if s1 < s2 {
        sha256::digest(s1.clone() + &*s2.clone())
    } else {
        sha256::digest(s2.clone() + &*s1.clone())
    }
}

fn check_proof(mut s1: String, proofs: &Vec<String>, root: &String) -> bool {
    for proof in proofs {
        s1 = calc_hash_from_two(&s1, proof);
    }
    s1 == *root
}

fn calcMerkleTree(shards: Vec<Vec<u8>>, name: &String) {
    let mut leaves: Vec<String> = shards
        .iter()
        .map(|x| sha256::digest_bytes(x))
        .collect();
    println!("{:?}", leaves);

    let n = leaves.len();
    let mut sz = 1;
    while sz < n {
        sz <<= 1;
    }
    sz *= 2;

    let mut mt = vec!["".to_string(); sz-1];

    for i in sz / 2 .. sz / 2 + n {
        mt[i-1] = leaves[i - sz/2].clone();
    }

    for i in (0..sz/2-1).rev() {
        mt[i] = calc_hash_from_two(&mt[i*2 + 1], &mt[i*2+2]);
    }

    for i in 0..n {
        let mut j = sz / 2 - 1 + i;
        //println!("{} {}", i, mt[j]);
        let mut proofs = Vec::<String>::new();
        while j >= 1 {
            if j % 2 == 0 {
                proofs.push(mt[j-1].clone());
            } else {
                proofs.push(mt[j+1].clone());
            }
            j = (j-1) / 2;
        }
        //println!("{:?}", proofs);
        assert!(check_proof(mt[sz / 2 - 1 + i].clone(), &proofs, &mt[0]));
        let merkle_proof = MerkleProof {proof: proofs};
        let serialized = serde_json::to_string(&merkle_proof).unwrap();
        std::fs::write(format!("{}.shards/{}.proofs.{}", name, name, i.to_string()), serialized).unwrap();
    }

    std::fs::write(format!("{}.shards/{}.proofs.root", name, name), mt[0].to_string()).unwrap();
}

fn main () {
    let args: Vec<String> = env::args().collect();

    //println!("{:?}", args);

    if args.len() != 4 {
        eprintln!("4 arguments must be passed, now it is only {}", args.len());
    }

    let buffer = get_file_as_byte_vec(&args[1]);

    let n: usize = args[2].parse::<usize>().unwrap();
    let k: usize = args[3].parse::<usize>().unwrap();

    let chunk_size = (buffer.len() + n-1) / n;

    let mut chunks: Vec<Vec<u8>> = buffer.chunks(chunk_size).map(|chunk| chunk.to_vec()).collect();

    let last_index = chunks.len() - 1;
    let mut number_to_add = chunk_size - chunks.last().unwrap().len();

    while number_to_add > 0 {
        chunks[last_index].push(0);
        number_to_add -= 1;
    }

    for _ in 0..k {
        chunks.push(vec![0; chunk_size]);
    }

    let r = ReedSolomon::new(n, k).unwrap();

    //println!("{:?}", chunks);

    let mut master_copy: Vec<Vec<u8>> = chunks;

    println!("{} {} {} ", n, k, master_copy.len());

    let now = Instant::now();
    {
        r.encode(&mut master_copy).unwrap();
    }
    let elapsed_time = now.elapsed();
    println!("encoding took {} mill sec.", elapsed_time.as_millis());

    //println!("{:?}", master_copy);

    fs::create_dir(format!("{}.shards", &args[1]));

    calcMerkleTree(master_copy.clone(), &args[1]);

    for (i, v) in master_copy.iter().enumerate() {
        std::fs::write(format!("{}.shards/{}.shards.{}", &args[1], &args[1], i.to_string()), v).unwrap();
    };

    // Make a copy and transform it into option shards arrangement
    // for feeding into reconstruct_shards
    let mut shards: Vec<_> = master_copy.iter().cloned().map(Some).collect();

    for i in 0..k {
        shards[i] = None;
    }

    //println!("いくつか削除 {:?}", shards);

    let now = Instant::now();
    {
        // Try to reconstruct missing shards
        r.reconstruct_data(&mut shards).unwrap();
    }
    let elapsed_time = now.elapsed();
    println!("decoding took {} mill sec.", elapsed_time.as_millis());

    // Convert back to normal shard arrangement
    let result: Vec<_> = shards.into_iter().filter_map(|x| x).collect();

    /*assert!(r.verify(&result).unwrap());
    assert_eq!(master_copy, result);*/

    for i in 0..n {
        assert_eq!(master_copy[i], result[i]);
    }

    //println!("回復 {:?}", result);
}
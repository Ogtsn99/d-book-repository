use std::str::FromStr;
use ethers_signers::{LocalWallet, Signer};
use ethers_core::{k256::ecdsa::SigningKey, types::TransactionRequest};
use dotenv::dotenv;
use std::env;
use ethers_core::types::Signature;

#[async_std::main]
async fn main() {
    dotenv().ok();

    Account::from_str("0x724a077F4A5012744327b1a5a7E2649cdEe26F05");
    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    let wallet = LocalWallet::from_str(&private_key).unwrap();
    //let signature = wallet.sign_message("hello world").await.unwrap();
    let signature = Signature::from_str("cc17cefe8008e6abacfc261324726aca827fd78036e09b3c08a0a78e6f573ffb680b2af9934bf15196cbb6ae80971a0756acd373720de05dc640583c0a051b931b").unwrap();

    match signature.verify("hello world", wallet.address()) {
        Ok(_) => {
            println!("Yes!");
        }
        _ => {
                println!("OMG");
        }
    };
}

use ethers::abi::{Abi, Address};
use serde::Deserialize;


#[derive(Deserialize)]
pub struct ContractData {
    pub(crate) contract_address: Address,
    pub(crate) abi: Abi,
}
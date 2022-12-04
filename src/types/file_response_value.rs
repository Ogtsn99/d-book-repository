use serde::Serialize;
use serde::Deserialize;

#[derive(Serialize)]
#[derive(Deserialize)]
pub struct FileResponseValue {
    pub file: Vec<u8>,
    pub proof: Vec<u8>,
    pub group: u8,
}
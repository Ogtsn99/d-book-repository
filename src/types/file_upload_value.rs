use serde::Serialize;
use serde::Deserialize;

#[derive(Serialize)]
#[derive(Deserialize)]
pub struct FileUploadValue {
    pub file_name: String,
    pub file: Vec<u8>,
    pub proof: Vec<u8>,
}
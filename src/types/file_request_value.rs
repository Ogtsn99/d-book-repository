use serde::Serialize;
use serde::Deserialize;

#[derive(Serialize)]
#[derive(Deserialize)]
pub struct FileRequestValue {
    pub file: String,
    pub address: String,
    pub signature: String,
}
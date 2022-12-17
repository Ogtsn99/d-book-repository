use serde::Serialize;
use serde::Deserialize;

#[derive(Serialize)]
#[derive(Deserialize)]
pub struct Proof {
    pub proof: Vec<String>
}
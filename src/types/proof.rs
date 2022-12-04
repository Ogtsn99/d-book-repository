use serde::Serialize;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Proof {
    pub proof: Vec<String>
}
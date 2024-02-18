use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AskBalanceRequest {
    pub document_number: String,
}

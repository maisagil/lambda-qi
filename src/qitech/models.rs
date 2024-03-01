use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AskBalanceRequest {
    pub document_number: String,
}

#[derive(Deserialize, Debug)]
pub struct AskBalanceResponse {
    document_number: String,
    available_balance_key: String,
    status: String,
    status_events: serde_json::Value,
}

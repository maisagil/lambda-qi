mod client;
mod models;

pub use models::*;

use reqwest::StatusCode;

use crate::configuration::QIClientSettings;

use self::client::{ClientError, Method, QiTechClient};

use serde::Deserialize;
use serde::Serialize;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderStandardError {
    code: String,
    description: String,
    title: String,
    translation: String,
}

pub struct QiTechProvider {
    client: QiTechClient,
}

impl QiTechProvider {
    pub fn new(client: QIClientSettings) -> Self {
        let client = QiTechClient::new(
            client.base_url,
            client.api_key,
            client.private_key,
            Some(client.private_key_password),
            client.provider_pub_key,
        );
        Self { client }
    }
}

impl QiTechProvider {
    pub async fn ask_for_balance(&self, data: AskBalanceRequest) -> Result<String, ProviderError> {
        let client = &self.client;
        let request = client
            .get_request(Method::POST, "/baas/v2/fgts/available_balance")
            .json(&data);
        let response = client.execute_request(request).await?;

        let body = match response.status() {
            StatusCode::OK => {
                let body = response.text().await;
                body.map_err(|e| ProviderError::ResponseParse(e.to_string()))
            }
            StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST => {
                let body = response.text().await;
                body.map_err(|e| ProviderError::ResponseParse(e.to_string()))
            }
            _ => response
                .text()
                .await
                .map_err(|e| ProviderError::ResponseParse(e.to_string())),
        }?;
        Ok(body)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ProviderError {
    #[error("The response could not be parsed successfully")]
    ResponseParse(String),
    #[error(transparent)]
    Client(#[from] ClientError),
}

#[cfg(test)]
mod tests {
    use self::client::tests::create_client;
    use self::client::Response;

    use super::*;
    use claims::assert_ok;
    use jwt::ToBase64;
    use secrecy::Secret;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub const TEST_ESKEY: &str = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IUUNBUUVFSUw2ZlQvTjBYOUdJTk03N3VkQ2UwSzV5RVR4Y2h4UGQ2c0R0enFaSXlsMTJvQWNHQlN1QkJBQUsKb1VRRFFnQUVNREdHbHRBRlFocXMyUUJ1aWRCcHQvWTg3RkhqVUlCZEFDQlJ0dFlpSWV1b2RObSt5a0tzcU9vYQo1OFVZc1VnWS84YTU3V2pZZ0IwNmNhWnE1NVdBNXc9PQotLS0tLUVORCBFQyBQUklWQVRFIEtFWS0tLS0tCg==";
    pub const TEST_PUBLIC_ESKEY: &str = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUFvRFFnQUVNREdHbHRBRlFocXMyUUJ1aWRCcHQvWTg3RkhqVUlCZApBQ0JSdHRZaUlldW9kTm0reWtLc3FPb2E1OFVZc1VnWS84YTU3V2pZZ0IwNmNhWnE1NVdBNXc9PQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0K";

    impl QiTechProvider {
        pub async fn get_test(&self) -> Result<Response, ClientError> {
            let client = &self.client;
            let endpoint = "/test".to_string(); // format!("/test/{}", std::env!("QI_API_KEY"));
            let request = client.get_request(Method::GET, &endpoint);
            client.execute_request(request).await
        }

        pub async fn post_test(&self) -> Result<Response, ClientError> {
            let client = &self.client;
            let endpoint = "/test".to_string(); // format!("/test/{}", std::env!("QI_API_KEY"));
            let request = client.get_request(Method::POST, &endpoint);
            client.execute_request(request).await
        }
    }

    // impl wiremock::Match for SendEmailBodyMatcher {
    //     fn matches(&self, request: &Request) -> bool {
    //         let result: Result<serde_json::Value, _> = serde_json::from_slice(&request.body);
    //         if let Ok(body) = result {
    //             body.get("From").is_some()
    //                 && body.get("To").is_some()
    //                 && body.get("Subject").is_some()
    //                 && body.get("HtmlBody").is_some()
    //                 && body.get("TextBody").is_some()
    //         } else {
    //             false
    //         }
    //     }
    // }

    #[tokio::test]
    async fn get_test_returns_200() {
        let mock_server = MockServer::start().await;
        let client = create_provider(mock_server.uri());
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let response = client.get_test().await;
        println!("{:?}", response);
        assert_ok!(response);
    }

    #[tokio::test]
    async fn ask_for_balance_requests_has_a_valid_request_body() {
        todo!()
    }

    #[tokio::test]
    async fn ask_for_balance_returns_200() {
        let body = r#"{"document_number": "05577889944"}"#;
        let body = serde_json::from_str::<AskBalanceRequest>(body).unwrap();
        let mock_server = MockServer::start().await;
        let provider = create_provider(mock_server.uri());
        Mock::given(method("POST"))
            .and(path("/baas/v2/fgts/available_balance"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "available_balance_key": "7521981f-0b06-43d2-9a75-d3a1f215fbbf",
                "document_number": "06568225037",
                "status": "pending",
                "status_events": [{
                    "event_datetime": "2022-12-26T13:36:16",
                    "status": "pending"
                }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let response = provider.ask_for_balance(body).await;
        assert_ok!(response);
    }

    #[tokio::test]
    async fn qi_tech_receives_a_valid_request() {
        let body = r#"{"document_number": "05577889944"}"#;
        let body = serde_json::from_str::<AskBalanceRequest>(body).unwrap();
        let mock_server = MockServer::start().await;
        let provider = create_provider(mock_server.uri());
        Mock::given(method("POST"))
            .and(path("/baas/v2/fgts/available_balance"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "available_balance_key": "7521981f-0b06-43d2-9a75-d3a1f215fbbf",
                "document_number": "06568225037",
                "status": "pending",
                "status_events": [{
                    "event_datetime": "2022-12-26T13:36:16",
                    "status": "pending"
                }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let response = provider.ask_for_balance(body).await;
        assert_ok!(response);

        let received_request = mock_server
            .received_requests()
            .await
            .unwrap()
            .pop()
            .unwrap();
        println!("Request: {:?}", received_request);
        println!("Body: {:?}", received_request.body.to_base64());
    }

    fn create_provider(base_url: String) -> QiTechProvider {
        let client = create_client(
            base_url,
            Secret::new("superverysecretkey".to_string()),
            TEST_PUBLIC_ESKEY.to_string(),
        );
        QiTechProvider { client }
    }
}

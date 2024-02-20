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
    pub async fn ask_for_balance(
        &self,
        data: AskBalanceRequest,
    ) -> Result<serde_json::Value, ProviderError> {
        let client = &self.client;
        let request = client
            .get_request(Method::POST, "/baas/v2/fgts/available_balance")
            .json(&data);
        let response = client.execute_request(request).await?;
        // println!("{:?}", &response);

        let body = match response.status() {
            StatusCode::OK => {
                let body = response.json::<serde_json::Value>().await;
                body.map_err(|e| ProviderError::ResponseParse(e.to_string()))
            }
            StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST => {
                let body = response.json::<serde_json::Value>().await;
                body.map_err(|e| ProviderError::ResponseParse(e.to_string()))
            }
            _ => todo!(),
        }?;
        Ok(body)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ProviderError {
    #[error("The provider returned an error {0}")]
    Provider(serde_json::Value),
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
    use openssl::pkey::PKey;
    use secrecy::Secret;
    // use fake::{Fake, Faker};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub const TEST_ESKEY: &str = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1JSGNBZ0VCQkVJQnJpc3hBNWY5SjlGM21iS0ZKUmIwdWQyMXYwTDkxbFd1NzVjNFdtZWJvN1J0aHF5dDNWam0KSmxGckN1OExmOFV1SXlxWG12KzFzTmdpeklpYlJqaUhPeFNnQndZRks0RUVBQ09oZ1lrRGdZWUFCQUFNRGdEUQpiV29xMGdkK1c2ZGg0MkFZaWZ2WUI1T2lqVlQrazdKckVrcWdkbGZ2U0ZwQ1hxejZ1ME5IV25SU2ZKL1hXNDZGCjNVcENSNllOT1YxKzk5Zkx0Z0J0bmR1aTR1R2dOOFU2OXFHKy9PNktQdUdFMWFaWXdnRjhNN1F0ZEI4b0dXa1kKcFdCTlFMUlBDZFpybDNOUTBtaGZSdi9zV0tybFVxdHBHdm0yY2dEc3BnPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=";
    pub const TEST_PUBLIC_ESKEY: &str = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHYk1CQUdCeXFHU000OUFnRUdCU3VCQkFBakE0R0dBQVFBREE0QTBHMXFLdElIZmx1blllTmdHSW43MkFlVApvbzFVL3BPeWF4SktvSFpYNzBoYVFsNnMrcnREUjFwMFVueWYxMXVPaGQxS1FrZW1EVGxkZnZmWHk3WUFiWjNiCm91TGhvRGZGT3ZhaHZ2enVpajdoaE5XbVdNSUJmRE8wTFhRZktCbHBHS1ZnVFVDMFR3bldhNWR6VU5Kb1gwYi8KN0ZpcTVWS3JhUnI1dG5JQTdLWT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";

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

    fn create_provider(base_url: String) -> QiTechProvider {
        let client = create_client(
            base_url,
            Secret::new(TEST_ESKEY.to_string()),
            TEST_PUBLIC_ESKEY.to_string(),
        );
        QiTechProvider { client }
    }
}

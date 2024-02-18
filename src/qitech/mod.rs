mod client;
mod models;

pub use models::*;

use reqwest::StatusCode;
use secrecy::Secret;

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
    pub fn new() -> Self {
        let base_url = std::env!("QI_BASE_URL").to_string();
        let api_key = Secret::new(std::env!("QI_API_KEY").to_string());
        let client_private_key = Secret::new(std::env!("QI_CLIENT_PRIVATE_KEY").to_string());
        let client_private_key_password =
            Secret::new(std::env!("QI_CLIENT_PRIVATE_KEY_PASSWORD").to_string());
        let provider_public_key = std::env!("QI_PUBLIC_KEY").to_string();
        let client = QiTechClient::new(
            base_url,
            api_key,
            client_private_key,
            Some(client_private_key_password),
            provider_public_key,
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
    // use fake::{Fake, Faker};
    use secrecy::Secret;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub const TEST_ESKEY: &str = r#"-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBrisxA5f9J9F3mbKFJRb0ud21v0L91lWu75c4Wmebo7Rthqyt3Vjm
JlFrCu8Lf8UuIyqXmv+1sNgizIibRjiHOxSgBwYFK4EEACOhgYkDgYYABAAMDgDQ
bWoq0gd+W6dh42AYifvYB5OijVT+k7JrEkqgdlfvSFpCXqz6u0NHWnRSfJ/XW46F
3UpCR6YNOV1+99fLtgBtndui4uGgN8U69qG+/O6KPuGE1aZYwgF8M7QtdB8oGWkY
pWBNQLRPCdZrl3NQ0mhfRv/sWKrlUqtpGvm2cgDspg==
-----END EC PRIVATE KEY-----
"#;
    pub const TEST_PUBLIC_ESKEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQADA4A0G1qKtIHflunYeNgGIn72AeT
oo1U/pOyaxJKoHZX70haQl6s+rtDR1p0Unyf11uOhd1KQkemDTldfvfXy7YAbZ3b
ouLhoDfFOvahvvzuij7hhNWmWMIBfDO0LXQfKBlpGKVgTUC0TwnWa5dzUNJoX0b/
7Fiq5VKraRr5tnIA7KY=
-----END PUBLIC KEY-----
"#;

    impl QiTechProvider {
        pub async fn get_test(&self) -> Result<Response, ClientError> {
            let client = &self.client;
            let endpoint = format!("/test/{}", std::env!("QI_API_KEY"));
            let request = client.get_request(Method::GET, &endpoint);
            client.execute_request(request).await
        }

        pub async fn post_test(&self) -> Result<Response, ClientError> {
            let client = &self.client;
            let endpoint = format!("/test/{}", std::env!("QI_API_KEY"));
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
        let client = create_client(base_url);
        QiTechProvider { client }
    }
}

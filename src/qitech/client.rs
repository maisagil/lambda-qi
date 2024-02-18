use std::fmt::{Debug, Display};

use base64::Engine as _;
use chrono::prelude::Utc;
use jwt::algorithm::openssl::PKeyWithDigest;
use jwt::{header::HeaderType, AlgorithmType, Header, SignWithKey, Token, VerifyWithKey};
use openssl::pkey::{PKey, Private, Public};
use reqwest::{header, Body, Client, RequestBuilder};
use secrecy::{ExposeSecret, Secret};

pub type Method = reqwest::Method;
pub type Request = reqwest::Request;
pub type Response = reqwest::Response;
pub type Url = reqwest::Url;

/// Client that makes authed requests to QiTech
pub struct QiTechClient {
    http_client: Client,
    base_url: Url,
    private_key: PKey<Private>,
    provider_public_key: PKey<Public>,
    api_key: Secret<String>,
}

impl QiTechClient {
    pub fn new(
        base_url: String,
        api_key: Secret<String>,
        pkey: Secret<String>,
        pkey_password: Option<Secret<String>>,
        provider_public_key: String,
    ) -> Self {
        let private_key = match pkey_password {
            Some(password) => {
                let private_key = openssl::ec::EcKey::private_key_from_pem_passphrase(
                    pkey.expose_secret().as_bytes(),
                    password.expose_secret().as_bytes(),
                )
                .unwrap();
                PKey::from_ec_key(private_key).expect("PKey should be a valid EC key")
            }
            None => {
                let private_key =
                    openssl::ec::EcKey::private_key_from_pem(pkey.expose_secret().as_bytes())
                        .unwrap();
                PKey::from_ec_key(private_key).expect("PKey should be a valid EC key")
            }
        };

        let provider_public_key = PKey::public_key_from_pem(provider_public_key.as_bytes())
            .expect("provider_public_key should be valid PKey");
        let http_client = Client::new();
        let base_url = Url::parse(&base_url).expect("Should be able to parse base url");
        Self {
            http_client,
            base_url,
            private_key,
            provider_public_key,
            api_key,
        }
    }

    pub fn new_with_base64_pkey(
        base_url: String,
        api_key: Secret<String>,
        base64_pkey: Secret<String>,
        pkey_password: Secret<String>,
        provider_public_key: String,
    ) -> Self {
        let private_key = QiTechClient::read_pkey(base64_pkey, pkey_password);
        let provider_public_key =
            PKey::public_key_from_pem(&QiTechClient::decode_base64(provider_public_key))
                .expect("Should be able to create PKey");
        let http_client = Client::new();
        let base_url = Url::parse(&base_url).expect("Should be able to parse base url");
        Self {
            http_client,
            base_url,
            private_key,
            provider_public_key,
            api_key,
        }
    }

    fn decode_base64(base64_pkey: String) -> Vec<u8> {
        let mut buf = vec![0; base64_pkey.len() * 4 / 3 + 4];
        let bytes_written = base64::engine::general_purpose::STANDARD
            .decode_slice(base64_pkey, &mut buf)
            .expect("Should be able to decode base64");
        buf.truncate(bytes_written);
        buf
    }

    /// read the private key from a base64 secret.
    fn read_pkey(base64_pkey: Secret<String>, pkey_password: Secret<String>) -> PKey<Private> {
        let pkey = PKey::private_key_from_pem_passphrase(
            &QiTechClient::decode_base64(base64_pkey.expose_secret().clone()),
            pkey_password.expose_secret().as_bytes(),
        )
        .expect("Should be able to create PKey");
        pkey
    }

    /// get the private key with digest to compute the jwt.
    fn get_digest<T>(pkey: PKey<T>) -> PKeyWithDigest<T> {
        PKeyWithDigest {
            digest: openssl::hash::MessageDigest::sha512(),
            key: pkey,
        }
    }

    fn encode_body(pkey: PKey<Private>, body: &Body) -> Result<(String, String), ClientError> {
        let pkey = QiTechClient::get_digest(pkey);
        let header = Header {
            algorithm: AlgorithmType::Es512,
            type_: Some(HeaderType::JsonWebToken),
            ..Default::default()
        };

        let body = String::from_utf8(
            body.as_bytes()
                .ok_or_else(|| ClientError::InvalidRequestBody)?
                .to_vec(),
        )
        .map_err(|_| ClientError::InvalidRequestBody)?;

        let encoded_body_token = Token::new(header, body).sign_with_key(&pkey)?;

        let encoded_body = String::from(encoded_body_token.as_str());

        let md5_hash = format!("{:x}", md5::compute(encoded_body_token.as_str()));

        Ok((encoded_body, md5_hash))
    }

    fn decode_body(pkey: PKey<Public>, token_str: &str) -> Result<String, ClientError> {
        let pkey = QiTechClient::get_digest(pkey);

        let token: Token<Header, String, _> = token_str.verify_with_key(&pkey)?;
        Ok(token.claims().clone())
    }

    fn encode_headers(
        &self,
        method: Method,
        md5_hash: impl Display,
        content_type: impl Display,
        endpoint: impl Display,
    ) -> Result<String, ClientError> {
        let pkey = QiTechClient::get_digest(self.private_key.clone());
        let api_key = self.api_key.clone();
        let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let epoch_timestamp = Utc::now().timestamp();
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}\n{}",
            method, md5_hash, content_type, timestamp, endpoint
        );

        let header = Header {
            algorithm: AlgorithmType::Es512,
            type_: Some(HeaderType::JsonWebToken),
            ..Default::default()
        };

        let claims = QiClaims::new(
            api_key.expose_secret().clone(),
            epoch_timestamp,
            string_to_sign,
        );

        let encoded_header_token = Token::new(header, claims).sign_with_key(&pkey)?;

        let authorization_header = format!(
            "QIT {}:{}",
            api_key.expose_secret(),
            encoded_header_token.as_str()
        );
        Ok(authorization_header)
    }

    // generate encoded_body and auth headers for request
    fn authenticate_request(&self, request: Request) -> Result<Request, ClientError> {
        let request_body = request.body();
        let request_headers = request.headers();

        let (encoded_body, md5_hash) = match request_body {
            Some(body) => QiTechClient::encode_body(self.private_key.clone(), body)?,
            None => ("".to_string(), "".to_string()),
        };

        let content_type = request_headers
            .get(header::CONTENT_TYPE)
            .ok_or_else(|| ClientError::MissingHeader)?
            .to_str()
            .map_err(|_| ClientError::MissingHeader)?;
        let url = request.url();
        let endpoint = url.path();
        let method = request.method();
        let authorization_header = self
            .encode_headers(method.into(), md5_hash, content_type, endpoint)?
            .parse()?;

        let mut new_request = request
            .try_clone()
            .ok_or_else(|| ClientError::InvalidRequestBody)?;
        let request_headers = new_request.headers_mut();
        request_headers.insert(header::AUTHORIZATION, authorization_header);

        let api_key = self.api_key.expose_secret().to_string().parse()?;
        request_headers.insert("API-CLIENT-KEY", api_key);

        let _ = new_request.body_mut().insert(encoded_body.into());
        Ok(new_request)
    }

    /// Get a request builder for the base url.
    /// Endpoint should start with a /
    /// ```
    /// // Example
    /// let request = get_request(Method::GET, "/test");
    /// ```
    pub fn get_request(&self, method: Method, endpoint: &str) -> RequestBuilder {
        let url = self.base_url.join(endpoint).expect("Url should be valid.");
        self.http_client
            .request(method, url)
            .header(header::CONTENT_TYPE, "application/json")
    }

    /// Authorize and execute a request.
    /// You should use this to make requests.
    pub async fn execute_request(&self, request: RequestBuilder) -> Result<Response, ClientError> {
        let request = request.build()?;
        // return a authorized request
        let request = self.authenticate_request(request)?;
        // execute the request
        Ok(self.http_client.execute(request).await?)
    }
}

/// Claims for JWT token generation, in the format that the QiTech wants.
#[derive(serde::Serialize)]
struct QiClaims {
    sub: String,
    iat: i64,
    signature: String,
}

impl QiClaims {
    fn new(sub: String, iat: i64, signature: String) -> Self {
        Self {
            sub,
            iat,
            signature,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("Invalid request body")]
    InvalidRequestBody,
    #[error("Missing request header")]
    MissingHeader,
    #[error("Invalid request headers")]
    InvalidRequestHeaders(#[from] reqwest::header::InvalidHeaderValue),
    #[error("Client could not make the request")]
    ExecutionError(#[from] reqwest::Error),
    #[error("JWT sign or decode failed.")]
    JwtSignatureError(#[from] jwt::error::Error),
}

#[cfg(test)]
pub mod tests {
    use claims::assert_gt;

    use crate::qitech::tests::{TEST_ESKEY, TEST_PUBLIC_ESKEY};

    use super::*;

    const BASE_URL: &str = r#"http://127.0.0.1/test"#;
    const TEST_ENDPOINT: &str = "/test";
    const TEST_JSON_BODY: &str = r#"{"name":"Tester"}"#;

    #[derive(serde::Deserialize, Debug)]
    struct EncodedBody {
        encoded_body: String,
    }

    pub fn create_client(base_url: String) -> QiTechClient {
        let api_key = Secret::new(std::env!("QI_API_KEY").to_string());

        let client_private_key = Secret::new(TEST_ESKEY.to_string());
        let provider_public_key = std::env!("QI_PUBLIC_KEY").to_string();

        QiTechClient::new(
            base_url,
            api_key,
            client_private_key,
            None,
            provider_public_key,
        )
    }

    #[test]
    fn can_encode_json_body() {
        let pkey = PKey::private_key_from_pem(TEST_ESKEY.as_bytes()).unwrap();

        // return a authorized request
        let (encoded_body, md5_hash) =
            QiTechClient::encode_body(pkey, &TEST_JSON_BODY.to_string().into()).unwrap();

        assert_gt!(encoded_body.len(), 0);
        assert_gt!(md5_hash.len(), 0);
    }

    #[test]
    fn can_decode_json_body() {
        //generate Ecdsa key
        let pkey = PKey::private_key_from_pem(TEST_ESKEY.as_bytes()).unwrap();

        let pub_key = PKey::public_key_from_pem(TEST_PUBLIC_ESKEY.as_bytes()).unwrap();
        // return a authorized request
        let (encoded_body, _) =
            QiTechClient::encode_body(pkey, &TEST_JSON_BODY.to_string().into()).unwrap();

        let decoded_body = QiTechClient::decode_body(pub_key, &encoded_body).unwrap();

        assert_eq!(decoded_body, TEST_JSON_BODY);
    }

    #[test]
    fn can_encode_headers() {
        let pkey = PKey::private_key_from_pem(TEST_ESKEY.as_bytes()).unwrap();

        // return a authorized request
        let (encoded_body, md5_hash) =
            QiTechClient::encode_body(pkey, &TEST_JSON_BODY.to_string().into()).unwrap();

        assert_gt!(encoded_body.len(), 0);
        assert_gt!(md5_hash.len(), 0);
        // TODO: Validate that the headers are correct
        todo!()
    }

    #[test]
    fn can_decode_headers() {
        todo!()
    }

    #[test]
    fn json_request_is_populated_with_auth_data() {
        todo!()
    }

    #[test]
    fn empty_request_is_populated_with_auth_data() {
        todo!()
    }
}

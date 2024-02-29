use std::fmt::{Debug, Display};

use base64::Engine as _;
use chrono::prelude::*;
use josekit::jws::{JwsHeader, ES512};
use josekit::jwt::JwtPayload;
use openssl::pkey::{PKey, Private, Public};
use reqwest::{header, Client, RequestBuilder};
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
        base64_pkey: Secret<String>,
        pkey_password: Option<Secret<String>>,
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
    fn read_pkey(base64_pkey: Secret<String>, password: Option<Secret<String>>) -> PKey<Private> {
        let pkey = match password {
            Some(password) => PKey::private_key_from_pem_passphrase(
                &QiTechClient::decode_base64(base64_pkey.expose_secret().clone()),
                password.expose_secret().as_bytes(),
            )
            .expect("Should be able to create PKey"),
            None => PKey::private_key_from_pem(&QiTechClient::decode_base64(
                base64_pkey.expose_secret().clone(),
            ))
            .expect("Should be able to create PKey"),
        };
        pkey
    }

    fn encode_body(
        pkey: PKey<Private>,
        body: &serde_json::Value,
    ) -> Result<(EncodedBody, String), ClientError> {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");

        let payload: JwtPayload = JwtPayload::from_map(body.as_object().unwrap().clone()).unwrap();

        let signer = ES512
            .signer_from_der(pkey.private_key_to_der().unwrap())
            .unwrap();
        let jwt = josekit::jwt::encode_with_signer(&payload, &header, &signer).unwrap();
        // let encoded_body_token = Token::new(header, body).sign_with_key(&pkey)?;

        let md5_hash = format!("{:x}", md5::compute(jwt.as_str()));

        let encoded_body: EncodedBody = EncodedBody { encoded_body: jwt };

        Ok((encoded_body, md5_hash))
    }

    fn decode_body(pkey: PKey<Public>, token_str: &str) -> Result<serde_json::Value, ClientError> {
        // let pkey = QiTechClient::get_digest(pkey);
        //
        // let token: Token<Header, serde_json::Value, Verified> = token_str.verify_with_key(&pkey)?;
        // Ok(token.claims().clone())
        todo!()
    }

    fn encode_headers(
        pkey: PKey<Private>,
        api_key: Secret<String>,
        method: Method,
        md5_hash: impl Display,
        content_type: impl Display,
        endpoint: impl Display,
    ) -> Result<String, ClientError> {
        let epoch_timestamp = Utc::now().timestamp();
        let formated_date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}\n{}",
            method, md5_hash, content_type, formated_date, endpoint
        );

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");

        let mut payload = JwtPayload::new();

        payload.set_claim("sub", Some(api_key.expose_secret().clone().into()))?;
        payload.set_claim("iat", Some(epoch_timestamp.into()))?;
        payload.set_claim("signature", Some(string_to_sign.into()))?;

        let signer = ES512
            .signer_from_der(pkey.private_key_to_der().unwrap())
            .unwrap();
        let jwt = josekit::jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let authorization_header = format!("QIT {}:{}", api_key.expose_secret(), jwt.as_str());
        Ok(authorization_header)
    }

    // generate encoded_body and auth headers for request
    fn authenticate_request(&self, request: Request) -> Result<Request, ClientError> {
        let request_body = request.body();
        let request_headers = request.headers();

        let (encoded_body, md5_hash) = match request_body {
            Some(body) => {
                let body: serde_json::Value = serde_json::from_slice(
                    body.as_bytes()
                        .ok_or_else(|| ClientError::InvalidRequestBody)?,
                )
                .map_err(|_| ClientError::InvalidRequestBody)?;
                QiTechClient::encode_body(self.private_key.clone(), &body)?
            }
            None => todo!(),
        };

        let content_type = request_headers
            .get(header::CONTENT_TYPE)
            .ok_or_else(|| ClientError::MissingHeader)?
            .to_str()
            .map_err(|_| ClientError::MissingHeader)?;
        let url = request.url();
        let endpoint = url.path();
        let method = request.method();
        let authorization_header = QiTechClient::encode_headers(
            self.private_key.clone(),
            self.api_key.clone(),
            method.into(),
            md5_hash,
            content_type,
            endpoint,
        )?
        .parse()?;

        let mut new_request = request
            .try_clone()
            .ok_or_else(|| ClientError::InvalidRequestBody)?;
        let request_headers = new_request.headers_mut();
        request_headers.insert(header::AUTHORIZATION, authorization_header);

        let api_key = self.api_key.expose_secret().to_string().parse()?;
        request_headers.insert("api-client-key", api_key);

        let string_body = serde_json::to_vec(&encoded_body).unwrap();
        let _ = new_request
            .body_mut()
            .insert(reqwest::Body::from(string_body));

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
        // decode_body
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
struct EncodedBody {
    encoded_body: String,
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
    JwtSignatureError(#[from] josekit::JoseError),
}

#[cfg(test)]
pub mod tests {
    use claims::assert_gt;

    use crate::qitech::tests::{TEST_ESKEY, TEST_PUBLIC_ESKEY};

    use super::*;

    const BASE_URL: &str = r#"http://127.0.0.1"#;
    const TEST_ENDPOINT: &str = "/test";
    const TEST_JSON_BODY: &str = r#"{"name":"Tester"}"#;

    fn get_pkey() -> PKey<Private> {
        QiTechClient::read_pkey(Secret::new(TEST_ESKEY.to_string()), None)
    }

    fn get_pubkey() -> PKey<Public> {
        PKey::public_key_from_pem(&QiTechClient::decode_base64(TEST_PUBLIC_ESKEY.to_string()))
            .expect("Should be able to create PKey")
    }

    pub fn create_client(
        base_url: String,
        api_key: Secret<String>,
        pub_key: String,
    ) -> QiTechClient {
        let client_private_key = Secret::new(TEST_ESKEY.to_string());

        QiTechClient::new(base_url, api_key, client_private_key, None, pub_key)
    }

    #[test]
    fn can_encode_json_body() {
        let pkey = get_pkey();

        // return a authorized request
        let body = serde_json::from_str::<serde_json::Value>(TEST_JSON_BODY).unwrap();
        let (encoded_body, md5_hash) = QiTechClient::encode_body(pkey, &body).unwrap();

        assert_gt!(encoded_body.encoded_body.len(), 0);
        assert_gt!(md5_hash.len(), 0);
    }

    #[test]
    fn can_decode_json_body() {
        //generate Ecdsa key
        let pkey = get_pkey();

        let pub_key = get_pubkey();
        // return a authorized request
        let body = serde_json::from_str::<serde_json::Value>(TEST_JSON_BODY).unwrap();
        let (encoded_body, _) = QiTechClient::encode_body(pkey, &body).unwrap();

        let decoded_body = QiTechClient::decode_body(pub_key, &encoded_body.encoded_body).unwrap();

        assert_eq!(body, decoded_body);
    }

    #[test]
    fn can_encode_headers() {
        let pkey = get_pkey();

        // return a authorized request
        let body = serde_json::from_str::<serde_json::Value>(TEST_JSON_BODY).unwrap();
        let (encoded_body, md5_hash) = QiTechClient::encode_body(pkey.clone(), &body).unwrap();

        assert_gt!(encoded_body.encoded_body.len(), 0);
        assert_gt!(md5_hash.len(), 0);
        let content_type = "application/json".to_string();
        let url: Url = format!("{}{}", BASE_URL, TEST_ENDPOINT).parse().unwrap();
        let endpoint = url.path();
        let method = Method::GET;
        let authorization_header = QiTechClient::encode_headers(
            pkey.clone(),
            Secret::new("verysupersecretkey".into()),
            method,
            md5_hash,
            content_type,
            endpoint,
        )
        .unwrap();
        // TODO: Validate that the headers are correct
        assert_gt!(authorization_header.len(), 0);
    }

    #[test]
    fn can_decode_headers() {
        let pkey = get_pkey();

        let pub_key = get_pubkey();

        let body = serde_json::from_str::<serde_json::Value>(TEST_JSON_BODY).unwrap();

        let (encoded_body, _) = QiTechClient::encode_body(pkey, &body).unwrap();
        let decoded_body = QiTechClient::decode_body(pub_key, &encoded_body.encoded_body).unwrap();

        assert_eq!(body, decoded_body);
    }

    #[test]
    fn json_request_is_populated_with_auth_data() {
        let client = create_client(
            BASE_URL.into(),
            Secret::new(TEST_ESKEY.into()),
            TEST_PUBLIC_ESKEY.into(),
        );
        let request = client
            .get_request(Method::GET, TEST_ENDPOINT)
            .json(TEST_JSON_BODY)
            .build()
            .unwrap();
        let authorized_request = client.authenticate_request(request).unwrap();
        // if the serde can parse this, then the request has a valid body.
        let _ = serde_json::from_slice::<EncodedBody>(
            authorized_request.body().unwrap().as_bytes().unwrap(),
        )
        .unwrap();
        assert!(authorized_request.headers().get("API-CLIENT-KEY").is_some());
        assert!(authorized_request.headers().get("AUTHORIZATION").is_some());
    }

    #[test]
    fn empty_request_is_populated_with_auth_data() {
        let client = create_client(
            BASE_URL.into(),
            Secret::new(TEST_ESKEY.into()),
            TEST_PUBLIC_ESKEY.into(),
        );
        let request = client
            .get_request(Method::GET, TEST_ENDPOINT)
            .build()
            .unwrap();
        let authorized_request = client.authenticate_request(request).unwrap();

        assert!(authorized_request.headers().get("API-CLIENT-KEY").is_some());
        assert!(authorized_request.headers().get("AUTHORIZATION").is_some());
    }
}

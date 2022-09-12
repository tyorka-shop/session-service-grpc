mod session_service;

pub use session_service::session_service_server as server;

pub use session_service::{TokenStatus, VerifyRequest, VerifyResponse};

use tonic::Request;

use session_service::session_service_client::SessionServiceClient;
use tonic_reflection::server::{ServerReflection, ServerReflectionServer};
use log::error;

#[derive(Debug)]
pub enum VerifyError {
    Connect(tonic::transport::Error),
    Request(tonic::Status),
    Unautorized(TokenStatus),
}

impl TokenStatus {
    fn from_num(value: i32) -> Self {
        match value {
            0 => TokenStatus::Ok,
            1 => TokenStatus::Expired,
            2 => TokenStatus::NotGrunted,
            _ => TokenStatus::Invalid,
        }
    }
}

#[derive(Clone)]
pub struct Client {
    pub url: String,
}

impl Client {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
        }
    }

    pub async fn verify(&self, token: &str) -> Result<String, VerifyError> {
        let mut client = SessionServiceClient::connect(self.url.to_owned())
            .await
            .map_err(|e| {
                error!("Failed to connect to session service: {}", e);
                VerifyError::Connect(e)
            })?;

        let request = Request::new(VerifyRequest {
            token: token.to_string(),
        });

        let response = client
            .verify(request)
            .await
            .map_err(|e| {
                error!("Failed to send request: {}", e);
                VerifyError::Request(e)
            })?
            .into_inner();

        match TokenStatus::from_num(response.status) {
            TokenStatus::Ok => Ok(response.email),
            status => Err(VerifyError::Unautorized(status)),
        }
    }
}

pub fn make_reflection_service() -> ServerReflectionServer<impl ServerReflection> {
    let file_descriptor_set: &[u8] = include_bytes!("description.bin");
    tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(file_descriptor_set)
        .build()
        .unwrap()
}

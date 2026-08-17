//! Minimal fail-stop BIP340 signer for a Bitcoin statechain.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey, rand, schnorr::Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROTOCOL_VERSION: u32 = 1;
pub type CoinId = [u8; 32];
pub type Capability = [u8; 32];
pub type HandoffToken = [u8; 32];
pub const INITIAL_HANDOFF: HandoffToken = [0; 32];
pub type Enclave = Signer<21_000>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub coin_id: CoinId,
    pub initial_capability_hash: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub coin_id: CoinId,
    pub current_capability: Capability,
    pub current_handoff: HandoffToken,
    pub next_capability_hash: [u8; 32],
    pub sighash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignResponse {
    pub signature: Signature,
    pub next_handoff: HandoffToken,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoinStatus {
    pub coin_id: CoinId,
    pub signing_pubkey: XOnlyPublicKey,
    pub authorization: [u8; 32],
    pub signature_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "method", content = "params")]
pub enum Request {
    Register(RegisterRequest),
    Status { coin_id: CoinId },
    Sign(SignRequest),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "method", content = "result")]
pub enum Response {
    Status(CoinStatus),
    Signature(SignResponse),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum Error {
    #[error("coin is not registered")]
    UnknownCoin,
    #[error("enclave coin capacity is exhausted")]
    CapacityReached,
    #[error("current capability or handoff is stale")]
    Unauthorized,
    #[error("next capability is unchanged")]
    UnchangedCapability,
    #[error("signature count is exhausted")]
    SignatureCountOverflow,
}

pub fn capability_hash(capability: &Capability) -> [u8; 32] {
    tagged_hash(b"Tinylayer/Capability/v1", &[capability])
}

pub fn authorization(
    coin_id: &CoinId,
    capability_hash: &[u8; 32],
    handoff: &HandoffToken,
) -> [u8; 32] {
    tagged_hash(
        b"Tinylayer/Authorization/v1",
        &[coin_id, capability_hash, handoff],
    )
}

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    parts.iter().for_each(|part| hash.update(part));
    hash.finalize().into()
}

pub struct Signer<const LIMIT: usize> {
    coins: HashMap<CoinId, Coin>,
}

struct Coin {
    signing_key: SecretKey,
    authorization: [u8; 32],
    signature_count: u64,
    last: Option<(SignRequest, SignResponse)>,
}

impl<const LIMIT: usize> Signer<LIMIT> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            coins: HashMap::new(),
        }
    }

    pub fn handle(&mut self, request: Request) -> Result<Response, Error> {
        match request {
            Request::Register(request) => self.register(request).map(Response::Status),
            Request::Status { coin_id } => self.status(coin_id).map(Response::Status),
            Request::Sign(request) => self.sign(request).map(Response::Signature),
        }
    }

    pub fn register(&mut self, request: RegisterRequest) -> Result<CoinStatus, Error> {
        if self.coins.contains_key(&request.coin_id) {
            return self.status(request.coin_id);
        }
        if self.coins.len() >= LIMIT {
            return Err(Error::CapacityReached);
        }
        let coin = Coin {
            authorization: authorization(
                &request.coin_id,
                &request.initial_capability_hash,
                &INITIAL_HANDOFF,
            ),
            signing_key: SecretKey::new(&mut rand::thread_rng()),
            signature_count: 0,
            last: None,
        };
        let status = coin.status(request.coin_id);
        self.coins.insert(request.coin_id, coin);
        Ok(status)
    }

    pub fn status(&self, coin_id: CoinId) -> Result<CoinStatus, Error> {
        self.coins
            .get(&coin_id)
            .map(|coin| coin.status(coin_id))
            .ok_or(Error::UnknownCoin)
    }

    pub fn sign(&mut self, request: SignRequest) -> Result<SignResponse, Error> {
        let coin = self
            .coins
            .get_mut(&request.coin_id)
            .ok_or(Error::UnknownCoin)?;
        if let Some((last, response)) = &coin.last
            && last == &request
        {
            return Ok(*response);
        }
        let current_capability_hash = capability_hash(&request.current_capability);
        let expected = authorization(
            &request.coin_id,
            &current_capability_hash,
            &request.current_handoff,
        );
        if expected != coin.authorization {
            return Err(Error::Unauthorized);
        }
        if request.next_capability_hash == current_capability_hash {
            return Err(Error::UnchangedCapability);
        }
        let next_count = coin
            .signature_count
            .checked_add(1)
            .ok_or(Error::SignatureCountOverflow)?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &coin.signing_key);
        let response = SignResponse {
            signature: secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(request.sighash), &keypair),
            next_handoff: rand::random(),
        };
        let next_authorization = authorization(
            &request.coin_id,
            &request.next_capability_hash,
            &response.next_handoff,
        );
        (coin.authorization, coin.signature_count, coin.last) =
            (next_authorization, next_count, Some((request, response)));
        Ok(response)
    }
}

impl Coin {
    fn status(&self, coin_id: CoinId) -> CoinStatus {
        CoinStatus {
            coin_id,
            signing_pubkey: self.signing_key.x_only_public_key(&Secp256k1::new()).0,
            authorization: self.authorization,
            signature_count: self.signature_count,
        }
    }
}

#[cfg(feature = "workload")]
pub mod workload {
    use std::sync::Arc;

    use axum::{
        Json, Router,
        extract::{DefaultBodyLimit, State},
        http::StatusCode,
        routing::{get, post},
    };
    pub(crate) use tokio::{net::TcpListener as Tcp, sync::Mutex};

    use crate::{Enclave, Request, Response};

    pub fn router(enclave: Enclave) -> Router {
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/v1", post(handle))
            .layer(DefaultBodyLimit::max(4 * 1024))
            .with_state(Arc::new(Mutex::new(enclave)))
    }

    async fn handle(
        State(enclave): State<Arc<Mutex<Enclave>>>,
        Json(request): Json<Request>,
    ) -> Result<Json<Response>, (StatusCode, String)> {
        let result = enclave.lock().await.handle(request);
        result
            .map(Json)
            .map_err(|error| (StatusCode::CONFLICT, error.to_string()))
    }
}

#[cfg(feature = "workload")]
#[tokio::main]
pub async fn main() {
    let listener = workload::Tcp::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, workload::router(Enclave::new()))
        .await
        .expect("serve workload");
}

use std::{error::Error as _, future::Future};

use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use enclavia::Pcrs;
use enclavia_protocol::{
    CborTransport, ClientMessage, ServerMessage, attestation::test_utils::FakeAttestation,
    perform_cbor_handshake_as_responder,
};
use tinylayer_client::{
    CoinStatus, INITIAL_HANDOFF, PROTOCOL_VERSION, RegisterRequest, RemoteEnclave, RemoteError,
    SignRequest, SignResponse, authorization, capability_hash, verify_sign_response,
};
use tinylayer_enclave::{Enclave, Request, Response};
use tokio::{net::TcpListener, task::JoinHandle};

#[path = "support/mod.rs"]
mod support;
#[path = "support/ws_adapter.rs"]
mod ws_adapter;

type Transport = CborTransport<ws_adapter::WsByteStream>;

fn pcrs() -> Pcrs {
    Pcrs {
        pcr0: vec![0x11; 48],
        pcr1: vec![0x12; 48],
        pcr2: vec![0x13; 48],
    }
}

async fn spawn_server<F, Fut>(handler: F) -> (String, JoinHandle<()>)
where
    F: FnOnce(Transport) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let websocket = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let (mut transport, handshake_hash) =
            perform_cbor_handshake_as_responder(ws_adapter::wrap_ws(websocket))
                .await
                .unwrap();
        assert!(matches!(
            transport.receive::<ClientMessage>().await.unwrap(),
            ClientMessage::RequestAttestation
        ));
        transport
            .send(&ServerMessage::Attestation {
                data: FakeAttestation::with_seed(0x11, handshake_hash).encode(),
                control_nonce: [0; 32],
            })
            .await
            .unwrap();
        handler(transport).await;
    });
    (format!("ws://{address}"), task)
}

async fn receive_request(transport: &mut Transport) -> (u64, Vec<u8>) {
    match transport.receive::<ClientMessage>().await.unwrap() {
        ClientMessage::Data { id, payload } => (id, payload),
        message => panic!("unexpected client message: {message:?}"),
    }
}

async fn send_http(transport: &mut Transport, id: u64, status: u16, body: &[u8]) {
    let reason = match status {
        200 => "OK",
        409 => "Conflict",
        418 => "I'm a teapot",
        _ => "Error",
    };
    let mut payload = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    payload.extend_from_slice(body);
    transport
        .send(&ServerMessage::Data { id, payload })
        .await
        .unwrap();
}

async fn serve_enclave(mut transport: Transport, request_count: usize) {
    let mut enclave = Enclave::new();
    for _ in 0..request_count {
        let (id, payload) = receive_request(&mut transport).await;
        if payload.starts_with(b"GET /health ") {
            send_http(&mut transport, id, 200, b"ok").await;
            continue;
        }
        assert!(payload.starts_with(b"POST /v1 "));
        let body = payload
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| &payload[index + 4..])
            .unwrap();
        let request: Request = serde_json::from_slice(body).unwrap();
        match enclave.handle(request) {
            Ok(response) => {
                send_http(
                    &mut transport,
                    id,
                    200,
                    &serde_json::to_vec(&response).unwrap(),
                )
                .await;
            }
            Err(error) => send_http(&mut transport, id, 409, error.to_string().as_bytes()).await,
        }
    }
}

#[tokio::test]
async fn remote_v1_client_completes_protocol_over_attested_noise() {
    let (url, server) = spawn_server(|transport| serve_enclave(transport, 6)).await;
    let remote = RemoteEnclave::connect_debug(&url, pcrs()).await.unwrap();
    remote.health().await.unwrap();
    assert_eq!(PROTOCOL_VERSION, 1);

    let capability = [3; 32];
    let next_capability = [4; 32];
    let registration = RegisterRequest {
        coin_id: [1; 32],
        initial_capability_hash: capability_hash(&capability),
    };
    let registered = remote.register(&registration).await.unwrap();
    assert_eq!(registered.signature_count, 0);
    assert_eq!(
        registered.authorization,
        authorization(
            &registration.coin_id,
            &registration.initial_capability_hash,
            &INITIAL_HANDOFF,
        )
    );
    assert_eq!(
        remote.status(registration.coin_id).await.unwrap(),
        registered
    );

    let sign = SignRequest {
        coin_id: registration.coin_id,
        current_capability: capability,
        current_handoff: INITIAL_HANDOFF,
        next_capability_hash: capability_hash(&next_capability),
        sighash: [5; 32],
    };
    let response = remote.sign(&sign).await.unwrap();
    let completed = remote.status(sign.coin_id).await.unwrap();
    verify_sign_response(&sign, 0, &completed, &response).unwrap();
    assert_eq!(
        completed.authorization,
        authorization(
            &sign.coin_id,
            &sign.next_capability_hash,
            &response.next_handoff,
        )
    );
    assert_eq!(remote.sign(&sign).await.unwrap(), response);
    server.await.unwrap();
}

#[tokio::test]
async fn remote_client_surfaces_protocol_and_non_utf8_error_bodies() {
    let (url, server) = spawn_server(|transport| serve_enclave(transport, 1)).await;
    let remote = RemoteEnclave::connect_debug(&url, pcrs()).await.unwrap();
    let error = remote.status([9; 32]).await.unwrap_err();
    assert!(matches!(
        error,
        RemoteError::Protocol { status: 409, ref message }
            if message == "coin is not registered"
    ));
    assert_eq!(
        error.to_string(),
        "enclave returned HTTP 409: coin is not registered"
    );
    server.await.unwrap();

    let (url, server) = spawn_server(|mut transport| async move {
        let (id, _) = receive_request(&mut transport).await;
        send_http(&mut transport, id, 418, &[0xff]).await;
    })
    .await;
    let remote = RemoteEnclave::connect_debug(&url, pcrs()).await.unwrap();
    let error = remote.health().await.unwrap_err();
    assert!(matches!(
        error,
        RemoteError::Protocol { status: 418, ref message } if message == "�"
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn remote_client_rejects_malformed_and_wrong_response_variants() {
    let (url, server) = spawn_server(|mut transport| async move {
        let (id, payload) = receive_request(&mut transport).await;
        assert!(payload.starts_with(b"POST /v1 "));
        send_http(&mut transport, id, 200, b"{").await;
    })
    .await;
    let remote = RemoteEnclave::connect_debug(&url, pcrs()).await.unwrap();
    assert!(matches!(
        remote.status([1; 32]).await,
        Err(RemoteError::Json(_))
    ));
    server.await.unwrap();

    let responses = [
        Response::Signature(test_response()),
        Response::Signature(test_response()),
        Response::Status(test_status()),
    ];
    let (url, server) = spawn_server(|mut transport| async move {
        for response in responses {
            let (id, payload) = receive_request(&mut transport).await;
            assert!(payload.starts_with(b"POST /v1 "));
            send_http(
                &mut transport,
                id,
                200,
                &serde_json::to_vec(&response).unwrap(),
            )
            .await;
        }
    })
    .await;
    let remote = RemoteEnclave::connect_debug(&url, pcrs()).await.unwrap();
    let registration = RegisterRequest {
        coin_id: [1; 32],
        initial_capability_hash: [2; 32],
    };
    let sign = SignRequest {
        coin_id: registration.coin_id,
        current_capability: [3; 32],
        current_handoff: INITIAL_HANDOFF,
        next_capability_hash: [4; 32],
        sighash: [5; 32],
    };
    assert_unexpected(remote.register(&registration).await.unwrap_err());
    assert_unexpected(remote.status(registration.coin_id).await.unwrap_err());
    assert_unexpected(remote.sign(&sign).await.unwrap_err());
    server.await.unwrap();
}

#[tokio::test]
async fn production_connection_rejects_synthetic_attestation() {
    let (url, server) = spawn_server(|transport| async move { drop(transport) }).await;
    assert!(matches!(
        RemoteEnclave::connect(&url, pcrs()).await,
        Err(RemoteError::Enclavia(_))
    ));
    server.await.unwrap();
}

#[test]
fn remote_error_conversions_preserve_context() {
    let enclavia = RemoteError::from(enclavia::Error::InvalidUrl("bad URL".into()));
    assert_eq!(
        enclavia.to_string(),
        "Enclavia connection failed: Invalid URL: bad URL"
    );
    assert!(enclavia.source().is_none());

    let json_error = serde_json::from_slice::<Response>(b"{").unwrap_err();
    let json = RemoteError::from(json_error);
    assert!(json.to_string().starts_with("invalid enclave response:"));
    assert!(json.source().is_none());
}

fn test_response() -> SignResponse {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &support::secret(7));
    SignResponse {
        signature: secp.sign_schnorr_no_aux_rand(&Message::from_digest([8; 32]), &keypair),
        next_handoff: [9; 32],
    }
}

fn test_status() -> CoinStatus {
    CoinStatus {
        coin_id: [1; 32],
        signing_pubkey: support::xonly(7),
        authorization: [2; 32],
        signature_count: 0,
    }
}

fn assert_unexpected(error: RemoteError) {
    assert!(matches!(
        error,
        RemoteError::Protocol { status: 500, ref message }
            if message == "unexpected enclave response"
    ));
}

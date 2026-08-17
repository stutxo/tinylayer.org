use axum::{
    body::Body,
    http::{Request as HttpRequest, StatusCode},
};
use http_body_util::BodyExt as _;
use secp256k1::{Message, Secp256k1};
use tinylayer_enclave::{
    CoinStatus, Enclave, INITIAL_HANDOFF, RegisterRequest, Request, Response, SignRequest,
    SignResponse, authorization, capability_hash, workload,
};
use tower::ServiceExt as _;

#[tokio::test]
async fn health_and_v1_endpoint_work_without_v2() {
    let app = workload::router(Enclave::new());
    let health = app
        .clone()
        .oneshot(HttpRequest::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(health.into_body().collect().await.unwrap().to_bytes(), "ok");

    let registered = response(
        post(
            app.clone(),
            &Request::Register(RegisterRequest {
                coin_id: [1; 32],
                initial_capability_hash: capability_hash(&[2; 32]),
            }),
        )
        .await,
    )
    .await;
    assert!(matches!(registered, Response::Status(_)));

    let unsupported_route = app
        .oneshot(
            HttpRequest::post("/v2")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unsupported_route.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn signing_is_atomic_and_verifiable_over_json_http() {
    let (app, request, initial) = registered_app().await;
    let signed = response(post(app.clone(), &Request::Sign(request.clone())).await).await;
    let Response::Signature(signed) = signed else {
        panic!("unexpected response")
    };
    verify(&initial, &request, &signed);

    let completed = response(
        post(
            app.clone(),
            &Request::Status {
                coin_id: request.coin_id,
            },
        )
        .await,
    )
    .await;
    assert!(matches!(
        completed,
        Response::Status(status)
            if status.signature_count == 1
                && status.signing_pubkey == initial.signing_pubkey
                && status.authorization == authorization(
                    &request.coin_id,
                    &request.next_capability_hash,
                    &signed.next_handoff
                )
    ));

    let retried = response(post(app, &Request::Sign(request)).await).await;
    assert_eq!(retried, Response::Signature(signed));
}

#[tokio::test]
async fn protocol_errors_are_conflicts_with_explanatory_bodies() {
    let response = post(
        workload::router(Enclave::new()),
        &Request::Status { coin_id: [9; 32] },
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "coin is not registered"
    );
}

#[tokio::test]
async fn unsupported_methods_paths_and_content_types_fail() {
    let app = workload::router(Enclave::new());
    let get_protocol = app
        .clone()
        .oneshot(HttpRequest::get("/v1").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(get_protocol.status(), StatusCode::METHOD_NOT_ALLOWED);
    let unknown_path = app
        .clone()
        .oneshot(
            HttpRequest::post("/unsupported")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_path.status(), StatusCode::NOT_FOUND);
    let no_content_type = app
        .oneshot(
            HttpRequest::post("/v1")
                .body(Body::from(r#"{"method":"status","params":{"coin_id":[]}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_content_type.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn cloned_routers_share_one_idempotent_registration() {
    let app = workload::router(Enclave::new());
    let request = Request::Register(RegisterRequest {
        coin_id: [1; 32],
        initial_capability_hash: [2; 32],
    });
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let app = app.clone();
        let request = request.clone();
        tasks.spawn(async move { response(post(app, &request).await).await });
    }
    let mut statuses = Vec::new();
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Response::Status(status) => statuses.push(status),
            _ => panic!("unexpected response"),
        }
    }
    assert_eq!(statuses.len(), 32);
    assert!(statuses.windows(2).all(|pair| pair[0] == pair[1]));
}

#[tokio::test]
async fn concurrent_conflicting_registrations_return_the_first_live_state() {
    let app = workload::router(Enclave::new());
    let first = Request::Register(RegisterRequest {
        coin_id: [1; 32],
        initial_capability_hash: [2; 32],
    });
    let second = Request::Register(RegisterRequest {
        coin_id: [1; 32],
        initial_capability_hash: [3; 32],
    });
    let (first, second) = tokio::join!(post(app.clone(), &first), post(app, &second));
    let first = response(first).await;
    let second = response(second).await;
    assert_eq!(first, second);
}

#[tokio::test]
async fn concurrent_identical_signs_return_one_cached_result() {
    let (app, request, _) = registered_app().await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let app = app.clone();
        let request = Request::Sign(request.clone());
        tasks.spawn(async move { response(post(app, &request).await).await });
    }
    let mut signatures = Vec::new();
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Response::Signature(response) => signatures.push(response),
            _ => panic!("unexpected response"),
        }
    }
    assert_eq!(signatures.len(), 32);
    assert!(signatures.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(matches!(
        response(
            post(
                app,
                &Request::Status {
                    coin_id: request.coin_id,
                },
            )
            .await,
        )
        .await,
        Response::Status(status) if status.signature_count == 1
    ));
}

#[tokio::test]
async fn concurrent_conflicting_signs_have_one_counted_winner() {
    let (app, first, _) = registered_app().await;
    let mut second = first.clone();
    second.sighash[0] ^= 1;
    second.next_capability_hash = capability_hash(&[9; 32]);
    let first_call = Request::Sign(first.clone());
    let second_call = Request::Sign(second);
    let (first_response, second_response) = tokio::join!(
        post(app.clone(), &first_call),
        post(app.clone(), &second_call),
    );
    assert_one_winner([first_response.status(), second_response.status()]);
    assert!(matches!(
        response(
            post(
                app,
                &Request::Status {
                    coin_id: first.coin_id,
                },
            )
            .await,
        )
        .await,
        Response::Status(status) if status.signature_count == 1
    ));
}

#[tokio::test]
async fn malformed_and_oversized_requests_fail_at_the_http_boundary() {
    let app = workload::router(Enclave::new());
    let malformed = raw_post(app.clone(), Body::from("{}")).await;
    assert_eq!(malformed.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let oversized = raw_post(app, Body::from(vec![b' '; 4 * 1024 + 1])).await;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn body_limit_accepts_exactly_four_kibibytes() {
    let request = Request::Register(RegisterRequest {
        coin_id: [1; 32],
        initial_capability_hash: [2; 32],
    });
    let mut body = serde_json::to_vec(&request).unwrap();
    body.resize(4 * 1024, b' ');
    let response = raw_post(workload::router(Enclave::new()), Body::from(body)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

async fn registered_app() -> (axum::Router, SignRequest, CoinStatus) {
    let app = workload::router(Enclave::new());
    let coin_id = [1; 32];
    let capability = [3; 32];
    let registered = response(
        post(
            app.clone(),
            &Request::Register(RegisterRequest {
                coin_id,
                initial_capability_hash: capability_hash(&capability),
            }),
        )
        .await,
    )
    .await;
    let Response::Status(status) = registered else {
        panic!("unexpected response")
    };
    (
        app,
        SignRequest {
            coin_id,
            current_capability: capability,
            current_handoff: INITIAL_HANDOFF,
            next_capability_hash: capability_hash(&[5; 32]),
            sighash: [7; 32],
        },
        status,
    )
}

fn verify(status: &CoinStatus, request: &SignRequest, response: &SignResponse) {
    Secp256k1::verification_only()
        .verify_schnorr(
            &response.signature,
            &Message::from_digest(request.sighash),
            &status.signing_pubkey,
        )
        .unwrap();
}

fn assert_one_winner(statuses: [StatusCode; 2]) {
    assert_eq!(
        statuses.iter().filter(|status| status.is_success()).count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CONFLICT)
            .count(),
        1
    );
}

async fn post(app: axum::Router, value: &Request) -> axum::response::Response {
    raw_post(app, Body::from(serde_json::to_vec(value).unwrap())).await
}

async fn raw_post(app: axum::Router, body: Body) -> axum::response::Response {
    app.oneshot(
        HttpRequest::post("/v1")
            .header("content-type", "application/json")
            .body(body)
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn response(response: axum::response::Response) -> Response {
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

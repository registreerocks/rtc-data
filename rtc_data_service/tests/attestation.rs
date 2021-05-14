//! Tests for [`rtc_data_service::exec_token`]

use std::sync::Arc;

use actix::Actor;
use actix_web::web::Bytes;
use actix_web::App;
use actix_web::{http, test};

use rtc_data_service::attestation;
use rtc_data_service::data_enclave_actor::DataEnclaveActor;

#[actix_rt::test]
async fn data_service_attestation_ok() {
    // TODO: Split this test into re-usable components
    let app = test::init_service(
        App::new()
            .data(
                DataEnclaveActor::new(Arc::new(rtc_uenclave::EnclaveConfig {
                    lib_path: "/root/rtc-data/rtc_data_enclave/build/bin/enclave.signed.so"
                        .to_string(),
                    ..Default::default()
                }))
                .start(),
            )
            .service(attestation::req_attestation_jwt),
    )
    .await;

    // Call the endpoint

    // TODO: Placeholder request data, for now.
    let req_body = attestation::models::RequestBody {
        metadata: attestation::models::Metadata {
            requester_pub_key: vec![0_u8; 32],
            nonce: vec![0_u8; 24],
        },
        payload: vec![0_u8; 0],
    };

    let req = test::TestRequest::post()
        .uri("/auth/attest")
        .set_json(&req_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status: http::StatusCode = resp.status();
    let body: Bytes = test::read_body(resp).await;

    assert!(
        status.is_success(),
        "status = {}, body = {:?}",
        status,
        body
    );

    // Check the returned execution token

    let actual: attestation::models::ResponseBody = serde_json::from_slice(body.as_ref()).unwrap();

    // TODO: Placeholder value matching rtc_uenclave::rtc_enclave
    let expected = attestation::models::ResponseBody {
        attestation_jwt: vec![128; 6],
        nonce: vec![7; 24],
    };
    assert_eq!(expected, actual)
}

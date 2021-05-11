//! Tests for [`rtc_data_service::exec_token`]

use std::sync::Arc;

use actix::Actor;
use actix_web::web::Bytes;
use actix_web::App;
use actix_web::{http, test};

use rtc_data_service::data_enclave_actor::DataEnclaveActor;
use rtc_data_service::exec_token;

#[actix_rt::test]
async fn data_service_exec_token_ok() {
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
            .service(exec_token::req_exec_token),
    )
    .await;

    // Call the endpoint

    // TODO: Placeholder request data, for now.
    let req_body = exec_token::models::RequestBody {
        metadata: exec_token::models::Metadata {
            uploader_pub_key: vec![0_u8; 32],
            nonce: vec![0_u8; 24],
        },
        payload: vec![0_u8; 0],
    };

    let req = test::TestRequest::post()
        .uri("/auth/tokens")
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

    let actual: exec_token::models::ResponseBody = serde_json::from_slice(body.as_ref()).unwrap();

    // TODO: Placeholder value matching get_exec_token in rtc_uenclave::rtc_enclave
    let expected = exec_token::models::ResponseBody {
        execution_token: vec![128; 9],
        nonce: vec![7; 24],
    };
    assert_eq!(expected, actual)
}

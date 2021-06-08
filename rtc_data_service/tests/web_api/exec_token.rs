//! Tests for [`rtc_data_service::exec_token`]

use actix_web::web::Bytes;
use actix_web::{http, test};

use rtc_data_service::exec_token;

use crate::helpers;

#[actix_rt::test]
async fn data_service_exec_token_ok() {
    let app = helpers::init_rtc_service().await;

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

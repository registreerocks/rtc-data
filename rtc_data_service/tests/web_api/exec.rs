//! Tests for [`rtc_data_service::exec`]

use actix_web::web::Bytes;
use actix_web::{http, test};

use rtc_data_service::exec;

use crate::helpers;

/// [`exec::service::request_execution`]
#[actix_rt::test]
async fn data_service_request_execution_ok() {
    let app = helpers::init_rtc_service().await;

    // Call the endpoint

    // TODO: Placeholder request data, for now.
    let req_body = exec::models::RequestBody {
        metadata: exec::models::Metadata {
            uploader_pub_key: vec![0_u8; 32],
            nonce: vec![0_u8; 24],
        },
        payload: vec![0_u8; 0],
    };

    let req = test::TestRequest::post()
        .uri("/exec/request")
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

    // Check the returned value

    let actual: exec::models::ResponseBody = serde_json::from_slice(body.as_ref()).unwrap();

    // TODO: Placeholder value
    let expected = exec::models::ResponseBody {};
    assert_eq!(expected, actual)
}

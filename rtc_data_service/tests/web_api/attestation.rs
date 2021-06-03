use actix_web::test;

use crate::helpers;

#[actix_rt::test]
async fn auth_service_attestation_ok() {
    attestation_ok("/auth/attest").await;
}

#[actix_rt::test]
async fn data_service_attestation_ok() {
    attestation_ok("/data/attest").await;
}

async fn attestation_ok(uri_path: &str) {
    let app = helpers::init_rtc_service().await;

    let req = test::TestRequest::get().uri(uri_path).to_request();
    let resp = test::call_service(&app, req).await;

    insta::assert_debug_snapshot!(resp);

    let body = test::read_body(resp).await;
    insta::assert_debug_snapshot!(body);
}

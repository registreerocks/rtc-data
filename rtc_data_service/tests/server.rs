use actix::Actor;
use actix_web::{
    http,
    test::{self, read_body},
    App,
};
use base64;
use insta;
use rtc_data_service::auth_enclave_actor::AuthEnclaveActor;
use rtc_data_service::data_enclave_actor::DataEnclaveActor;
use rtc_data_service::handlers::*;
use rtc_types::{DataUploadResponse, UploadMetadata};
use rtc_uenclave::EnclaveConfig;
use sgx_types::sgx_target_info_t;
use sodalite;

use std::sync::Arc;

#[actix_rt::test]
async fn auth_service_attestation_ok() {
    attestation_ok("/auth/attest").await;
}

#[actix_rt::test]
async fn data_service_attestation_ok() {
    attestation_ok("/data/attest").await;
}

async fn attestation_ok(uri_path: &str) {
    let mut app = test::init_service(
        App::new()
            .data(
                AuthEnclaveActor::new(Arc::new(EnclaveConfig {
                    lib_path: "/root/rtc-data/rtc_auth_enclave/build/bin/enclave.signed.so"
                        .to_string(),
                    ..Default::default()
                }))
                .start(),
            )
            .data(
                DataEnclaveActor::new(Arc::new(EnclaveConfig {
                    lib_path: "/root/rtc-data/rtc_data_enclave/build/bin/enclave.signed.so"
                        .to_string(),
                    ..Default::default()
                }))
                .start(),
            )
            .service(auth_enclave_attestation)
            .service(data_enclave_attestation),
    )
    .await;

    let req = test::TestRequest::get().uri(uri_path).to_request();
    let resp = test::call_service(&mut app, req).await;

    insta::assert_debug_snapshot!(resp);

    let body = read_body(resp).await;
    insta::assert_debug_snapshot!(body);
}

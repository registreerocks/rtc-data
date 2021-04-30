use actix::Actor;
use actix_web::{
    http,
    test::{self, read_body},
    App,
};
use insta;
use rtc_data_service::enclave_actor::*;
use rtc_data_service::handlers::*;
use rtc_types::UploadMetadata;
use rtc_uenclave::EnclaveConfig;
use sgx_types::sgx_target_info_t;
use sodalite;

use std::sync::Arc;

#[actix_rt::test]
async fn data_service_attestation_ok() {
    let mut app = test::init_service(
        App::new()
            .data(
                EnclaveActor::new(Arc::new(EnclaveConfig {
                    lib_path: "/root/rtc-data/rtc_data_enclave/build/bin/enclave.signed.so"
                        .to_string(),
                    ..Default::default()
                }))
                .start(),
            )
            .service(data_enclave_attestation),
    )
    .await;

    let req = test::TestRequest::get().uri("/data/attest").to_request();
    let resp = test::call_service(&mut app, req).await;

    insta::assert_debug_snapshot!(resp);

    let body = read_body(resp).await;
    insta::assert_debug_snapshot!(body);
}

#[test]
fn test_test() {
    println!("hi");
    let enclave = rtc_uenclave::RtcEnclave::init(EnclaveConfig {
        lib_path: "/root/rtc-data/rtc_data_enclave/build/bin/enclave.signed.so".to_string(),
        ..Default::default()
    })
    .unwrap();
    let ehd = enclave
        .create_report(&sgx_target_info_t::default())
        .unwrap()
        .enclave_held_data;

    let mut pubkey = [0_u8; 32];
    let mut privkey = [0_u8; 32];

    sodalite::box_keypair_seed(&mut pubkey, &mut privkey, &[2_u8; 32]);

    let plaintext = [[0_u8; 32], [12_u8; 32]].concat();
    let mut ciphertext = vec![0_u8; plaintext.len()];
    let nonce = [8_u8; 24];

    sodalite::box_(&mut ciphertext, &plaintext, &nonce, &ehd, &privkey);

    println!("{:?}", ciphertext);

    let res = enclave.upload_data(
        &ciphertext,
        UploadMetadata {
            uploader_pub_key: pubkey,
            nonce,
        },
    );

    println!("res: {:?}", res);
}

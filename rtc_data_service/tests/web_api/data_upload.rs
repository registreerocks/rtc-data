//! Tests for [`rtc_data_service::data_upload`]

use std::convert::TryInto;
use std::path::Path;

use actix_web::test;
use rtc_data_service::data_upload::models;
use sgx_types::sgx_target_info_t;
use uuid::Uuid;

// See rtc_tenclave/src/crypto.rs
use crate::{helpers, CRYPTO_BOX_BOXZEROBYTES, CRYPTO_BOX_ZEROBYTES};

/// Upload some data, decrypt and check the result.
#[actix_rt::test]
async fn data_service_data_upload_ok() {
    let app = helpers::init_rtc_service().await;

    // TODO: Add a test that can run inside of the enclave and use the JWT token to get
    // the enclave key
    let enclave = helpers::init_data_enclave();

    let enclave_pubkey = enclave
        .create_report(&sgx_target_info_t::default())
        .unwrap()
        .enclave_held_data;

    let mut pubkey = [0_u8; 32];
    let mut privkey = [0_u8; 32];

    sodalite::box_keypair_seed(&mut pubkey, &mut privkey, &[2_u8; 32]);

    let plaintext = [[0_u8; 32], [12_u8; 32]].concat();
    let mut ciphertext = vec![0_u8; plaintext.len()];
    let nonce = [8_u8; 24];

    sodalite::box_(
        &mut ciphertext,
        &plaintext,
        &nonce,
        &enclave_pubkey,
        &privkey,
    )
    .unwrap();

    let req_body = models::RequestBody {
        metadata: models::Metadata {
            uploader_pub_key: pubkey.to_vec(),
            nonce: nonce.to_vec(),
        },
        payload: ciphertext[CRYPTO_BOX_BOXZEROBYTES..].to_vec(),
    };

    let req = test::TestRequest::post()
        .uri("/data/uploads")
        .set_json(&req_body)
        .to_request();

    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let body: models::ResponseBody = serde_json::from_slice(&test::read_body(resp).await).unwrap();

    // NOTE: re-add padding since sodalite supports the C-style nacl api
    let mut m = vec![0_u8; body.ciphertext.len() + CRYPTO_BOX_BOXZEROBYTES];

    // TODO: Test bad privkey, nonce etc and ensure failure

    let open_result = sodalite::box_open(
        &mut m,
        &[&[0_u8; CRYPTO_BOX_BOXZEROBYTES] as &[u8], &body.ciphertext].concat(),
        &body.nonce.try_into().unwrap(),
        &enclave_pubkey,
        &privkey,
    );

    assert!(open_result.is_ok());

    // Skip over the padding
    let padding: &[u8; CRYPTO_BOX_ZEROBYTES] =
        m[..CRYPTO_BOX_ZEROBYTES].try_into().expect("bad padding");
    assert_eq!(
        padding, &[0_u8; CRYPTO_BOX_ZEROBYTES],
        "padding should be zero"
    );

    // Parse the rest of the result
    let _access_key: &[u8; 24] = &m[CRYPTO_BOX_ZEROBYTES..CRYPTO_BOX_ZEROBYTES + 24]
        .try_into()
        .expect("bad access key");
    let uuid = Uuid::from_slice(&m[CRYPTO_BOX_ZEROBYTES + 24..]).expect("bad UUID length");

    // TODO: Test access key validity?

    let path = format!("sealed_data/{}", uuid);
    let path = Path::new(&path);
    assert!(path.exists(), "saved upload file {:?} should exist", path);
}

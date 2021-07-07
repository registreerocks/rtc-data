use std::convert::TryInto;
use std::str::FromStr;

use rtc_types::ExecReqMetadata;
use rtc_uenclave::{EnclaveConfig, RtcAuthEnclave};
use serde::{Deserialize, Serialize};
use sgx_types::sgx_target_info_t;

use crate::{helpers, CRYPTO_BOX_BOXZEROBYTES, CRYPTO_BOX_ZEROBYTES};

#[derive(Serialize, Deserialize)]
pub struct ExecReqData {
    dataset_uuid: [u8; 16],
    dataset_access_key: [u8; 24],
    exec_module_hash: [u8; 32],
    number_of_uses: u32,
}

fn make_request(
    enclave: &RtcAuthEnclave<EnclaveConfig>,
) -> ([u8; 32], [u8; 32], Vec<u8>, ExecReqMetadata) {
    let enclave_pubkey = enclave
        .create_report(&sgx_target_info_t::default())
        .unwrap()
        .enclave_held_data;

    let mut pubkey = [0_u8; 32];
    let mut privkey = [0_u8; 32];

    sodalite::box_keypair_seed(&mut pubkey, &mut privkey, &[2_u8; 32]);

    let uuid = uuid::Uuid::from_str("dd12012195c04ae8990ebd2512ae03ab").unwrap();
    let exec_module_hash: Vec<u8> = (0u8..32).collect();

    let req_json = serde_json::to_vec(&ExecReqData {
        dataset_uuid: *uuid.as_bytes(),
        dataset_access_key: [1; 24],
        exec_module_hash: exec_module_hash.try_into().unwrap(),
        number_of_uses: 10,
    })
    .unwrap();

    let plaintext = [vec![0_u8; 32], req_json].concat();
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

    let payload = ciphertext[CRYPTO_BOX_BOXZEROBYTES..].to_vec();

    let metadata = ExecReqMetadata {
        uploader_pub_key: pubkey,
        nonce,
    };

    (enclave_pubkey, privkey, payload, metadata)
}

#[test]
fn test_issue_execution_token_success() {
    let enclave = helpers::init_auth_enclave();

    let (enclave_pubkey, privkey, payload, metadata) = make_request(&enclave);

    let result = enclave.issue_execution_token(&payload, metadata).unwrap();

    let mut m = vec![0_u8; result.ciphertext.len() + CRYPTO_BOX_BOXZEROBYTES];

    let padded_c = [
        vec![0u8; CRYPTO_BOX_BOXZEROBYTES],
        result.ciphertext.to_vec(),
    ]
    .concat();

    // TODO: Test bad privkey, nonce etc and ensure failure

    let open_result =
        sodalite::box_open(&mut m, &padded_c, &result.nonce, &enclave_pubkey, &privkey);

    assert!(open_result.is_ok());

    // Skip over the padding
    let padding: &[u8; CRYPTO_BOX_ZEROBYTES] =
        m[..CRYPTO_BOX_ZEROBYTES].try_into().expect("bad padding");

    assert_eq!(
        padding, &[0_u8; CRYPTO_BOX_ZEROBYTES],
        "padding should be zero"
    );

    // TODO: Assert that decrypted value is a valid JWT
}

//! Test ECALL: `save_access_key`

use rtc_types::enclave_messages::set_access_key;

use crate::helpers;

#[test]
fn save_access_key_smoke_test() {
    let auth_enclave = helpers::init_auth_enclave();
    let encrypted_request = set_access_key::EncryptedRequest {
        tag: Default::default(),
        ciphertext: [0; set_access_key::REQUEST_SIZE], // Default::default() not implemented for this size
        aad: Default::default(),
        nonce: Default::default(),
    };
    let encrypted_response = auth_enclave.save_access_key(encrypted_request).unwrap();

    let set_access_key::EncryptedResponse {
        tag,
        ciphertext,
        aad,
        nonce,
    } = encrypted_response;
    assert_eq!(
        (tag, ciphertext, aad, nonce),
        (
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        )
    )
}

//! Test ECALL: `save_access_key`

use rtc_types::byte_formats::rkyv_format;
use rtc_types::enclave_messages::set_access_key;
use sgx_types::sgx_enclave_id_t;

use crate::helpers;

#[test]
fn save_access_key_smoke_test() {
    let auth_enclave = helpers::init_auth_enclave();

    let dummy_ciphertext = [123; set_access_key::REQUEST_SIZE];
    let dummy_sending_enclave_id: sgx_enclave_id_t = 456;
    let encrypted_request = set_access_key::EncryptedRequest {
        tag: Default::default(),
        ciphertext: dummy_ciphertext,
        aad: rkyv_format::write_array(&dummy_sending_enclave_id).unwrap(),
        nonce: Default::default(),
    };
    let result = auth_enclave.save_access_key(encrypted_request).unwrap();
    let sealing_error = result.unwrap_err();

    assert_eq!(
        format!("{}", sealing_error),
        "Failed to acquire ProtectedChannel: No active session for enclave ID 456"
    )
}

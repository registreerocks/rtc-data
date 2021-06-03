//! ECALL definition: [`save_access_key`]

use std::{dbg, format};

use sgx_types::sgx_enclave_id_t;

use rtc_types::enclave_messages::ng_set_access_key;
use rtc_types::enclave_messages::set_access_key;

/// FFI wrapper for [`save_access_key_impl`].
///
/// This takes care of converting from and to the [`ng_set_access_key`] types.
#[no_mangle]
pub extern "C" fn save_access_key(
    encrypted_request: ng_set_access_key::EncryptedRequest,
) -> ng_set_access_key::EncryptedResponse {
    let encrypted_request: set_access_key::EncryptedRequest = encrypted_request.into();
    let encrypted_response: set_access_key::EncryptedResponse =
        save_access_key_impl(encrypted_request);
    encrypted_response.into()
}

/// Implementation for [`save_access_key`].
fn save_access_key_impl(
    encrypted_request: set_access_key::EncryptedRequest,
) -> set_access_key::EncryptedResponse {
    // FIXME: Get sending enclave ID via AAD?
    let dummy_enclave_id = sgx_enclave_id_t::default();

    let other_enclave_id = dummy_enclave_id;

    let sessions: &crate::DhSessions<_, _> = crate::dh_sessions();
    let channel_mutex = sessions.get_active(other_enclave_id).expect(&format!(
        "save_access_key_impl: no active DH session for sending enclave {:?}",
        other_enclave_id,
    ));
    let channel = channel_mutex
        .lock()
        .expect("save_access_key_impl: protected channel mutex poisoned");

    let request_bytes = channel
        .decrypt_message(encrypted_request)
        .expect("TODO: return Result<>");
    dbg!(request_bytes);
    // TODO: deserialize,

    let response = set_access_key::Response { success: false };
    dbg!(response);
    // TODO: serialize

    set_access_key::EncryptedResponse {
        tag: Default::default(),
        ciphertext: Default::default(),
        aad: Default::default(),
        nonce: Default::default(),
    }
}

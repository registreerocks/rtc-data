//! ECALL definition: [`save_access_key`]

use std::dbg;

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
    dbg!(
        encrypted_request.tag,
        encrypted_request.ciphertext,
        encrypted_request.aad,
        encrypted_request.nonce,
    );
    set_access_key::EncryptedResponse {
        tag: Default::default(),
        ciphertext: Default::default(),
        aad: Default::default(),
        nonce: Default::default(),
    }
}

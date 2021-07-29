//! OCALL definition: [`rtc_save_access_key_u`]

use rtc_types::enclave_messages::ffi_set_access_key;

#[no_mangle]
pub unsafe extern "C" fn rtc_save_access_key_u(
    #[allow(unused)] // TODO
    request: ffi_set_access_key::SetAccessKeyEncryptedRequest,
) -> ffi_set_access_key::SetAccessKeyResult {
    todo!()
}

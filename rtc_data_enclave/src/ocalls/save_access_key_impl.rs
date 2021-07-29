//! OCALL definition: `save_access_key` (`rtc_save_access_key_u`)
//!
//! This call is responsible for establishing a protected channel with the auth enclave,
//! and relaying the sealed exchange with the auth enclave's `save_access_key` ECALL.

use rtc_tenclave::dh::{dh_sessions, sealing, DhSessions, ProtectedChannel};
use rtc_types::enclave_messages::errors::SealingError;
pub use rtc_types::enclave_messages::ffi_set_access_key::SetAccessKeyEncryptedRequest;
use rtc_types::enclave_messages::{ffi_set_access_key, set_access_key};
use rtc_types::EcallResult;
use sgx_tstd::enclave::get_enclave_id;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};

// Handle protected channel establishment
pub(crate) fn save_access_key(
    auth_enclave_id: sgx_enclave_id_t,
    request: set_access_key::Request,
) -> Result<set_access_key::Response, SealingError> {
    let sessions: &DhSessions<_, _> = dh_sessions();
    sessions.with_acquire_new_or_established(auth_enclave_id, |channel| {
        save_access_key_sealing(auth_enclave_id, channel, request)
    })?
}

// Handle message sealing
fn save_access_key_sealing(
    auth_enclave_id: sgx_enclave_id_t,
    channel: &mut ProtectedChannel,
    request: set_access_key::Request,
) -> Result<set_access_key::Response, SealingError> {
    let sending_enclave_id: sgx_enclave_id_t = get_enclave_id();

    // Seal the request
    let encrypted_request =
        sealing::rkyv_seal_associated(channel, &request, &sending_enclave_id).unwrap();

    // Exchange with the auth enclave
    let encrypted_response = save_access_key_ffi(auth_enclave_id, encrypted_request)?;

    // Unseal the response
    let response =
        unsafe { sealing::rkyv_unseal::<set_access_key::Response>(channel, encrypted_response) }?;
    Ok(response)
}

/// Handle converting between the [`ffi_set_access_key`] and [`set_access_key`] types.
fn save_access_key_ffi(
    auth_enclave_id: sgx_enclave_id_t,
    encrypted_request: set_access_key::EncryptedRequest,
) -> set_access_key::SetAccessKeyResult {
    let ffi_encrypted_request = encrypted_request.into();
    let ffi_result = save_access_key_u(auth_enclave_id, ffi_encrypted_request);
    ffi_result.into()
}

// Handle call
fn save_access_key_u(
    auth_enclave_id: sgx_enclave_id_t,
    encrypted_request: ffi_set_access_key::SetAccessKeyEncryptedRequest,
) -> ffi_set_access_key::SetAccessKeyResult {
    let mut retval = ffi_set_access_key::SetAccessKeyResult::default();

    // Safety: Copies ffi_set_access_key::SetAccessKeyResult into retval,
    // but only valid for sgx_status_t::SGX_SUCCESS.
    match unsafe { rtc_save_access_key_u(&mut retval, auth_enclave_id, encrypted_request) } {
        sgx_status_t::SGX_SUCCESS => retval,
        status_err => EcallResult::Err(status_err.into()),
    }
}

extern "C" {
    fn rtc_save_access_key_u(
        retval: *mut ffi_set_access_key::SetAccessKeyResult,
        auth_enclave_id: sgx_enclave_id_t,
        request: ffi_set_access_key::SetAccessKeyEncryptedRequest,
    ) -> sgx_status_t;
}

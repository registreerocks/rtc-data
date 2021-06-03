//! ECALL definition: [`save_access_key`]

use rtc_tenclave::dh::{sealing, ProtectedChannel};
use rtc_types::enclave_messages::{ffi_set_access_key, set_access_key};
use sgx_types::sgx_enclave_id_t;

use crate::ecalls::save_access_key_impl::save_access_key_impl;
use crate::DhSessions;

/// FFI wrapper.
///
/// This takes care of converting between the [`ffi_set_access_key`] and [`set_access_key`] types.
#[no_mangle]
pub unsafe extern "C" fn save_access_key(
    encrypted_request: ffi_set_access_key::SetAccessKeyEncryptedRequest,
) -> ffi_set_access_key::SetAccessKeyResult {
    let encrypted_request: set_access_key::EncryptedRequest = encrypted_request.into();
    let result: set_access_key::SetAccessKeyResult =
        unsafe { save_access_key_acquiring_channel(encrypted_request) };
    result.into()
}

/// This takes care of acquiring the sending enclave's channel.
unsafe fn save_access_key_acquiring_channel(
    encrypted_request: set_access_key::EncryptedRequest,
) -> set_access_key::SetAccessKeyResult {
    let &claimed_sending_enclave_id = unsafe {
        sealing::rkyv_peek_associated::<set_access_key::Request, sgx_enclave_id_t>(
            &encrypted_request,
        )
    };

    let sessions: &DhSessions<_, _> = crate::dh_sessions();
    let result = sessions
        .with_acquire_established(claimed_sending_enclave_id, |channel| unsafe {
            save_access_key_sealing(channel, encrypted_request)
        })?;
    result
}

/// This takes care of the sealing and unsealing.
unsafe fn save_access_key_sealing(
    channel: &mut ProtectedChannel,
    encrypted_request: set_access_key::EncryptedRequest,
) -> set_access_key::SetAccessKeyResult {
    // Unseal the request
    let (request, _sending_enclave_id) = unsafe {
        sealing::rkyv_unseal_associated::<set_access_key::Request, sgx_enclave_id_t>(
            channel,
            encrypted_request,
        )
    }?;

    let response = &save_access_key_impl(request);

    // Seal the response
    let sealed_response = sealing::rkyv_seal(channel, response)?;
    Ok(sealed_response)
}

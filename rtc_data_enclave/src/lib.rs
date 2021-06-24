#![deny(unsafe_op_in_unsafe_fn)]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![deny(clippy::mem_forget)]
// TODO: Clean up existing cases causing a flood of warnings for this check, and re-enable
// #![warn(missing_docs)]

use sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

mod data_upload;
mod ocalls;

use core::slice;
use std::prelude::v1::*;

#[allow(unused_imports)] // for ECALL linking
use rtc_tenclave::enclave::enclave_create_report;
use rtc_types::*;
use sgx_types::*;

/// Validates and save a payload encrypted for the enclave
///
/// # Safety
/// The caller (SGX) should ensure that `payload_ptr` is valid for a slice of
/// length `payload_len`
#[no_mangle]
pub unsafe extern "C" fn validate_and_save(
    #[allow(unused)] auth_enclave_id: sgx_enclave_id_t, // TODO: pass to validate_and_seal
    payload_ptr: *const u8,
    payload_len: usize,
    metadata: UploadMetadata,
) -> DataUploadResult {
    // TODO: Add out-vars that contain the client payload

    let payload: Box<[u8]> = unsafe { slice::from_raw_parts(payload_ptr, payload_len) }.into();
    let sealed = match data_upload::validate_and_seal(metadata, payload) {
        Ok(res) => res,
        Err(err) => return EcallResult::Err(err),
    };

    match ocalls::save_sealed_blob_u(sealed.sealed_data, sealed.uuid) {
        sgx_status_t::SGX_SUCCESS => EcallResult::Ok(sealed.client_payload.into()),
        err => EcallResult::Err(DataUploadError::Sealing(err)),
    }
}

/// Tries to perform local attestation to an enclave at dest_enclave_id.
///
/// See: [`DhSessions::establish_new`]
#[no_mangle]
pub unsafe extern "C" fn local_attestation(dest_enclave_id: sgx_enclave_id_t) -> sgx_status_t {
    let res = rtc_tenclave::dh::dh_sessions().establish_new(dest_enclave_id);
    match res {
        Ok(_) => sgx_status_t::SGX_SUCCESS,
        Err(err) => err,
    }
}

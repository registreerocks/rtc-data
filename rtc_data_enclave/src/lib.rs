#![feature(unsafe_block_in_unsafe_fn)]
#![deny(unsafe_op_in_unsafe_fn)]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(const_generics)]
#![feature(const_evaluatable_checked)]
#![deny(clippy::mem_forget)]
// TODO: Clean up existing cases causing a flood of warnings for this check, and re-enable
// #![warn(missing_docs)]

use rtc_tenclave::crypto::{RtcCrypto, SodaBoxCrypto};
use sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
use sgx_tcrypto;
use sgx_tse;

mod data_upload;
mod ocalls;

use core::slice;
use rtc_types::*;
use sgx_tse::rsgx_create_report;
use sgx_types::*;
use std::prelude::v1::*;

use sgx_tcrypto::rsgx_sha256_slice;
use zeroize::Zeroize;

use rtc_tenclave::enclave::*;

/// Validates and save a payload encrypted for the enclave
///
/// # Safety
/// The caller (SGX) should ensure that `payload_ptr` is valid for a slice of
/// length `payload_len`
#[no_mangle]
pub unsafe extern "C" fn validate_and_save(
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
        (sgx_status_t::SGX_SUCCESS) => EcallResult::Ok(sealed.client_payload.into()),
        (err) => EcallResult::Err(DataUploadError::Sealing(err)),
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

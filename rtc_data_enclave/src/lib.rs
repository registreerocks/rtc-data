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

use crypto::{RtcCrypto, SodaBoxCrypto};
use sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
use sgx_tcrypto;
use sgx_tse;

mod crypto;
mod data_upload;
mod ocalls;
mod util;

use core::slice;
use rtc_types::*;
use sgx_tse::rsgx_create_report;
use sgx_types::*;
use std::prelude::v1::*;

use sgx_tcrypto::rsgx_sha256_slice;
use zeroize::Zeroize;

fn create_report_impl(
    qe_target_info: &sgx_target_info_t,
) -> Result<([u8; ENCLAVE_HELD_PUB_KEY_SIZE], sgx_report_t), CreateReportResult> {
    let crypto = SodaBoxCrypto::new();
    let pubkey = crypto.get_pubkey();

    let pubkey_hash = match rsgx_sha256_slice(&pubkey) {
        Ok(hash) => hash,
        Err(err) => return Err(err.into()),
    };

    let mut p_data = sgx_report_data_t::default();
    p_data.d[0..32].copy_from_slice(&pubkey_hash);

    // AFAIK any SGX function with out-variables provide no guarantees on what
    // data will be written to those variables in the case of failure. It is
    // our responsibility to ensure data does not get leaked in the case
    // of function failure.
    match rsgx_create_report(qe_target_info, &p_data) {
        Ok(report) => Ok((pubkey, report)),
        Err(err) => Err(CreateReportResult::Sgx(err)),
    }
}

/// Creates and returns a report for the enclave alongside a public key used to encrypt
/// data sent to the enclave.
///
/// # Safety
/// The pointers from SGX is expected to be valid, not-null, correctly aligned and of the
/// correct type. Sanity checks are done for null-pointers, but none of the other conditions.
#[no_mangle]
pub unsafe extern "C" fn enclave_create_report(
    p_qe3_target: *const sgx_target_info_t,
    enclave_pubkey: *mut EnclaveHeldData,
    p_report: *mut sgx_report_t,
) -> CreateReportResult {
    if p_qe3_target.is_null() || enclave_pubkey.is_null() || p_report.is_null() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER.into();
    }
    let qe_target_info = unsafe { &*p_qe3_target };
    let (key, report) = match create_report_impl(qe_target_info) {
        Ok(res) => res,
        Err(x) => {
            unsafe {
                // TODO: Use secrecy crate instead? This will allow for more
                // guarantees and might make the code easier to audit
                (*enclave_pubkey).zeroize();
            }
            return x.into();
        }
    };

    unsafe {
        *p_report = report;
        (*enclave_pubkey).copy_from_slice(&key);
    }

    CreateReportResult::Success
}

/// Validates and save a payload encrypted for the enclave
///
/// # Safety
/// The caller (SGX) should ensure that `payload_ptr` is valid for a slice of
/// length `payload_len`
#[no_mangle]
pub unsafe extern "C" fn rtc_validate_and_save(
    payload_ptr: *const u8,
    payload_len: usize,
    metadata: UploadMetadata,
) -> DataUploadResult {
    // TODO: Add out-vars that contain the client payload

    let payload: Box<[u8]> = unsafe { slice::from_raw_parts(payload_ptr, payload_len) }.into();
    let sealed = match data_upload::validate_and_seal(data_upload::UploadPayload {
        metadata,
        blob: payload,
    }) {
        Ok(res) => res,
        Err(err) => return EcallResult::Err(err),
    };

    match ocalls::save_sealed_blob_u(sealed.sealed_data, sealed.uuid) {
        (sgx_status_t::SGX_SUCCESS) => EcallResult::Ok(sealed.client_payload.into()),
        (err) => EcallResult::Err(DataUploadError::Sealing(err)),
    }
}

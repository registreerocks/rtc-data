#![crate_type = "staticlib"]
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::mem_forget)]

mod jwt;
mod token_store;

#[cfg(not(target_env = "sgx"))]
extern crate sgx_tstd as std;

use core::slice;
use std::ptr;
use std::string::{String, ToString};

use rtc_tenclave::crypto::{RtcCrypto, SodaBoxCrypto as Crypto};
pub use rtc_tenclave::dh::*;
#[allow(unused_imports)] // for ECALL linking
use rtc_tenclave::enclave::enclave_create_report;
use rtc_types::{EcallResult, EncryptedMessage, ExecReqMetadata, ExecTokenError, IssueTokenResult};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Minimum size for the out_token parameter's buffer.
///
/// From my testing, the total token size (including auth bytes) were never bigger than 500.
const MIN_OUT_TOKEN_LEN: usize = 500;

/// Maximum size for the out_token parameter's buffer.
const MAX_OUT_TOKEN_LEN: usize = 1000;

#[derive(Serialize, Deserialize)]
pub struct ExecReqData {
    dataset_uuid: [u8; 16],
    dataset_access_key: [u8; 24],
    exec_module_hash: [u8; 32],
    number_of_uses: u32,
}

/// Issue an execution token using the parameters defined in the payload.
///
/// # Safety
/// This function expects
///   1. `payload_ptr` to be valid for a slice of len `payload_len`
///   2. `metadata_ptr` should be a valid pointer.
///   3. An allocated buffer of size `out_token_len` that starts at `out_token_ptr`
/// The edge code from sgx must uphold the above.
#[no_mangle]
pub unsafe extern "C" fn issue_execution_token(
    payload_ptr: *const u8,
    payload_len: usize,
    metadata_ptr: *const ExecReqMetadata,
    out_token_ptr: *mut u8,
    out_token_capacity: usize,
    out_token_used: *mut usize,
) -> IssueTokenResult {
    // Ensure that the out token len is reasonable before proceeding
    if out_token_capacity < MIN_OUT_TOKEN_LEN || out_token_capacity > MAX_OUT_TOKEN_LEN {
        return EcallResult::Err(ExecTokenError::OutputBufferSize);
    }

    let payload = unsafe { slice::from_raw_parts(payload_ptr, payload_len) };
    let metadata = unsafe { &*metadata_ptr };

    match issue_execution_token_impl(payload, metadata) {
        Ok(message) if message.ciphertext.len() <= out_token_capacity => {
            let out_token_len = message.ciphertext.len();
            unsafe {
                *out_token_used = out_token_len;
                ptr::copy_nonoverlapping(message.ciphertext.as_ptr(), out_token_ptr, out_token_len);
            }
            EcallResult::Ok(message.nonce)
        }
        Ok(_) => EcallResult::Err(ExecTokenError::OutputBufferSize),
        Err(err) => EcallResult::Err(err),
    }
}

fn issue_execution_token_impl(
    payload: &[u8],
    metadata: &ExecReqMetadata,
) -> Result<EncryptedMessage, ExecTokenError> {
    let mut crypto = Crypto::new();
    let message_bytes =
        crypto.decrypt_message(payload, &metadata.uploader_pub_key, &metadata.nonce)?;

    let message: ExecReqData = serde_json::from_slice(message_bytes.expose_secret())
        .map_err(|_| ExecTokenError::Validation)?;

    if let Some(dataset_size) =
        validate_dataset_access_key(message.dataset_uuid, message.dataset_access_key)
    {
        let token = token_store::issue_token(
            Uuid::from_bytes(message.dataset_uuid),
            message.dataset_access_key,
            message.exec_module_hash,
            message.number_of_uses,
            dataset_size,
        )?;

        let token_vec = token.into_bytes();

        Ok(crypto.encrypt_message(
            Secret::new(token_vec.into_boxed_slice()),
            &metadata.uploader_pub_key,
        )?)
    } else {
        Err(ExecTokenError::Validation)
    }
}

/// The size of the dataset in bytes
type DatasetSize = u64;

// This is a placeholder and the signature might change when the dataset and access key store gets implemented.
fn validate_dataset_access_key(
    _dataset_uuid: [u8; 16],
    _access_key: [u8; 24],
) -> Option<DatasetSize> {
    Some(20)
}

pub(crate) fn uuid_to_string(uuid: Uuid) -> String {
    let mut uuid_buf = Uuid::encode_buffer();
    uuid.to_simple().encode_lower(&mut uuid_buf).to_string()
}

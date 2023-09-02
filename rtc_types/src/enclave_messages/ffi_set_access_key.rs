//! FIXME: Non-generic version of [`set_access_key`], with conversions.
//!
//! This is a workaround for cbindgen not supporting const generics in structs yet,
//! and should be removed once cbindgen implements that.
//!
//! Tracking issue: <https://github.com/eqrion/cbindgen/issues/687>
//!
//! These sizes should match the ones computed in `set_access_key`.
//! (The Rust compiler should report an error if these don't line up:
//! this can be used to update these if `set_access_key` changes.)

use sgx_types::{sgx_aes_gcm_128bit_tag_t, sgx_status_t};

use super::{set_access_key, RecommendedAesGcmIv};
use crate::enclave_messages::errors::SealingError;
use crate::EcallResult;

// See enclave_messages::ARCHIVED_ENCLAVE_ID_SIZE
pub const ARCHIVED_ENCLAVE_ID_SIZE: usize = 8;

// Begin FFI types
// (Keep these FFI type comments in sync between set_access_key and ffi_set_access_key, for diffing!)

// FFI type: REQUEST_SIZE
pub const SET_ACCESS_KEY_REQUEST_SIZE: usize = 48;

// FFI type: EncryptedRequest
#[repr(C)]
pub struct SetAccessKeyEncryptedRequest {
    pub tag: sgx_aes_gcm_128bit_tag_t,
    pub ciphertext: [u8; SET_ACCESS_KEY_REQUEST_SIZE],
    pub aad: [u8; ARCHIVED_ENCLAVE_ID_SIZE],
    pub nonce: RecommendedAesGcmIv,
}

// FFI type: RESPONSE_SIZE
pub const SET_ACCESS_KEY_RESPONSE_SIZE: usize = 1;

// FFI type: EncryptedResponse
#[derive(Default)]
#[repr(C)]
pub struct SetAccessKeyEncryptedResponse {
    pub tag: sgx_aes_gcm_128bit_tag_t,
    pub ciphertext: [u8; SET_ACCESS_KEY_RESPONSE_SIZE],
    pub aad: [u8; 0],
    pub nonce: RecommendedAesGcmIv,
}

// FFI type: SetAccessKeyResult
pub type SetAccessKeyResult = EcallResult<SetAccessKeyEncryptedResponse, SealingError>;

// End FFI types

impl Default for SetAccessKeyResult {
    fn default() -> Self {
        EcallResult::Err(SealingError::Sgx(sgx_status_t::SGX_ERROR_UNEXPECTED))
    }
}

// Boilerplate From implementations:

impl From<set_access_key::EncryptedRequest> for SetAccessKeyEncryptedRequest {
    fn from(
        set_access_key::EncryptedRequest {
            tag,
            ciphertext,
            aad,
            nonce,
        }: set_access_key::EncryptedRequest,
    ) -> Self {
        SetAccessKeyEncryptedRequest {
            tag,
            ciphertext,
            aad,
            nonce,
        }
    }
}

impl From<SetAccessKeyEncryptedRequest> for set_access_key::EncryptedRequest {
    fn from(
        SetAccessKeyEncryptedRequest {
            tag,
            ciphertext,
            aad,
            nonce,
        }: SetAccessKeyEncryptedRequest,
    ) -> Self {
        set_access_key::EncryptedRequest {
            tag,
            ciphertext,
            aad,
            nonce,
        }
    }
}

impl From<set_access_key::EncryptedResponse> for SetAccessKeyEncryptedResponse {
    fn from(
        set_access_key::EncryptedResponse {
            tag,
            ciphertext,
            aad,
            nonce,
        }: set_access_key::EncryptedResponse,
    ) -> Self {
        SetAccessKeyEncryptedResponse {
            tag,
            ciphertext,
            aad,
            nonce,
        }
    }
}

impl From<SetAccessKeyEncryptedResponse> for set_access_key::EncryptedResponse {
    fn from(
        SetAccessKeyEncryptedResponse {
            tag,
            ciphertext,
            aad,
            nonce,
        }: SetAccessKeyEncryptedResponse,
    ) -> Self {
        set_access_key::EncryptedResponse {
            tag,
            ciphertext,
            aad,
            nonce,
        }
    }
}

impl From<set_access_key::SetAccessKeyResult> for SetAccessKeyResult {
    fn from(result: set_access_key::SetAccessKeyResult) -> Self {
        Self::from(result.map(SetAccessKeyEncryptedResponse::from))
    }
}

impl From<SetAccessKeyResult> for set_access_key::SetAccessKeyResult {
    fn from(result: SetAccessKeyResult) -> Self {
        Self::from(result.map(set_access_key::EncryptedResponse::from))
    }
}

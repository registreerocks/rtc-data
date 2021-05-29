// TODO: Document
#![cfg_attr(feature = "teaclave_sgx", no_std)]
#[cfg(feature = "teaclave_sgx")]
extern crate sgx_tstd as std;
extern crate sgx_types;
#[cfg(not(feature = "teaclave_sgx"))]
extern crate thiserror;
#[cfg(feature = "teaclave_sgx")]
extern crate thiserror_sgx as thiserror;

use std::fmt::Display;
use thiserror::Error;

use sgx_types::*;

use std::boxed::Box;

mod data_upload;
pub mod dh;
pub use data_upload::*;

mod exec_token;
pub use exec_token::*;

mod ecall_result;
pub use ecall_result::*;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct EncryptedMessage {
    pub ciphertext: Box<[u8]>,
    pub nonce: [u8; 24],
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct SizedEncryptedMessage<const MESSAGE_LEN: usize> {
    pub ciphertext: [u8; MESSAGE_LEN],
    pub nonce: [u8; 24],
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug, Error)]
pub enum CryptoError {
    #[error("Crypto rng error: {}", .0)]
    Rand(u32),
    #[error("Unknown crypto error")]
    Unknown,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug, Error)]
pub enum CreateReportResult {
    #[error("Success")]
    Success,
    #[error("Failed with SGX error: {}", .0.as_str())]
    Sgx(sgx_status_t),
    #[error("Failed to get Public Key")]
    FailedToGetPublicKey,
    #[error("Failed to encode Public Key")]
    FailedEncodePublicKey,
}

impl From<sgx_status_t> for CreateReportResult {
    fn from(err: sgx_status_t) -> Self {
        CreateReportResult::Sgx(err)
    }
}

pub const RSA3072_PKCS8_DER_SIZE: usize = 420;

pub const ENCLAVE_HELD_PUB_KEY_SIZE: usize = 32;

/// Size of all the enclave held data shared and validated during attestation
pub const ENCLAVE_HELD_DATA_SIZE: usize = ENCLAVE_HELD_PUB_KEY_SIZE;

pub type EnclaveHeldData = [u8; ENCLAVE_HELD_DATA_SIZE];

pub type PubkeyPkcs8 = [u8; RSA3072_PKCS8_DER_SIZE];

#[derive(Error, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug)]
pub enum EcallError<T: 'static + std::error::Error + Display> {
    // Error from the sgx runtime. Ecall returned with an error.
    #[error("Ecall failed in SGX runtime: {}", .0.as_str())]
    SgxRuntime(sgx_status_t),

    // Error from the RTC enclave code. This can be caused by RTC code, or a library
    // called from RTC code, including any sgx library.
    #[error("Ecall failed in the RTC enclave: {}", .0)]
    RtcEnclave(#[from] T),
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

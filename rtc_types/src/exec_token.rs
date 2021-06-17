use std::io;
use std::vec::Vec;

use thiserror::Error;

use crate::{CryptoError, EcallResult, Nonce};

#[repr(C)]
#[derive(Debug)]
pub struct ExecReqMetadata {
    pub uploader_pub_key: [u8; 32],
    pub nonce: [u8; 24],
}

#[repr(C)]
#[derive(Debug)]
pub struct ExecTokenResponse {
    pub execution_token: Vec<u8>,
    pub nonce: [u8; 24],
}

pub type IssueTokenResult = EcallResult<Nonce, ExecTokenError>;

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug, Error)]
pub enum ExecTokenError {
    #[error("Failed to generate Execution Token")]
    Generate,
    #[error("Data validation failed")]
    Validation,
    #[error("Output token buffer is either to small or too large")]
    OutputBufferSize,
    #[error("Encryption/Decryption failed")]
    Crypto,
    #[error("IO operation failed")]
    IO,
}

impl From<CryptoError> for ExecTokenError {
    fn from(_: CryptoError) -> Self {
        ExecTokenError::Crypto
    }
}

impl From<io::Error> for ExecTokenError {
    fn from(_: io::Error) -> Self {
        ExecTokenError::IO
    }
}

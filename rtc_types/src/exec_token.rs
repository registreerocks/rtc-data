use std::vec::Vec;
use thiserror::Error;

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

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug, Error)]
pub enum ExecTokenError {
    #[error("Failed to generate Execution Token")]
    Generate,
    #[error("Data validation failed")]
    Validation,
}

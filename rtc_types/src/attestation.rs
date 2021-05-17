use std::vec::Vec;
use thiserror::Error;

#[repr(C)]
#[derive(Debug)]
pub struct AttestReqMetadata {
    pub requester_pub_key: [u8; 32],
    pub nonce: [u8; 24],
}

#[repr(C)]
#[derive(Debug)]
pub struct AttestationResponse {
    pub attestation_jwt: String,
    pub nonce: [u8; 24],
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug, Error)]
pub enum AttestError {
    #[error("Failed to get attestation JWT token")]
    Generate,
    #[error("Data validation failed")]
    Validation,
}

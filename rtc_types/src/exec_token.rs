use super::*;
use std::vec::Vec;
use thiserror;
use thiserror::Error;

#[repr(C)]
#[derive(Debug)]
pub struct ExecTokenResponse {
    pub execution_token: Vec<u8>,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug, Error)]
pub enum ExecTokenError {
    #[error("Failed to generate Execution Token")]
    Generate,
    #[error("Data validation failed")]
    Validation,
}

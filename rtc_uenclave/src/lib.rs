//! Base library used to interact with an rtc_enclave from a non-sgx environment
#![deny(clippy::mem_forget)]
#![feature(unsafe_block_in_unsafe_fn)]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(toowned_clone_into)]
#![warn(missing_docs)]
extern crate rtc_types;
extern crate sgx_types;
#[cfg(not(test))]
extern crate sgx_urts;

#[cfg(test)]
extern crate mockall;
extern crate mockall_double;

mod ecalls;
mod quote;
mod rtc_enclave;

pub use ecalls::{CreateReportError, EnclaveReportResult};
pub use rtc_enclave::*;

// TODO: Use newtype construct?
pub use rtc_enclave::SgxEnclave;

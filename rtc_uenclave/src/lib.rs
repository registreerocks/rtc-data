//! Base library used to interact with an rtc_enclave from a non-sgx environment
#![cfg_attr(test, allow(unused))]
#![deny(clippy::mem_forget)]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(toowned_clone_into)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

mod azure_attestation;
mod ecalls;
mod enclaves;
mod http_client;
mod quote;
mod rtc_enclave;

pub use ecalls::{CreateReportError, EnclaveReportResult};
pub use enclaves::*;
pub use rtc_enclave::*;

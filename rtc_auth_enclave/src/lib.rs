#![crate_type = "staticlib"]
#![no_std]
#![feature(unsafe_block_in_unsafe_fn)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::mem_forget)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

pub use rtc_tenclave::dh::*;
#[allow(unused_imports)] // for ECALL linking
use rtc_tenclave::enclave::enclave_create_report;

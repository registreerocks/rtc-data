#![crate_type = "staticlib"]
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::mem_forget)]

#[cfg(not(target_env = "sgx"))]
extern crate sgx_tstd as std;

pub use rtc_tenclave::dh::*;
pub use rtc_tenclave::enclave::*;

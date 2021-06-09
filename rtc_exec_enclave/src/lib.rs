#![crate_type = "staticlib"]
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::mem_forget)]

mod sample_functions;
mod types;

#[cfg(not(target_env = "sgx"))]
extern crate sgx_tstd as std;

use std::boxed::Box;
use std::vec;

pub use rtc_tenclave::dh::*;
pub use rtc_tenclave::enclave::*;

use crate::types::*;

pub struct Token {
    binary_hash: [u8; 32],
}

#[allow(clippy::result_unit_err)]
pub fn request_execution(token: Token, _params: ()) -> Result<Box<[u8]>, ()> {
    let exec_module = match get_module_by_id(token.binary_hash) {
        Some(val) => val,
        None => return Err(()),
    };
    let data = get_data(&token);

    // as_ptr() does not take ownership, so the data will be dropped at the end of this function
    let result = unsafe { exec_module.call(data.as_ptr(), data.len()) };

    match result {
        Ok(val) => Ok(val),
        // XXX: The error handling here should take into account the Traps from WASM once we call
        // WASM functions
        Err(_) => Err(()),
    }
}

// XXX: This is placeholder until we completed the data retrieval flow and know what values
// we need to pass through to the data enclave
fn get_data(_token: &Token) -> Box<[u8]> {
    vec![123; 43].into_boxed_slice()
}

// XXX: The implementation is only for the sample functions currently
pub(crate) fn get_module_by_id(module_id: [u8; 32]) -> Option<Box<dyn ExecModule>> {
    use sample_functions::*;
    match module_id {
        SHA256_HASH_MODULE_ID => Some(Box::new(Sha256HashModule)),
        MEDIAN_MODULE_ID => Some(Box::new(MedianModule)),
        _ => None,
    }
}

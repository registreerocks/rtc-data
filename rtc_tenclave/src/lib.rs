#![feature(unsafe_block_in_unsafe_fn)]
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![allow(incomplete_features)]
#![feature(const_generics)]
#![feature(const_evaluatable_checked)]
#![deny(clippy::mem_forget)]
#![cfg_attr(not(test), no_std)]

#[cfg(not(test))]
#[macro_use]
extern crate sgx_tstd as std;

cfg_if::cfg_if! {
    if #[cfg(test)] {
        extern crate thiserror_std as thiserror;
        extern crate rand_std as rand;
        extern crate sgx_ucrypto as sgx_tcrypto;
        extern crate serde_std as serde;
        extern crate serde_json_std as serde_json;
    }
}

pub mod crypto;
pub mod dh;
pub mod enclave;
pub mod kv_store;
pub mod util;

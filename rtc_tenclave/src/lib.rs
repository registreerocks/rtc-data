#![feature(unsafe_block_in_unsafe_fn)]
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(const_generics)]
#![feature(const_evaluatable_checked)]
#![deny(clippy::mem_forget)]

#[cfg(not(test))]
#[macro_use]
extern crate sgx_tstd as std;

pub mod crypto;
pub mod util;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

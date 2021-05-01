#![deny(clippy::mem_forget)]
#![feature(toowned_clone_into)]
#![feature(try_blocks)]
#![warn(rust_2018_idioms)]

pub mod app_config;
pub mod data_enclave_actor;
pub mod handlers;
pub mod merge_error;

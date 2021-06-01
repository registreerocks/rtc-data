#![deny(clippy::mem_forget)]
#![feature(toowned_clone_into)]
#![feature(try_blocks)]
#![warn(rust_2018_idioms)]

pub mod app_config;
pub mod auth_enclave_actor;
pub mod data_enclave_actor;
pub mod data_upload;
pub mod exec_token;
pub mod handlers;
pub mod merge_error;
pub mod validation;

use base64;
use base64_serde::base64_serde_type;

base64_serde_type!(pub Base64Standard, base64::STANDARD);

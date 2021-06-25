//! Top-level test module

// See rtc_tenclave/src/crypto.rs
pub const CRYPTO_BOX_ZEROBYTES: usize = 32;
pub const CRYPTO_BOX_BOXZEROBYTES: usize = 16;

mod helpers;

mod ecalls;
mod web_api;

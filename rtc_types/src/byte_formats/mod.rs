//! Helpers for serializing the types in this library to various byte formats.
//!
//! # Naming convention
//!
//! Sub-modules should be named `{name}_format`, for each binary format implemented.
//!
//! Functions in each module use the following naming convention:
//!
//! > `(write|read|view)_(array|slice)`
//!
//! 1. Operation:
//!
//!    - `write` to serialize a structure to bytes
//!    - `read` to deserialize bytes to a new Rust structure (copying data)
//!    - `view` to deserialize bytes to a structured view (sharing data)
//!
//! 2. Type suffix, for the byte representation:
//!
//!    - `array` for working with constant-sized arrays (`[u8; ?]`)
//!    - `slice` for working with variable-sized slices (`[u8]`)

pub mod rkyv_format;

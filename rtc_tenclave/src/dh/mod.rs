//! Support for establishing secure local inter-enclave sessions using [`sgx_tdh`].

mod protected_channel;
mod sessions;
mod types;

pub use sessions::*;

#[cfg(test)]
mod enclave {
    //! Stub [`sgx_tstd::enclave`] for testing.

    use sgx_types::sgx_enclave_id_t;

    pub fn get_enclave_id() -> sgx_enclave_id_t {
        78
    }
}

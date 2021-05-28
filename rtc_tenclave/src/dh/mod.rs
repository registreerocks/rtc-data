mod protected_channel;
mod sessions;
mod types;

pub use sessions::*;

#[cfg(test)]
mod enclave {
    use sgx_types::sgx_enclave_id_t;

    pub fn get_enclave_id() -> sgx_enclave_id_t {
        78
    }
}

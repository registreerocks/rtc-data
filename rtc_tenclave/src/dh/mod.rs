mod protected_channel;
mod sessions;
mod types;

pub use sessions::*;

#[cfg(test)]
mod enclave {
    pub fn get_enclave_id() -> u64 {
        78
    }
}

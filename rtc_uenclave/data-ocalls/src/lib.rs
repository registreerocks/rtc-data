use std::fs;
use std::io;
use std::slice;
use uuid::Uuid;

use sgx_types::*;

/// Saves a blob of data received from the enclave
///
/// Safety:
/// Caller needs to ensure that the blob_ptr is valid for a slice of length `blob_len`
#[no_mangle]
pub unsafe extern "C" fn rtc_save_sealed_blob_u(
    blob_ptr: *const u8,
    blob_len: usize,
    uuid: *const [u8; 16],
) -> sgx_status_t {
    // Safety: SGX should copy a buffer of the correct size, and the pointer
    // will be valid for a slice of length `blob_len`
    let blob = unsafe { slice::from_raw_parts(blob_ptr, blob_len) };

    // TODO: use some run time path for saving the data. (read path from a file next to execution or use env vars)
    // TODO: save in blob storage
    let path = format!("./{}", unsafe { Uuid::from_bytes(*uuid) });

    fs::write(path, blob);

    sgx_status_t::SGX_SUCCESS
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

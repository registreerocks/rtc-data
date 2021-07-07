#![deny(unsafe_op_in_unsafe_fn)]

use std::fs::OpenOptions;
use std::io::Write;
use std::{fs, slice};

use sgx_types::*;
use uuid::Uuid;

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

    // TODO: Replace this with Azure Blob storage.
    let uuid = Uuid::from_bytes(unsafe { *uuid });
    if let Err(err) = save_sealed_blob_to_fs(uuid, blob) {
        println!("rtc_save_sealed_blob_u: failed to save {:?}: {}", uuid, err);
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    };

    sgx_status_t::SGX_SUCCESS
}

/// Stop-gap helper: Save `blob` to the file system under `sealed_data/{uuid}`.
///
/// If saving fails, just return a plain string error to report, for now.
///
fn save_sealed_blob_to_fs(uuid: Uuid, blob: &[u8]) -> Result<(), String> {
    // TODO: use some run time path for saving the data? (read path from a file next to execution or use env vars)
    let data_dir = "sealed_data";
    fs::create_dir_all(data_dir)
        .map_err(|err| format!("create_dir_all({:?}) failed: {:?}", data_dir, err))?;

    let data_file_path = format!("{}/{}", data_dir, uuid);
    let mut data_file = OpenOptions::new()
        // Abort if a data file already exists for this UUID.
        .create_new(true)
        .write(true)
        .open(&data_file_path)
        .map_err(|err| format!("open {:?} failed: {}", data_file_path, err))?;

    data_file
        .write_all(blob)
        .map_err(|err| format!("write_all to {:?} failed: {}", data_file, err))?;

    Ok(())
}

use std::boxed::Box;

use sgx_types::*;
use uuid::Uuid;

extern "C" {
    // rtc_save_sealed_blob_u(sgx_status_t* retval, const uint8_t* blob_ptr, size_t blob_len);
    fn rtc_save_sealed_blob_u(
        retval: *mut sgx_status_t,
        blob_ptr: *const u8,
        blob_len: usize,
        uuid: &[u8; 16],
    ) -> sgx_status_t;
}

pub fn save_sealed_blob_u(blob: Box<[u8]>, uuid: Uuid) -> sgx_status_t {
    let mut retval = sgx_status_t::default();
    let sgx_res = unsafe {
        rtc_save_sealed_blob_u(
            &mut retval as *mut _,
            blob.as_ptr(),
            blob.len(),
            uuid.as_bytes(),
        )
    };

    if retval != sgx_status_t::SGX_SUCCESS {
        retval
    } else if sgx_res != sgx_status_t::SGX_SUCCESS {
        sgx_res
    } else {
        sgx_status_t::SGX_SUCCESS
    }
}

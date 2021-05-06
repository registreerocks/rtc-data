#![crate_type = "staticlib"]
#![no_std]
#![feature(unsafe_block_in_unsafe_fn)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::mem_forget)]

use sgx_types::{sgx_report_t, sgx_status_t, sgx_target_info_t};

use rtc_types::{CreateReportResult, EnclaveHeldData};

/// TODO: Stubbed out, for now.
#[no_mangle]
pub extern "C" fn enclave_create_report(
    _p_qe3_target: *const sgx_target_info_t,
    _enclave_pubkey: *mut EnclaveHeldData,
    _p_report: *mut sgx_report_t,
) -> CreateReportResult {
    CreateReportResult::Sgx(sgx_status_t::SGX_ERROR_UNEXPECTED)
}

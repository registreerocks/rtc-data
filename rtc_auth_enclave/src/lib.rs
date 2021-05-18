#![crate_type = "staticlib"]
#![no_std]
#![feature(unsafe_block_in_unsafe_fn)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::mem_forget)]

use sgx_types::{sgx_report_t, sgx_status_t, sgx_target_info_t};

use rtc_types::{CreateReportResult, EnclaveHeldData};

use rtc_tenclave::enclave::*;

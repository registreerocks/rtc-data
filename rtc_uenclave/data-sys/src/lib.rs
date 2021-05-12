#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use data_ocalls;
use rtc_ecalls::RtcEnclaveEcalls;
use rtc_types::*;
use sgx_types::*;
use sgx_urts;

pub mod ffi {
    use super::*;
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(Default)]
pub struct DataSys();

impl RtcEnclaveEcalls for DataSys {
    unsafe fn enclave_create_report(
        &self,
        eid: sgx_enclave_id_t,
        retval: *mut CreateReportResult,
        p_qe3_target: *const sgx_target_info_t,
        enclave_data: *mut EnclaveHeldData,
        p_report: *mut sgx_report_t,
    ) -> sgx_status_t {
        ffi::enclave_create_report(eid, retval, p_qe3_target, enclave_data, p_report)
    }
}

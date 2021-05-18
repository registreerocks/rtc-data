#[allow(unused_imports)]
use sgx_urts;

use rtc_ecalls::RtcEnclaveEcalls;
use rtc_types::*;
use sgx_types::*;

pub mod ffi {
    use super::*;
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(Default)]
pub struct AuthSys();

impl RtcEnclaveEcalls for AuthSys {
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

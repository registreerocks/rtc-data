use rtc_ecalls::RtcEnclaveEcalls;
use rtc_types::*;
use sgx_types::*;
use sgx_urts;

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
        todo!();
    }
}

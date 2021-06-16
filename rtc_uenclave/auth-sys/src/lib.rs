use rtc_ecalls::RtcEnclaveEcalls;
use rtc_types::dh::*;
pub use rtc_types::enclave_messages::ffi_set_access_key::*;
use rtc_types::*;
use rtc_udh;
use sgx_types::*;
#[allow(unused_imports)]
pub use sgx_urts;

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
        ffi::rtc_auth_enclave_create_report(eid, retval, p_qe3_target, enclave_data, p_report)
    }
}

impl rtc_udh::ResponderSys for AuthSys {
    unsafe fn rtc_session_request(
        &self,
        eid: sgx_enclave_id_t,
        retval: *mut SessionRequestResult,
        src_enclave_id: sgx_enclave_id_t,
    ) -> sgx_status_t {
        ffi::rtc_auth_session_request(eid, retval, src_enclave_id)
    }

    unsafe fn rtc_exchange_report(
        &self,
        eid: sgx_enclave_id_t,
        retval: *mut ExchangeReportResult,
        src_enclave_id: sgx_enclave_id_t,
        dh_msg2_ptr: *const sgx_dh_msg2_t,
    ) -> sgx_status_t {
        ffi::rtc_auth_exchange_report(eid, retval, src_enclave_id, dh_msg2_ptr)
    }

    unsafe fn rtc_end_session(
        &self,
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        src_enclave_id: sgx_enclave_id_t,
    ) -> sgx_status_t {
        ffi::rtc_auth_end_session(eid, retval, src_enclave_id)
    }
}

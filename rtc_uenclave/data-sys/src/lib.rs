#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[allow(unused_imports)]
use data_ocalls;
#[allow(unused_imports)]
use sgx_urts;

use rtc_ecalls::RtcEnclaveEcalls;
use rtc_types::dh::*;
use rtc_types::*;
use rtc_udh;
use sgx_types::*;

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

impl rtc_udh::ResponderSys for DataSys {
    unsafe fn rtc_session_request(
        &self,
        eid: sgx_enclave_id_t,
        retval: *mut SessionRequestResult,
        src_enclave_id: sgx_enclave_id_t,
    ) -> sgx_status_t {
        ffi::rtc_session_request(eid, retval, src_enclave_id)
    }

    unsafe fn rtc_exchange_report(
        &self,
        eid: sgx_enclave_id_t,
        retval: *mut ExchangeReportResult,
        src_enclave_id: sgx_enclave_id_t,
        dh_msg2_ptr: *const sgx_dh_msg2_t,
    ) -> sgx_status_t {
        ffi::rtc_exchange_report(eid, retval, src_enclave_id, dh_msg2_ptr)
    }

    unsafe fn rtc_end_session(
        &self,
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        src_enclave_id: sgx_enclave_id_t,
    ) -> sgx_status_t {
        ffi::rtc_end_session(eid, retval, src_enclave_id)
    }
}

use rtc_types::{
    dh::{ExchangeReportResult, SessionRequestResult},
    EcallResult,
};
use sgx_types::*;

pub trait ResponderSys: Send {
    unsafe fn rtc_session_request(
        &self,
        eid: sgx_enclave_id_t,
        retval: *mut SessionRequestResult,
        src_enclave_id: sgx_enclave_id_t,
    ) -> sgx_status_t;

    unsafe fn rtc_exchange_report(
        &self,
        eid: sgx_enclave_id_t,
        retval: *mut ExchangeReportResult,
        src_enclave_id: sgx_enclave_id_t,
        dh_msg2_ptr: *const sgx_dh_msg2_t,
    ) -> sgx_status_t;

    unsafe fn rtc_end_session(
        &self,
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        src_enclave_id: sgx_enclave_id_t,
    ) -> sgx_status_t;
}

pub(crate) struct Responder {
    eid: sgx_enclave_id_t,
    sys: Box<dyn ResponderSys>,
}

// TODO: Unsafe comments
impl Responder {
    pub fn new(eid: sgx_enclave_id_t, sys: Box<dyn ResponderSys>) -> Self {
        Self { eid, sys }
    }

    pub fn session_request(&self, src_enclave_id: sgx_enclave_id_t) -> SessionRequestResult {
        let mut retval = SessionRequestResult::default();
        let ecall_res = unsafe {
            self.sys
                .rtc_session_request(self.eid, &mut retval, src_enclave_id)
        };
        if ecall_res == sgx_status_t::SGX_SUCCESS {
            retval
        } else {
            println!("Session request ecall failed for enclave: {}", self.eid);
            EcallResult::Err(ecall_res)
        }
    }

    pub fn exchange_report(
        &self,
        src_enclave_id: sgx_enclave_id_t,
        dh_msg2_ptr: *const sgx_dh_msg2_t,
    ) -> ExchangeReportResult {
        let mut retval = ExchangeReportResult::default();
        let ecall_res = unsafe {
            self.sys
                .rtc_exchange_report(self.eid, &mut retval, src_enclave_id, dh_msg2_ptr)
        };

        if ecall_res == sgx_status_t::SGX_SUCCESS {
            retval
        } else {
            println!("Exchange report ecall failed for enclave: {}", self.eid);
            EcallResult::Err(ecall_res)
        }
    }

    pub fn end_session(&self, src_enclave_id: sgx_enclave_id_t) -> sgx_status_t {
        let mut retval = sgx_status_t::SGX_SUCCESS;
        let ecall_res = unsafe {
            self.sys
                .rtc_end_session(self.eid, &mut retval, src_enclave_id)
        };

        if ecall_res == sgx_status_t::SGX_SUCCESS {
            retval
        } else {
            println!("End session ecall failed for enclave: {}", self.eid);
            ecall_res
        }
    }
}

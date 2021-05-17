mod responder;

use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::{Arc, Mutex, RwLock},
};

use once_cell::sync::OnceCell;
use responder::Responder;
pub use responder::ResponderSys;
use rtc_types::{
    dh::{ExchangeReportResult, SessionRequestResult},
    EcallResult,
};
use sgx_types::*;

type SyncSendResponder = Arc<Mutex<Responder>>;

type DhResponders = HashMap<sgx_enclave_id_t, SyncSendResponder>;

fn dh_responders() -> &'static RwLock<DhResponders> {
    static DH_RESPONDERS: OnceCell<RwLock<DhResponders>> = OnceCell::new();
    DH_RESPONDERS.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn set_responder(
    enclave_id: u64,
    responder: Box<(dyn ResponderSys + 'static)>,
) -> Result<(), sgx_status_t> {
    match dh_responders().write() {
        Ok(mut resp_map) => {
            resp_map.insert(
                enclave_id,
                Arc::new(Mutex::new(Responder::new(enclave_id, responder))),
            );
            Ok(())
        }
        Err(_) => Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
    }
}

fn get_responder(id: &u64) -> Result<SyncSendResponder, sgx_status_t> {
    dh_responders()
        .read()
        .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        .get(id)
        .ok_or(sgx_status_t::SGX_ERROR_INVALID_ENCLAVE_ID)
        .map(Clone::clone)
}

#[no_mangle]
pub extern "C" fn rtc_session_request_u(
    src_enclave_id: sgx_enclave_id_t,
    dest_enclave_id: sgx_enclave_id_t,
) -> SessionRequestResult {
    // TODO: Refactor our duplicated code here, this is tricky because of variable
    // scoping when working with locks
    match get_responder(&dest_enclave_id) {
        Ok(res) => res
            .lock()
            .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))
            .and_then(|resp| resp.session_request(src_enclave_id).into())
            .into(),
        Err(err) => EcallResult::Err(err),
    }
}

#[no_mangle]
extern "C" fn rtc_exchange_report_u(
    src_enclave_id: sgx_enclave_id_t,
    dest_enclave_id: sgx_enclave_id_t,
    dh_msg2: *const sgx_dh_msg2_t,
) -> ExchangeReportResult {
    match get_responder(&dest_enclave_id) {
        Ok(res) => res
            .lock()
            .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))
            .and_then(|resp| resp.exchange_report(src_enclave_id, dh_msg2).into())
            .into(),
        Err(err) => EcallResult::Err(err),
    }
}

#[no_mangle]
extern "C" fn rtc_end_session_u(
    src_enclave_id: sgx_enclave_id_t,
    dest_enclave_id: sgx_enclave_id_t,
) -> sgx_status_t {
    match get_responder(&dest_enclave_id) {
        Ok(res) => res
            .lock()
            .map_or(sgx_status_t::SGX_ERROR_UNEXPECTED, |resp| {
                resp.end_session(src_enclave_id)
            }),
        Err(err) => err,
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

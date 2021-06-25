mod responder;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use once_cell::sync::OnceCell;
use responder::Responder;
pub use responder::ResponderSys;
use rtc_types::dh::{ExchangeReportResult, SessionRequestResult};
use rtc_types::EcallResult;
use sgx_types::*;

type SyncSendResponder = Arc<Mutex<Responder>>;

type DhResponders = HashMap<sgx_enclave_id_t, SyncSendResponder>;

fn dh_responders() -> &'static RwLock<DhResponders> {
    static DH_RESPONDERS: OnceCell<RwLock<DhResponders>> = OnceCell::new();
    DH_RESPONDERS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register enclave as a DH responder.
///
/// # Panics
///
/// If `enclave_id` already has a registered responder.
pub fn set_responder(
    enclave_id: sgx_enclave_id_t,
    responder: Box<(dyn ResponderSys + 'static)>,
) -> Result<(), sgx_status_t> {
    match dh_responders().write() {
        Ok(mut resp_map) => {
            let value = Arc::new(Mutex::new(Responder::new(enclave_id, responder)));

            // TODO: Use [`HashMap::try_insert`] once stable.
            // Unstable tracking issue: <https://github.com/rust-lang/rust/issues/82766>
            match resp_map.entry(enclave_id) {
                // TODO: Is there any way to report more useful debug information about
                //       the new and existing responders?
                Entry::Occupied(_entry) => panic!(
                    "set_responder: enclave_id {:?} already has a registered responder",
                    enclave_id,
                ),
                Entry::Vacant(entry) => entry.insert(value),
            };
            Ok(())
        }
        Err(_) => Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
    }
}

/// Retrieve enclave's registered responder.
fn get_responder(enclave_id: sgx_enclave_id_t) -> Result<SyncSendResponder, sgx_status_t> {
    dh_responders()
        .read()
        .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        .get(&enclave_id)
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
    match get_responder(dest_enclave_id) {
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
    match get_responder(dest_enclave_id) {
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
    match get_responder(dest_enclave_id) {
        Ok(res) => res
            .lock()
            .map_or(sgx_status_t::SGX_ERROR_UNEXPECTED, |resp| {
                resp.end_session(src_enclave_id)
            }),
        Err(err) => err,
    }
}

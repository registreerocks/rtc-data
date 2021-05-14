mod types;

use once_cell::sync::Lazy;
use sgx_tdh::{SgxDhInitiator, SgxDhMsg1, SgxDhMsg2, SgxDhMsg3, SgxDhResponder};
use sgx_tstd::{collections::HashMap, enclave, sync::SgxRwLock};
use sgx_types::*;
use types::*;

#[no_mangle]
pub unsafe extern "C" fn test_dh() {
    init_initiator(enclave::get_enclave_id());
}

// NOTE: Something similar can be done in the OCALL library
// (by storing pointers to data inside the enclave)
// TODO: Figure out session timeouts
static DH_SESSIONS: Lazy<SgxRwLock<HashMap<sgx_enclave_id_t, DhSession>>> =
    Lazy::new(|| SgxRwLock::new(HashMap::new()));

pub fn init_initiator(dest_enclave_id: sgx_enclave_id_t) -> Result<(), sgx_status_t> {
    let this_enclave_id = enclave::get_enclave_id();
    let mut initiator: SgxDhInitiator = SgxDhInitiator::init_session();

    let dh_msg1 = init_responder(this_enclave_id)?;

    let mut dh_msg2 = SgxDhMsg2::default();
    initiator.proc_msg1(&dh_msg1, &mut dh_msg2)?;
    let dh_msg3 = exchange_report(this_enclave_id, &dh_msg2)?;

    let mut aek = sgx_align_key_128bit_t::default(); // Session Key
    let mut responder_identity = sgx_dh_session_enclave_identity_t::default();

    // TODO: Verify identity
    initiator.proc_msg3(&dh_msg3, &mut aek.key, &mut responder_identity)?;
    println!("{:?}", aek);

    match DH_SESSIONS.write() {
        Ok(mut sessions) => {
            sessions.insert(
                dest_enclave_id,
                DhSession {
                    session_status: DhSessionStatus::Active(aek),
                    ..Default::default()
                },
            );
            Ok(())
        }
        Err(_) => {
            // TODO: error that terminates enclave
            return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
        }
    }
}

pub fn init_responder(src_enclave_id: sgx_enclave_id_t) -> Result<sgx_dh_msg1_t, sgx_status_t> {
    let mut responder = SgxDhResponder::init_session();

    let mut dh_msg1 = SgxDhMsg1::default();

    responder.gen_msg1(&mut dh_msg1)?;

    match DH_SESSIONS.write() {
        Ok(mut sessions) => {
            sessions.insert(
                src_enclave_id,
                DhSession {
                    session_status: DhSessionStatus::InProgress(responder),
                    ..Default::default()
                },
            );

            println!("msg1 {:?}", dh_msg1);
            Ok(dh_msg1)
        }
        Err(_) => {
            // TODO: Poisoned lock is pretty bad in this context, we should probably stop the
            // enclave and start with clean state.
            Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
        }
    }
}

pub fn exchange_report(
    src_enclave_id: sgx_enclave_id_t,
    dh_msg2: &sgx_dh_msg2_t,
) -> Result<SgxDhMsg3, sgx_status_t> {
    // Acquire write lock for the whole function since we need to mutate the session value
    let mut sessions = DH_SESSIONS
        .write()
        .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?;

    // TODO: Custom error type
    let mut responder_session = sessions
        .get_mut(&src_enclave_id)
        .ok_or(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)?;

    let (dh_msg3, aek) = match responder_session.session_status {
        DhSessionStatus::InProgress(mut responder) => {
            let mut msg3 = SgxDhMsg3::default();
            let mut aek = sgx_align_key_128bit_t::default(); // Session Key
            let mut initiator_identity = sgx_dh_session_enclave_identity_t::default();

            responder.proc_msg2(dh_msg2, &mut msg3, &mut aek.key, &mut initiator_identity)?;

            // TODO: Verify initiator_identity
            (msg3, aek)
        }
        // TODO: Custom error type
        _ => return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER),
    };

    println!("{:?}", aek);

    responder_session.session_status = DhSessionStatus::Active(aek);
    Ok(dh_msg3)
}

mod protected_channel;

use once_cell::sync::OnceCell;
use sgx_tdh::{SgxDhInitiator, SgxDhMsg1, SgxDhMsg2, SgxDhMsg3, SgxDhResponder};

use sgx_tstd::{
    collections::HashMap,
    enclave,
    sync::{Arc, SgxMutex, SgxRwLock, SgxRwLockWriteGuard},
};
use sgx_types::*;
use std::ops::Deref;

use protected_channel::ProtectedChannel;

#[no_mangle]
pub unsafe extern "C" fn test_dh() {
    dh_sessions()
        .establish_new(&enclave::get_enclave_id())
        .expect("test failed");
}

enum AtomicSession {
    // TODO: Add session closing mechanism
    Closed,
    InProgress(SgxDhResponder),
    Active(Arc<SgxMutex<ProtectedChannel>>),
}

pub struct DhSessions {
    sessions: SgxRwLock<HashMap<u64, Arc<AtomicSession>>>,
}

impl DhSessions {
    fn get(&self, id: &u64) -> Option<Arc<AtomicSession>> {
        self.sessions
            .read()
            .expect("RwLock poisoned")
            .get(id)
            .map(Clone::clone)
    }

    fn lock_write(&self) -> SgxRwLockWriteGuard<HashMap<u64, Arc<AtomicSession>>> {
        self.sessions.write().expect("RwLock poisoned")
    }

    pub fn get_active(&self, id: &u64) -> Option<Arc<SgxMutex<ProtectedChannel>>> {
        match self.get(id)?.as_ref() {
            AtomicSession::Active(x) => Some(x.clone()),
            _ => None,
        }
    }

    pub fn take_in_progress(&self, id: &u64) -> Option<SgxDhResponder> {
        let mut sessions = self.lock_write();

        if matches!(sessions.get(id)?.as_ref(), AtomicSession::InProgress(_)) {
            match sessions.remove(id)?.deref() {
                AtomicSession::InProgress(responder) => Some(*responder),
                _ => unreachable!(),
            }
        } else {
            None
        }
    }

    // TODO: rewrite invariants that will be upheld seperately for responder and initiator

    fn set_active(&self, id: &u64, key: sgx_key_128bit_t) -> Result<(), sgx_status_t> {
        let result = self.lock_write().insert(
            *id,
            Arc::new(AtomicSession::Active(Arc::new(SgxMutex::new(
                ProtectedChannel::init(key),
            )))),
        );

        match result {
            // None -> Active = Ok
            None => Ok(()),
            // Closed -> Active = Ok (new session after closing)
            Some(x) if matches!(x.as_ref(), AtomicSession::Closed) => Ok(()),
            // InProgress -> Active = Err
            // (since the only way to do this is by borrowing the in-progress value as a
            //  responder, which is not a valid op)
            // TODO: There is a special case here if we go from
            //       Responder -> Initiator (the handshake dropped). We should check that
            Some(_) => Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
            // Active -> Active = Err (Session should be closed to prevent resetting nonce-counter with same key)
        }
    }

    fn set_in_progress(&self, id: &u64, responder: SgxDhResponder) -> Result<(), sgx_status_t> {
        let _result = self
            .lock_write()
            .insert(*id, Arc::new(AtomicSession::InProgress(responder)));

        // InProgress -> InProgress = ok (new session started by initiator that is being responded to)
        // Closed -> InProgress = Ok (new session after closing)
        // Active -> In Progress = Ok if keying material differs (the caller might need to uphold this)
        // TODO: ^
        Ok(())
    }

    pub fn establish_new(&self, dest_enclave_id: &sgx_enclave_id_t) -> Result<(), sgx_status_t> {
        let this_enclave_id = enclave::get_enclave_id();
        let mut initiator: SgxDhInitiator = SgxDhInitiator::init_session();

        let dh_msg1 = init_responder_ocall(&this_enclave_id)?;

        let mut dh_msg2 = SgxDhMsg2::default();
        initiator.proc_msg1(&dh_msg1, &mut dh_msg2)?;
        let dh_msg3 = exchange_report_ocall(&this_enclave_id, &dh_msg2)?;

        let mut aek = sgx_align_key_128bit_t::default(); // Session Key
        let mut responder_identity = sgx_dh_session_enclave_identity_t::default();

        // TODO: Verify identity
        initiator.proc_msg3(&dh_msg3, &mut aek.key, &mut responder_identity)?;

        // TODO: REMOVE
        println!("{:?}", aek);

        self.set_active(dest_enclave_id, aek.key)
    }

    pub fn initiate_response(
        &self,
        src_enclave_id: &sgx_enclave_id_t,
    ) -> Result<sgx_dh_msg1_t, sgx_status_t> {
        let mut responder = SgxDhResponder::init_session();

        let mut dh_msg1 = SgxDhMsg1::default();

        responder.gen_msg1(&mut dh_msg1)?;

        self.set_in_progress(src_enclave_id, responder)?;

        println!("msg1 {:?}", dh_msg1);
        Ok(dh_msg1)
    }

    pub fn exchange_report(
        &self,
        src_enclave_id: &sgx_enclave_id_t,
        dh_msg2: &sgx_dh_msg2_t,
    ) -> Result<SgxDhMsg3, sgx_status_t> {
        let mut responder = self
            .take_in_progress(&src_enclave_id)
            // TODO: custom error
            .ok_or(sgx_status_t::SGX_ERROR_UNEXPECTED)?;

        let mut msg3 = SgxDhMsg3::default();
        let mut aek = sgx_align_key_128bit_t::default(); // Session Key
        let mut initiator_identity = sgx_dh_session_enclave_identity_t::default();

        responder.proc_msg2(dh_msg2, &mut msg3, &mut aek.key, &mut initiator_identity)?;

        // TODO: Verify initiator_identity

        // TODO: REMOVE
        println!("{:?}", aek);

        self.set_active(src_enclave_id, aek.key)?;

        Ok(msg3)
    }
}

fn init_responder_ocall(this_enclave_id: &u64) -> Result<sgx_dh_msg1_t, sgx_status_t> {
    dh_sessions().initiate_response(this_enclave_id)
    // TODO: this should call the ocall to the peer enclave.
}

fn exchange_report_ocall(
    this_enclave_id: &u64,
    dh_msg2: &sgx_dh_msg2_t,
) -> Result<SgxDhMsg3, sgx_status_t> {
    dh_sessions().exchange_report(this_enclave_id, dh_msg2)
    // TODO: this should call the ocall to the peer enclave.
}

pub fn dh_sessions() -> &'static DhSessions {
    // NOTE: Something similar can be done in the OCALL library
    // (by storing pointers to data inside the enclave, outside of the enclave)
    // TODO: Figure out session timeouts
    static DH_SESSIONS: OnceCell<DhSessions> = OnceCell::new();
    DH_SESSIONS.get_or_init(|| DhSessions {
        sessions: SgxRwLock::new(HashMap::new()),
    })
}

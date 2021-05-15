mod protected_channel;

use once_cell::sync::OnceCell;
use rtc_types::dh::{ExchangeReportResult, SessionRequestResult};
use sgx_tdh::{SgxDhInitiator, SgxDhMsg1, SgxDhMsg2, SgxDhMsg3, SgxDhResponder};

use sgx_tstd::{
    collections::HashMap,
    enclave,
    sync::{Arc, SgxMutex, SgxRwLock, SgxRwLockWriteGuard},
};
use sgx_types::*;
use std::{mem, ops::Deref};

use protected_channel::ProtectedChannel;

extern "C" {
    pub fn rtc_session_request_u(
        ret: *mut SessionRequestResult,
        src_enclave_id: sgx_enclave_id_t,
        dest_enclave_id: sgx_enclave_id_t,
    ) -> sgx_status_t;
    pub fn rtc_exchange_report_u(
        ret: *mut ExchangeReportResult,
        src_enclave_id: sgx_enclave_id_t,
        dest_enclave_id: sgx_enclave_id_t,
        dh_msg2: *const sgx_dh_msg2_t,
    ) -> sgx_status_t;
    pub fn rtc_end_session_u(
        ret: *mut sgx_status_t,
        src_enclave_id: sgx_enclave_id_t,
        dest_enclave_id: sgx_enclave_id_t,
    ) -> sgx_status_t;
}

#[no_mangle]
pub unsafe extern "C" fn test_dh() {
    dh_sessions()
        .establish_new(enclave::get_enclave_id())
        .expect("test failed");
}

enum AtomicSession {
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

    fn take_in_progress(&self, id: &u64) -> Option<SgxDhResponder> {
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

    pub fn close_session(&self, id: &u64) -> () {
        let mut sessions = self.lock_write();
        sessions.insert(*id, Arc::new(AtomicSession::Closed));
        ()
    }

    /// Creates and sets an active session between this enclave and the enclave with `id` using
    /// the `key`.
    ///
    /// # Valid Operations (It is the responsibility of the caller to ensure these hold)
    /// None -> Active = Ok
    /// Closed -> Active = Ok
    /// InProgress -> Active = Err if it is the same session
    ///   - In progress value needs to be removed from the map before using it to finalize a session
    /// Active -> Active = Err
    ///   - A session should be closed and then recreated to prevent resetting the nonce counter
    ///     with the same key.
    fn set_active(
        &self,
        id: u64,
        key: sgx_key_128bit_t,
    ) -> Result<Arc<SgxMutex<ProtectedChannel>>, sgx_status_t> {
        let channel = Arc::new(SgxMutex::new(ProtectedChannel::init(key)));
        self.lock_write()
            .insert(id, Arc::new(AtomicSession::Active(channel.clone())));
        Ok(channel)
    }

    /// Sets an in_progress session for a responding enclave linked to the provided enclave.
    ///
    /// # Valid Operations (It is the responsibility of the caller to ensure these hold)
    /// InProgress -> InProgress = Ok
    /// Closed -> InProgress = Ok
    /// Active -> In Progress = Ok if keying material differs
    fn set_in_progress(&self, id: &u64, responder: SgxDhResponder) -> Result<(), sgx_status_t> {
        let _result = self
            .lock_write()
            .insert(*id, Arc::new(AtomicSession::InProgress(responder)));

        Ok(())
    }

    pub fn establish_new(
        &self,
        dest_enclave_id: sgx_enclave_id_t,
    ) -> Result<Arc<SgxMutex<ProtectedChannel>>, sgx_status_t> {
        let this_enclave_id = enclave::get_enclave_id();
        let mut initiator: SgxDhInitiator = SgxDhInitiator::init_session();

        let dh_msg1 = init_responder_ocall(this_enclave_id, dest_enclave_id)?;

        let mut dh_msg2 = SgxDhMsg2::default();
        initiator.proc_msg1(&dh_msg1, &mut dh_msg2)?;
        let dh_msg3 = exchange_report_ocall(this_enclave_id, dest_enclave_id, &dh_msg2)?;

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
        src_enclave_id: sgx_enclave_id_t,
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

    pub fn get_or_create_session(
        &self,
        dest_enclave_id: u64,
    ) -> Result<Arc<SgxMutex<ProtectedChannel>>, sgx_status_t> {
        if let Some(channel) = self.get_active(&dest_enclave_id) {
            Ok(channel)
        } else {
            self.establish_new(dest_enclave_id)
        }
    }
}

fn init_responder_ocall(
    this_enclave_id: u64,
    dest_enclave_id: u64,
) -> Result<sgx_dh_msg1_t, sgx_status_t> {
    let mut ret = SessionRequestResult::default();

    // TODO: Safety
    let ocall_res = unsafe { rtc_session_request_u(&mut ret, this_enclave_id, dest_enclave_id) };

    match ocall_res {
        sgx_status_t::SGX_SUCCESS => ret.into(),
        err => Err(err),
    }

    // dh_sessions().initiate_response(this_enclave_id)
}

fn exchange_report_ocall(
    this_enclave_id: u64,
    dest_enclave_id: u64,
    dh_msg2: &sgx_dh_msg2_t,
) -> Result<SgxDhMsg3, sgx_status_t> {
    let mut ret = ExchangeReportResult::default();

    // TODO: Safety
    let ocall_res =
        unsafe { rtc_exchange_report_u(&mut ret, this_enclave_id, dest_enclave_id, dh_msg2) };

    match ocall_res {
        sgx_status_t::SGX_SUCCESS => {
            let res: Result<sgx_dh_msg3_t, sgx_status_t> = ret.into();
            let mut msg3_raw = res?;

            let raw_len =
                mem::size_of::<sgx_dh_msg3_t>() as u32 + msg3_raw.msg3_body.additional_prop_length;

            // TODO: Safety
            unsafe { SgxDhMsg3::from_raw_dh_msg3_t(&mut msg3_raw, raw_len) }
                .ok_or(sgx_status_t::SGX_ERROR_UNEXPECTED)
        }
        err => Err(err),
    }

    // dh_sessions().exchange_report(this_enclave_id, dh_msg2)
}

#[no_mangle]
pub extern "C" fn rtc_session_request(src_enclave_id: sgx_enclave_id_t) -> SessionRequestResult {
    dh_sessions().initiate_response(&src_enclave_id).into()
}

#[no_mangle]
pub unsafe extern "C" fn rtc_exchange_report(
    src_enclave_id: sgx_enclave_id_t,
    dh_msg2_ptr: *const sgx_dh_msg2_t,
) -> ExchangeReportResult {
    // TODO: Safety
    let dh_msg2 = unsafe { &*dh_msg2_ptr };

    dh_sessions()
        .exchange_report(src_enclave_id, dh_msg2)
        .map(|msg3| {
            let mut msg3_raw = sgx_dh_msg3_t::default();
            unsafe { msg3.to_raw_dh_msg3_t(&mut msg3_raw, msg3.calc_raw_sealed_data_size()) };
            msg3_raw
        })
        .into()
}

// TODO: Integrate using function reference with similar signature or a config obj
fn verify_peer_enclave_trust(peer_identity: &sgx_dh_session_enclave_identity_t) -> Result<(), ()> {
    let required_flags = SGX_FLAGS_INITTED;
    let denied_flags = SGX_FLAGS_DEBUG;
    let expected_mrenclave = [0_u8; SGX_HASH_SIZE];
    let expected_mrsigner = [0_u8; SGX_HASH_SIZE];

    if peer_identity.attributes.flags & required_flags == required_flags {
        return Err(());
    }
    if peer_identity.attributes.flags & denied_flags != 0 {
        return Err(());
    }
    if peer_identity.mr_enclave.m != expected_mrenclave {
        return Err(());
    }
    if peer_identity.mr_signer.m != expected_mrsigner {
        return Err(());
    }

    return Ok(());
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

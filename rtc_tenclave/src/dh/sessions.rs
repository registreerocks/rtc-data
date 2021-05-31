use std::collections::HashMap;
use std::marker::PhantomData;
use std::prelude::v1::*;
use std::sync::Arc;

use once_cell::sync::OnceCell;
use rtc_types::dh::{ExchangeReportResult, SessionRequestResult};
use secrecy::Secret;
use sgx_types::*;

use super::protected_channel::ProtectedChannel;
use super::types::{AlignedKey, RtcDhInitiator, RtcDhResponder};

#[cfg(not(test))]
use sgx_tstd::enclave;
#[cfg(not(test))]
use sgx_tstd::sync::{
    SgxMutex as Mutex, SgxRwLock as RwLock, SgxRwLockWriteGuard as RwLockWriteGuard,
};

#[cfg(test)]
use super::enclave;
#[cfg(test)]
use std::sync::{Mutex, RwLock, RwLockWriteGuard};

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

enum AtomicSession<TResp>
where
    TResp: RtcDhResponder,
{
    Closed,
    InProgress(TResp),
    Active(Arc<Mutex<ProtectedChannel>>),
}

pub struct DhSessions<TResp, TInit>
where
    TResp: RtcDhResponder,
    TInit: RtcDhInitiator,
{
    sessions: RwLock<HashMap<sgx_enclave_id_t, Arc<AtomicSession<TResp>>>>,
    _phantom_init: PhantomData<TInit>,
}

impl<TResp, TInit> DhSessions<TResp, TInit>
where
    TResp: RtcDhResponder,
    TInit: RtcDhInitiator,
{
    fn get(&self, enclave_id: sgx_enclave_id_t) -> Option<Arc<AtomicSession<TResp>>> {
        self.sessions
            .read()
            .expect("RwLock poisoned")
            .get(&enclave_id)
            .map(Clone::clone)
    }

    fn lock_write(&self) -> RwLockWriteGuard<HashMap<sgx_enclave_id_t, Arc<AtomicSession<TResp>>>> {
        self.sessions.write().expect("RwLock poisoned")
    }

    pub fn get_active(&self, enclave_id: sgx_enclave_id_t) -> Option<Arc<Mutex<ProtectedChannel>>> {
        match self.get(enclave_id)?.as_ref() {
            AtomicSession::Active(x) => Some(x.clone()),
            _ => None,
        }
    }

    fn take_in_progress(&self, enclave_id: sgx_enclave_id_t) -> Option<TResp> {
        let mut sessions = self.lock_write();

        if matches!(
            sessions.get(&enclave_id)?.as_ref(),
            AtomicSession::InProgress(_)
        ) {
            match Arc::try_unwrap(sessions.remove(&enclave_id)?) {
                Ok(AtomicSession::InProgress(resp)) => Some(resp),
                Ok(_) => unreachable!(),
                Err(_) => None,
            }
        } else {
            None
        }
    }

    pub fn close_session(&self, enclave_id: sgx_enclave_id_t) -> () {
        let mut sessions = self.lock_write();
        sessions.insert(enclave_id, Arc::new(AtomicSession::Closed));
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
        enclave_id: sgx_enclave_id_t,
        key: Secret<AlignedKey>,
    ) -> Result<Arc<Mutex<ProtectedChannel>>, sgx_status_t> {
        let channel = Arc::new(Mutex::new(ProtectedChannel::init(key)));
        self.lock_write()
            .insert(enclave_id, Arc::new(AtomicSession::Active(channel.clone())));
        Ok(channel)
    }

    /// Sets an in_progress session for a responding enclave linked to the provided enclave.
    ///
    /// # Valid Operations (It is the responsibility of the caller to ensure these hold)
    /// InProgress -> InProgress = Ok
    /// Closed -> InProgress = Ok
    /// Active -> In Progress = Ok if keying material differs
    fn set_in_progress(
        &self,
        enclave_id: sgx_enclave_id_t,
        responder: TResp,
    ) -> Result<(), sgx_status_t> {
        let _result = self
            .lock_write()
            .insert(enclave_id, Arc::new(AtomicSession::InProgress(responder)));

        Ok(())
    }

    /// Attest and establish a new active session between this enclave and `dest_enclave_id`.
    ///
    /// The responding enclave must be registered using [`rtc_udh::set_responder`].
    pub fn establish_new(
        &self,
        dest_enclave_id: sgx_enclave_id_t,
    ) -> Result<Arc<Mutex<ProtectedChannel>>, sgx_status_t> {
        let this_enclave_id = enclave::get_enclave_id();
        let mut initiator = TInit::init_session();

        let dh_msg1 = init_responder_ocall(this_enclave_id, dest_enclave_id)?;

        let dh_msg2 = initiator.proc_msg1(&dh_msg1)?;
        let mut dh_msg3 = exchange_report_ocall(this_enclave_id, dest_enclave_id, &dh_msg2)?;

        // TODO: Verify identity
        let dh_values = initiator.proc_msg3(&mut dh_msg3)?;

        self.set_active(dest_enclave_id, dh_values.session_key)
    }

    pub fn initiate_response(
        &self,
        src_enclave_id: sgx_enclave_id_t,
    ) -> Result<sgx_dh_msg1_t, sgx_status_t> {
        let mut responder = TResp::init_session();

        let dh_msg1 = responder.gen_msg1()?;

        self.set_in_progress(src_enclave_id, responder)?;

        Ok(dh_msg1)
    }

    pub fn exchange_report(
        &self,
        src_enclave_id: sgx_enclave_id_t,
        dh_msg2: &sgx_dh_msg2_t,
    ) -> Result<sgx_dh_msg3_t, sgx_status_t> {
        let mut responder = self
            .take_in_progress(src_enclave_id)
            // TODO: custom error
            .ok_or(sgx_status_t::SGX_ERROR_UNEXPECTED)?;

        let (msg3, dh_values) = responder.proc_msg2(dh_msg2)?;

        // TODO: Verify initiator_identity

        self.set_active(src_enclave_id, dh_values.session_key)?;

        Ok(msg3)
    }

    pub fn get_or_create_session(
        &self,
        dest_enclave_id: sgx_enclave_id_t,
    ) -> Result<Arc<Mutex<ProtectedChannel>>, sgx_status_t> {
        if let Some(channel) = self.get_active(dest_enclave_id) {
            Ok(channel)
        } else {
            self.establish_new(dest_enclave_id)
        }
    }
}

fn init_responder_ocall(
    this_enclave_id: sgx_enclave_id_t,
    dest_enclave_id: sgx_enclave_id_t,
) -> Result<sgx_dh_msg1_t, sgx_status_t> {
    let mut ret = SessionRequestResult::default();

    // TODO: Safety
    let ocall_res = unsafe { rtc_session_request_u(&mut ret, this_enclave_id, dest_enclave_id) };

    match ocall_res {
        sgx_status_t::SGX_SUCCESS => ret.into(),
        err => Err(err),
    }
}

fn exchange_report_ocall(
    this_enclave_id: sgx_enclave_id_t,
    dest_enclave_id: sgx_enclave_id_t,
    dh_msg2: &sgx_dh_msg2_t,
) -> Result<sgx_dh_msg3_t, sgx_status_t> {
    let mut ret = ExchangeReportResult::default();

    // TODO: Safety
    let ocall_res =
        unsafe { rtc_exchange_report_u(&mut ret, this_enclave_id, dest_enclave_id, dh_msg2) };

    match ocall_res {
        sgx_status_t::SGX_SUCCESS => ret.into(),
        err => Err(err),
    }
}

#[no_mangle]
pub extern "C" fn session_request(src_enclave_id: sgx_enclave_id_t) -> SessionRequestResult {
    dh_sessions().initiate_response(src_enclave_id).into()
}

#[no_mangle]
pub extern "C" fn end_session(src_enclave_id: sgx_enclave_id_t) -> sgx_status_t {
    // TODO: Ensure sessions close on both ends?
    dh_sessions().close_session(src_enclave_id);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn exchange_report(
    src_enclave_id: sgx_enclave_id_t,
    dh_msg2_ptr: *const sgx_dh_msg2_t,
) -> ExchangeReportResult {
    // TODO: Safety
    let dh_msg2 = unsafe { &*dh_msg2_ptr };

    dh_sessions()
        .exchange_report(src_enclave_id, dh_msg2)
        .into()
}

// TODO: Integrate using function reference with similar signature or a config obj
#[allow(dead_code)] // not used yet, but will be
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

#[cfg(not(test))]
pub use sgx_impl::dh_sessions;

#[cfg(test)]
pub use test::dh_sessions;

#[cfg(not(test))]
mod sgx_impl {
    use super::*;
    use sgx_tdh::{SgxDhInitiator, SgxDhResponder};

    pub fn dh_sessions() -> &'static DhSessions<SgxDhResponder, SgxDhInitiator> {
        // NOTE: Something similar can be done in the OCALL library
        // (by storing pointers to data inside the enclave, outside of the enclave)
        // TODO: Figure out session timeouts
        static DH_SESSIONS: OnceCell<DhSessions<SgxDhResponder, SgxDhInitiator>> = OnceCell::new();
        DH_SESSIONS.get_or_init(|| DhSessions {
            sessions: RwLock::new(HashMap::new()),
            _phantom_init: PhantomData::default(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::types::*;
    use super::*;

    pub fn dh_sessions() -> &'static DhSessions<MockRtcDhResponder, MockRtcDhInitiator> {
        // NOTE: Something similar can be done in the OCALL library
        // (by storing pointers to data inside the enclave, outside of the enclave)
        // TODO: Figure out session timeouts
        static DH_SESSIONS: OnceCell<DhSessions<MockRtcDhResponder, MockRtcDhInitiator>> =
            OnceCell::new();
        DH_SESSIONS.get_or_init(|| DhSessions {
            sessions: RwLock::new(HashMap::new()),
            _phantom_init: PhantomData::default(),
        })
    }
}

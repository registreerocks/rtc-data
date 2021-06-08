//! [`Actor`] implementation for [`RtcExecEnclave`]
//!
//! TODO: The `*_enclave_actor` modules currently mirror each other,
//!       and should be kept in sync until we factor out the shared code.

use actix::prelude::*;
use rtc_uenclave::{AttestationError, EnclaveConfig, RtcExecEnclave};
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct RequestAttestation;

type RequestAttestationResult = Result<String, AttestationError>;

impl Message for RequestAttestation {
    type Result = RequestAttestationResult;
}

pub struct ExecEnclaveActor {
    enclave: Option<RtcExecEnclave<Arc<EnclaveConfig>>>,
    config: Arc<EnclaveConfig>,
}

impl ExecEnclaveActor {
    pub fn new(config: Arc<EnclaveConfig>) -> Self {
        Self {
            enclave: None,
            config,
        }
    }

    /// Return a reference to this actor's RTC enclave.
    ///
    /// # Panics
    ///
    /// Panics if the enclave was not initialised.
    pub(crate) fn get_enclave(&self) -> &RtcExecEnclave<Arc<EnclaveConfig>> {
        self.enclave
            .as_ref()
            .expect("ExecEnclaveActor: tried to access enclave while not initialised")
    }
}

impl Actor for ExecEnclaveActor {
    type Context = Context<ExecEnclaveActor>;

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        self.enclave.take().map(|enclave| enclave.destroy());
    }

    fn started(&mut self, _ctx: &mut Self::Context) {
        self.enclave
            .replace(RtcExecEnclave::init(self.config.clone()).expect("enclave to initialize"));
    }
}

impl Handler<RequestAttestation> for ExecEnclaveActor {
    type Result = RequestAttestationResult;

    fn handle(&mut self, _msg: RequestAttestation, _ctx: &mut Self::Context) -> Self::Result {
        self.get_enclave().dcap_attestation_azure()
    }
}

// TODO: Investigate supervisor returning `Err(Cancelled)` (see supervisor docs on Actix)
impl actix::Supervised for ExecEnclaveActor {
    fn restarting(&mut self, _ctx: &mut Context<ExecEnclaveActor>) {
        self.enclave
            .replace(RtcExecEnclave::init(self.config.clone()).expect("enclave to be initialized"))
            .map(|enc| enc.destroy());
    }
}

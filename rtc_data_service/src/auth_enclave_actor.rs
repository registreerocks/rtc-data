//! [`Actor`] implementation for [`RtcAuthEnclave`]
//!
//! TODO: The `*_enclave_actor` modules currently mirror each other,
//!       and should be kept in sync until we factor out the shared code.

use std::sync::Arc;

use actix::prelude::*;
use rtc_uenclave::{EnclaveConfig, RtcAuthEnclave};
use sgx_types::sgx_enclave_id_t;

use crate::enclave_messages::{GetEnclaveId, RequestAttestation, RequestAttestationResult};

pub struct AuthEnclaveActor {
    enclave: Option<RtcAuthEnclave<Arc<EnclaveConfig>>>,
    config: Arc<EnclaveConfig>,
}

impl AuthEnclaveActor {
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
    pub(crate) fn get_enclave(&self) -> &RtcAuthEnclave<Arc<EnclaveConfig>> {
        self.enclave
            .as_ref()
            .expect("AuthEnclaveActor: tried to access enclave while not initialised")
    }
}

impl Actor for AuthEnclaveActor {
    type Context = Context<AuthEnclaveActor>;

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        self.enclave.take().map(|enclave| enclave.destroy());
    }

    fn started(&mut self, _ctx: &mut Self::Context) {
        self.enclave
            .replace(RtcAuthEnclave::init(self.config.clone()).expect("enclave to initialize"));
    }
}

impl Handler<GetEnclaveId> for AuthEnclaveActor {
    type Result = sgx_enclave_id_t;

    fn handle(&mut self, _msg: GetEnclaveId, _ctx: &mut Self::Context) -> Self::Result {
        self.get_enclave().geteid()
    }
}

impl Handler<RequestAttestation> for AuthEnclaveActor {
    type Result = RequestAttestationResult;

    fn handle(&mut self, _msg: RequestAttestation, _ctx: &mut Self::Context) -> Self::Result {
        self.get_enclave().dcap_attestation_azure()
    }
}

// TODO: Investigate supervisor returning `Err(Cancelled)` (see supervisor docs on Actix)
impl actix::Supervised for AuthEnclaveActor {
    fn restarting(&mut self, _ctx: &mut Context<AuthEnclaveActor>) {
        self.enclave
            .replace(RtcAuthEnclave::init(self.config.clone()).expect("enclave to be initialized"))
            .map(|enc| enc.destroy());
    }
}

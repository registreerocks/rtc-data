use actix::prelude::*;
use rtc_uenclave::{AttestationError, EnclaveConfig, RtcAuthEnclave};
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct RequestAttestation;

type RequestAttestationResult = Result<String, AttestationError>;

impl Message for RequestAttestation {
    type Result = RequestAttestationResult;
}

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

impl Handler<RequestAttestation> for AuthEnclaveActor {
    type Result = RequestAttestationResult;

    fn handle(&mut self, _msg: RequestAttestation, _ctx: &mut Self::Context) -> Self::Result {
        self.get_enclave().dcap_attestation_azure()
    }
}

impl actix::Supervised for AuthEnclaveActor {
    fn restarting(&mut self, _ctx: &mut Context<AuthEnclaveActor>) {
        self.enclave
            .replace(RtcAuthEnclave::init(self.config.clone()).expect("enclave to be initialized"))
            .map(|enc| enc.destroy());
    }
}

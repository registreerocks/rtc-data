use actix::prelude::*;
use rtc_uenclave::{AttestationError, EnclaveConfig, RtcEnclave};
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct RequestAttestation;

type RequestAttestationResult = Result<String, AttestationError>;

impl Message for RequestAttestation {
    type Result = RequestAttestationResult;
}

pub(crate) struct EnclaveActor {
    enclave: Option<RtcEnclave<Arc<EnclaveConfig>>>,
    config: Arc<EnclaveConfig>,
}

impl EnclaveActor {
    pub fn new(config: Arc<EnclaveConfig>) -> Self {
        Self {
            enclave: None,
            config,
        }
    }
}

impl Drop for EnclaveActor {
    fn drop(&mut self) {
        println!("Dropping enclave actor");
    }
}

impl Actor for EnclaveActor {
    type Context = Context<EnclaveActor>;

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        self.enclave.take().map(|enclave| enclave.destroy());
    }

    fn started(&mut self, _ctx: &mut Self::Context) {
        self.enclave
            .replace(RtcEnclave::init(self.config.clone()).expect("enclave to initialize"));
    }
}

impl Handler<RequestAttestation> for EnclaveActor {
    type Result = RequestAttestationResult;

    fn handle(&mut self, _msg: RequestAttestation, _ctx: &mut Self::Context) -> Self::Result {
        self.enclave
            .as_ref()
            .expect("RequestAttestation sent to uninitialized EnclaveActor")
            .dcap_attestation_azure()
    }
}

// TODO: Investigate supervisor returning `Err(Cancelled)` (see supervisor docs on Actix)
impl actix::Supervised for EnclaveActor {
    fn restarting(&mut self, _ctx: &mut Context<EnclaveActor>) {
        self.enclave
            .replace(RtcEnclave::init(self.config.clone()).expect("enclave to be initialized"))
            .map(|enc| enc.destroy());
    }
}

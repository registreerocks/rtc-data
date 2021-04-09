use actix::prelude::*;
use rtc_uenclave::{AttestationError, EnclaveConfig, RtcEnclave};
use std::cell::Cell;

// TODO: use env vars for this config
static ENCLAVE_CONFIG: EnclaveConfig = EnclaveConfig {
    attestation_provider_url: "https://sharedeus.eus.attest.azure.net",
    debug: true,
    lib_path: "enclave.signed.so",
};

#[derive(Default)]
pub(crate) struct RequestAttestation;

type RequestAttestationResult = Result<String, AttestationError>;

impl Message for RequestAttestation {
    type Result = RequestAttestationResult;
}

#[derive(Default)]
pub(crate) struct EnclaveActor(Cell<RtcEnclave>);

impl Actor for EnclaveActor {
    type Context = Context<EnclaveActor>;

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        self.0.take().destroy();
    }

    fn started(&mut self, _ctx: &mut Self::Context) {
        // TODO: Should we use expect here or handle the errors in some
        // other way?
        self.0
            .set(RtcEnclave::init(ENCLAVE_CONFIG.clone()).expect("Enclave to be initialized"));
    }
}

impl Handler<RequestAttestation> for EnclaveActor {
    type Result = RequestAttestationResult;

    fn handle(&mut self, _msg: RequestAttestation, _ctx: &mut Self::Context) -> Self::Result {
        self.0.get_mut().dcap_attestation_azure()
    }
}

// TODO: Investigate supervisor returning `Err(Cancelled)` (see supervisor docs on Actix)
impl actix::Supervised for EnclaveActor {
    fn restarting(&mut self, _ctx: &mut Context<EnclaveActor>) {
        self.0
            .replace(RtcEnclave::init(ENCLAVE_CONFIG.clone()).expect("enclave to be initialized"))
            .destroy()
    }
}

impl SystemService for EnclaveActor {}

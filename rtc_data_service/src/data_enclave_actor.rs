use actix::prelude::*;
use rtc_uenclave::{AttestationError, EnclaveConfig, RtcEnclave};
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct RequestAttestation;

type RequestAttestationResult = Result<String, AttestationError>;

impl Message for RequestAttestation {
    type Result = RequestAttestationResult;
}

pub struct DataEnclaveActor {
    enclave: Option<RtcEnclave<Arc<EnclaveConfig>>>,
    config: Arc<EnclaveConfig>,
}

impl DataEnclaveActor {
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
    pub(crate) fn get_enclave(&self) -> &RtcEnclave<Arc<EnclaveConfig>> {
        self.enclave
            .as_ref()
            .expect("DataEnclaveActor: tried to access enclave while not initialised")
    }
}

impl Drop for DataEnclaveActor {
    fn drop(&mut self) {
        println!("Dropping enclave actor");
    }
}

impl Actor for DataEnclaveActor {
    type Context = Context<DataEnclaveActor>;

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        self.enclave.take().map(|enclave| enclave.destroy());
    }

    fn started(&mut self, _ctx: &mut Self::Context) {
        self.enclave
            .replace(RtcEnclave::init(self.config.clone()).expect("enclave to initialize"));
    }
}

impl Handler<RequestAttestation> for DataEnclaveActor {
    type Result = RequestAttestationResult;

    fn handle(&mut self, _msg: RequestAttestation, _ctx: &mut Self::Context) -> Self::Result {
        self.get_enclave().dcap_attestation_azure()
    }
}

// TODO: Investigate supervisor returning `Err(Cancelled)` (see supervisor docs on Actix)
impl actix::Supervised for DataEnclaveActor {
    fn restarting(&mut self, _ctx: &mut Context<DataEnclaveActor>) {
        self.enclave
            .replace(RtcEnclave::init(self.config.clone()).expect("enclave to be initialized"))
            .map(|enc| enc.destroy());
    }
}

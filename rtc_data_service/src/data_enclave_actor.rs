//! [`Actor`] implementation for [`RtcDataEnclave`]
//!
//! TODO: The `*_enclave_actor` modules currently mirror each other,
//!       and should be kept in sync until we factor out the shared code.

use std::sync::Arc;

use actix::prelude::*;
use rtc_uenclave::{EnclaveConfig, RtcDataEnclave};
use sgx_types::sgx_enclave_id_t;

use crate::enclave_messages::{GetEnclaveId, RequestAttestation, RequestAttestationResult};

pub struct DataEnclaveActor {
    enclave: Option<RtcDataEnclave<Arc<EnclaveConfig>>>,
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
    pub(crate) fn get_enclave(&self) -> &RtcDataEnclave<Arc<EnclaveConfig>> {
        self.enclave
            .as_ref()
            .expect("DataEnclaveActor: tried to access enclave while not initialised")
    }
}

impl Actor for DataEnclaveActor {
    type Context = Context<DataEnclaveActor>;

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        self.enclave.take().map(|enclave| enclave.destroy());
    }

    fn started(&mut self, _ctx: &mut Self::Context) {
        self.enclave
            .replace(RtcDataEnclave::init(self.config.clone()).expect("enclave to initialize"));
    }
}

impl Handler<GetEnclaveId> for DataEnclaveActor {
    type Result = sgx_enclave_id_t;

    fn handle(&mut self, _msg: GetEnclaveId, _ctx: &mut Self::Context) -> Self::Result {
        self.get_enclave().geteid()
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
            .replace(RtcDataEnclave::init(self.config.clone()).expect("enclave to be initialized"))
            .map(|enc| enc.destroy());
    }
}

use actix::prelude::*;
use rtc_uenclave::{AttestationError, EnclaveConfig, RtcEnclave};
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct RequestAttestation;

#[derive(Message)]
#[rtype(result = "UploadResult")]
pub struct DataPayload;

type RequestAttestationResult = Result<String, AttestationError>;
type UploadResult = String;

impl Message for RequestAttestation {
    type Result = RequestAttestationResult;
}

// impl Message for DataPayload {
//     type Result = UploadResult;
// }

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
        self.enclave
            .as_ref()
            .expect("RequestAttestation sent to uninitialized EnclaveActor")
            .dcap_attestation_azure()
    }
}

impl Handler<DataPayload> for DataEnclaveActor {
    type Result = String;

    fn handle(&mut self, msg: DataPayload, ctx: &mut Self::Context) -> Self::Result {
        // TODO: Handle file upload
        println!("Inside DataPayload Handler");
        "Successfully Uploaded Encrypted file".to_string()
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

use crate::data_enclave_actor::DataEnclaveActor;
use actix::{Handler, Message};
use rtc_types::{AttestReqMetadata, AttestError, AttestationResponse};

// TODO : Change struct values to resemble request Body (add data access key, uuid, hash, keypair, nonce..)
pub struct AttestationMessage {
    pub metadata: AttestReqMetadata,
    pub payload: Box<[u8]>,
}

impl Message for AttestationMessage {
    type Result = Result<AttestationResponse, AttestError>;
}

impl Handler<AttestationMessage> for DataEnclaveActor {
    type Result = <AttestationMessage as Message>::Result;

    fn handle(&mut self, _msg: AttestationMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.get_enclave().get_attestaion_token()
    }
}

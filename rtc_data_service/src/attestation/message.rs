use crate::data_enclave_actor::DataEnclaveActor;
use actix::{Handler, Message};
use actix_web::error::ErrorInternalServerError;
use rtc_types::{AttestError, AttestReqMetadata, AttestationResponse};
use rtc_uenclave::AttestationError;

// TODO : Change struct values to resemble request Body (add data access key, uuid, hash, keypair, nonce..)
pub struct AttestationMessage {
    pub metadata: AttestReqMetadata,
    pub payload: Box<[u8]>,
}

impl Message for AttestationMessage {
    type Result = Result<AttestationResponse, AttestationError>;
}

impl Handler<AttestationMessage> for DataEnclaveActor {
    type Result = <AttestationMessage as Message>::Result;

    fn handle(&mut self, _msg: AttestationMessage, _ctx: &mut Self::Context) -> Self::Result {
        let jwt = self.get_enclave().dcap_attestation_azure();
        match jwt {
            Ok(result) => Ok(AttestationResponse{
                attestation_jwt: result,
                nonce: [7; 24]
            }),
            Err(err) => Err(err)
        }
    }
}

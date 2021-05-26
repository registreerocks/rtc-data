use crate::auth_enclave_actor::AuthEnclaveActor;
use actix::{Handler, Message};
use actix_web::error::ErrorInternalServerError;
use rtc_uenclave::AttestationError;

#[derive(Default)]
pub struct AttestationMessage;

impl Message for AttestationMessage {
    type Result = Result<String, AttestationError>;
}

impl Handler<AttestationMessage> for AuthEnclaveActor {
    type Result = <AttestationMessage as Message>::Result;

    fn handle(&mut self, _msg: AttestationMessage, _ctx: &mut Self::Context) -> Self::Result {
        let jwt = self.get_enclave().dcap_attestation_azure();
        match jwt {
            Ok(result) => Ok(result),
            Err(err) => Err(err),
        }
    }
}

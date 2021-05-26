use std::convert::TryInto;

use actix::{Addr, MailboxError};
use actix_web::{error::ErrorInternalServerError, get, web, HttpRequest};
use rtc_uenclave::AttestationError;

use crate::auth_enclave_actor::AuthEnclaveActor;
use crate::merge_error::*;

use super::AttestationMessage;

#[get("auth/attest")]
pub async fn req_attestation_jwt(
    _req: HttpRequest,
    enclave: web::Data<Addr<AuthEnclaveActor>>,
) -> actix_web::Result<String> {
    let result=
        enclave.send(AttestationMessage::default())
        .await
        .merge_err();
    match result {
        Ok(resp) => Ok(resp),
        Err(err) => Err(ErrorInternalServerError(err)),
    }
}

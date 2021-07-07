//! Common message types for the enclave actors.

use actix::Message;
use rtc_uenclave::AttestationError;

#[derive(Default)]
pub(crate) struct RequestAttestation;

pub(crate) type RequestAttestationResult = Result<String, AttestationError>;

impl Message for RequestAttestation {
    type Result = RequestAttestationResult;
}

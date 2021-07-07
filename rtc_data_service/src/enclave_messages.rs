//! Common message types for the enclave actors.

use actix::Message;
use rtc_uenclave::AttestationError;

/// [`Message`]: Request enclave attestation.
/// Return JWT with quote and enclave data.
///
/// See: [`rtc_uenclave::rtc_enclave::dcap_attestation_azure`]
#[derive(Default)]
pub(crate) struct RequestAttestation;

pub(crate) type RequestAttestationResult = Result<String, AttestationError>;

impl Message for RequestAttestation {
    type Result = RequestAttestationResult;
}

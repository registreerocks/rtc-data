//! Common message types for the enclave actors.

use actix::Message;
use rtc_uenclave::AttestationError;
use sgx_types::sgx_enclave_id_t;

/// [`Message`]: Get the enclave's ID.
/// Return [`sgx_enclave_id_t`].
///
/// See: [`rtc_uenclave::rtc_enclave::geteid`]
#[derive(Default)]
pub(crate) struct GetEnclaveId;

impl Message for GetEnclaveId {
    type Result = sgx_enclave_id_t;
}

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

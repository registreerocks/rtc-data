use std::borrow::Borrow;

use crate::{AttestationError, EnclaveConfig, EnclaveReportResult, RtcEnclave};
use auth_sys::AuthSys;
use rtc_types::{EcallError, EncryptedMessage, ExecReqMetadata, ExecTokenError};
use sgx_types::*;

/// Wraps all the functionality for interacting with the auth enclave
pub struct RtcAuthEnclave<TCfg>(RtcEnclave<TCfg, AuthSys>)
where
    TCfg: Borrow<EnclaveConfig>;

impl<TCfg> RtcAuthEnclave<TCfg>
where
    TCfg: Borrow<EnclaveConfig>,
{
    /// Creates a new enclave instance with the provided configuration
    pub fn init(cfg: TCfg) -> Result<Self, sgx_status_t> {
        Ok(Self(RtcEnclave::init(cfg)?))
    }

    /// Creates a report and signed enclave held data for the enclave
    pub fn create_report(
        &self,
        qe_target_info: &sgx_target_info_t,
    ) -> Result<EnclaveReportResult, AttestationError> {
        self.0.create_report(qe_target_info)
    }

    /// Performs dcap attestation using Azure Attestation
    ///
    /// Returns the JWT token with the quote and enclave data
    pub fn dcap_attestation_azure(&self) -> Result<String, AttestationError> {
        self.0.dcap_attestation_azure()
    }

    /// Take ownership of self and drop resources
    pub fn destroy(self) {
        // Take ownership of self and drop
    }

    /// `true` if the enclave have been initialized
    pub fn is_initialized(&self) -> bool {
        self.0.is_initialized()
    }

    /// Get the id of this enclave instance
    pub fn geteid(&self) -> sgx_enclave_id_t {
        self.0.geteid()
    }

    /// Issues an execution token using the provided payload
    pub fn issue_execution_token(
        &self,
        payload: &[u8],
        metadata: ExecReqMetadata,
    ) -> Result<EncryptedMessage, EcallError<ExecTokenError>> {
        ecalls::issue_execution_token(self.geteid(), payload, metadata)
    }
}

pub mod ecalls {
    use auth_sys::ffi;
    use rtc_types::*;
    use sgx_types::*;

    pub fn issue_execution_token(
        eid: sgx_enclave_id_t,
        payload: &[u8],
        metadata: ExecReqMetadata,
    ) -> Result<EncryptedMessage, EcallError<ExecTokenError>> {
        let mut out_token_buffer = vec![0u8; 416].into_boxed_slice();
        let mut retval = IssueTokenResult::Ok([0u8; 24]);

        // Safety: Since the payload, and out buffer is allocated and valid this will be
        // correctly handled by the SGX edge code
        let res = unsafe {
            ffi::rtc_auth_issue_execution_token(
                eid,
                &mut retval,
                payload.as_ptr(),
                payload.len(),
                &metadata,
                out_token_buffer.as_mut_ptr(),
                out_token_buffer.len(),
            )
        };

        let x: Result<Nonce, EcallError<ExecTokenError>> = retval.to_ecall_err(res).into();

        x.map(|r| EncryptedMessage {
            ciphertext: out_token_buffer,
            nonce: r,
        })
    }
}

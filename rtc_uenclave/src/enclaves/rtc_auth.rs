use std::borrow::Borrow;

use auth_sys::AuthSys;
use sgx_types::*;

use crate::{AttestationError, EnclaveConfig, EnclaveReportResult, RtcEnclave};

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
}

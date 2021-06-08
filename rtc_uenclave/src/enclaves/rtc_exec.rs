use std::borrow::Borrow;

use crate::{AttestationError, EnclaveConfig, EnclaveReportResult, RtcEnclave};
use exec_sys::ExecSys;
use sgx_types::*;

/// Wraps all the functionality for interacting with the exec enclave
pub struct RtcExecEnclave<TCfg>(RtcEnclave<TCfg, ExecSys>)
where
    TCfg: Borrow<EnclaveConfig>;

impl<TCfg> RtcExecEnclave<TCfg>
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
}

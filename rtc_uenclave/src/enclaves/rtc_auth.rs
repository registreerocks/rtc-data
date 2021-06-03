use std::borrow::Borrow;

use crate::{AttestationError, EnclaveConfig, EnclaveReportResult, RtcEnclave};
use auth_sys::AuthSys;
use sgx_types::*;

use rtc_types::enclave_messages::set_access_key;

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

    /// Save the generated access key for some data.
    ///
    /// This should be called from the data enclave with messages encrypted
    /// using an established protected channel.
    pub fn save_access_key(
        &self,
        encrypted_request: set_access_key::EncryptedRequest,
    ) -> Result<set_access_key::EncryptedResponse, sgx_status_t> {
        ecalls::save_access_key(self.0.geteid(), encrypted_request)
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

mod ecalls {
    //! Rust-friendly wrappers for the Edger8r-generated untrusted ECALL bridge functions.

    use sgx_types::{sgx_enclave_id_t, sgx_status_t};

    use rtc_types::enclave_messages::ng_set_access_key;
    use rtc_types::enclave_messages::set_access_key;

    use auth_sys::ffi;

    /// Implement [`super::RtcAuthEnclave::save_access_key`].
    ///
    /// This takes care of converting between the [`set_access_key`] and [`ng_set_access_key`] types.
    pub(crate) fn save_access_key(
        eid: sgx_enclave_id_t,
        encrypted_request: set_access_key::EncryptedRequest,
    ) -> Result<set_access_key::EncryptedResponse, sgx_status_t> {
        let mut retval = ng_set_access_key::EncryptedResponse::default();
        let encrypted_request: ng_set_access_key::EncryptedRequest = encrypted_request.into();

        // Safety: Copies ng_set_access_key::EncryptedRequest into retval,
        // but only valid for sgx_status_t::SGX_SUCCESS.
        let status = unsafe { ffi::rtc_auth_save_access_key(eid, &mut retval, encrypted_request) };

        match status {
            sgx_status_t::SGX_SUCCESS => {
                let retval: set_access_key::EncryptedResponse = retval.into();
                Ok(retval)
            }
            err => Err(err),
        }
    }
}

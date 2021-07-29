use std::borrow::Borrow;

use data_sys::DataSys;
use rtc_types::*;
use sgx_types::*;

use crate::{AttestationError, EnclaveConfig, EnclaveReportResult, RtcEnclave};

/// Wraps all the functionality for interacting with the data enclave
pub struct RtcDataEnclave<TCfg>(RtcEnclave<TCfg, DataSys>)
where
    TCfg: Borrow<EnclaveConfig>;

impl<TCfg> RtcDataEnclave<TCfg>
where
    TCfg: Borrow<EnclaveConfig>,
{
    /// Creates a new enclave instance with the provided configuration
    pub fn init(cfg: TCfg) -> Result<Self, sgx_status_t> {
        Ok(Self(RtcEnclave::init(cfg)?))
    }

    /// Creates a report and signed enclave held data
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

    /// Decrypts, seal and save upload data inside of the enclave
    ///
    /// Returns an encrypted payload with the UUID and access-key for
    /// uploaded data
    pub fn upload_data(
        &self,
        auth_enclave_id: sgx_enclave_id_t,
        payload: &[u8],
        metadata: UploadMetadata,
    ) -> Result<DataUploadResponse, EcallError<DataUploadError>> {
        ecalls::validate_and_save(self.0.geteid(), auth_enclave_id, payload, metadata)
    }

    /// Issue a new execution token.
    pub fn get_exec_token(&self) -> Result<ExecTokenResponse, ExecTokenError> {
        // TODO: Placeholder response
        Ok(ExecTokenResponse {
            execution_token: vec![128; 9],
            nonce: [7; 24],
        })
    }

    /// Performs local attestation to the destination enclave
    pub fn local_attestation(&self, dest_enclave_id: sgx_enclave_id_t) -> sgx_status_t {
        ecalls::local_attestation(self.0.geteid(), dest_enclave_id)
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

pub mod ecalls {
    use data_sys::ffi;
    use rtc_types::*;
    use sgx_types::*;

    pub fn validate_and_save(
        eid: sgx_enclave_id_t,
        auth_enclave_id: sgx_enclave_id_t,
        payload: &[u8],
        metadata: UploadMetadata,
    ) -> Result<DataUploadResponse, EcallError<DataUploadError>> {
        let mut retval = DataUploadResult::default();
        // TODO: Safety
        let res = unsafe {
            ffi::rtc_data_validate_and_save(
                eid,
                &mut retval,
                auth_enclave_id,
                payload.as_ptr(),
                payload.len(),
                metadata,
            )
        };
        retval.to_ecall_err(res).into()
    }

    pub fn local_attestation(
        eid: sgx_enclave_id_t,
        dest_enclave_id: sgx_enclave_id_t,
    ) -> sgx_status_t {
        let mut retval = sgx_status_t::SGX_SUCCESS;
        let res = unsafe { ffi::rtc_data_local_attestation(eid, &mut retval, dest_enclave_id) };

        match res {
            sgx_status_t::SGX_SUCCESS => res,
            err => {
                println!("local_attestation err, ecall failed: {:?}", err);
                err
            }
        }
    }
}

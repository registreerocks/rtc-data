#[cfg(test)]
use mockall::automock;
#[cfg(test)]
use mockall::predicate::*;
use mockall_double::double;

use rtc_types::*;
use sgx_types::*;

#[cfg_attr(test, automock)]
#[allow(dead_code)]
mod ffi {
    use super::*;
    // #[link(name = "Enclave_u", kind = "static")]
    extern "C" {
        pub(super) fn enclave_create_report(
            eid: sgx_enclave_id_t,
            retval: *mut CreateReportResult,
            p_qe3_target: *const sgx_target_info_t,
            enclave_pubkey: *mut PubkeyPkcs8,
            p_report: *mut sgx_report_t,
        ) -> sgx_status_t;
    }
}

#[double]
use self::ffi as ecalls;

/// Report result from an enclave alongside a public key used to encrypt data for that enclave.
#[derive(Debug, Clone, PartialEq)]
pub struct EnclaveReport {
    /// Report containing the hash of the public key in the report data field
    pub report: sgx_report_t,
    /// Public key of the enclave the report is for.
    pub enclave_pubkey: PubkeyPkcs8,
}

/// Error returned when the enclave fails to create a report
pub type CreateReportError = EcallError<CreateReportResult>;

#[cfg_attr(test, automock)]
pub(crate) mod inner {
    use super::*;

    pub fn create_report(
        eid: sgx_enclave_id_t,
        qe_target_info: &sgx_target_info_t,
    ) -> Result<EnclaveReport, CreateReportError> {
        let mut retval = CreateReportResult::Success;
        let mut ret_report: sgx_report_t = sgx_report_t::default();
        let mut ret_pubkey: PubkeyPkcs8 = [0; RSA3072_PKCS8_DER_SIZE];

        // Safety
        // SGX will return the correct type and the mutable values will be written to
        // with a value of the same type.
        let sgx_result = unsafe {
            ecalls::enclave_create_report(
                eid,
                &mut retval,
                qe_target_info,
                &mut ret_pubkey,
                &mut ret_report,
            )
        };

        match (sgx_result, retval) {
            (sgx_status_t::SGX_SUCCESS, CreateReportResult::Success) => {
                // TODO: add check that ensures the out variables are correctly written to by unsafe code?
                Ok(EnclaveReport {
                    report: ret_report,
                    enclave_pubkey: ret_pubkey,
                })
            }
            (sgx_status_t::SGX_SUCCESS, err) => Err(CreateReportError::RtcEnclave(err)),
            (sgx_err, _) => Err(CreateReportError::SgxRuntime(sgx_err)),
        }
    }
}

// pub use inner::create_report;

#[cfg(not(test))]
pub(crate) use inner::*;
#[cfg(test)]
pub(crate) use mock_inner::*;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_works() {
        let eid = 12u64;
        let qe_target_info = sgx_target_info_t::default();
        let pubkey = [2; RSA3072_PKCS8_DER_SIZE];
        let report = sgx_report_t::default();

        let ffi_ctx = ecalls::enclave_create_report_context();
        ffi_ctx
            .expect()
            .withf_st(move |id, _, ti, _, _| eid == *id && qe_target_info == unsafe { **ti })
            .returning(move |_, ret, _, key, rep| {
                unsafe {
                    *rep = report;
                    (*key).copy_from_slice(&pubkey);
                    *ret = CreateReportResult::Success;
                }
                sgx_status_t::SGX_SUCCESS
            });

        let result = inner::create_report(eid, &qe_target_info);
        assert!(result.is_ok());
        let ok_res = result.unwrap();
        assert_eq!(ok_res.report, report);
        assert_eq!(ok_res.enclave_pubkey, pubkey);
    }
}

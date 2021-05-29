#[cfg(test)]
use mockall::automock;
#[cfg(test)]
use mockall::mock;
#[cfg(test)]
use mockall::predicate::*;

use rtc_ecalls::RtcEnclaveEcalls;
use rtc_types::*;
use sgx_types::*;

/// Report result from an enclave alongside a public key used to encrypt data for that enclave.
#[derive(Debug, Clone, PartialEq)]
pub struct EnclaveReportResult {
    /// Report containing the hash of the public key in the report data field
    pub enclave_report: sgx_report_t,
    /// Public key of the enclave the report is for.
    pub enclave_held_data: EnclaveHeldData,
}

/// Error returned when the enclave fails to create a report
pub type CreateReportError = EcallError<CreateReportResult>;

pub trait RtcEcalls {
    fn create_report(
        &self,
        eid: sgx_enclave_id_t,
        qe_target_info: &sgx_target_info_t,
    ) -> Result<EnclaveReportResult, CreateReportError>;
}

impl<T: RtcEnclaveEcalls> RtcEcalls for T {
    fn create_report(
        &self,
        eid: sgx_enclave_id_t,
        qe_target_info: &sgx_target_info_t,
    ) -> Result<EnclaveReportResult, CreateReportError> {
        let mut retval = CreateReportResult::Success;
        let mut ret_report: sgx_report_t = sgx_report_t::default();
        let mut ret_enclave_data: EnclaveHeldData = [0; ENCLAVE_HELD_DATA_SIZE];

        // Safety
        // SGX will return the correct type and the mutable values will be written to
        // with a value of the same type.
        let sgx_result = unsafe {
            self.enclave_create_report(
                eid,
                &mut retval,
                qe_target_info,
                &mut ret_enclave_data,
                &mut ret_report,
            )
        };

        match (sgx_result, retval) {
            (sgx_status_t::SGX_SUCCESS, CreateReportResult::Success) => {
                // TODO: add check that ensures the out variables are correctly written to by unsafe code?
                Ok(EnclaveReportResult {
                    enclave_report: ret_report,
                    enclave_held_data: ret_enclave_data,
                })
            }
            (sgx_status_t::SGX_SUCCESS, err) => Err(CreateReportError::RtcEnclave(err)),
            (sgx_err, _) => Err(CreateReportError::SgxRuntime(sgx_err)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rtc_ecalls::MockRtcEnclaveEcalls;

    #[test]
    fn it_works() {
        let eid = 12u64;
        let qe_target_info = sgx_target_info_t::default();
        let ehd = [2; ENCLAVE_HELD_DATA_SIZE];
        let report = sgx_report_t::default();
        let mut sys_mock = MockRtcEnclaveEcalls::default();
        sys_mock
            .expect_enclave_create_report()
            .withf_st(move |id, _, ti, _, _| eid == *id && qe_target_info == unsafe { **ti })
            .returning(move |_, ret, _, key, rep| {
                unsafe {
                    *rep = report;
                    (*key).copy_from_slice(&ehd);
                    *ret = CreateReportResult::Success;
                }
                sgx_status_t::SGX_SUCCESS
            });

        let result = sys_mock.create_report(eid, &qe_target_info);
        assert!(result.is_ok());
        let ok_res = result.unwrap();
        assert_eq!(ok_res.enclave_report, report);
        assert_eq!(ok_res.enclave_held_data, ehd);
    }
}

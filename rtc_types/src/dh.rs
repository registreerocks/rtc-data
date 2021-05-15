use crate::EcallResult;
use sgx_types::*;

pub type SessionRequestResult = EcallResult<sgx_dh_msg1_t, sgx_status_t>;
pub type ExchangeReportResult = EcallResult<sgx_dh_msg3_t, sgx_status_t>;

impl Default for SessionRequestResult {
    fn default() -> Self {
        Self::Err(sgx_status_t::SGX_SUCCESS)
    }
}

impl Default for ExchangeReportResult {
    fn default() -> Self {
        Self::Err(sgx_status_t::SGX_SUCCESS)
    }
}

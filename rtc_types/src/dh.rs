use sgx_types::*;

use crate::EcallResult;

pub type SessionRequestResult = EcallResult<sgx_dh_msg1_t, sgx_status_t>;
pub type ExchangeReportResult = EcallResult<sgx_dh_msg3_t, sgx_status_t>;

// Note: The following Default implementations are intended for allocating out-parameters only.

impl Default for SessionRequestResult {
    fn default() -> Self {
        Self::Ok(sgx_dh_msg1_t::default())
    }
}

impl Default for ExchangeReportResult {
    fn default() -> Self {
        Self::Ok(sgx_dh_msg3_t::default())
    }
}

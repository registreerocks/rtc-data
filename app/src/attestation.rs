#[cfg(test)]
use mockall::*;
use rsa::RSAPublicKey;
use rtc_enclave::*;
use sgx_types::{sgx_quote3_error_t, sgx_report_t, sgx_target_info_t};
use thiserror::Error;

#[cfg(test)]
#[automock]
#[allow(dead_code)]
mod qe_functions {
    use sgx_types::{sgx_quote3_error_t, sgx_report_t, sgx_target_info_t, uint32_t, uint8_t};
    extern "C" {
        pub fn sgx_qe_get_target_info(
            p_qe_target_info: *mut sgx_target_info_t,
        ) -> sgx_quote3_error_t;
        pub fn sgx_qe_get_quote_size(p_quote_size: *mut uint32_t) -> sgx_quote3_error_t;
        pub fn sgx_qe_get_quote(
            p_app_report: *const sgx_report_t,
            quote_size: uint32_t,
            p_quote: *mut uint8_t,
        ) -> sgx_quote3_error_t;
    }
}

#[cfg(test)]
use self::mock_qe_functions::*;

#[cfg(not(test))]
use sgx_types::{sgx_qe_get_quote, sgx_qe_get_quote_size, sgx_qe_get_target_info};

pub struct AttestationResult {
    pub quote: Vec<u8>,
    pub enclave_pub_key: RSAPublicKey,
}

pub fn get_quote_and_pubkey(
    enclave: &dyn RtcEnclave,
) -> Result<AttestationResult, AttestationError> {
    let qe_target_info = get_target_info()?;
    let quote_size = get_quote_size()?;
    let EnclaveReport {
        report,
        enclave_pub_key,
    } = enclave.create_report(&qe_target_info)?;

    Ok(AttestationResult {
        quote: get_quote(report, quote_size)?,
        enclave_pub_key,
    })
}

fn get_quote(report: sgx_report_t, quote_size: u32) -> Result<Vec<u8>, sgx_quote3_error_t> {
    let mut quote_vec: Vec<u8> = vec![0; quote_size as usize];

    let qe3_ret =
        unsafe { sgx_qe_get_quote(&report as _, quote_size, quote_vec.as_mut_ptr() as _) };
    match qe3_ret {
        sgx_quote3_error_t::SGX_QL_SUCCESS => Ok(quote_vec),
        _ => Err(qe3_ret),
    }
}

fn get_target_info() -> Result<sgx_target_info_t, sgx_quote3_error_t> {
    let mut qe_target_info = sgx_target_info_t::default();
    let qe3_ret = unsafe { sgx_qe_get_target_info(&mut qe_target_info as *mut _) };
    match qe3_ret {
        sgx_quote3_error_t::SGX_QL_SUCCESS => Ok(qe_target_info),
        _ => Err(qe3_ret),
    }
}

fn get_quote_size() -> Result<u32, sgx_quote3_error_t> {
    let mut quote_size: u32 = 0;
    let qe3_ret = unsafe { sgx_qe_get_quote_size(&mut quote_size as _) };
    match qe3_ret {
        sgx_quote3_error_t::SGX_QL_SUCCESS => Ok(quote_size),
        _ => Err(qe3_ret),
    }
}

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("Failed to get quote: {}", .0.as_str())]
    QuotingEnclave(sgx_quote3_error_t),
    #[error("Failed to get application report: {}", .0)]
    AppEnclave(#[from] ReportError),
}

impl From<sgx_quote3_error_t> for AttestationError {
    fn from(err: sgx_quote3_error_t) -> Self {
        AttestationError::QuotingEnclave(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_target_info() {
        let ctx = sgx_qe_get_target_info_context();
        ctx.expect()
            .return_const(sgx_quote3_error_t::SGX_QL_SUCCESS);
        let res = get_target_info();
        assert!(res.is_ok())
    }

    #[test]
    fn test_get_quote_size() {
        let ctx = sgx_qe_get_quote_size_context();
        ctx.expect()
            .return_const(sgx_quote3_error_t::SGX_QL_SUCCESS);
        let res = get_quote_size();
        assert!(res.is_ok())
    }

    #[test]
    fn test_get_quote() {
        let ctx = sgx_qe_get_quote_context();
        ctx.expect()
            .return_const(sgx_quote3_error_t::SGX_QL_SUCCESS);
        let res = get_quote(sgx_report_t::default(), 4);
        assert!(res.is_ok())
    }
}

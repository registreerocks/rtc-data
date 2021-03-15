use rsa::RSAPublicKey;
use rtc_enclave::*;
use sgx_types::*;
use thiserror::Error;

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

    let mut quote_vec: Vec<u8> = vec![0; quote_size as usize];

    let qe3_ret =
        // TODO: Condsider wrapping this unsafe block into a function as well
        unsafe { sgx_qe_get_quote(&report as _, quote_size, quote_vec.as_mut_ptr() as _) };

    match qe3_ret {
        sgx_quote3_error_t::SGX_QL_SUCCESS => Ok(AttestationResult {
            quote: quote_vec,
            enclave_pub_key,
        }),
        _ => Err(qe3_ret.into()),
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

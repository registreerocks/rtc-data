#[cfg(test)]
use mock::mock_rsgx_create_report as rsgx_create_report;
use rtc_types::{CreateReportResult, EnclaveHeldData, ENCLAVE_HELD_PUB_KEY_SIZE};
use secrecy::Zeroize;
use sgx_tcrypto::rsgx_sha256_slice;
#[cfg(not(test))]
use sgx_tse::rsgx_create_report;
use sgx_types::*;

use crate::crypto::{RtcCrypto, SodaBoxCrypto};

fn create_report_impl(
    qe_target_info: &sgx_target_info_t,
) -> Result<([u8; ENCLAVE_HELD_PUB_KEY_SIZE], sgx_report_t), CreateReportResult> {
    let crypto = SodaBoxCrypto::new();
    let pubkey = crypto.get_pubkey();

    let pubkey_hash = match rsgx_sha256_slice(&pubkey) {
        Ok(hash) => hash,
        Err(err) => return Err(err.into()),
    };

    let mut p_data = sgx_report_data_t::default();
    p_data.d[0..32].copy_from_slice(&pubkey_hash);

    // AFAIK any SGX function with out-variables provide no guarantees on what
    // data will be written to those variables in the case of failure. It is
    // our responsibility to ensure data does not get leaked in the case
    // of function failure.
    match rsgx_create_report(qe_target_info, &p_data) {
        Ok(report) => Ok((pubkey, report)),
        Err(err) => Err(CreateReportResult::Sgx(err)),
    }
}

/// Creates and returns a report for the enclave alongside a public key used to encrypt
/// data sent to the enclave.
///
/// # Safety
/// The pointers from SGX is expected to be valid, not-null, correctly aligned and of the
/// correct type. Sanity checks are done for null-pointers, but none of the other conditions.
#[no_mangle]
pub unsafe extern "C" fn enclave_create_report(
    p_qe3_target: *const sgx_target_info_t,
    enclave_pubkey: *mut EnclaveHeldData,
    p_report: *mut sgx_report_t,
) -> CreateReportResult {
    if p_qe3_target.is_null() || enclave_pubkey.is_null() || p_report.is_null() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER.into();
    }
    let qe_target_info = unsafe { &*p_qe3_target };
    let (key, report) = match create_report_impl(qe_target_info) {
        Ok(res) => res,
        Err(x) => {
            unsafe {
                (*enclave_pubkey).zeroize();
            }
            return x.into();
        }
    };

    unsafe {
        *p_report = report;
        (*enclave_pubkey).copy_from_slice(&key);
    }

    CreateReportResult::Success
}

#[cfg(test)]
mod mock {
    use sgx_types::*;

    #[allow(unused_variables)]
    pub(crate) fn mock_rsgx_create_report(
        target_info: &sgx_target_info_t,
        report_data: &sgx_report_data_t,
    ) -> Result<sgx_report_t, sgx_status_t> {
        Ok(sgx_report_t::default())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn enclave_create_report_ok() {
        let qe_ti = sgx_target_info_t::default();
        let mut pubkey_out = EnclaveHeldData::default();
        let mut report_out = sgx_report_t::default();

        let result = unsafe { enclave_create_report(&qe_ti, &mut pubkey_out, &mut report_out) };

        assert_eq!(result, CreateReportResult::Success);
    }
}

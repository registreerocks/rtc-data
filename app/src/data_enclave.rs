extern crate sgx_types;
extern crate sgx_urts;
#[cfg(test)]
use self::MockSgxEnclave as SgxEnclave;
#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;
use mockall_double::double;
use sgx_types::*;
#[cfg(not(test))]
use sgx_urts::SgxEnclave;

const PUBKEY_SIZE: usize = SGX_RSA3072_KEY_SIZE + SGX_RSA3072_PUB_EXP_SIZE;

#[cfg_attr(test, automock)]
mod ffi {
    use super::*;
    extern "C" {
        pub(super) fn enclave_create_report(
            eid: sgx_enclave_id_t,
            retval: *mut i32,
            p_qe3_target: &sgx_target_info_t,
            enclave_pubkey: &mut [u8; PUBKEY_SIZE], // Public key in format [...modulus, ...exponent]
            p_report: *mut sgx_report_t,
        ) -> sgx_status_t;
    }
}

#[double]
use self::ffi as ecalls;

#[cfg_attr(test, automock)]
pub trait DataEnclave {
    // TODO: Might make sense to pull this out into a RtcEnclave trait with a default implementation
    /// Create a report for the data enclave
    fn create_report(
        &self,
        qe_target_info: &sgx_target_info_t,
    ) -> Result<(sgx_report_t, [u8; PUBKEY_SIZE]), sgx_status_t>;
}

impl DataEnclave for SgxEnclave {
    fn create_report(
        &self,
        qe_target_info: &sgx_target_info_t,
    ) -> Result<(sgx_report_t, [u8; PUBKEY_SIZE]), sgx_status_t> {
        let mut retval: i32 = 0;
        let mut ret_report: sgx_report_t = sgx_report_t::default();
        let mut enclave_pubkey: [u8; PUBKEY_SIZE] = [0; PUBKEY_SIZE];
        let result = unsafe {
            ecalls::enclave_create_report(
                self.geteid(),
                &mut retval as *mut i32,
                qe_target_info,
                &mut enclave_pubkey,
                &mut ret_report as *mut sgx_report_t,
            )
        };
        match result {
            sgx_status_t::SGX_SUCCESS => Ok((ret_report, enclave_pubkey)),
            _ => Err(result),
        }
    }
}

#[cfg(test)]
mock! {
    pub SgxEnclave {
        pub fn create(
            file_name: &str,
            debug: i32,
            launch_token: &mut sgx_launch_token_t,
            launch_token_updated: &mut i32,
            misc_attr: &mut sgx_misc_attribute_t) -> SgxResult<SgxEnclave>;
        pub fn geteid(&self) -> sgx_enclave_id_t;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_report() {
        let expected_key: [u8; PUBKEY_SIZE] = [1; PUBKEY_SIZE];
        let expected_config_svn = 12;

        let mut mock = MockSgxEnclave::default();
        mock.expect_geteid().return_const(1u64 as sgx_enclave_id_t);

        let ctx = ecalls::enclave_create_report_context();
        // TODO: add expected target info value
        ctx.expect().returning(move |_, _, _, key, rep| {
            expected_key.clone_into(key);
            unsafe {
                *rep = sgx_report_t::default();
                (*rep).body.config_svn = expected_config_svn;
            }
            sgx_status_t::SGX_SUCCESS
        });

        let res = SgxEnclave::create_report(&mock, &sgx_target_info_t::default()).unwrap();

        assert_eq!(res.1, expected_key);
        // Check one value being set on the result
        assert_eq!(res.0.body.config_svn, expected_config_svn)
    }
}

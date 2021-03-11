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
    use proptest::collection::size_range;
    use proptest::prelude::*;
    use std::convert::TryInto;

    prop_compose! {
        fn arb_sgx_measurement_t()(m in any::<[u8; SGX_HASH_SIZE]>()) -> sgx_measurement_t {
            sgx_measurement_t { m }
        }
    }

    prop_compose! {
        fn arb_sgx_attributes_t()(flags in any::<u64>(), xfrm in any::<u64>()) -> sgx_attributes_t {
            sgx_attributes_t { flags, xfrm }
        }
    }

    prop_compose! {
        fn arb_pubkey()(key_vec in any_with::<Vec<u8>>(size_range(PUBKEY_SIZE).lift())) -> [u8; PUBKEY_SIZE] {
            key_vec.try_into().unwrap()
        }
    }

    prop_compose! {
        fn arb_sgx_target_info_t()
            (mr_enclave in arb_sgx_measurement_t(),
             attributes in arb_sgx_attributes_t(),
             reserved1 in any::<[u8; SGX_TARGET_INFO_RESERVED1_BYTES]>(),
             config_svn in any::<u16>(),
             misc_select in any::<u32>(),
             reserved2 in any::<[u8; SGX_TARGET_INFO_RESERVED2_BYTES]>(),
             config_id in any_with::<Vec<u8>>(size_range(SGX_CONFIGID_SIZE).lift()),
             reserved3 in any_with::<Vec<u8>>(size_range(SGX_TARGET_INFO_RESERVED3_BYTES).lift()),
             ) -> sgx_target_info_t {
             sgx_target_info_t {
                mr_enclave,
                attributes,
                reserved1,
                config_svn,
                misc_select,
                reserved2,
                config_id: config_id.try_into().unwrap(),
                reserved3: reserved3.try_into().unwrap(),
            }
        }
    }

    proptest! {
        #[test]
        fn create_report(qe_ti in arb_sgx_target_info_t(), expected_key in arb_pubkey()) {
            let expected_config_svn = 12;

            let mut mock = MockSgxEnclave::default();
            mock.expect_geteid().return_const(1u64 as sgx_enclave_id_t);

            let ctx = ecalls::enclave_create_report_context();
            ctx.expect().withf(move |_,_,ti, _, _| &qe_ti ==  ti).returning(move |_, _, _, key, rep| {
                expected_key.clone_into(key);
                unsafe {
                    *rep = sgx_report_t::default();
                    (*rep).body.config_svn = expected_config_svn;
                }
                sgx_status_t::SGX_SUCCESS
            });

            let res = SgxEnclave::create_report(&mock, &qe_ti).unwrap();

            prop_assert_eq!(res.1, expected_key);

            // TODO: use arb report value
            assert_eq!(res.0.body.config_svn, expected_config_svn)
        }
    }
}

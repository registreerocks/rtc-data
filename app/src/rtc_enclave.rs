extern crate sgx_types;
extern crate sgx_urts;
#[cfg(test)]
use self::MockSgxEnclave as SgxEnclave;
#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;
use mockall_double::double;
use rsa::errors::Error as RSAError;
use rsa::{BigUint, RSAPublicKey};
use sgx_types::*;
#[cfg(not(test))]
use sgx_urts::SgxEnclave;
use thiserror::Error;

pub const PUBKEY_SIZE: usize = SGX_RSA3072_KEY_SIZE + SGX_RSA3072_PUB_EXP_SIZE;

#[cfg_attr(test, automock)]
#[allow(dead_code)]
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

#[derive(Debug)]
pub struct EnclaveReport {
    pub report: sgx_report_t,
    pub enclave_pub_key: RSAPublicKey,
}

#[cfg_attr(test, automock)]
pub trait RtcEnclave {
    /// Request the enclave to create a report
    fn create_report(
        &self,
        qe_target_info: &sgx_target_info_t,
    ) -> Result<EnclaveReport, ReportError>;
}

impl RtcEnclave for SgxEnclave {
    // TODO: Consider splitting this into 2 function, one to only wrap unsafe code, and one to do other operations
    fn create_report(
        &self,
        qe_target_info: &sgx_target_info_t,
    ) -> Result<EnclaveReport, ReportError> {
        let mut retval: i32 = 0;
        let mut ret_report: sgx_report_t = sgx_report_t::default();
        let mut ret_pubkey: [u8; PUBKEY_SIZE] = [0; PUBKEY_SIZE];
        let result = unsafe {
            ecalls::enclave_create_report(
                self.geteid(),
                &mut retval as *mut i32,
                qe_target_info,
                &mut ret_pubkey,
                &mut ret_report as *mut sgx_report_t,
            )
        };
        match result {
            sgx_status_t::SGX_SUCCESS => {
                println!("{:?}", ret_pubkey);
                let enclave_pub_key = RSAPublicKey::new(
                    // TODO: Check if bytes are in big-or-little endian order
                    BigUint::from_bytes_le(&ret_pubkey[0..SGX_RSA3072_KEY_SIZE]),
                    BigUint::from_bytes_le(&ret_pubkey[SGX_RSA3072_KEY_SIZE..]),
                )?;
                Ok(EnclaveReport {
                    report: ret_report,
                    enclave_pub_key,
                })
            }
            _ => Err(ReportError::Enclave(result)),
        }
    }
}

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("Public key returned by enclave is invalid: {}", .0)]
    PublicKey(#[from] RSAError),
    #[error("Enclave failed to create report: {}", .0.as_str())]
    Enclave(sgx_status_t),
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
    use num_traits::FromPrimitive;
    use proptest::collection::size_range;
    use proptest::prelude::*;
    use rsa::PublicKeyParts;
    use std::convert::TryInto;

    // Using 32 bit integers since the max size of the returned exponent from sgx is 32 bits
    static MIN_EXP: u32 = 2;
    static MAX_EXP: u32 = 1 << (31 - 1);

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
        fn arb_pubkey_exp()(e in MIN_EXP..MAX_EXP) -> u32 {
            e
        }

    }

    prop_compose! {
        // See https://github.com/RustCrypto/RSA/blob/616b08d94bbb03c8fdb1a57188c38701faf6877b/src/key.rs#L642-L654
        // for info on how keys get validated
        fn arb_pubkey()(
            e in arb_pubkey_exp(),
            n in any_with::<Vec<u8>>(size_range(SGX_RSA3072_KEY_SIZE).lift())
        ) -> ([u8; PUBKEY_SIZE], u32, [u8; SGX_RSA3072_KEY_SIZE]) {
            // TODO: Figure out a way to generate more arrays without using vectors
            let e_bytes = e.clone().to_le_bytes().to_vec();
            let n_bytes = n.clone().try_into().unwrap();
            let key_arr = [n, e_bytes].concat().try_into().unwrap();

            (key_arr, e, n_bytes)

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

    // TODO: test result on bad key

    proptest! {
        #[test]
        fn create_report(qe_ti in arb_sgx_target_info_t(), (key_arr, key_e, key_n) in arb_pubkey()) {

            let expected_config_svn = 12;

            let mut mock = MockSgxEnclave::default();
            mock.expect_geteid().return_const(1u64 as sgx_enclave_id_t);

            let ctx = ecalls::enclave_create_report_context();
            ctx.expect().withf(move |_,_,ti, _, _| &qe_ti ==  ti).returning(move |_, _, _, key, rep| {
                key_arr.clone_into(key);
                unsafe {
                    *rep = sgx_report_t::default();
                    (*rep).body.config_svn = expected_config_svn;
                }
                sgx_status_t::SGX_SUCCESS
            });

            let res = SgxEnclave::create_report(&mock, &qe_ti).unwrap();

            prop_assert_eq!(res.enclave_pub_key.n(), &BigUint::from_bytes_le(&key_n));
            prop_assert_eq!(res.enclave_pub_key.e(), &BigUint::from_u32(key_e).unwrap());

            // TODO: use arb report value
            // I am testing that the function returns the result from the enclave. Do we care about that?
            assert_eq!(res.report.body.config_svn, expected_config_svn)
        }
    }
}

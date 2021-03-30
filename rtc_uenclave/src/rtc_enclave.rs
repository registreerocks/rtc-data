use ecalls::EnclaveReportResult;
#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;
use sgx_types::*;
use thiserror::Error;

use crate::{ecalls, CreateReportError};

use crate::quote::*;

#[cfg(test)]
pub use self::MockSgxEnclave as SgxEnclave;
#[cfg(not(test))]
pub use sgx_urts::SgxEnclave;

/// Trait for RTC Enclaves
///
/// This trait contains the basic functionality required from all RTC enclaves
pub trait RtcEnclave {
    /// Request the enclave to create a report
    fn create_report(
        &self,
        qe_target_info: &sgx_target_info_t,
    ) -> Result<EnclaveReportResult, AttestationError>;

    /// Performs dcap attestation using Azure Attestation
    ///
    /// Returns the JWT token with the quote and enclave data
    fn dcap_attestation_azure(&self) -> Result<(), AttestationError> {
        let qe_ti = QuotingEnclave.get_target_info()?;
        let EnclaveReportResult {
            enclave_report,
            enclave_pubkey,
        } = self.create_report(&qe_ti)?;

        let quote = QuotingEnclave.request_quote(enclave_report)?;

        todo!()
    }

    // TODO: Remove this method and call quoting enclave in the dcap_attestation method
    // directly. This is only here to test functionality in Azure at this stage
    #[allow(missing_docs)]
    fn request_quote(&self, report: sgx_report_t) -> Result<Vec<u8>, AttestationError> {
        Ok(QuotingEnclave.request_quote(report)?)
    }
}

impl RtcEnclave for SgxEnclave {
    fn create_report(
        &self,
        qe_target_info: &sgx_target_info_t,
    ) -> Result<EnclaveReportResult, AttestationError> {
        Ok(ecalls::create_report(self.geteid(), qe_target_info)?)
    }
}

/// Attestation process failed
#[derive(Debug, Error)]
pub enum AttestationError {
    /// Failed to get quote
    #[error("Failed to get quote: {}", .0.as_str())]
    Quote(sgx_quote3_error_t),
    /// Failed to get application report
    #[error("Failed to get application report: {}", .0)]
    Report(#[from] CreateReportError),
}

impl From<sgx_quote3_error_t> for AttestationError {
    fn from(err: sgx_quote3_error_t) -> Self {
        AttestationError::Quote(err)
    }
}

#[cfg(test)]
mock! {

    #[allow(missing_docs)]
    pub SgxEnclave {

        #[allow(missing_docs)]
        pub fn create(
            file_name: &str,
            debug: i32,
            launch_token: &mut sgx_launch_token_t,
            launch_token_updated: &mut i32,
            misc_attr: &mut sgx_misc_attribute_t) -> SgxResult<SgxEnclave>;

        #[allow(missing_docs)]
        pub fn geteid(&self) -> sgx_enclave_id_t;

        #[allow(missing_docs)]
        pub fn destroy(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint;
    use num_traits::FromPrimitive;
    use proptest::collection::size_range;
    use proptest::prelude::*;
    use rtc_types::RSA3072_PKCS8_DER_SIZE;
    use simple_asn1::{to_der, ASN1Block, BigInt, BigUint, OID};
    use std::convert::TryInto;

    // Using 32 bit integers since the max size of the returned exponent from sgx is 32 bits
    static MIN_EXP: u32 = 0xffffff + 1; // Always have at least 4 bytes for constant size encoding
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

    fn arb_pubkey_mod() -> impl Strategy<Value = [u8; SGX_RSA3072_KEY_SIZE]> {
        (any_with::<Vec<u8>>(size_range(SGX_RSA3072_KEY_SIZE).lift()))
            .prop_map(|n_bytes| {
                let n = num_bigint::BigInt::from_signed_bytes_be(&n_bytes);
                if n.sign() == num_bigint::Sign::Plus {
                    n
                } else {
                    -n
                }
                .to_signed_bytes_be()
            })
            .prop_filter("Vector must be of the correct length", |n_bytes| {
                // The length should be correct in most cases, however there are
                // some edgecases where the length will be incorrect.
                n_bytes.len() == SGX_RSA3072_KEY_SIZE
            })
            .prop_map(|n_bytes| n_bytes.try_into().unwrap())
    }

    prop_compose! {
        // See https://github.com/RustCrypto/RSA/blob/616b08d94bbb03c8fdb1a57188c38701faf6877b/src/key.rs#L642-L654
        // for info on how keys get validated
        fn arb_pubkey()(
            e in arb_pubkey_exp(),
            n in arb_pubkey_mod()) -> ([u8; RSA3072_PKCS8_DER_SIZE], u32, [u8; SGX_RSA3072_KEY_SIZE]) {

            let key = get_pkcs8(&n, e);

            (key.try_into().expect("failed to convert key to correct size DER"), e, n)

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
        fn create_report(qe_ti in arb_sgx_target_info_t(), (key_arr, _key_e, _key_n) in arb_pubkey()) {

            let enclave_id = 3u64;
            let report = sgx_report_t::default();

            let mut mock = MockSgxEnclave::default();
            mock.expect_geteid().return_const(enclave_id as sgx_enclave_id_t);

            let ctx = ecalls::create_report_context();
            ctx.expect().with(eq(enclave_id), eq(qe_ti)).return_const(Ok(ecalls::EnclaveReportResult{
                enclave_pubkey: key_arr,
                enclave_report: report
            }));

            let res = SgxEnclave::create_report(&mock, &qe_ti).unwrap();

            assert_eq!(res.enclave_report, report)
        }
    }

    pub(crate) fn rsa_oid() -> OID {
        // 9 bytes
        simple_asn1::oid!(1, 2, 840, 113549, 1, 1, 1)
    }

    fn get_pkcs1(n_bytes: &[u8], e: u32) -> [u8; 398] {
        let n_block = ASN1Block::Integer(0, BigInt::from_signed_bytes_be(n_bytes));

        let e_block = ASN1Block::Integer(0, BigInt::from_u32(e).unwrap());
        let blocks = vec![n_block, e_block];

        to_der(&ASN1Block::Sequence(0, blocks))
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn get_pkcs8(n_bytes: &[u8], e: u32) -> [u8; RSA3072_PKCS8_DER_SIZE] {
        let oid = ASN1Block::ObjectIdentifier(0, rsa_oid());
        let alg = ASN1Block::Sequence(0, vec![oid]);

        let bz = get_pkcs1(n_bytes, e);

        let octet_string = ASN1Block::BitString(0, bz.len(), bz.to_vec());

        let blocks = vec![alg, octet_string];

        to_der(&ASN1Block::Sequence(0, blocks))
            .unwrap()
            .try_into()
            .unwrap()
    }
}

use std::borrow::Borrow;

use ecalls::EnclaveReportResult;
#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;
use mockall_double::double;
use rtc_udh::{self, ResponderSys};
use serde::Deserialize;
use sgx_types::*;
#[cfg(not(test))]
pub use sgx_urts::SgxEnclave;
use thiserror::Error;

#[cfg(test)]
use self::MockAzureAttestationClient as AzureAttestationClient;
#[cfg(test)]
pub use self::MockSgxEnclave as SgxEnclave;
use crate::azure_attestation::AttestSgxEnclaveRequest;
#[cfg(not(test))]
use crate::azure_attestation::AzureAttestationClient;
use crate::ecalls::RtcEcalls;
use crate::http_client::HttpRequestError;
#[double]
use crate::quote::QuotingEnclave;
use crate::{ecalls, CreateReportError};

/// Configuration for a RtcEnclave
#[derive(Default, Clone, Deserialize, Debug)]
pub struct EnclaveConfig {
    /// Path of the `.so` file for this enclave
    pub lib_path: String,

    /// URL used to request attestation results.
    ///
    /// NOTE: The URL should point to a valid provider in the same region as
    /// the virtual machine
    ///
    /// For as list of shared providers per region, see:
    /// <https://docs.microsoft.com/en-us/azure/attestation/basic-concepts#regional-shared-provider>
    pub attestation_provider_url: String,

    /// `true` to run the enclave in debug mode (INSECURE).
    pub debug: bool,
}

/// Struct for RTC Enclaves
///
/// This struct contains the basic functionality required from all RTC enclaves
#[cfg_attr(not(test), derive(Debug))]
pub(crate) struct RtcEnclave<TCfg, TEcalls>
where
    TCfg: Borrow<EnclaveConfig>,
    TEcalls: RtcEcalls + Default + ResponderSys + 'static,
{
    pub(crate) base_enclave: SgxEnclave,
    pub(crate) quoting_enclave: QuotingEnclave,
    pub(crate) attestation_client: AzureAttestationClient<ureq::Agent>,
    pub(crate) config: TCfg,
    ecalls: TEcalls,
}

impl<TCfg, TEcalls> RtcEnclave<TCfg, TEcalls>
where
    TCfg: Borrow<EnclaveConfig>,
    TEcalls: RtcEcalls + Default + ResponderSys + 'static,
{
    /// Creates a new enclave instance with the provided configuration
    pub fn init(cfg: TCfg) -> Result<Self, sgx_status_t> {
        let base_enclave = Self::init_base_enclave(cfg.borrow())?;
        rtc_udh::set_responder(base_enclave.geteid(), Box::new(TEcalls::default()))
            .expect("Failed to register enclave as dh responder");

        Ok(RtcEnclave {
            attestation_client: Self::init_attestation_client(),
            quoting_enclave: Self::init_quoting_enclave(),
            base_enclave,
            config: cfg,
            ecalls: TEcalls::default(),
        })
    }

    fn init_attestation_client() -> AzureAttestationClient<ureq::Agent> {
        AzureAttestationClient::<ureq::Agent>::new()
    }

    fn init_quoting_enclave() -> QuotingEnclave {
        QuotingEnclave::default()
    }

    fn init_base_enclave(config: &EnclaveConfig) -> Result<SgxEnclave, sgx_status_t> {
        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;
        // TODO: Confirm the launch parameters
        let debug = if config.debug { 1 } else { 0 };
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
            misc_select: 0,
        };
        SgxEnclave::create(
            &config.lib_path,
            debug,
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        )
    }

    pub fn create_report(
        &self,
        qe_target_info: &sgx_target_info_t,
    ) -> Result<EnclaveReportResult, AttestationError> {
        Ok(self
            .ecalls
            .create_report(self.base_enclave.geteid(), qe_target_info)?)
    }

    /// `true` if the enclave have been initialized
    pub fn is_initialized(&self) -> bool {
        // TODO: Find a better way to check if the enclave session exists
        self.base_enclave.geteid() > 0
    }

    /// Performs dcap attestation using Azure Attestation
    ///
    /// Returns the JWT token with the quote and enclave data
    pub fn dcap_attestation_azure(&self) -> Result<String, AttestationError> {
        let qe_ti = self.quoting_enclave.get_target_info()?;
        let EnclaveReportResult {
            enclave_report,
            enclave_held_data: enclave_pubkey,
        } = self.create_report(&qe_ti)?;

        let quote = self.quoting_enclave.request_quote(enclave_report)?;

        let body = AttestSgxEnclaveRequest::from_quote(&quote, &enclave_pubkey);

        let response = self
            .attestation_client
            .attest(body, &self.config.borrow().attestation_provider_url)?;

        Ok(response.token)
    }

    pub fn geteid(&self) -> sgx_enclave_id_t {
        self.base_enclave.geteid()
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
    /// Failed to get azure attestation JWT
    #[error("Failed to get azure attestation JWT: {}", .0)]
    Azure(#[from] HttpRequestError),
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
#[allow(missing_docs)]
mock! {
    pub(crate) AzureAttestationClient<T: crate::http_client::HttpClient + Sized> {
        pub(crate) fn attest(
            &self,
            body: AttestSgxEnclaveRequest,
            instance_url: &str,
        ) -> Result<crate::azure_attestation::AttestationResponse, HttpRequestError>;
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use num_bigint;
    use num_traits::FromPrimitive;
    use proptest::collection::size_range;
    use proptest::prelude::*;
    use rtc_ecalls::MockRtcEnclaveEcalls;
    use rtc_types::dh::{ExchangeReportResult, SessionRequestResult};
    use rtc_types::{
        CreateReportResult,
        EnclaveHeldData,
        ENCLAVE_HELD_DATA_SIZE,
        RSA3072_PKCS8_DER_SIZE,
    };
    use simple_asn1::{to_der, ASN1Block, BigInt, BigUint, OID};

    use super::*;
    use crate::azure_attestation::AttestationResponse;

    mock! {
        TEcalls {}

        impl RtcEcalls for TEcalls {
            fn create_report(
                &self,
                eid: sgx_enclave_id_t,
                qe_target_info: &sgx_target_info_t,
            ) -> Result<EnclaveReportResult, CreateReportError>;
        }

        impl ResponderSys for TEcalls {
            unsafe fn rtc_session_request(
                &self,
                eid: sgx_enclave_id_t,
                retval: *mut SessionRequestResult,
                src_enclave_id: sgx_enclave_id_t,
            ) -> sgx_status_t;

            unsafe fn rtc_exchange_report(
                &self,
                eid: sgx_enclave_id_t,
                retval: *mut ExchangeReportResult,
                src_enclave_id: sgx_enclave_id_t,
                dh_msg2_ptr: *const sgx_dh_msg2_t,
            ) -> sgx_status_t;

            unsafe fn rtc_end_session(
                &self,
                eid: sgx_enclave_id_t,
                retval: *mut sgx_status_t,
                src_enclave_id: sgx_enclave_id_t,
            ) -> sgx_status_t;
        }
    }

    #[test]
    fn dcap_azure_attestation_works() {
        let sut = {
            let enclave_id = 3u64;
            let mut mock_qe = QuotingEnclave::default();
            mock_qe
                .expect_get_target_info()
                .return_const(Ok(sgx_target_info_t::default()));
            mock_qe
                .expect_request_quote()
                .return_const(Ok(vec![1, 2, 3]));

            let mut mock_be = MockSgxEnclave::default();
            mock_be
                .expect_geteid()
                .return_const(enclave_id as sgx_enclave_id_t);

            let mut mock_aa_client = AzureAttestationClient::default();
            mock_aa_client
                .expect_attest()
                .returning(|_, _| Ok(AttestationResponse::default()));

            let eid = 12u64;
            let qe_target_info = sgx_target_info_t::default();
            let ehd = [2; ENCLAVE_HELD_DATA_SIZE];
            let report = sgx_report_t::default();

            let mut tecalls_mock = MockTEcalls::default();
            tecalls_mock
                .expect_create_report()
                .return_const(Ok(EnclaveReportResult {
                    enclave_report: report,
                    enclave_held_data: ehd,
                }));

            RtcEnclave {
                base_enclave: mock_be,
                quoting_enclave: mock_qe,
                attestation_client: mock_aa_client,
                config: EnclaveConfig::default(),
                ecalls: tecalls_mock,
            }
        };

        let result = sut.dcap_attestation_azure();

        assert!(result.is_ok());
    }

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
        fn create_report(qe_ti in arb_sgx_target_info_t(), ehd in any::<[u8; ENCLAVE_HELD_DATA_SIZE]>()) {

            let enclave_id = 3u64;
            let report = sgx_report_t::default();

            let mut mock = MockSgxEnclave::default();
            mock.expect_geteid().return_const(enclave_id as sgx_enclave_id_t);

            let eid = 12u64;
            let qe_target_info = sgx_target_info_t::default();

            let mut tecalls_mock = MockTEcalls::default();
            tecalls_mock
                .expect_create_report()
                .return_const(Ok(EnclaveReportResult {
                    enclave_report: report,
                    enclave_held_data: ehd,
                }));

            let sut = RtcEnclave{
                base_enclave: mock,
                quoting_enclave: QuotingEnclave::default(),
                attestation_client: AzureAttestationClient::<ureq::Agent>::default(),
                config: EnclaveConfig::default(),
                ecalls: tecalls_mock,
            };

            let res = sut.create_report(&qe_ti).unwrap();

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

//! Test ECALL: `local_attestation`

use sgx_types::sgx_status_t;

use rtc_uenclave::EnclaveConfig;

#[test]
fn test_local_attestation_success() {
    let auth_enclave = rtc_uenclave::RtcAuthEnclave::init(EnclaveConfig {
        lib_path: "/root/rtc-data/rtc_auth_enclave/build/bin/enclave.signed.so".to_string(),
        ..Default::default()
    })
    .unwrap();

    let data_enclave = rtc_uenclave::RtcDataEnclave::init(EnclaveConfig {
        lib_path: "/root/rtc-data/rtc_data_enclave/build/bin/enclave.signed.so".to_string(),
        ..Default::default()
    })
    .unwrap();

    let res = data_enclave.local_attestation(auth_enclave.geteid());
    assert_eq!(res, sgx_status_t::SGX_SUCCESS);

    // TODO: Integration test for message sending
    // We should consider moving the integration tests for enclave interaction into rtc_uenclave
    // since these tests does not need anything from the data_service
}

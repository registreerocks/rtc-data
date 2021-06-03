//! Test ECALL: `local_attestation`

use sgx_types::sgx_status_t;

use crate::helpers;

#[test]
fn test_local_attestation_success() {
    let auth_enclave = helpers::init_auth_enclave();
    let data_enclave = helpers::init_data_enclave();

    let res = data_enclave.local_attestation(auth_enclave.geteid());
    assert_eq!(res, sgx_status_t::SGX_SUCCESS);

    // TODO: Integration test for message sending
    // We should consider moving the integration tests for enclave interaction into rtc_uenclave
    // since these tests does not need anything from the data_service
}

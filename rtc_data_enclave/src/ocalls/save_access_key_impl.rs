//! OCALL definition: `save_access_key` (`rtc_save_access_key_u`)
//!
//! This call is responsible for establishing a protected channel with the auth enclave,
//! and relaying the sealed exchange with the auth enclave's `save_access_key` ECALL.

use rtc_types::enclave_messages::ffi_set_access_key;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};

extern "C" {
    #[allow(dead_code)] // TODO
    fn rtc_save_access_key_u(
        retval: *mut ffi_set_access_key::SetAccessKeyResult,
        auth_enclave_id: sgx_enclave_id_t,
        request: ffi_set_access_key::SetAccessKeyEncryptedRequest,
    ) -> sgx_status_t;
}

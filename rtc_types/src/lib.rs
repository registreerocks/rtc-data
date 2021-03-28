// TODO: Document

extern crate sgx_types;
extern crate thiserror;
use std::fmt::Display;
use thiserror::Error;

use sgx_types::*;

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug, Error)]
pub enum CreateReportResult {
    #[error("Success")]
    Success,
    #[error("Failed with SGX error: {}", .0.as_str())]
    Sgx(sgx_status_t),
    #[error("Failed to get Public Key")]
    FailedToGetPublicKey,
    #[error("Failed to encode Public Key")]
    FailedEncodePublicKey,
}

pub const RSA3072_PKCS8_DER_SIZE: usize = 420;

pub type PubkeyPkcs8 = [u8; RSA3072_PKCS8_DER_SIZE];

#[derive(Error, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug)]
pub enum EcallError<T: 'static + std::error::Error + Display> {
    // Error from the sgx runtime. Ecall returned with an error.
    #[error("Ecall failed in SGX runtime: {}", .0.as_str())]
    SgxRuntime(sgx_status_t),

    // Error from the RTC enclave code. This can be caused by RTC code, or a library
    // called from RTC code, including any sgx library.
    #[error("Ecall failed in the RTC enclave: {}", .0)]
    RtcEnclave(#[from] T),
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

use thiserror;
use thiserror::Error;

use super::*;
use crate::enclave_messages::errors::SealingError;

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug, Error)]
pub enum DataUploadError {
    #[error("Data validation failed")]
    Validation,
    #[error("Data sealing failed: {}", .0)]
    Sealing(sgx_status_t),
    #[error("Crypto failed: {}", .0)]
    Crypto(#[from] CryptoError),

    #[error("save_access_key OCALL sealing error: {0}")]
    SaveAccessKeySealingError(SealingError),

    #[error("save_access_key OCALL failed")]
    SaveAccessKeyFailed,
}

#[repr(C)]
#[derive(Debug)]
pub struct UploadMetadata {
    pub uploader_pub_key: [u8; 32],
    pub nonce: [u8; 24],
}

/// 16 byte MAC + encrypted payload (24 byte data access key + 16 byte UUID)
pub const DATA_UPLOAD_RESPONSE_LEN: usize = 16 + (24 + 16);

#[repr(C)]
#[derive(Clone, Debug)]
pub struct DataUploadResponse {
    pub ciphertext: [u8; DATA_UPLOAD_RESPONSE_LEN],
    pub nonce: [u8; 24],
}

impl From<SizedEncryptedMessage<DATA_UPLOAD_RESPONSE_LEN>> for DataUploadResponse {
    fn from(message: SizedEncryptedMessage<DATA_UPLOAD_RESPONSE_LEN>) -> Self {
        DataUploadResponse {
            ciphertext: message.ciphertext,
            nonce: message.nonce,
        }
    }
}

pub type DataUploadResult = EcallResult<DataUploadResponse, DataUploadError>;

impl Default for DataUploadResult {
    fn default() -> Self {
        EcallResult::Err(DataUploadError::Validation)
    }
}

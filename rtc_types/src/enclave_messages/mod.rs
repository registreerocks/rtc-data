use sgx_types::sgx_aes_gcm_128bit_tag_t;

// NIST AES-GCM recommended IV size
pub type RecommendedAesGcmIv = [u8; 12];

#[repr(C)]
pub struct EncryptedEnclaveMessage<const MESSAGE_SIZE: usize, const AAD_SIZE: usize> {
    pub tag: sgx_aes_gcm_128bit_tag_t,
    pub ciphertext: [u8; MESSAGE_SIZE],
    pub aad: [u8; AAD_SIZE],
    pub nonce: RecommendedAesGcmIv,
}

/// XXX: Ignore this module to work around cbindgen generic type handling
///
/// Issues:
///
/// * <https://github.com/eqrion/cbindgen/issues/7>
/// * <https://github.com/eqrion/cbindgen/issues/286>
/// * <https://github.com/eqrion/cbindgen/issues/573>
///
/// cbindgen:ignore
pub mod set_access_key;

pub mod ffi_set_access_key;

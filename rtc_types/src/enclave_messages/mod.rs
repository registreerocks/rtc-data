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

pub mod set_access_key;

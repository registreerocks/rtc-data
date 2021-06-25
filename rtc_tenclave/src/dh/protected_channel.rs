//! Secure symmetric communication channels based on [`sgx_tcrypto`]'s AES-GCM.

use rtc_types::enclave_messages::{EncryptedEnclaveMessage, RecommendedAesGcmIv};
use secrecy::{ExposeSecret, Secret};
use sgx_tcrypto::{rsgx_rijndael128GCM_decrypt, rsgx_rijndael128GCM_encrypt};
#[cfg(not(test))]
use sgx_tstd::enclave;
use sgx_types::*;

#[cfg(test)]
use super::enclave;
use super::types::AlignedKey;
use crate::util::concat_u8;

pub struct ProtectedChannel {
    iv_constructor: DeterministicAesGcmIvConstructor,
    key: Secret<AlignedKey>,
}

impl ProtectedChannel {
    pub fn init(key: Secret<AlignedKey>) -> Self {
        Self {
            iv_constructor: DeterministicAesGcmIvConstructor::for_current_enclave(),
            key,
        }
    }

    pub fn encrypt_message<const MESSAGE_SIZE: usize, const AAD_SIZE: usize>(
        &mut self,
        plaintext: [u8; MESSAGE_SIZE],
        aad: [u8; AAD_SIZE],
    ) -> Result<EncryptedEnclaveMessage<MESSAGE_SIZE, AAD_SIZE>, sgx_status_t> {
        let nonce = self.iv_constructor.next();
        let mut dst = [0_u8; MESSAGE_SIZE];
        let mut mac = sgx_aes_gcm_128bit_tag_t::default();
        rsgx_rijndael128GCM_encrypt(
            self.key.expose_secret().key(),
            &plaintext,
            &nonce,
            &aad,
            &mut dst,
            &mut mac,
        )?;

        Ok(EncryptedEnclaveMessage {
            tag: mac,
            ciphertext: dst,
            aad,
            nonce,
        })
    }

    pub fn decrypt_message<const MESSAGE_SIZE: usize, const AAD_SIZE: usize>(
        &self,
        message: EncryptedEnclaveMessage<MESSAGE_SIZE, AAD_SIZE>,
    ) -> Result<([u8; MESSAGE_SIZE], [u8; AAD_SIZE]), sgx_status_t> {
        let mut dst = [0_u8; MESSAGE_SIZE];
        rsgx_rijndael128GCM_decrypt(
            self.key.expose_secret().key(),
            &message.ciphertext,
            &message.nonce,
            &message.aad,
            &message.tag,
            &mut dst,
        )?;
        Ok((dst, message.aad))
    }
}

/// Implement the deterministic construction of AES-GCM IVs, as described in section 8.2.1 of [NIST SP 800-38D],
/// "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC".
///
/// In this construction, the IV is the concatenation of two fields:
///
/// 1. The **fixed** field, unique between each device using a given secret key.
///    This implementation uses a 64-bit enclave identifier.
///
/// 2. The **invocation** field, unique for each device message.
///    This implementation uses a 32-bit counter.
///
/// Note that _NIST SP 800-38D_ recommends a 32-bit fixed field and 64-bit invocation field,
/// but this implementation swaps the sizes around, to match the enclave identifier size.
///
/// [NIST SP 800-38D]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
struct DeterministicAesGcmIvConstructor {
    fixed: [u8; 8],
    invocation_counter: u32,
}

impl DeterministicAesGcmIvConstructor {
    /// Initialise a new instance based on [`sgx_tstd::enclave::get_enclave_id`].
    fn for_current_enclave() -> Self {
        DeterministicAesGcmIvConstructor {
            fixed: enclave::get_enclave_id().to_ne_bytes(),
            invocation_counter: Default::default(),
        }
    }

    /// Return the next constructed IV.
    ///
    /// # Panics
    ///
    /// This will panic if the 32-bit invocation counter overflows.
    /// This should not happen during normal use, as a given secret key should not be used for more than 2^32 invocations.
    fn next(&mut self) -> RecommendedAesGcmIv {
        self.invocation_counter = self.invocation_counter.checked_add(1).expect(
            "DeterministicAesGcmIvConstructor: invocation counter overflow, unsafe to proceed",
        );

        concat_u8(&self.fixed, &self.invocation_counter.to_ne_bytes())
    }
}

use secrecy::{ExposeSecret, Secret};
use sgx_tcrypto::{rsgx_rijndael128GCM_decrypt, rsgx_rijndael128GCM_encrypt};
use sgx_tstd::enclave;
use sgx_types::*;
use std::{convert::TryInto, u32};

// NIST AES-GCM recommended IV size
type GcmNonce = [u8; 12];

pub struct ProtectedChannel {
    counter: u32,
    key: Secret<sgx_key_128bit_t>,
}

impl ProtectedChannel {
    pub fn init(key: sgx_key_128bit_t) -> Self {
        Self {
            counter: 1,
            key: Secret::new(key),
        }
    }

    pub fn encrypt_message<const MESSAGE_SIZE: usize, const AAD_SIZE: usize>(
        &mut self,
        plaintext: [u8; MESSAGE_SIZE],
        aad: [u8; AAD_SIZE],
    ) -> Result<EncryptedEnclaveMessage<MESSAGE_SIZE, AAD_SIZE>, sgx_status_t> {
        let nonce = self.gen_nonce();
        let mut dst = [0_u8; MESSAGE_SIZE];
        let mut mac = sgx_aes_gcm_128bit_tag_t::default();
        rsgx_rijndael128GCM_encrypt(
            self.key.expose_secret(),
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
    ) -> Result<[u8; MESSAGE_SIZE], sgx_status_t> {
        let mut dst = [0_u8; MESSAGE_SIZE];
        rsgx_rijndael128GCM_decrypt(
            self.key.expose_secret(),
            &message.ciphertext,
            &message.nonce,
            &message.aad,
            &message.tag,
            &mut dst,
        )?;
        Ok(dst)
    }

    fn gen_nonce(&mut self) -> GcmNonce {
        self.counter = self.counter + 1;
        let counter_bytes = self.counter.to_ne_bytes();
        // TODO: Verify all parameters used here is valid for the local attestation context
        // Constructing the iv (nonce) using a counter and value unique to the running
        // enclave (for the purposes of local attestation).
        // See: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
        [
            enclave::get_enclave_id().to_ne_bytes().as_ref(), // 8 bytes unique to this enclave
            counter_bytes.as_ref(),                           // 4 bytes incrementing on access
        ]
        .concat()
        .try_into()
        .unwrap()
    }
}

pub struct EncryptedEnclaveMessage<const MESSAGE_SIZE: usize, const AAD_SIZE: usize> {
    tag: sgx_aes_gcm_128bit_tag_t,
    ciphertext: [u8; MESSAGE_SIZE],
    aad: [u8; AAD_SIZE],
    nonce: GcmNonce,
}

// impl<const MESSAGE_SIZE: usize, const AAD_SIZE: usize> EncryptedEnclaveMessage {
//     // IV should contain 64 random bits, and 32 counter bits
//     fn encrypt_ecall(
//         key: Secret<sgx_aes_gcm_128bit_key_t>,
//         plaintext: [u8; MESSAGE_SIZE],
//     ) -> Result<Self, ()> {
//     }

//     fn decrypt_ecall<T>(&self, key: Secret<sgx_aes_gcm_128bit_key_t>) -> Result<T, ()> {}
// }

// fn encrypt_ecall<const MESSAGE_SIZE: usize>(key: Secret<sgx_aes_gcm_128bit_key_t>) -> Result<EncryptedEcall, ()> {}

// fn decrypt_ecall<T>(key: Secret<sgx_aes_gcm_128bit_key_t>) -> Result<T, ()> {}

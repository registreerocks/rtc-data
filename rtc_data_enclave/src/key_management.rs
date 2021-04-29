use rand::prelude::*;
use secrecy::{ExposeSecret, Secret};
use sgx_tse::{rsgx_get_key, rsgx_self_report};
use sgx_types::*;
use sodalite;
use std::prelude::v1::*;
use thiserror::Error;
use zeroize::Zeroize;

pub type SecretBytes = Secret<Box<[u8]>>;

pub struct EncryptedMessage {
    ciphertext: Box<[u8]>,
    nonce: [u8; 24],
}

pub trait RtcCrypto {
    type PublicKey; // = [u8; 32];
    type PrivateKey; // = Secret<[u8; 32]>;
    type Nonce; // = [u8; 24];

    fn decrypt_message(
        &self,
        ciphertext: &[u8],
        their_pk: &Self::PublicKey,
        nonce: &Self::Nonce,
    ) -> Result<SecretBytes, self::Error>;

    fn encrypt_message(
        &mut self,
        message: SecretBytes,
        their_pk: &Self::PublicKey,
    ) -> Result<EncryptedMessage, self::Error>;

    fn get_pubkey(&self) -> Self::PublicKey;

    fn get_nonce(&mut self) -> Result<Self::Nonce, self::Error>;
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Crypto rng error: {}", .0)]
    Rand(#[from] rand::Error),
    #[error("Unknown crypto error")]
    Unknown,
}

pub struct SodaBoxCrypto {
    public_key: [u8; 32],
    private_key: Secret<[u8; 32]>,
    rng: Box<dyn RngCore>,
}

impl SodaBoxCrypto {
    pub fn new() -> Self {
        let enclave_key = get_enclave_key();
        let mut pub_key = [0_u8; 32];
        let mut priv_key = [0_u8; 32];
        let mut seed = [0_u8; 32];
        let (left, right) = seed.split_at_mut(16);

        // This should never panic since the file_key is size 16
        // TODO: Guard against the panics
        left.copy_from_slice(enclave_key.expose_secret());
        right.copy_from_slice(enclave_key.expose_secret());

        // TODO: Create a PR to make the requirement for seed broader if possible
        sodalite::box_keypair_seed(&mut pub_key, &mut priv_key, &seed);

        // Zero copies of enclave key
        seed.zeroize();
        Self {
            public_key: pub_key,
            private_key: Secret::new(priv_key),
            rng: Box::new(rand::thread_rng()),
        }
    }
}

impl RtcCrypto for SodaBoxCrypto {
    type PublicKey = [u8; 32];

    type PrivateKey = Secret<[u8; 32]>;

    type Nonce = [u8; 24];

    fn decrypt_message(
        &self,
        ciphertext: &[u8],
        their_pk: &Self::PublicKey,
        nonce: &Self::Nonce,
    ) -> Result<SecretBytes, Error> {
        let mut message = vec![0_u8; ciphertext.len()];

        match sodalite::box_open(
            &mut message,
            ciphertext,
            &nonce,
            their_pk,
            self.private_key.expose_secret(),
        ) {
            Ok(_) => Ok(Secret::new(message.into_boxed_slice())),
            // TODO: return compound error type
            Err(_) => Err(self::Error::Unknown),
        }
    }

    fn encrypt_message(
        &mut self,
        message: SecretBytes,
        their_pk: &Self::PublicKey,
    ) -> Result<EncryptedMessage, Error> {
        let nonce = self.get_nonce()?;
        let mut ciphertext = vec![0_u8; message.expose_secret().len()].into_boxed_slice();

        match sodalite::box_(
            &mut ciphertext,
            message.expose_secret(),
            &nonce,
            their_pk,
            self.private_key.expose_secret(),
        ) {
            Ok(_) => Ok(EncryptedMessage { ciphertext, nonce }),
            Err(_) => Err(self::Error::Unknown),
        }
    }

    fn get_pubkey(&self) -> Self::PublicKey {
        self.public_key
    }

    fn get_nonce(&mut self) -> Result<Self::Nonce, self::Error> {
        let mut nonce = [0_u8; 24];
        // TODO: don't use just random nonces, since it might not
        // be applicable to all situations
        match self.rng.try_fill(&mut nonce) {
            Ok(_) => Ok(nonce),
            Err(err) => Err(self::Error::Rand(err)),
        }
    }
}

fn get_enclave_key() -> Secret<sgx_key_128bit_t> {
    // From my testing, this is deterministic if the environment and binary is the same
    // TODO: Test in Azure VM using HW mode
    // TODO: Find documentation that confirms that the effect is normative
    let report = rsgx_self_report();
    let attribute_mask = sgx_attributes_t {
        flags: TSEAL_DEFAULT_FLAGSMASK,
        xfrm: 0,
    };
    let key_id = sgx_key_id_t::default();

    let key_request = sgx_key_request_t {
        key_name: SGX_KEYSELECT_SEAL,
        key_policy: SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER,
        isv_svn: report.body.isv_svn,
        reserved1: 0_u16,
        cpu_svn: report.body.cpu_svn,
        attribute_mask,
        key_id,
        misc_mask: TSEAL_DEFAULT_MISCMASK,
        config_svn: report.body.config_svn,
        reserved2: [0_u8; SGX_KEY_REQUEST_RESERVED2_BYTES],
    };

    // This should never fail since the input values are constant
    // TODO: remove unwrap and deal with error?
    Secret::new(rsgx_get_key(&key_request).unwrap())
}

// TODO: Use feature flags to toggle use of different crypto libs
// NOTE: Keeping this comment as a reference to AEAD using Ring
// fn generate_client_payload_ring(key_bytes: &[u8]) -> Option<(Box<[u8]>, Uuid)> {
//     use ring::aead;

//     let key = match aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key_bytes) {
//         Ok(k) => aead::LessSafeKey::new(k),
//         Err(_) => return None,
//     };
//     let mut rng = rand::thread_rng();
//     // TODO: use static SecureRandom from ring instead
//     match generate_pass_and_uuid(move |x| rng.try_fill(x)) {
//         Ok((mut pass, uuid)) => {
//             let mut in_out = [
//                 &mut uuid.as_bytes().clone() as &mut [u8],
//                 &mut pass as &mut [u8],
//             ]
//             .concat();

//             let mut nonce = [0u8; 12];

//             if rng.try_fill(&mut nonce).is_err() {
//                 return None;
//             }

//             key.seal_in_place_append_tag(
//                 aead::Nonce::assume_unique_for_key(nonce),
//                 aead::Aad::empty(),
//                 &mut in_out,
//             );
//             Some((in_out.into_boxed_slice(), uuid))
//         }
//         Err(_) => None,
//     }
// }

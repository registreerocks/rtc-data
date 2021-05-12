use rand::prelude::*;
use rtc_types::EncryptedMessage;
use rtc_types::{CryptoError as Error, SizedEncryptedMessage};
use secrecy::{ExposeSecret, Secret};
use sgx_types::*;
use std::{convert::TryInto, prelude::v1::*};
use zeroize::Zeroize;

#[cfg(not(test))]
use sgx_tse::{rsgx_get_key, rsgx_self_report};

// FIXME: sodalite should expose these padding constants.
// Values referenced from https://tweetnacl.cr.yp.to/20140427/tweetnacl.h

/// C NaCl Box API: Zero padding for plaintext.
const CRYPTO_BOX_ZEROBYTES: usize = 32;

/// C NaCl Box API: Zero padding for ciphertext.
const CRYPTO_BOX_BOXZEROBYTES: usize = 16;

pub type SecretBytes = Secret<Box<[u8]>>;

pub trait RtcCrypto {
    type PublicKey; // = [u8; 32];
    type PrivateKey; // = Secret<[u8; 32]>;
    type Nonce; // = [u8; 24];

    // TODO: This currently hardcodes various constants for the message padding and MAC sizes to
    //       what's used by tweetnacl / sodalite. These should be changed to associated constants
    //       once we have another implementation?

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

    fn encrypt_sized_message<const MESSAGE_LEN: usize>(
        &mut self,
        message: [u8; MESSAGE_LEN],
        their_pk: &Self::PublicKey,
    ) -> Result<
        SizedEncryptedMessage<{ MESSAGE_LEN + 16 }>, // 16 = CRYPTO_BOX_ZEROBYTES - CRYPTO_BOX_BOXZEROBYTES
        Error,
    >
    // NOTE: We need to indicate to the compiler that `MESSAGE_LEN + 32`
    // should be a valid usize (that wont overflow) so that it can enforce
    // this at compile time.
    // see: https://github.com/rust-lang/rust/issues/82509
    // Also see compiler error if omitted on later compilers
    where
        [(); MESSAGE_LEN + /* CRYPTO_BOX_ZEROBYTES */ 32]: ;

    fn get_pubkey(&self) -> Self::PublicKey;

    fn get_nonce(&mut self) -> Result<Self::Nonce, self::Error>;
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
        // It is the responsibility of the caller to pad ciphertext
        // see: https://github.com/registreerocks/rtc-data/issues/51
        let padded_ciphertext = &[&[0u8; CRYPTO_BOX_BOXZEROBYTES] as &[u8], ciphertext].concat();
        let mut message = vec![0_u8; padded_ciphertext.len()];

        // Docs: https://nacl.cr.yp.to/box.html
        //
        // "The caller must ensure, before calling the crypto_box_open function,
        // that the first crypto_box_BOXZEROBYTES bytes of the ciphertext c are all 0.
        // The crypto_box_open function ensures (in case of success) that
        // the first crypto_box_ZEROBYTES bytes of the plaintext m are all 0."
        //
        match sodalite::box_open(
            &mut message,
            padded_ciphertext,
            &nonce,
            their_pk,
            self.private_key.expose_secret(),
        ) {
            Ok(_) => Ok(Secret::new({
                message.rotate_left(CRYPTO_BOX_ZEROBYTES);
                message.truncate(message.len() - CRYPTO_BOX_ZEROBYTES);
                message.into_boxed_slice()
            })),
            // TODO: return compound error type
            Err(_) => Err(self::Error::Unknown),
        }
    }

    fn encrypt_sized_message<const MESSAGE_LEN: usize>(
        &mut self,
        // Cannot be wrapped in a secret because of unknown size, will be zeroed manually
        mut message: [u8; MESSAGE_LEN],
        their_pk: &Self::PublicKey,
    ) -> Result<
        SizedEncryptedMessage<{ MESSAGE_LEN + 16 }>, // 16 = CRYPTO_BOX_ZEROBYTES - CRYPTO_BOX_BOXZEROBYTES
        Error,
    >
    where
        [(); MESSAGE_LEN + /* CRYPTO_BOX_ZEROBYTES */ 32]: ,
    {
        let nonce = self.get_nonce()?;
        let mut ciphertext = [0_u8; MESSAGE_LEN + /* CRYPTO_BOX_ZEROBYTES */ 32];

        // NOTE: the message gets copied here, the copied value will be zeroed manually
        let mut padded_message: [u8; MESSAGE_LEN + /* CRYPTO_BOX_ZEROBYTES */ 32] =
            pad_msg(&message);

        // Docs: https://nacl.cr.yp.to/box.html
        //
        // "The caller must ensure, before calling the C NaCl crypto_box function,
        // that the first crypto_box_ZEROBYTES bytes of the message m are all 0.
        // The crypto_box function ensures that the first crypto_box_BOXZEROBYTES
        // bytes of the ciphertext c are all 0."
        //
        let res = match sodalite::box_(
            &mut ciphertext,
            &padded_message,
            &nonce,
            their_pk,
            self.private_key.expose_secret(),
        ) {
            Ok(_) => Ok(SizedEncryptedMessage {
                // This should never panic since
                // (MESSAGE_LEN + 32 - 16) = (MESSAGE_LEN + 16)
                ciphertext: ciphertext[CRYPTO_BOX_BOXZEROBYTES..].try_into().unwrap(),
                nonce,
            }),
            Err(_) => Err(self::Error::Unknown),
        };

        (&mut padded_message as &mut [u8]).zeroize();
        message.zeroize();

        res
    }

    fn encrypt_message(
        &mut self,
        message: SecretBytes,
        their_pk: &Self::PublicKey,
    ) -> Result<EncryptedMessage, Error> {
        let nonce = self.get_nonce()?;
        // Length is padded here since the message needs to be padded with 32 `0_u8`
        // at the front
        let mut ciphertext = vec![0_u8; message.expose_secret().len() + CRYPTO_BOX_ZEROBYTES];

        // Docs: https://nacl.cr.yp.to/box.html
        //
        // "The caller must ensure, before calling the C NaCl crypto_box function,
        // that the first crypto_box_ZEROBYTES bytes of the message m are all 0.
        // The crypto_box function ensures that the first crypto_box_BOXZEROBYTES
        // bytes of the ciphertext c are all 0."
        //
        match sodalite::box_(
            &mut ciphertext,
            &[
                &[0u8; CRYPTO_BOX_ZEROBYTES] as &[u8],
                message.expose_secret(),
            ]
            .concat(),
            &nonce,
            their_pk,
            self.private_key.expose_secret(),
        ) {
            Ok(_) => {
                ciphertext.rotate_left(CRYPTO_BOX_BOXZEROBYTES);
                ciphertext.truncate(ciphertext.len() - CRYPTO_BOX_BOXZEROBYTES);
                Ok(EncryptedMessage {
                    ciphertext: ciphertext.into_boxed_slice(),
                    nonce,
                })
            }
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
            // TODO: Better conversion from rand::Error? (See also data_upload.rs)
            Err(err) => Err(self::Error::Rand(err.code().map_or(0, |code| code.get()))),
        }
    }
}

#[cfg(not(test))]
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

// TODO: rather create a mock with mockall
#[cfg(test)]
fn get_enclave_key() -> Secret<sgx_key_128bit_t> {
    Secret::new([12_u8; 16])
}

fn pad_msg<const MESSAGE_LEN: usize>(msg: &[u8; MESSAGE_LEN]) -> [u8; MESSAGE_LEN + 32] {
    let mut whole = [0_u8; MESSAGE_LEN + 32];
    let (_, msg_dest) = whole.split_at_mut(32);
    msg_dest.copy_from_slice(msg);
    whole
}

/// Drop the first `prefix_len` elements of `vec`, keeping the rest.
fn drop_prefix<T>(prefix_len: usize, mut vec: Vec<T>) -> Vec<T> {
    vec.rotate_left(prefix_len);
    vec.truncate(vec.len() - prefix_len);
    vec
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

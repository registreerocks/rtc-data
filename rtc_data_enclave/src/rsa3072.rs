use core::convert::TryInto;
use sgx_crypto_helper::RsaKeyPair;
use sgx_tcrypto::{rsgx_create_rsa_key_pair, SgxRsaPrivKey, SgxRsaPubKey};
use sgx_types::sgx_status_t;
use sgx_types::{SGX_RSA3072_KEY_SIZE, SGX_RSA3072_PRI_EXP_SIZE, SGX_RSA3072_PUB_EXP_SIZE};
use simple_asn1::{to_der, ASN1Block, ASN1EncodeErr, BigInt, BigUint, OID};
use std::prelude::v1::*;
use std::vec::Vec;

use serde_big_array::big_array;
use serde_derive::{Deserialize, Serialize};

big_array! {
    BigArray;
}

pub const SGX_RSA3072_DEFAULT_E: [u8; SGX_RSA3072_PUB_EXP_SIZE] = [0x01, 0x00, 0x00, 0x01]; // 16777217

pub const RSA3072_PKCS8_DER_SIZE: usize = 420;

// TODO: This would be a lot easier if we could get the value of "n" and "e" directly from the
// Rsa3072KeyPair type in the crypto helper library. Maybe consider a PR for this.
// Ideally we should not be maintaining this code
// see https://github.com/apache/incubator-teaclave-sgx-sdk/tree/master/sgx_crypto_helper

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct Rsa3072KeyPair {
    #[serde(with = "BigArray")]
    pub n: [u8; SGX_RSA3072_KEY_SIZE],
    #[serde(with = "BigArray")]
    d: [u8; SGX_RSA3072_PRI_EXP_SIZE],
    pub e: [u8; SGX_RSA3072_PUB_EXP_SIZE],
    #[serde(with = "BigArray")]
    p: [u8; SGX_RSA3072_KEY_SIZE / 2],
    #[serde(with = "BigArray")]
    q: [u8; SGX_RSA3072_KEY_SIZE / 2],
    #[serde(with = "BigArray")]
    dmp1: [u8; SGX_RSA3072_KEY_SIZE / 2],
    #[serde(with = "BigArray")]
    dmq1: [u8; SGX_RSA3072_KEY_SIZE / 2],
    #[serde(with = "BigArray")]
    iqmp: [u8; SGX_RSA3072_KEY_SIZE / 2],
}

impl Default for Rsa3072KeyPair {
    fn default() -> Self {
        Rsa3072KeyPair {
            n: [0; SGX_RSA3072_KEY_SIZE],
            d: [0; SGX_RSA3072_PRI_EXP_SIZE],
            e: SGX_RSA3072_DEFAULT_E,
            p: [0; SGX_RSA3072_KEY_SIZE / 2],
            q: [0; SGX_RSA3072_KEY_SIZE / 2],
            dmp1: [0; SGX_RSA3072_KEY_SIZE / 2],
            dmq1: [0; SGX_RSA3072_KEY_SIZE / 2],
            iqmp: [0; SGX_RSA3072_KEY_SIZE / 2],
        }
    }
}

impl RsaKeyPair for Rsa3072KeyPair {
    fn new() -> sgx_types::SgxResult<Self>
    where
        Self: Sized,
    {
        let mut newkey = Self::default();
        match rsgx_create_rsa_key_pair(
            SGX_RSA3072_KEY_SIZE as i32,
            SGX_RSA3072_PUB_EXP_SIZE as i32,
            &mut newkey.n,
            &mut newkey.d,
            &mut newkey.e,
            &mut newkey.p,
            &mut newkey.q,
            &mut newkey.dmp1,
            &mut newkey.dmq1,
            &mut newkey.iqmp,
        ) {
            Ok(()) => Ok(newkey),
            Err(x) => Err(x),
        }
    }

    fn new_with_e(e: u32) -> sgx_types::SgxResult<Self>
    where
        Self: Sized,
    {
        let mut newkey = Self::default();
        newkey.e = e.to_le_bytes();
        match rsgx_create_rsa_key_pair(
            SGX_RSA3072_KEY_SIZE as i32,
            SGX_RSA3072_PUB_EXP_SIZE as i32,
            &mut newkey.n,
            &mut newkey.d,
            &mut newkey.e,
            &mut newkey.p,
            &mut newkey.q,
            &mut newkey.dmp1,
            &mut newkey.dmq1,
            &mut newkey.iqmp,
        ) {
            Ok(()) => Ok(newkey),
            Err(x) => Err(x),
        }
    }

    fn to_privkey(self) -> sgx_types::SgxResult<SgxRsaPrivKey> {
        let result = SgxRsaPrivKey::new();
        match result.create(
            SGX_RSA3072_KEY_SIZE as i32,
            SGX_RSA3072_PRI_EXP_SIZE as i32,
            &self.e,
            &self.p,
            &self.q,
            &self.dmp1,
            &self.dmq1,
            &self.iqmp,
        ) {
            Ok(()) => Ok(result),
            Err(x) => Err(x),
        }
    }

    fn to_pubkey(self) -> sgx_types::SgxResult<SgxRsaPubKey> {
        let result = SgxRsaPubKey::new();
        match result.create(
            SGX_RSA3072_KEY_SIZE as i32,
            SGX_RSA3072_PUB_EXP_SIZE as i32,
            &self.n,
            &self.e,
        ) {
            Ok(()) => Ok(result),
            Err(x) => Err(x),
        }
    }

    fn encrypt_buffer(
        self,
        plaintext: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> sgx_types::SgxResult<usize> {
        let pubkey = self.to_pubkey()?;
        let bs = 384;

        let bs_plain = bs - 2 * 256 / 8 - 2;
        let count = (plaintext.len() + bs_plain - 1) / bs_plain;
        ciphertext.resize(bs * count, 0);

        for i in 0..count {
            let cipher_slice = &mut ciphertext[i * bs..i * bs + bs];
            let mut out_len = bs;
            let plain_slice =
                &plaintext[i * bs_plain..std::cmp::min(i * bs_plain + bs_plain, plaintext.len())];

            pubkey.encrypt_sha256(cipher_slice, &mut out_len, plain_slice)?;
        }

        Ok(ciphertext.len())
    }

    fn decrypt_buffer(
        self,
        ciphertext: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> sgx_types::SgxResult<usize> {
        let privkey = self.to_privkey()?;
        let bs = 384;

        if ciphertext.len() % bs != 0 {
            return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
        }

        // Additional one byte is required in 1.0.9
        // let bs_plain = bs - 2 * 256 / 8 - 2;
        // In 2.6, we need a longer buf to put the decrypted data.
        // The output length is exactly bs_plain above, but it results in
        // SGX_ERROR_INVALID_PARAMETER.
        let bs_plain = bs;
        let count = ciphertext.len() / bs;
        plaintext.clear();

        for i in 0..count {
            let cipher_slice = &ciphertext[i * bs..i * bs + bs];
            let plain_slice = &mut vec![0; bs_plain];
            let mut plain_len = bs_plain;

            privkey.decrypt_sha256(plain_slice, &mut plain_len, cipher_slice)?;
            let mut decoded_vec = plain_slice[..plain_len].to_vec();
            plaintext.append(&mut decoded_vec);
        }

        Ok(plaintext.len())
    }
}
pub trait PublicKeyEncoding {
    fn to_pkcs1(&self) -> Result<[u8; 398], ASN1EncodeErr>;
    fn to_pkcs8(&self) -> Result<[u8; RSA3072_PKCS8_DER_SIZE], ASN1EncodeErr>;
}

impl PublicKeyEncoding for Rsa3072KeyPair {
    /// Encodes a Public key to into `PKCS1` bytes.
    ///
    /// This data will be `base64` encoded which would be used
    /// following a `-----BEGIN <name> PUBLIC KEY-----` header.
    ///
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem>
    fn to_pkcs1(&self) -> Result<[u8; 398], ASN1EncodeErr> {
        // 388 Bytes: (T = 1, L = 3, V = SGX_RSA3072_KEY_SIZE = 384)
        let n = ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&self.n));
        // 6 Bytes: (T = 1, L = 1, V = SGX_RSA3072_PUB_EXP_SIZE = 4)
        let e = ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&self.e));
        let blocks = vec![n, e];

        // 398 Bytes: (T = 1, L = 3, V = 394)
        to_der(&ASN1Block::Sequence(0, blocks)).map(|der| {
            // NOTE: The size will only be correct if the exponent is 4 bytes long.
            // Since the exponent is constant we can assume the size of the der bytes.
            der.try_into()
                .expect("Wrong Size of PKCS#1 DER for public key")
        })
    }

    /// Encodes a Public key to into `PKCS8` bytes.
    ///
    /// This data will be `base64` encoded which would be used
    /// following a `-----BEGIN PUBLIC KEY-----` header.
    ///
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem>
    fn to_pkcs8(&self) -> Result<[u8; RSA3072_PKCS8_DER_SIZE], ASN1EncodeErr> {
        // 11 Bytes: (T = 1, L = 1, V = 9)
        let oid = ASN1Block::ObjectIdentifier(0, rsa_oid());
        // 13 Bytes: (T = 1, L = 1, V = 11)
        let alg = ASN1Block::Sequence(0, vec![oid]);

        // 398 Bytes
        let bz = self.to_pkcs1()?;

        // 403 Bytes: (T = 1, L = 3, V = 399 [388 + leading byte specifying unused bits])
        let octet_string = ASN1Block::BitString(0, bz.len(), bz.to_vec());

        let blocks = vec![alg, octet_string];

        // 420 Bytes: (T = 1, L = 3, V = 416 [len(octet_string) + len(alg)])
        to_der(&ASN1Block::Sequence(0, blocks)).map(|der| {
            der.try_into()
                .expect("Wrong Size of PKCS#8 DER for Public Key")
        })
    }
}

pub(crate) fn rsa_oid() -> OID {
    // 9 bytes
    simple_asn1::oid!(1, 2, 840, 113549, 1, 1, 1)
}

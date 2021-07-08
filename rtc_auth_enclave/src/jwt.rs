use std::string::{String, ToString};
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec;

use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use sgx_tstd::untrusted::time::SystemTimeEx;
use thiserror::Error;
use uuid::Uuid;

use crate::uuid_to_string;

const HEADER_TYP: &'static str = "ntlexec+jwt";
const CLAIMS_ISS: &'static str = "ntls_auth_enclave";
const CLAIMS_AUD: &'static str = "ntls_exec_enclave";

/// Claims body of the JWT token
///
/// Example output:
/// ```
/// {
///     "iss": "ntls_auth_enclave",
///     "nbf": 1623762799,
///     "iat": 1623762799,
///     "jti": "b300fe149d144e05aa9a9600816b42ca",
///     "exec_module_hash": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
///     "dataset_uuid": "dd12012195c04ae8990ebd2512ae03ab"
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Claims {
    // Registered Claim Names: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
    // TODO: serialize to hex string? This can be mrenclave or mrsigner
    iss: String,
    nbf: u64,
    iat: u64,
    pub(crate) jti: String,
    // TODO: Better names. use `x-ntls-mod-hash` etc?
    pub(crate) exec_module_hash: String,
    pub(crate) dataset_uuid: String, // TODO: use sub?
    dataset_size: u64,
}

impl Claims {
    fn new(
        exec_module_hash: String,
        dataset_uuid: String,
        token_id: String,
        dataset_size: u64,
    ) -> Self {
        // TODO: Look at the attack vectors opened up by using untrusted system time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before UNIX Epoch")
            .as_secs();

        Self {
            iss: CLAIMS_ISS.to_string(),
            nbf: now,
            iat: now,
            jti: token_id,
            exec_module_hash,
            dataset_uuid,
            dataset_size,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum DecodeError {
    #[error("Decoding failed: {}", .0)]
    JWT(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid typ field in the jwt header")]
    Typ,
}

pub(crate) struct DecodedExecutionToken(TokenData<Claims>);

impl DecodedExecutionToken {
    pub(crate) fn decode(token: &str) -> Result<DecodedExecutionToken, DecodeError> {
        let validation = Validation {
            validate_nbf: true,
            iss: Some(CLAIMS_ISS.to_string()),
            algorithms: vec![Algorithm::HS256],

            ..Validation::default()
        };

        let decoded = jsonwebtoken::decode::<Claims>(token, &get_decoding_key(), &validation)?;

        match decoded.header.typ.as_deref() {
            Some(HEADER_TYP) => Ok(DecodedExecutionToken(decoded)),
            Some(_) | None => Err(DecodeError::Typ),
        }
    }

    pub(crate) fn claims<'a>(&'a self) -> &'a Claims {
        &self.0.claims
    }

    pub(crate) fn header<'a>(&'a self) -> &'a Header {
        &self.0.header
    }
}

pub(crate) struct EncodedExecutionToken {
    pub token: String,
    pub token_id: Uuid,
}

impl EncodedExecutionToken {
    pub(crate) fn new(exec_module_hash: [u8; 32], dataset_uuid: Uuid, dataset_size: u64) -> Self {
        let token_id = Uuid::new_v4();

        let claims = Claims::new(
            base64::encode(exec_module_hash),
            uuid_to_string(dataset_uuid),
            uuid_to_string(token_id),
            dataset_size,
        );

        let encoding_key = get_encoding_key();
        // Header size 48 characters base64
        let header = Header {
            // Explicit typing for the token type
            // SEE: https://datatracker.ietf.org/doc/html/draft-ietf-secevent-token-02#section-2.2
            typ: Some(HEADER_TYP.to_string()),
            ..Header::default()
        };

        // Signature length: 44
        let token = encode(&header, &claims, &encoding_key)
            .expect("encoding and signing execution token failed");

        Self { token, token_id }
    }
}

fn get_encoding_key() -> EncodingKey {
    // TODO: Use a signing key that corresponds to the public key
    // in the attestation enclave held data and move to crypto module in tenclave.
    EncodingKey::from_secret("secret".as_ref())
}

fn get_decoding_key<'a>() -> DecodingKey<'a> {
    // TODO: Use a decoding key that can is intrinsic to this enclave instance.
    DecodingKey::from_secret("secret".as_ref())
}

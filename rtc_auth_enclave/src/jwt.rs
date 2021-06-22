use std::string::{String, ToString};
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sgx_tstd::untrusted::time::SystemTimeEx;
use uuid::Uuid;

use crate::uuid_to_string;

/// Claims body of the JWT token
///
/// Example output:
/// ```
/// {
///     "iss": "registree_auth_enclave",
///     "nbf": 1623762799,
///     "iat": 1623762799,
///     "jti": "b300fe149d144e05aa9a9600816b42ca",
///     "exec_module_hash": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
///     "dataset_uuid": "dd12012195c04ae8990ebd2512ae03ab"
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    // Registered Claim Names: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
    // TODO: serialize to hex string? This can be mrenclave or mrsigner
    iss: String,
    nbf: u64,
    iat: u64,
    jti: String,
    // TODO: Better names. use `x-ntls-mod-hash` etc?
    exec_module_hash: String,
    dataset_uuid: String,
}

impl Claims {
    fn new(exec_module_hash: String, dataset_uuid: String, token_id: String) -> Self {
        // TODO: Look at the attack vectors opened up by using untrusted system time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before UNIX Epoch")
            .as_secs();

        Self {
            iss: "registree_auth_enclave".to_string(),
            nbf: now,
            iat: now,
            jti: token_id,
            exec_module_hash,
            dataset_uuid,
        }
    }
}

pub(crate) struct EncodedExecutionToken {
    pub token: String,
    pub token_id: Uuid,
}

impl EncodedExecutionToken {
    pub(crate) fn new(exec_module_hash: [u8; 32], dataset_uuid: Uuid) -> Self {
        let token_id = Uuid::new_v4();

        let claims = Claims::new(
            base64::encode(exec_module_hash),
            uuid_to_string(dataset_uuid),
            uuid_to_string(token_id),
        );

        // TODO: Use a signing key that corresponds to the public key
        // in the attestation enclave held data and move to crypto module in tenclave.
        let encoding_key = EncodingKey::from_secret("secret".as_ref());
        // Header size 48 characters base64
        let header = Header {
            // Explicit typing for the token type
            // SEE: https://datatracker.ietf.org/doc/html/draft-ietf-secevent-token-02#section-2.2
            typ: Some("ntlexec+jwt".to_string()),
            ..Header::default()
        };

        // Signature length: 44
        let token = encode(&header, &claims, &encoding_key)
            .expect("encoding and signing execution token failed");

        Self { token, token_id }
    }
}

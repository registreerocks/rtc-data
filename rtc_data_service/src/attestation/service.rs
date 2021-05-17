use std::convert::TryInto;

use actix::{Addr, MailboxError};
use actix_web::{error::ErrorInternalServerError, post, web, HttpRequest};
use models::*;
use rtc_types::{AttestError, AttestationResponse};

use crate::data_enclave_actor::DataEnclaveActor;
use crate::merge_error::*;

use super::AttestationMessage;

#[post("auth/attest")]
pub async fn req_attestation_jwt(
    _req: HttpRequest,
    req_body: web::Json<RequestBody>,
    enclave: web::Data<Addr<DataEnclaveActor>>,
) -> actix_web::Result<web::Json<ResponseBody>> {
    let message: AttestationMessage = req_body.0.try_into()?;

    let result: Result<AttestationResponse, MergedError<AttestError, MailboxError>> =
        enclave.send(message).await.merge_err();
    match result {
        Ok(resp) => Ok(web::Json(resp.into())),
        Err(err) => Err(ErrorInternalServerError(err)),
    }
}

pub mod models {
    use crate::validation::ValidationError;
    use crate::Base64Standard;
    use rtc_types::{AttestReqMetadata, AttestationResponse};
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;

    use crate::attestation::AttestationMessage;

    #[derive(Serialize, Deserialize, Debug)]
    pub struct RequestBody {
        pub metadata: Metadata,
        #[serde(with = "Base64Standard")]
        pub payload: Vec<u8>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct Metadata {
        #[serde(with = "Base64Standard")]
        pub requester_pub_key: Vec<u8>,
        #[serde(with = "Base64Standard")]
        pub nonce: Vec<u8>,
    }

    #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
    pub struct ResponseBody {
        #[serde(with = "Base64Standard")]
        pub attestation_jwt: Vec<u8>,
        #[serde(with = "Base64Standard")]
        pub nonce: Vec<u8>,
    }

    impl From<AttestationResponse> for ResponseBody {
        fn from(resp: AttestationResponse) -> Self {
            ResponseBody {
                attestation_jwt: resp.attestation_jwt.as_bytes().to_vec(),
                nonce: resp.nonce.to_vec(),
            }
        }
    }

    impl TryFrom<RequestBody> for AttestationMessage {
        type Error = ValidationError;

        fn try_from(request_body: RequestBody) -> Result<Self, Self::Error> {
            let requester_pub_key = TryFrom::try_from(request_body.metadata.requester_pub_key)
                .map_err(|_| ValidationError::new("Invalid pub key"))?;
            let nonce = TryFrom::try_from(request_body.metadata.nonce)
                .map_err(|_| ValidationError::new("Invalid nonce"))?;

            Ok(AttestationMessage {
                metadata: AttestReqMetadata {
                    requester_pub_key,
                    nonce,
                },
                payload: request_body.payload.into_boxed_slice(),
            })
        }
    }
}

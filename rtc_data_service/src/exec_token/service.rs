use std::convert::TryInto;

use actix::{Addr, MailboxError};
use actix_web::error::ErrorInternalServerError;
use actix_web::{post, web, HttpRequest};
use models::*;
use rtc_types::{ExecTokenError, ExecTokenResponse};

use super::ExecTokenMessage;
use crate::data_enclave_actor::DataEnclaveActor;
use crate::merge_error::*;

#[post("auth/tokens")]
pub async fn req_exec_token(
    _req: HttpRequest,
    req_body: web::Json<RequestBody>,
    enclave: web::Data<Addr<DataEnclaveActor>>,
) -> actix_web::Result<web::Json<ResponseBody>> {
    let message: ExecTokenMessage = req_body.0.try_into()?;

    let result: Result<ExecTokenResponse, MergedError<ExecTokenError, MailboxError>> =
        enclave.send(message).await.merge_err();
    match result {
        Ok(resp) => Ok(web::Json(resp.into())),
        Err(err) => Err(ErrorInternalServerError(err)),
    }
}

pub mod models {
    use std::convert::TryFrom;

    use rtc_types::{ExecReqMetadata, ExecTokenResponse};
    use serde::{Deserialize, Serialize};

    use crate::exec_token::ExecTokenMessage;
    use crate::validation::ValidationError;
    use crate::Base64Standard;

    #[derive(Serialize, Deserialize, Debug)]
    pub struct RequestBody {
        pub metadata: Metadata,
        #[serde(with = "Base64Standard")]
        pub payload: Vec<u8>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct Metadata {
        #[serde(with = "Base64Standard")]
        pub uploader_pub_key: Vec<u8>,
        #[serde(with = "Base64Standard")]
        pub nonce: Vec<u8>,
    }

    #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
    pub struct ResponseBody {
        #[serde(with = "Base64Standard")]
        pub execution_token: Vec<u8>,
        #[serde(with = "Base64Standard")]
        pub nonce: Vec<u8>,
    }

    impl From<ExecTokenResponse> for ResponseBody {
        fn from(resp: ExecTokenResponse) -> Self {
            ResponseBody {
                execution_token: resp.execution_token.to_vec(),
                nonce: resp.nonce.to_vec(),
            }
        }
    }

    impl TryFrom<RequestBody> for ExecTokenMessage {
        type Error = ValidationError;

        fn try_from(request_body: RequestBody) -> Result<Self, Self::Error> {
            let uploader_pub_key = TryFrom::try_from(request_body.metadata.uploader_pub_key)
                .map_err(|_| ValidationError::new("Invalid pub key"))?;
            let nonce = TryFrom::try_from(request_body.metadata.nonce)
                .map_err(|_| ValidationError::new("Invalid nonce"))?;

            Ok(ExecTokenMessage {
                metadata: ExecReqMetadata {
                    uploader_pub_key,
                    nonce,
                },
                payload: request_body.payload.into_boxed_slice(),
            })
        }
    }
}

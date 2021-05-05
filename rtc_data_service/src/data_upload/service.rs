use actix::{Addr, MailboxError};
use actix_web::{error::ErrorInternalServerError, post, web, HttpRequest};
use models::*;
use rtc_types::{DataUploadError, DataUploadResponse, EcallError};

use crate::data_enclave_actor::DataEnclaveActor;
use crate::merge_error::*;

use super::DataUploadMessage;
use std::convert::TryInto;

#[post("/data/uploads")]
pub async fn upload_file(
    _req: HttpRequest,
    req_body: web::Json<RequestBody>,
    enclave: web::Data<Addr<DataEnclaveActor>>,
) -> actix_web::Result<web::Json<ResponseBody>> {
    let message: DataUploadMessage = req_body.0.try_into()?;

    let result: Result<DataUploadResponse, MergedError<EcallError<DataUploadError>, MailboxError>> =
        enclave.send(message).await.merge_err();

    match result {
        Ok(resp) => Ok(web::Json(resp.into())),
        Err(MergedError::Error1(err)) => Err(ErrorInternalServerError(err)),
        Err(MergedError::Error2(err)) => Err(ErrorInternalServerError(err)),
    }
}

pub mod models {
    use crate::validation::ValidationError;
    use crate::Base64Standard;
    use rtc_types::{DataUploadResponse, UploadMetadata};
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;

    use crate::data_upload::DataUploadMessage;

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

    #[derive(Serialize, Deserialize, Debug)]
    pub struct ResponseBody {
        #[serde(with = "Base64Standard")]
        pub ciphertext: Vec<u8>,
        #[serde(with = "Base64Standard")]
        pub nonce: Vec<u8>,
    }

    impl From<DataUploadResponse> for ResponseBody {
        fn from(resp: DataUploadResponse) -> Self {
            ResponseBody {
                ciphertext: resp.ciphertext.to_vec(),
                nonce: resp.nonce.to_vec(),
            }
        }
    }

    impl TryFrom<RequestBody> for DataUploadMessage {
        type Error = ValidationError;

        fn try_from(request_body: RequestBody) -> Result<Self, Self::Error> {
            let uploader_pub_key = TryFrom::try_from(request_body.metadata.uploader_pub_key)
                .or(Err(ValidationError::new("Invalid pub key")))?;
            let nonce = TryFrom::try_from(request_body.metadata.nonce)
                .or(Err(ValidationError::new("Invalid nonce")))?;

            Ok(DataUploadMessage {
                metadata: UploadMetadata {
                    uploader_pub_key,
                    nonce,
                },
                payload: request_body.payload.into_boxed_slice(),
            })
        }
    }
}

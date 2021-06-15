use std::convert::TryInto;

use actix::{Addr, MailboxError};
use actix_web::error::ErrorInternalServerError;
use actix_web::{post, web};
use models::*;
use rtc_types::{DataUploadError, DataUploadResponse, EcallError};

use super::DataUploadMessage;
use crate::data_enclave_actor::DataEnclaveActor;
use crate::merge_error::*;

/// Save uploaded data file using a [`DataUploadMessage`] for [`DataEnclaveActor`].
///
/// * Request: POST [`RequestBody`]
/// * Response: [`DataUploadMessage`]
///
/// FIXME: We should use a more efficient binary format (rather than Base64 over JSON) for the data file here.
///
#[post("/data/uploads")]
pub async fn upload_file(
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
    use std::convert::TryFrom;

    use rtc_types::{DataUploadResponse, UploadMetadata};
    use serde::{Deserialize, Serialize};

    use crate::data_upload::DataUploadMessage;
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

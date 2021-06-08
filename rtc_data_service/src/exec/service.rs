use std::convert::TryInto;

use actix::{Addr, MailboxError};
use actix_web::{error::ErrorInternalServerError, post, web};
use models::*;

use crate::{
    exec::{RequestExecutionError, RequestExecutionMessage, RequestExecutionResponse},
    exec_enclave_actor::ExecEnclaveActor,
    merge_error::*,
};

/// Request execution using an execution token
#[post("/exec/request")]
pub async fn request_execution(
    req_body: web::Json<RequestBody>,
    enclave: web::Data<Addr<ExecEnclaveActor>>,
) -> actix_web::Result<web::Json<ResponseBody>> {
    let message: RequestExecutionMessage = req_body.0.try_into()?;

    let result: Result<RequestExecutionResponse, MergedError<RequestExecutionError, MailboxError>> =
        enclave.send(message).await.merge_err();
    match result {
        Ok(resp) => Ok(web::Json(resp.into())),
        Err(err) => Err(ErrorInternalServerError(err)),
    }
}

pub mod models {
    use crate::exec::{RequestExecutionMessage, RequestExecutionResponse};
    use crate::validation::ValidationError;
    use crate::Base64Standard;
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;

    #[derive(Serialize, Deserialize, Debug)]
    pub struct Metadata {
        #[serde(with = "Base64Standard")]
        pub uploader_pub_key: Vec<u8>,
        #[serde(with = "Base64Standard")]
        pub nonce: Vec<u8>,
    }

    #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
    pub struct ResponseBody {}

    impl From<RequestExecutionResponse> for ResponseBody {
        fn from(_resp: RequestExecutionResponse) -> Self {
            ResponseBody {} // TODO
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct RequestBody {
        pub metadata: Metadata,
        #[serde(with = "Base64Standard")]
        pub payload: Vec<u8>,
    }

    impl TryFrom<RequestBody> for RequestExecutionMessage {
        type Error = ValidationError;

        fn try_from(request_body: RequestBody) -> Result<Self, Self::Error> {
            Ok(RequestExecutionMessage {
                metadata: (), // TODO
                payload: request_body.payload.into_boxed_slice(),
            })
        }
    }
}

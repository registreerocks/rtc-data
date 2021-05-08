use actix::{Addr, MailboxError};
use actix_web::{error::ErrorInternalServerError, post, web, HttpRequest};
use models::*;
use rtc_types::{EcallError, ExecTokenError, ExecTokenResponse};

use crate::data_enclave_actor::DataEnclaveActor;
use crate::merge_error::*;

use super::ExecTokenMessage;

#[post("auth/tokens")]
pub async fn req_exec_token(
    _req: HttpRequest,
    enclave: web::Data<Addr<DataEnclaveActor>>,
) -> actix_web::Result<web::Json<ResponseBody>> {
    let message = ExecTokenMessage {
        metadata: vec![16; 0],
    };

    let result: Result<ExecTokenResponse, MergedError<ExecTokenError, MailboxError>> =
        enclave.send(message).await.merge_err();
    match result {
        Ok(resp) => {
            println!("{:?}", resp);
            Ok(web::Json(resp.into()))
        }
        Err(err) => Err(ErrorInternalServerError(err)),
    }
}

pub mod models {
    use crate::validation::ValidationError;
    use crate::Base64Standard;
    use rtc_types::ExecTokenResponse;
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;

    #[derive(Serialize, Deserialize, Debug)]
    pub struct ResponseBody {
        #[serde(with = "Base64Standard")]
        pub execution_token: Vec<u8>,
    }

    impl From<ExecTokenResponse> for ResponseBody {
        fn from(resp: ExecTokenResponse) -> Self {
            ResponseBody {
                execution_token: resp.execution_token.to_vec(),
            }
        }
    }
}

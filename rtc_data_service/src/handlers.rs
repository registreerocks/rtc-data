use actix::Addr;
use actix_web::{error::ErrorInternalServerError, get, web, HttpRequest, HttpResponse};
use models::Status;

use crate::auth_enclave_actor;
use crate::auth_enclave_actor::AuthEnclaveActor;
use crate::data_enclave_actor;
use crate::data_enclave_actor::DataEnclaveActor;
use crate::merge_error::*;

pub async fn server_status(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().json(Status {
        status: "The server is up".to_string(),
    })
}

#[get("/auth/attest")]
pub async fn auth_enclave_attestation(
    _req: HttpRequest,
    enclave: web::Data<Addr<AuthEnclaveActor>>,
) -> actix_web::Result<String> {
    let jwt = enclave
        .send(auth_enclave_actor::RequestAttestation::default())
        .await
        .merge_err();
    dbg!(&jwt);

    match jwt {
        Ok(result) => Ok(result),
        // TODO: Look at the result here - change the error format and see if we want to sanitise the output in some way
        Err(err) => Err(ErrorInternalServerError(err)),
    }
}

#[get("/data/attest")]
pub async fn data_enclave_attestation(
    _req: HttpRequest,
    enclave: web::Data<Addr<DataEnclaveActor>>,
) -> actix_web::Result<String> {
    let jwt = enclave
        .send(data_enclave_actor::RequestAttestation::default())
        .await
        .merge_err();
    dbg!(&jwt);

    match jwt {
        Ok(result) => Ok(result),
        // TODO: Look at the result here - change the error format and see if we want to sanitise the output in some way
        Err(err) => Err(ErrorInternalServerError(err)),
    }
}

pub mod models {
    use serde::Serialize;

    #[derive(Serialize)]
    pub struct Status {
        pub status: String,
    }
}

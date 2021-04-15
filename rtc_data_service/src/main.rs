#![deny(clippy::mem_forget)]
#![feature(toowned_clone_into)]
#![feature(try_blocks)]
#![warn(rust_2018_idioms)]

use std::sync::Arc;

use crate::models::Status;
use actix::{Addr, Arbiter, Supervisor};
use actix_web::{
    get,
    web::{self, Data},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};

mod app_config;
mod enclave_actor;
mod merge_error;
use app_config::AppConfig;
use enclave_actor::*;
use merge_error::*;
use serde_json::json;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = AppConfig::new().expect("Server config expected");
    let enclave_config = Arc::new(config.data_enclave.clone());

    let enclave_arbiter = Arbiter::new();

    // Data uses Arc internally, so we don't have to worry about shared ownership
    // see: https://actix.rs/docs/application/
    // Addr might also use Arc internally, so we might have Arc<Arc<_>>. Not sure if this
    // is a big deal atm.
    let enclave_addr = Data::new(Supervisor::start_in_arbiter(
        &enclave_arbiter.handle(),
        move |_| EnclaveActor::new(enclave_config.clone()),
    ));

    println!(
        "Starting server at http://{}:{}/",
        config.http_server.host, config.http_server.port
    );

    HttpServer::new(move || {
        let app = App::new()
            .app_data(enclave_addr.clone())
            .route("/", web::get().to(server_status))
            .service(data_enclave_attestation);

        app
    })
    .bind(format!(
        "{}:{}",
        config.http_server.host, config.http_server.port
    ))?
    .run()
    .await
}

pub async fn server_status(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().json(Status {
        status: "The server is up".to_string(),
    })
}

#[get("/data/attest")]
pub(crate) async fn data_enclave_attestation(
    _req: HttpRequest,
    enclave: web::Data<Addr<EnclaveActor>>,
) -> impl Responder {
    let jwt = enclave
        .send(RequestAttestation::default())
        .await
        .merge_err();

    match jwt {
        Ok(result) => HttpResponse::Ok().json(json!({ "token": result })),
        // TODO: Look at the result here - change the error format and see if we want to sanitise the output in some way
        Err(err) => HttpResponse::InternalServerError().json(json!({ "error": err.to_string() })),
    }
}

mod models {
    use serde::Serialize;

    #[derive(Serialize)]
    pub struct Status {
        pub status: String,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use actix_web::{http, test};

    #[actix_rt::test]
    async fn test_server_status_ok() {
        // NOTE: This only works if the handler we are testing returns
        // `HttpResponse`. I am not sure how to get the tests
        // working with handlers returning `impl Responder`
        let req = test::TestRequest::get()
            .insert_header(("content-type", "text/plain"))
            .to_http_request();
        let resp = server_status(req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }
}

// TODO: Enable and clean warnings
//#![warn(missing_docs)]
#![deny(clippy::mem_forget)]
#![feature(toowned_clone_into)]
#![feature(try_blocks)]
extern crate base64;
#[cfg(test)]
extern crate mockall;
extern crate mockall_double;
#[cfg(test)]
extern crate num_bigint;
#[cfg(test)]
extern crate num_traits;
#[cfg(test)]
extern crate proptest;
#[cfg(test)]
extern crate rand;
extern crate rtc_types;
extern crate rtc_uenclave;
extern crate sgx_types;
#[cfg(test)]
extern crate simple_asn1;
extern crate thiserror;

use crate::models::Status;
use actix::SystemService;
use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;

mod config;
mod enclave_actor;
use enclave_actor::*;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let config = config::Config::from_env().expect("Server config expected");

    println!(
        "Starting server at http://{}:{}/",
        config.server.host, config.server.port
    );
    HttpServer::new(|| {
        let app = App::new()
            .route("/", web::get().to(server_status))
            .service(get_report);

        app
    })
    .bind(format!("{}:{}", config.server.host, config.server.port))?
    .run()
    .await
}

pub async fn server_status(_req: HttpRequest) -> impl Responder {
    HttpResponse::Ok().json(Status {
        status: "The server is up".to_string(),
    })
}

#[get("/report")]
pub async fn get_report(_req: HttpRequest) -> impl Responder {
    let res = EnclaveActor::from_registry()
        .send(CreateReport::default())
        .await;

    match try { res.ok()?.ok()? } {
        Some(_) => HttpResponse::Ok().body("hi"),
        None => HttpResponse::InternalServerError().body("HELP"),
    }
}

mod models {
    use serde::Serialize;

    #[derive(Serialize)]
    pub struct Status {
        pub status: String,
    }
}

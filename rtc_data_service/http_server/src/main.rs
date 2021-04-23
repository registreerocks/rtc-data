#![deny(clippy::mem_forget)]
#![feature(toowned_clone_into)]
#![feature(try_blocks)]
#![warn(rust_2018_idioms)]

use rtc_data_service::app_config::AppConfig;
use rtc_data_service::enclave_actor::*;
use rtc_data_service::handlers::*;
use rtc_data_service::merge_error;
use web::service;

use std::sync::Arc;

use actix::{Arbiter, Supervisor};
use actix_web::{
    web::{self, Data},
    App, HttpServer,
};

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
            .service(data_enclave_attestation)
            .service(upload_encrypted_file);

        app
    })
    .bind(format!(
        "{}:{}",
        config.http_server.host, config.http_server.port
    ))?
    .run()
    .await
}

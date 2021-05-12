#![deny(clippy::mem_forget)]
#![feature(toowned_clone_into)]
#![feature(try_blocks)]
#![warn(rust_2018_idioms)]

mod tls;

use rtc_data_service::app_config::AppConfig;
use rtc_data_service::data_enclave_actor::*;
use rtc_data_service::data_upload::*;
use rtc_data_service::exec_token::*;
use rtc_data_service::handlers::*;
use rtc_data_service::merge_error;
use rustls::{AllowAnyAuthenticatedClient, NoClientAuth, RootCertStore, ServerConfig};

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use actix::{Arbiter, Supervisor};
use actix_cors::Cors;
use actix_web::{
    http::header,
    web::{self, Data},
    App, HttpServer,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = AppConfig::new().expect("Server config expected");
    let enclave_config = Arc::new(config.data_enclave.clone());
    let allowed_origins = config.http_server.allowed_origins;

    let enclave_arbiter = Arbiter::new();

    // Data uses Arc internally, so we don't have to worry about shared ownership
    // see: https://actix.rs/docs/application/
    // Addr might also use Arc internally, so we might have Arc<Arc<_>>. Not sure if this
    // is a big deal atm.
    let enclave_addr = Data::new(Supervisor::start_in_arbiter(
        &enclave_arbiter.handle(),
        move |_| DataEnclaveActor::new(enclave_config.clone()),
    ));

    println!(
        "Starting server at http://{}:{}/",
        config.http_server.host, config.http_server.port
    );

    let server = HttpServer::new(move || {
        let cors = build_cors(&allowed_origins);
        let app = App::new()
            .wrap(cors)
            .app_data(enclave_addr.clone())
            .route("/", web::get().to(server_status))
            .service(data_enclave_attestation)
            .service(upload_file)
            .service(req_exec_token);

        app
    })
    .bind(format!(
        "{}:{}",
        config.http_server.host, config.http_server.port
    ))
    .expect("Failed to bind HTTP server");

    match config.tls {
        Some(tls_conf) => {
            println!(
                "Starting HTTPS server at https://{}:{}/",
                config.http_server.host, config.http_server.port_https
            );
            server
                .bind_rustls(
                    format!(
                        "{}:{}",
                        config.http_server.host, config.http_server.port_https,
                    ),
                    tls::get_tls_server_config(tls_conf).expect("Valid TLS config"),
                )?
                .run()
                .await
        }
        None => server.run().await,
    }
}

fn build_cors(allowed_origins: &Vec<String>) -> Cors {
    match &allowed_origins[..] {
        [allow_any] if allow_any == "*" => {
            println!("WARNING(CORS): All origins are allowed",);
            Cors::default().allow_any_origin()
        }
        [] => {
            println!("WARNING(CORS): No origins are allowed",);
            Cors::default()
        }
        _ => allowed_origins
            .into_iter()
            .fold(Cors::default(), |acc, el| acc.allowed_origin(el.as_ref())),
    }
    .allowed_methods(vec!["GET", "HEAD", "POST", "PUT", "OPTIONS"])
    .allowed_headers(vec![
        header::AUTHORIZATION,
        header::ACCEPT,
        header::CONTENT_TYPE,
    ])
}

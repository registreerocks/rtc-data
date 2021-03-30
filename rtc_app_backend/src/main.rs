mod config;
mod models;

use crate::models::Status;
use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use dotenv::dotenv;

async fn server_status() -> impl Responder {
    HttpResponse::Ok()
        .json(Status {status : "The server is up".to_string()})
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    dotenv().ok();

    let config = crate::config::Config::from_env().unwrap();

    print!("Starting server at http://{}:{}/", config.server.host, config.server.port);
    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(server_status))
    })
    .bind(format!("{}:{}", config.server.host, config.server.port))?
    .run()
    .await
}
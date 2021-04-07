mod actix_config{
    use config::ConfigError;
    use serde::Deserialize;

    // Configuration specific to the server
    #[derive(Deserialize)]
    pub struct ServerConfig {
        pub host : String,
        pub port : i32
    }


    // App configuration
    #[derive(Deserialize)]
    pub struct Config {
        pub server : ServerConfig
    }

    impl Config {
        // Loads configuration from the environment to the Config Struct
        pub fn from_env() -> Result<Self, ConfigError> {
            let mut cfg = config::Config::new();
            cfg.merge(config::Environment::new())?;
            cfg.try_into()
        }
    }
}

pub mod actix_server{
    use actix_web::{App, HttpResponse, HttpServer, Responder, web};
    use crate::actix::models::Status;
    use dotenv::dotenv;
    
    pub async fn server_status() -> impl Responder {
        HttpResponse::Ok()
            .json(Status {status : "The server is up".to_string()})
    }
    
    #[actix_web::main]
    pub async fn start_server() -> std::io::Result<()> {
    
        dotenv().ok();
    
        let config = crate::actix::actix_config::Config::from_env().expect("Server config expected");
    
        print!("Starting server at http://{}:{}/", config.server.host, config.server.port);
        HttpServer::new(|| {
            App::new()
                .route("/", web::get().to(server_status))
        })
        .bind(format!("{}:{}", config.server.host, config.server.port))?
        .run()
        .await
    }
}

mod models{
    use serde::Serialize;

    #[derive(Serialize)]
    pub struct Status {
        pub status : String
    }
}

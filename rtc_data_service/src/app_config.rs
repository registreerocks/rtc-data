use config::{Config, ConfigError, Environment, File};
use rtc_uenclave::EnclaveConfig;
use serde::Deserialize;
use std::env;

// Configuration specific to the server
#[derive(Deserialize, Clone, Default)]
pub struct ServerConfig {
    pub host: String,
    pub port: i32,
}

// App configuration
#[derive(Deserialize, Clone, Default)]
pub struct AppConfig {
    pub http_server: ServerConfig,
    pub data_enclave: EnclaveConfig,
}

impl AppConfig {
    // Loads app config from the config files
    // for the application
    pub fn new() -> Result<Self, ConfigError> {
        // Using hierarchical config here
        // see: https://github.com/mehcode/config-rs/blob/master/examples/hierarchical-env/src/settings.rs
        let mut conf = Config::new();

        conf.merge(File::with_name("config/default"))?;

        // Current environment file
        let env = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());
        conf.merge(File::with_name(&format!("config/{}", env)).required(false))?;

        // Local environment file -> Not checked in to git
        conf.merge(File::with_name("config/local").required(false))?;

        // Add in settings from the environment (with a prefix of APP)
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        conf.merge(Environment::with_prefix("app"))?;

        // You can deserialize (and thus freeze) the entire configuration as
        conf.try_into()
    }
}

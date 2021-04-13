use config::ConfigError;
use serde::Deserialize;

// Configuration specific to the server
#[derive(Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: i32,
}

// App configuration
#[derive(Deserialize)]
pub struct Config {
    pub server: ServerConfig,
}

impl Config {
    // Loads configuration from the environment to the Config Struct
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut cfg = config::Config::new();
        cfg.merge(config::Environment::new())?;
        cfg.try_into()
    }
}

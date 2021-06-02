use rtc_data_service::app_config::TlsConfig;
use rustls::{
    AllowAnyAuthenticatedClient, NoClientAuth, PrivateKey, RootCertStore,
    ServerConfig as TlsServerConfig,
};
use rustls_pemfile::{self, read_one, Item};
use thiserror::Error;

use std::io::BufReader;
use std::iter;
use std::{fs, io};

pub fn get_tls_server_config(config: TlsConfig) -> Result<TlsServerConfig, TlsConfigError> {
    let client_auth = match config.client_cert_path {
        Some(path) => {
            let roots = load_certs(&path)?;
            let mut client_auth_roots = RootCertStore::empty();
            for root in roots {
                client_auth_roots.add(&root)?;
            }

            println!("client-auth enabled");
            AllowAnyAuthenticatedClient::new(client_auth_roots)
        }
        None => {
            println!("client-auth disabled");
            NoClientAuth::new()
        }
    };
    let mut tls_conf = TlsServerConfig::new(client_auth);

    let certs = load_certs(&config.server_cert_path)?;

    let privkey = load_private_key(&config.priv_key_path)?;

    tls_conf.set_single_cert(certs, privkey)?;

    Ok(tls_conf)
}

#[derive(Debug, Error)]
pub enum TlsConfigError {
    /// I/O operation failed
    #[error("I/O operation failed: {}", .0)]
    IO(#[from] io::Error),
    /// Failed to parse certificate
    #[error("Failed to parse certificate: {}", .0)]
    Cert(#[from] webpki::Error),
    /// Private key file contained no private key
    #[error("Private key file contained no private key")]
    NoPrivateKey,
    /// TLS error from Rustls
    #[error("Rustls error: {}", .0)]
    Tls(#[from] rustls::TLSError),
}

fn load_certs(filename: &str) -> Result<Vec<rustls::Certificate>, io::Error> {
    let certfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();
    Ok(certs)
}

fn load_private_key(filename: &str) -> Result<PrivateKey, TlsConfigError> {
    let keyfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(keyfile);
    let x = iter::from_fn(|| read_one(&mut reader).transpose()).find_map(|s| match s {
        Ok(Item::RSAKey(key) | Item::PKCS8Key(key)) => Some(Ok(PrivateKey(key))),
        Ok(_) => None,
        Err(err) => Some(Err(err)),
    });

    x.map_or(Err(TlsConfigError::NoPrivateKey), |val| Ok(val?))
}

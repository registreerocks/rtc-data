//! Shared test helpers

mod types;

use std::sync::Arc;

use actix::Actor;
use actix_web::App;

use rtc_uenclave::{EnclaveConfig, RtcAuthEnclave, RtcDataEnclave};

use rtc_data_service::auth_enclave_actor::AuthEnclaveActor;
use rtc_data_service::data_enclave_actor::DataEnclaveActor;
use rtc_data_service::data_upload::upload_file;
use rtc_data_service::exec::request_execution;
use rtc_data_service::exec_enclave_actor::ExecEnclaveActor;
use rtc_data_service::exec_token::req_exec_token;
use rtc_data_service::handlers;

/// Initialise an auth enclave for testing.
pub(crate) fn init_auth_enclave() -> RtcAuthEnclave<EnclaveConfig> {
    RtcAuthEnclave::init(EnclaveConfig {
        lib_path: "/root/rtc-data/rtc_auth_enclave/build/bin/enclave.signed.so".to_string(),
        ..Default::default()
    })
    .unwrap()
}

/// Initialise a data enclave for testing.
pub(crate) fn init_data_enclave() -> RtcDataEnclave<EnclaveConfig> {
    RtcDataEnclave::init(EnclaveConfig {
        lib_path: "/root/rtc-data/rtc_data_enclave/build/bin/enclave.signed.so".to_string(),
        ..Default::default()
    })
    .unwrap()
}

/// Initialise an instance of our web API for testing.
///
/// This should (roughly) mirror our `HttpServer` definition in `http_server::main`.
pub(crate) async fn init_rtc_service() -> impl types::WebService {
    let app = App::new()
        .data(init_auth_enclave_actor().start())
        .data(init_data_enclave_actor().start())
        .data(init_exec_enclave_actor().start())
        .service(handlers::auth_enclave_attestation)
        .service(handlers::data_enclave_attestation)
        .service(handlers::exec_enclave_attestation)
        .service(upload_file)
        .service(req_exec_token)
        .service(request_execution);
    actix_web::test::init_service(app).await
}

fn init_auth_enclave_actor() -> AuthEnclaveActor {
    AuthEnclaveActor::new(Arc::new(EnclaveConfig {
        lib_path: "/root/rtc-data/rtc_auth_enclave/build/bin/enclave.signed.so".to_string(),
        ..Default::default()
    }))
}

fn init_data_enclave_actor() -> DataEnclaveActor {
    DataEnclaveActor::new(Arc::new(EnclaveConfig {
        lib_path: "/root/rtc-data/rtc_data_enclave/build/bin/enclave.signed.so".to_string(),
        ..Default::default()
    }))
}

fn init_exec_enclave_actor() -> ExecEnclaveActor {
    ExecEnclaveActor::new(Arc::new(EnclaveConfig {
        lib_path: "/root/rtc-data/rtc_exec_enclave/build/bin/enclave.signed.so".to_string(),
        ..Default::default()
    }))
}

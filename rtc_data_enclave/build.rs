use std::env;
use std::path::Path;
use std::process::Command;
extern crate cc;

fn main() {
    let sgx_sdk = env::var("SGX_SDK").unwrap();
    let edger8r = format!("{}/bin/x64/sgx_edger8r", sgx_sdk);
    let sgx_rust = String::from("/root/sgx-rust");

    run_edger8r(&sgx_sdk, &edger8r, &sgx_rust);
}

fn run_edger8r(sgx_sdk: &str, edger8r: &str, sgx_rust: &str) {
    // TODO: Write a build-dep that does this and can be shared
    Command::new(edger8r)
        .args(&["./Enclave.edl"])
        .args(&["--search-path", &format!("{}/include", sgx_sdk)])
        .args(&["--search-path", &format!("{}/edl", sgx_rust)])
        .args(&["--trusted-dir", "codegen"])
        .args(&["--untrusted-dir", "../rtc_data_service/codegen"])
        .status()
        .unwrap();
}

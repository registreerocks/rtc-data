extern crate cbindgen;
extern crate cc;

use cbindgen::{Config, ExportConfig, ItemType};
use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=Enclave.edl");

    let sgx_sdk = env::var("SGX_SDK").unwrap();
    let edger8r = format!("{}/bin/x64/sgx_edger8r", sgx_sdk);
    let sgx_rust = String::from("/root/sgx-rust");
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::Builder::new()
        .with_config(Config {
            export: ExportConfig {
                item_types: vec![
                    ItemType::Constants,
                    ItemType::Globals,
                    ItemType::Enums,
                    ItemType::Structs,
                    ItemType::Unions,
                    ItemType::Typedefs,
                    ItemType::OpaqueItems,
                ],
                ..Default::default()
            },
            ..Default::default()
        })
        .with_crate(crate_dir)
        .with_std_types(false)
        .with_language(cbindgen::Language::C)
        .with_no_includes()
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("../codegen/data_enclave/bindings.h");

    run_edger8r(&sgx_sdk, &edger8r, &sgx_rust);
}

fn run_edger8r(sgx_sdk: &str, edger8r: &str, sgx_rust: &str) {
    // TODO: Write a build-dep that does this and can be shared
    Command::new(edger8r)
        .args(&["./Enclave.edl"])
        .args(&["--search-path", &format!("{}/include", sgx_sdk)])
        .args(&["--search-path", &format!("{}/edl", sgx_rust)])
        .args(&["--trusted-dir", "../codegen/data_enclave"])
        .args(&["--untrusted-dir", "../codegen/data_enclave"])
        .status()
        .unwrap();
}

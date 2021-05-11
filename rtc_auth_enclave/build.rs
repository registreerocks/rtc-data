extern crate cbindgen;
extern crate cc;

use cbindgen::{Config, ExportConfig, ItemType};
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=Enclave.edl");
    println!("cargo:rerun-if-changed=src");

    // Also rebuild if we delete bindings.h
    println!("cargo:rerun-if-changed=../codegen/auth_enclave/bindings.h");

    let sgx_sdk = env::var("SGX_SDK").unwrap();
    let _edger8r = format!("{}/bin/x64/sgx_edger8r", sgx_sdk);
    let _sgx_rust = String::from("/root/sgx-rust");
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
        .with_parse_deps(true)
        .with_parse_include(&["rtc_types", "rtc_tenclave"])
        .with_parse_extra_bindings(&["rtc_types", "rtc_tenclave"])
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("../codegen/auth_enclave/bindings.h");
}

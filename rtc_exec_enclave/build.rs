extern crate cbindgen;
extern crate cc;

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=rtc_exec.edl");
    println!("cargo:rerun-if-changed=src");

    let cbindgen_config_file = "../cbindgen_enclaves.toml";
    println!("cargo:rerun-if-changed={}", cbindgen_config_file);
    // Also rebuild if we delete bindings.h
    println!("cargo:rerun-if-changed=../codegen/exec_enclave/bindings.h");

    let sgx_sdk = env::var("SGX_SDK").unwrap();
    let _edger8r = format!("{}/bin/x64/sgx_edger8r", sgx_sdk);
    let _sgx_rust = String::from("/root/sgx-rust");
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let cbindgen_config = cbindgen::Config::from_file(cbindgen_config_file).unwrap();
    cbindgen::Builder::new()
        .with_config(cbindgen_config)
        .with_crate(crate_dir)
        .with_std_types(false)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("../codegen/exec_enclave/bindings.h");
}

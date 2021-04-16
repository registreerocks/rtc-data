use cc;
use std::env;
fn main() {
    let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/sgxsdk".to_string());
    let profile = env::var("PROFILE").unwrap();
    let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

    let includes = vec![
        format!("{}/include", sdk_dir),
        "./codegen".to_string(),
        "../include".to_string(),
        "/root/sgx-rust/edl".to_string(),
    ];

    // NOTE: This is for the integration tests. Currently this only works if the
    // nightly toolchain is installed, and if you test running
    // `cargo +nightly test -Z extra-link-arg`
    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
    println!("cargo:rustc-link-arg=-lsgx_uprotected_fs");

    println!("cargo:rustc-link-arg=-lsgx_dcap_ql");

    match is_sim.as_ref() {
        "SW" => {
            println!("cargo:rustc-cfg=sgx_mode=\"SW\"");
            println!("cargo:rustc-link-arg=-lsgx_urts_sim");
            println!("cargo:rustc-link-arg=-lsgx_uae_service_sim");
        }
        _ => {
            // HW by default
            println!("cargo:rustc-cfg=sgx_mode=\"HW\"");
            println!("cargo:rustc-link-arg=-lsgx_urts");
            println!("cargo:rustc-link-arg=-lsgx_uae_service");
        }
    }
}

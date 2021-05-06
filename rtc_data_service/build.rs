use std::env;
use std::process::Command;
fn main() {
    let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/sgxsdk".to_string());
    let _profile = env::var("PROFILE").unwrap();
    let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

    println!("cargo:rerun-if-env-changed=SGX_MODE");
    // TODO: Automatically build the enclave if anything changed?

    // Build data-enclave file
    Command::new("make")
        .args(&["-c", "../rtc_data_enclave"])
        .status()
        .unwrap();

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

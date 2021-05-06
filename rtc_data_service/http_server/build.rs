use cc;
use std::env;

fn main() {
    let _test_enabled = env::var_os("CARGO_FEATURE_TEST").is_some();

    let _cur_dir = env::current_dir().unwrap();

    let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/sgxsdk".to_string());
    let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());
    let _profile = env::var("PROFILE").unwrap();

    println!("cargo:rerun-if-env-changed=SGX_MODE");

    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
    println!("cargo:rustc-link-lib=static=sgx_uprotected_fs");

    println!("cargo:rustc-link-lib=dylib=sgx_dcap_ql");

    match is_sim.as_ref() {
        "SW" => {
            println!("cargo:rustc-cfg=sgx_mode=\"SW\"");
            println!("cargo:rustc-link-lib=dylib=sgx_urts_sim");
            println!("cargo:rustc-link-lib=dylib=sgx_uae_service_sim");
        }
        _ => {
            // HW by default
            println!("cargo:rustc-cfg=sgx_mode=\"HW\"");
            println!("cargo:rustc-link-lib=dylib=sgx_urts");
            println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
        }
    }
}

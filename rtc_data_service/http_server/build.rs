use cc;
use std::env;

fn main() {
    let test_enabled = env::var_os("CARGO_FEATURE_TEST").is_some();

    let cur_dir = env::current_dir().unwrap();

    let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/sgxsdk".to_string());
    let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());
    let profile = env::var("PROFILE").unwrap();

    let includes = vec![
        format!("{}/include", sdk_dir),
        "../codegen".to_string(),
        "../../include".to_string(),
        "/root/sgx-rust/edl".to_string(),
    ];

    let mut base_u = cc::Build::new()
        .file("../codegen/Enclave_u.c")
        .no_default_flags(true)
        .includes(includes)
        .flag("-fstack-protector")
        .flag("-fPIC")
        .flag("-Wno-attributes")
        .flag("-m64")
        .flag("-ggdb")
        .shared_flag(true)
        .to_owned();

    if (profile == "release") {
        base_u.flag("-O2").compile("Enclave_u");
    } else {
        base_u.flag("-O0").flag("-g").compile("Enclave_u");
    }

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

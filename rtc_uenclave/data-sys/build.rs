use bindgen::{self, CodegenConfig};
use cc;
use std::env;
use std::path::PathBuf;

fn main() {
    let test_enabled = env::var_os("CARGO_FEATURE_TEST").is_some();

    let cur_dir = env::current_dir().unwrap();

    let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/sgxsdk".to_string());
    let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());
    let profile = env::var("PROFILE").unwrap();

    let includes = vec![
        format!("{}/include", sdk_dir),
        "./codegen".to_string(),
        "../include".to_string(),
        "/root/sgx-rust/edl".to_string(),
    ];

    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);

    let mut base_u = cc::Build::new()
        .file("./codegen/Enclave_u.c")
        .no_default_flags(true)
        .includes(&includes)
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

    println!("cargo:rerun-if-changed=wrapper.h");
    println!("-I '{}/include'", sdk_dir);

    let inc_args: Vec<&str> = includes
        .iter()
        .flat_map(|x| vec!["-I", x.as_str()])
        .collect();

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .with_codegen_config(CodegenConfig::FUNCTIONS | CodegenConfig::TYPES)
        .whitelist_recursively(false)
        .allowlist_function("enclave_create_report")
        .clang_args(&inc_args)
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

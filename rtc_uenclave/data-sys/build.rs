use bindgen::{self, CodegenConfig};
use cc;
use std::env;
use std::path::PathBuf;

fn main() {
    let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/sgxsdk".to_string());
    let profile = env::var("PROFILE").unwrap();
    let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

    let includes = vec![
        format!("{}/include", sdk_dir),
        "../../codegen/data_enclave".to_string(),
        "../include".to_string(),
        "/root/sgx-rust/edl".to_string(),
    ];

    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);

    let mut base_u = cc::Build::new()
        .file("../../codegen/data_enclave/Enclave_u.c")
        .no_default_flags(true)
        .includes(&includes)
        .flag("-fstack-protector")
        .flag("-fPIC")
        .flag("-Wno-attributes")
        .flag("-m64")
        .flag("-ggdb")
        .shared_flag(true)
        .to_owned();

    if profile == "release" {
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
        .allowlist_recursively(false)
        .array_pointers_in_arguments(true)
        // TODO: see if there is a way to include functions using globbing
        .allowlist_function("enclave_create_report")
        .allowlist_function("rtc_validate_and_save")
        .clang_args(&inc_args)
        .generate()
        .expect("Unable to generate bindings")
        .to_string();

    let mut bindings_string = "use mockall::automock;\n".to_owned();

    bindings_string.push_str("#[automock]\npub mod ffi {\nuse super::*;\n");
    bindings_string.push_str(&bindings);
    bindings_string.push_str("}\n");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    std::fs::write(out_path.join("bindings.rs"), bindings_string.as_bytes())
        .expect("Failed to save bindings");
}

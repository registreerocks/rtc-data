use bindgen::{self, CodegenConfig};
use cc;
use std::path::PathBuf;
use std::{env, path::Path};

fn main() {
    let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/sgxsdk".to_string());
    let profile = env::var("PROFILE").unwrap();
    let enclave_gen = Path::new("../../codegen/auth_enclave");

    let includes = vec![
        format!("{}/include", sdk_dir),
        enclave_gen.to_str().unwrap().to_string(),
        "../include".to_string(),
        "/root/sgx-rust/edl".to_string(),
    ];

    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);

    let filename_u = "rtc_auth_u";

    let mut base_u = cc::Build::new()
        .file(enclave_gen.join(filename_u).with_extension("c"))
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
        base_u.flag("-O2").compile(filename_u);
    } else {
        base_u.flag("-O0").flag("-g").compile(filename_u);
    }

    println!("cargo:rerun-if-changed=wrapper.h");
    println!("-I '{}/include'", sdk_dir);

    let inc_args: Vec<&str> = includes
        .iter()
        .flat_map(|x| vec!["-I", x.as_str()])
        .collect();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindgen::Builder::default()
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .with_codegen_config(CodegenConfig::FUNCTIONS | CodegenConfig::TYPES)
        .allowlist_recursively(false)
        .array_pointers_in_arguments(true)
        .allowlist_function("rtc_auth_.*")
        .clang_args(&inc_args)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings to file");
}

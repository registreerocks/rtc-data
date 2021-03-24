#![crate_name = "rtc_data_enclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate bincode;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_big_array;
extern crate sgx_crypto_helper;
extern crate sgx_tcrypto;
extern crate sgx_tse;
extern crate simple_asn1;

pub mod rsa3072;

use sgx_tse::rsgx_create_report;
use sgx_types::*;
use std::path::Path;
use std::prelude::v1::*;
use std::sgxfs::SgxFile;
use std::slice;
use std::string::String;
use std::vec::Vec;
use std::{
    io::{self, Write},
    untrusted::path::PathEx,
};

use rsa3072::{PublicKeyEncoding, Rsa3072KeyPair};
use sgx_tse::{rsgx_get_key, rsgx_self_report};

use sgx_crypto_helper::RsaKeyPair;
use sgx_tcrypto::rsgx_sha256_slice;

pub const KEYFILE: &str = "prov_key.bin";

pub const PUBKEY_SIZE: usize = SGX_RSA3072_KEY_SIZE + SGX_RSA3072_PUB_EXP_SIZE;

#[no_mangle]
pub extern "C" fn say_something(some_string: *const u8, some_len: usize) -> sgx_status_t {
    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ = io::stdout().write(str_slice);

    // A sample &'static string
    let rust_raw_string = "This is a in-Enclave ";
    // An array
    let word: [u8; 4] = [82, 117, 115, 116];
    // An vector
    let word_vec: Vec<u8> = vec![32, 115, 116, 114, 105, 110, 103, 33];

    // Construct a string from &'static string
    let mut hello_string = String::from(rust_raw_string);

    // Iterate on word array
    for c in word.iter() {
        hello_string.push(*c as char);
    }

    // Rust style convertion
    hello_string += String::from_utf8(word_vec).expect("Invalid UTF-8").as_str();

    // Ocall to normal world for output
    println!("{}", &hello_string);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn enclave_create_report(
    p_qe3_target: &sgx_target_info_t,
    enclave_pubkey: &mut [u8; PUBKEY_SIZE], // Public key in format [...modulus, ...exponent]
    p_report: *mut sgx_report_t,
) -> sgx_status_t {
    // TODO: Error handling
    let report_keypair = match get_or_create_report_keypair() {
        Ok(key) => key,
        Err(x) => panic!(x),
    };

    // TODO Change public key out variable to 420 bytes and return pkcs8 instead
    // This value can then be base64 encoded and passed through as the enclave held data
    // to Azure Attestation.

    let pkcs_pubkey = report_keypair.to_pkcs8().unwrap();
    println!("pkcs8 len: {:?}", pkcs_pubkey.len());
    println!("pkcs8 enclave: {:?}", pkcs_pubkey);
    let pubkey_hash = rsgx_sha256_slice(&pkcs_pubkey.as_slice()).unwrap();

    let mut p_data = sgx_report_data_t::default();
    p_data.d[0..32].copy_from_slice(&pubkey_hash);

    enclave_pubkey[0..SGX_RSA3072_KEY_SIZE].copy_from_slice(&report_keypair.n);
    enclave_pubkey[SGX_RSA3072_KEY_SIZE..].copy_from_slice(&report_keypair.e);

    match rsgx_create_report(p_qe3_target, &p_data) {
        Ok(report) => {
            // TODO: Investigate why this is unsafe here but not in PoC
            // SAFETY: As long as the raw pointer from the caller assigning to the
            // dereferenced value should be safe.
            unsafe {
                *p_report = report;
            }
            sgx_status_t::SGX_SUCCESS
        }
        Err(x) => {
            println!("rsgx_create_report failed! {:?}", x);
            x
        }
    }
}

fn get_file_key() -> sgx_key_128bit_t {
    // Retrieve file key from some kind of persistent state. This is crucial to allow persistent file keypairs
    create_file_key()
}

fn get_or_create_report_keypair() -> Result<Rsa3072KeyPair, sgx_status_t> {
    let file_key = get_file_key();

    let path = Path::new(KEYFILE);
    let key: Rsa3072KeyPair = if path.exists() {
        match SgxFile::open_ex(path, &file_key) {
            // TODO bad error handling, clean up
            Ok(f) => bincode::deserialize_from(f).unwrap(),
            Err(x) => panic!(x),
        }
    } else {
        match SgxFile::create_ex(path, &file_key) {
            Ok(f) => {
                // TODO bad error handling here, clean up
                let keypair = Rsa3072KeyPair::new().unwrap();
                bincode::serialize_into(f, &keypair).unwrap();
                keypair
            }
            Err(x) => panic!(x),
        }
    };
    Ok(key)
}

// From my testing, this is deterministic if the environment and binary is the same
// TODO: Test in Azure VM using HW mode
fn create_file_key() -> sgx_key_128bit_t {
    let report = rsgx_self_report();
    let attribute_mask = sgx_attributes_t {
        flags: TSEAL_DEFAULT_FLAGSMASK,
        xfrm: 0,
    };
    let key_id = sgx_key_id_t::default();

    let key_request = sgx_key_request_t {
        key_name: SGX_KEYSELECT_SEAL,
        key_policy: SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER,
        isv_svn: report.body.isv_svn,
        reserved1: 0_u16,
        cpu_svn: report.body.cpu_svn,
        attribute_mask,
        key_id,
        misc_mask: TSEAL_DEFAULT_MISCMASK,
        config_svn: report.body.config_svn,
        reserved2: [0_u8; SGX_KEY_REQUEST_RESERVED2_BYTES],
    };

    // This should never fail since the input values are constant
    rsgx_get_key(&key_request).expect("Failed to create a new file key")
}

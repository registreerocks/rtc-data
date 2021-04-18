#![feature(unsafe_block_in_unsafe_fn)]
#![deny(unsafe_op_in_unsafe_fn)]
#![crate_name = "rtc_data_enclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(min_const_generics)]
#![deny(clippy::mem_forget)]
// TODO: Clean up existing cases causing a flood of warnings for this check, and re-enable
// #![warn(missing_docs)]

use sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
use bincode;
use sgx_crypto_helper;
use sgx_tcrypto;
use sgx_tse;
use thiserror;

use zeroize;

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

use rsa3072::{PublicKeyEncoding, Rsa3072KeyPair, RSA3072_PKCS8_DER_SIZE};
use sgx_tse::{rsgx_get_key, rsgx_self_report};

use sgx_crypto_helper::RsaKeyPair;
use sgx_tcrypto::rsgx_sha256_slice;
use thiserror::Error;
use zeroize::Zeroize;

pub const KEYFILE: &str = "prov_key.bin";

pub const PUBKEY_SIZE: usize = SGX_RSA3072_KEY_SIZE + SGX_RSA3072_PUB_EXP_SIZE;

fn create_report_impl(
    qe_target_info: &sgx_target_info_t,
) -> Result<([u8; RSA3072_PKCS8_DER_SIZE], sgx_report_t), CreateReportResult> {
    // TODO: When returning with an error, clear the mutable buffers
    let report_keypair = match get_or_create_report_keypair() {
        Ok(key) => key,
        Err(x) => match x {
            GetKeypairError::IO(_) => return Err(CreateReportResult::FailedToGetPublicKey),
            GetKeypairError::Serialize(_) => return Err(CreateReportResult::FailedToGetPublicKey),
            GetKeypairError::Sgx(err) => return Err(err.into()),
        },
    };

    let pkcs8_pubkey = match report_keypair.to_pkcs8() {
        Ok(key) => key,
        Err(_) => return Err(CreateReportResult::FailedEncodePublicKey),
    };

    let pubkey_hash = match rsgx_sha256_slice(&pkcs8_pubkey) {
        Ok(hash) => hash,
        Err(err) => return Err(err.into()),
    };

    let mut p_data = sgx_report_data_t::default();
    p_data.d[0..32].copy_from_slice(&pubkey_hash);

    match rsgx_create_report(qe_target_info, &p_data) {
        Ok(report) => Ok((pkcs8_pubkey, report)),
        Err(err) => Err(CreateReportResult::Sgx(err)),
    }
}

/// Creates and returns a report for the enclave alongside a public key used to encrypt
/// data sent to the enclave.
///
/// # Safety
/// The pointers from SGX is expected to be valid, not-null, correctly aligned and of the
/// correct type. Sanity checks are done for null-pointers, but none of the other conditions.
#[no_mangle]
pub unsafe extern "C" fn enclave_create_report(
    p_qe3_target: *const sgx_target_info_t,
    enclave_pubkey: *mut [u8; RSA3072_PKCS8_DER_SIZE],
    p_report: *mut sgx_report_t,
) -> CreateReportResult {
    if p_qe3_target.is_null() || enclave_pubkey.is_null() || p_report.is_null() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER.into();
    }
    let qe_target_info = unsafe { &*p_qe3_target };
    let (key, report) = match create_report_impl(qe_target_info) {
        Ok(res) => res,
        Err(x) => {
            unsafe {
                // TODO: Use secrecy crate instead? This will allow for more
                // guarantees and might make the code easier to audit
                (*enclave_pubkey).zeroize();
            }
            return x.into();
        }
    };

    unsafe {
        *p_report = report;
        (*enclave_pubkey).copy_from_slice(&key);
    }

    CreateReportResult::Success
}

/// Return result when creating a report
///
/// This enum will be represented as a tagged union C type
/// see: https://github.com/rust-lang/rfcs/blob/master/text/2195-really-tagged-unions.md
/// Also see EDL file
///
/// The only reason the C type is defined in the EDL is for the correct size of the type to be copied over.
/// We might be able to work around this if we just use an opaque int type with the same size as `size_of::<CreateReportResult>`.
///
/// Maintainability of types like this pose a problem, since the edl will have to be updated whenever the type change. We might be
/// able to work around this if we use cbindgen to create a header file that is imported by the .edl file
/// TODO: Review above, add cbindgen to build steps?
#[repr(u32, C)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug)]
pub enum CreateReportResult {
    Success,
    Sgx(sgx_status_t),
    FailedToGetPublicKey,
    FailedEncodePublicKey,
}

impl From<GetKeypairError> for CreateReportResult {
    fn from(err: GetKeypairError) -> Self {
        match err {
            GetKeypairError::IO(_) | GetKeypairError::Serialize(_) => {
                return CreateReportResult::FailedToGetPublicKey
            }
            GetKeypairError::Sgx(err) => return err.into(),
        };
    }
}

impl From<sgx_status_t> for CreateReportResult {
    fn from(err: sgx_status_t) -> Self {
        CreateReportResult::Sgx(err)
    }
}

fn get_file_key() -> sgx_key_128bit_t {
    // Retrieve file key from some kind of persistent state. This is crucial to allow persistent file keypairs
    create_file_key()
}

fn get_or_create_report_keypair() -> Result<Rsa3072KeyPair, GetKeypairError> {
    let file_key = get_file_key();

    let path = Path::new(KEYFILE);
    let key: Rsa3072KeyPair = if path.exists() {
        match SgxFile::open_ex(path, &file_key) {
            // TODO bad error handling, clean up
            Ok(f) => bincode::deserialize_from(f)?,
            Err(x) => return Err(x.into()),
        }
    } else {
        match SgxFile::create_ex(path, &file_key) {
            Ok(f) => {
                // TODO bad error handling here, clean up
                let keypair = Rsa3072KeyPair::new()?;
                bincode::serialize_into(f, &keypair)?;
                keypair
            }
            Err(x) => return Err(x.into()),
        }
    };
    Ok(key)
}

#[derive(Error, Debug)]
enum GetKeypairError {
    #[error("Failed to create or open key file: {}", .0)]
    IO(#[from] io::Error),
    #[error("Failed to serialize or deserialize key file: {}", .0)]
    Serialize(#[from] bincode::Error),
    #[error("Failed to generate keypair: {}", .0.as_str())]
    Sgx(sgx_status_t),
}

impl From<sgx_status_t> for GetKeypairError {
    fn from(err: sgx_status_t) -> Self {
        GetKeypairError::Sgx(err)
    }
}

// From my testing, this is deterministic if the environment and binary is the same
// TODO: Test in Azure VM using HW mode
// TODO: Find documentation that confirms that the effect is normative
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

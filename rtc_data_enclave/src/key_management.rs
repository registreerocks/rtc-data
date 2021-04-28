use crate::rsa3072::{PublicKeyEncoding, Rsa3072KeyPair, RSA3072_PKCS8_DER_SIZE};
use sgx_tse::{rsgx_get_key, rsgx_self_report};
use sgx_types::*;
use std::io;
use std::path::Path;
use std::prelude::v1::*;
use std::sgxfs::SgxFile;
use std::untrusted::path::PathEx;
use thiserror::Error;

use sgx_crypto_helper::RsaKeyPair;

pub const KEYFILE: &str = "prov_key.bin";

pub fn get_or_create_report_keypair() -> Result<Rsa3072KeyPair, GetKeypairError> {
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
pub enum GetKeypairError {
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

fn get_file_key() -> sgx_key_128bit_t {
    // Retrieve file key from some kind of persistent state. This is crucial to allow persistent file keypairs
    create_file_key()
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

use rand::{prelude::*, Error};
use secrecy::{ExposeSecret, Secret};
use sgx_tse::{rsgx_get_key, rsgx_self_report};
use sgx_types::*;
use sodalite;
use std::io;
use std::path::Path;
use std::prelude::v1::*;
use std::sgxfs::SgxFile;
use std::untrusted::path::PathEx;
use thiserror::Error;
use zeroize::Zeroize;

pub fn decrypt_upload_data(
    ciphertext: &[u8],
    uploader_pk: &sodalite::BoxPublicKey,
) -> Result<Box<[u8]>, ()> {
    let mut rng = rand::thread_rng();
    let mut nonce = [0_u8; 24];
    rng.try_fill(&mut nonce).map_err(|_| ())?;

    let (_, our_sk) = get_upload_keypair();

    let mut message = vec![0_u8; ciphertext.len()];

    match sodalite::box_open(
        &mut message,
        ciphertext,
        &nonce,
        uploader_pk,
        our_sk.expose_secret(),
    ) {
        Ok(_) => Ok(message.into_boxed_slice()),
        // TODO: return compound error type
        Err(_) => Err(()),
    }
}

pub fn get_upload_pubkey() -> sodalite::BoxPublicKey {
    get_upload_keypair().0
}

fn get_upload_keypair() -> (sodalite::BoxPublicKey, Secret<sodalite::BoxSecretKey>) {
    let file_key = get_file_key();
    let mut pub_key = [0_u8; 32];
    let mut priv_key = [0_u8; 32];
    let mut seed = [0_u8; 32];
    let (left, right) = seed.split_at_mut(16);

    // This should never panic since the file_key is size 16
    left.copy_from_slice(file_key.expose_secret());
    right.copy_from_slice(file_key.expose_secret());

    // TODO: Create a PR to make the requirement for seed broader if possible
    sodalite::box_keypair_seed(&mut pub_key, &mut priv_key, &seed);

    // Zero copies from exposed secret
    seed.zeroize();

    (pub_key, Secret::new(priv_key))
}

fn get_file_key() -> Secret<sgx_key_128bit_t> {
    // Retrieve file key from some kind of persistent state. This is crucial to allow persistent file keypairs
    create_file_key()
}

// From my testing, this is deterministic if the environment and binary is the same
// TODO: Test in Azure VM using HW mode
// TODO: Find documentation that confirms that the effect is normative
fn create_file_key() -> Secret<sgx_key_128bit_t> {
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
    // TODO: remove unwrap and deal with error?
    Secret::new(rsgx_get_key(&key_request).unwrap())
}

use crate::key_management::get_or_create_report_keypair;
use rand::{prelude::*, Error};
use sgx_tseal::SgxSealedData;
use sgx_types::*;
use std::{prelude::v1::*, sync::SgxMutex};
use uuid::Uuid;

pub struct UploadPayload {
    metadata: Metadata,
    blob: Box<[u8]>,
}

pub struct Metadata {}

pub struct SealedResult {
    /// Uploaded data sealed for this enclave
    sealed_data: Box<[u8]>,
    /// Payload for client encrypted with the client's ephemeral key
    client_payload: Box<[u8]>,
}

pub enum DataError {
    Validation,
    Sealing(sgx_status_t),
    Unknown,
}
impl From<()> for DataError {
    fn from(err: ()) -> Self {
        DataError::Unknown
    }
}

pub struct UploadedData {
    ephemeral_key: Box<[u8]>,
    data: Box<[u8]>,
}

pub fn validate_and_seal(payload: UploadPayload) -> Result<SealedResult, DataError> {
    let UploadPayload { metadata, blob } = payload;
    let plaintext = decrypt_data(blob)?;

    match validate_data(&plaintext) {
        None => {}
        Some(_) => return Err(DataError::Validation),
    };

    let (client_payload, data_uuid) = match generate_client_payload(&plaintext[..32]) {
        Some(res) => res,
        None => return Err(DataError::Validation),
    };
    let sealed_data = seal_data(&plaintext).map_err(|err| DataError::Sealing(err))?;

    return Ok(SealedResult {
        client_payload,
        sealed_data,
    });
}

// TODO: Use feature flags to toggle use of different crypto libs
fn generate_client_payload_ring(key_bytes: &[u8]) -> Option<(Box<[u8]>, Uuid)> {
    use ring::aead;

    let key = match aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key_bytes) {
        Ok(k) => aead::LessSafeKey::new(k),
        Err(_) => return None,
    };
    let mut rng = rand::thread_rng();
    // TODO: use static SecureRandom from ring instead
    match generate_pass_and_uuid(move |x| rng.try_fill(x)) {
        Ok((mut pass, uuid)) => {
            let mut in_out = [
                &mut uuid.as_bytes().clone() as &mut [u8],
                &mut pass as &mut [u8],
            ]
            .concat();

            let mut nonce = [0u8; 12];

            if rng.try_fill(&mut nonce).is_err() {
                return None;
            }

            key.seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                &mut in_out,
            );
            Some((in_out.into_boxed_slice(), uuid))
        }
        Err(_) => None,
    }
}

fn generate_client_payload(key_bytes: &[u8]) -> Option<(Box<[u8]>, Uuid)> {
    use sodiumoxide::crypto::box_;
    use sodiumoxide::crypto::secretbox;

    let key = match secretbox::Key::from_slice(key_bytes) {
        Some(key) => key,
        None => return None,
    };

    let mut rng = rand::thread_rng();
    match generate_pass_and_uuid(move |x| rng.try_fill(x)) {
        Ok((mut pass, uuid)) => {
            let nonce = secretbox::gen_nonce();
            let ciphertext = secretbox::seal(
                &[uuid.as_bytes() as &[u8], &pass as &[u8]].concat(),
                &nonce,
                &key,
            );
            Some((ciphertext.into_boxed_slice(), uuid))
        }
        Err(_) => None,
    }
}

fn generate_pass_and_uuid<TErr, F>(mut rand_fn: F) -> Result<([u8; 24], Uuid), TErr>
where
    F: FnMut(&mut [u8; 24]) -> Result<(), TErr>,
{
    let mut pass = [0u8; 24];
    rand_fn(&mut pass)?;

    Ok((pass, Uuid::new_v4()))
}

fn seal_data(data: &[u8]) -> Result<Box<[u8]>, sgx_status_t> {
    let attribute_mask = sgx_attributes_t {
        flags: TSEAL_DEFAULT_FLAGSMASK,
        xfrm: 0,
    };
    let additional_text = [0_u8; 0];
    let sealed_data = SgxSealedData::<[u8]>::seal_data_ex(
        SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER,
        attribute_mask,
        TSEAL_DEFAULT_MISCMASK,
        &additional_text,
        data,
    )?;

    let raw_size: u32 = SgxSealedData::<[u8]>::calc_raw_sealed_data_size(
        sealed_data.get_add_mac_txt_len(),
        sealed_data.get_encrypt_txt_len(),
    );

    let mut sealed_data_ptr = vec![0_u8; raw_size as usize].into_boxed_slice();

    // Safety: The buffer of `sealed_data` will be of the correct size, since we calculated
    // the size using `sealed_data`, and used it to allocate the buffer.
    let sealed_data_raw = unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_data_ptr.as_mut_ptr() as *mut _, raw_size)
    };

    match sealed_data_raw {
        Some(_) => Ok(sealed_data_ptr),
        None => Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER),
    }
}

fn validate_data(data: &Box<[u8]>) -> Option<()> {
    None
}

fn decrypt_data(cipertext: Box<[u8]>) -> Result<Box<[u8]>, ()> {
    let keypair = get_or_create_report_keypair();

    todo!();
}

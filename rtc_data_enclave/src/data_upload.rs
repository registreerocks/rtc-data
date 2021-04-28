use crate::key_management::get_or_create_report_keypair;
use rand::prelude::*;
use sgx_tseal::SgxSealedData;
use sgx_types::*;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;
use std::prelude::v1::*;
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

    let ephemeral_key = match secretbox::Key::from_slice(&plaintext[..32]) {
        Some(key) => key,
        None => return Err(DataError::Validation),
    };

    let (client_payload, data_uuid) = generate_client_payload(ephemeral_key);
    let sealed_data = seal_data(&plaintext).map_err(|err| DataError::Sealing(err))?;

    return Ok(SealedResult {
        client_payload,
        sealed_data,
    });
}

fn generate_client_payload(key: secretbox::Key) -> (Box<[u8]>, Uuid) {
    let mut rng = rand::thread_rng();
    let uuid = Uuid::new_v4();
    let mut pass = [0u8; 24];
    match rng.try_fill(&mut pass) {
        Ok(_) => {
            let nonce = secretbox::gen_nonce();
            let ciphertext = secretbox::seal(
                &[uuid.as_bytes() as &[u8], &pass as &[u8]].concat(),
                &nonce,
                &key,
            );
            (ciphertext.into_boxed_slice(), uuid)
        }
        Err(err) => todo!(),
    }
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

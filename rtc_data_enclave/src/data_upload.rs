use crate::crypto::Error as CryptoError;
use crate::crypto::SodaBoxCrypto as Crypto;
use crate::crypto::{EncryptedMessage, RtcCrypto};
use rand::prelude::*;
use rtc_types::UploadMetadata as Metadata;
use secrecy::{ExposeSecret, Secret};
use sgx_tseal::SgxSealedData;
use sgx_types::*;
use std::prelude::v1::*;
use thiserror::Error;
use uuid::Uuid;

pub struct UploadPayload {
    pub metadata: Metadata,
    pub blob: Box<[u8]>,
}

pub struct SealedResult {
    /// Uploaded data sealed for this enclave
    pub sealed_data: Box<[u8]>,
    /// Payload for client encrypted with the client's ephemeral key
    pub client_payload: EncryptedMessage,

    pub uuid: Uuid,
}

#[derive(Debug, Error)]
pub enum DataError {
    #[error("Data validation failed")]
    Validation,
    #[error("Data sealing failed: {}", .0)]
    Sealing(sgx_status_t),
    #[error("Crypto failed: {}", .0)]
    Crypto(#[from] CryptoError),
    #[error("Unknown data upload error")]
    Unknown,
}

impl From<()> for DataError {
    fn from(_err: ()) -> Self {
        DataError::Unknown
    }
}

pub struct UploadedData {
    ephemeral_key: Box<[u8]>,
    data: Box<[u8]>,
}

pub fn validate_and_seal(payload: UploadPayload) -> Result<SealedResult, DataError> {
    let mut crypto = Crypto::new();
    let UploadPayload { metadata, blob } = payload;
    let plaintext = crypto.decrypt_message(&blob, &metadata.uploader_pub_key, &metadata.nonce)?;
    println!("{:?}", plaintext.expose_secret());

    match validate_data(plaintext.expose_secret()) {
        None => {}
        Some(_) => return Err(DataError::Validation),
    };

    let (client_payload, data_uuid) =
        match generate_client_payload(&metadata.uploader_pub_key, &mut crypto) {
            Ok(res) => res,
            Err(err) => return Err(DataError::Crypto(err)),
        };
    let sealed_data =
        seal_data(plaintext.expose_secret()).map_err(|err| DataError::Sealing(err))?;

    return Ok(SealedResult {
        client_payload,
        sealed_data,
        uuid: data_uuid,
    });
}

fn generate_client_payload(
    their_pk: &[u8; 32],
    crypto: &mut Crypto,
) -> Result<(EncryptedMessage, Uuid), CryptoError> {
    let mut rng = rand::thread_rng();

    let (pass, uuid) = match generate_pass_and_uuid(move |x| rng.try_fill(x)) {
        Ok(res) => res,
        Err(err) => return Err(CryptoError::Rand(err)),
    };

    let message = Secret::new(
        [pass.to_vec(), uuid.as_bytes().to_vec()]
            .concat()
            .into_boxed_slice(),
    );

    Ok((crypto.encrypt_message(message, their_pk)?, uuid))
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
    // TODO: Save the UUID as additional text
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

fn validate_data(_data: &Box<[u8]>) -> Option<()> {
    None
}

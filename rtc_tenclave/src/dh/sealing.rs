//! Helpers to seal and unseal enclave messages.

use core::mem::size_of;

use rkyv::ser::serializers::{BufferSerializer, BufferSerializerError};
use rkyv::{Aligned, Archive, Deserialize, Infallible, Serialize};
use rtc_types::byte_formats::rkyv_format;
use rtc_types::enclave_messages::EncryptedEnclaveMessage;
use sgx_types::sgx_status_t;

use crate::dh::ProtectedChannel;

/// Seal with associated data.
pub fn rkyv_seal_associated<T, A>(
    channel: &mut ProtectedChannel,
    unsealed: &T,
    associated: &A,
) -> Result<
    EncryptedEnclaveMessage<{ size_of::<T::Archived>() }, { size_of::<A::Archived>() }>,
    SealingError,
>
where
    T: Serialize<BufferSerializer<Aligned<[u8; size_of::<T::Archived>()]>>>,
    A: Serialize<BufferSerializer<Aligned<[u8; size_of::<A::Archived>()]>>>,
{
    let plaintext = rkyv_format::write_array(unsealed)?;
    let aad = rkyv_format::write_array(associated)?;
    let sealed = channel.encrypt_message(plaintext, aad)?;
    Ok(sealed)
}

/// Unseal with associated data.
///
/// # Safety
///
/// Callers must ensure that the sealed message contains valid serialized data,
/// to avoid undefined behaviour during deserialization.
///
/// See [`rkyv_format::read_array`] and [`rkyv_format::view_array`].
pub unsafe fn rkyv_unseal_associated<T, A>(
    channel: &ProtectedChannel,
    sealed: EncryptedEnclaveMessage<{ size_of::<T::Archived>() }, { size_of::<A::Archived>() }>,
) -> Result<(T, A), SealingError>
where
    T: Archive,
    T::Archived: Deserialize<T, Infallible>,
    A: Archive,
    A::Archived: Deserialize<A, Infallible>,
{
    let (plaintext, aad) = &channel.decrypt_message(sealed)?;
    let unsealed = unsafe { rkyv_format::read_array(plaintext) };
    let associated = unsafe { rkyv_format::read_array(aad) };
    Ok((unsealed, associated))
}

/// Seal without associated data.
pub fn rkyv_seal<T>(
    channel: &mut ProtectedChannel,
    unsealed: &T,
) -> Result<EncryptedEnclaveMessage<{ size_of::<T::Archived>() }, 0>, SealingError>
where
    T: Serialize<BufferSerializer<Aligned<[u8; size_of::<T::Archived>()]>>>,
{
    let plaintext = rkyv_format::write_array(unsealed)?;
    let sealed = channel.encrypt_message(plaintext, [])?;
    Ok(sealed)
}

/// Unseal without associated data.
///
/// # Safety
///
/// Callers must ensure that the sealed message contains valid serialized data,
/// to avoid undefined behaviour during deserialization.
///
/// See [`rkyv_format::read_array`] and [`rkyv_format::view_array`].
pub unsafe fn rkyv_unseal<T>(
    channel: &ProtectedChannel,
    sealed: EncryptedEnclaveMessage<{ size_of::<T::Archived>() }, 0>,
) -> Result<T, SealingError>
where
    T: Archive,
    T::Archived: Deserialize<T, Infallible>,
{
    let (plaintext, []) = &channel.decrypt_message(sealed)?;
    let unsealed = unsafe { rkyv_format::read_array(plaintext) };
    Ok(unsealed)
}

/// Peek at a sealed message's associated data, without authenticating it.
///
/// # Safety
///
/// Callers must ensure that the sealed message contains valid serialized data,
/// to avoid undefined behaviour during deserialization.
///
/// See: [`rkyv_format::view_array`]
pub unsafe fn rkyv_peek_associated<T, A>(
    sealed: &EncryptedEnclaveMessage<{ size_of::<T::Archived>() }, { size_of::<A::Archived>() }>,
) -> &A::Archived
where
    T: Archive,
    T::Archived: Deserialize<T, Infallible>,
    A: Archive,
    A::Archived: Deserialize<A, Infallible>,
{
    unsafe { rkyv_format::view_array::<A>(&sealed.aad) }
}

#[derive(Debug)]
pub enum SealingError {
    Rkyv(BufferSerializerError),
    Sgx(sgx_status_t),
}

impl From<BufferSerializerError> for SealingError {
    fn from(error: BufferSerializerError) -> Self {
        SealingError::Rkyv(error)
    }
}

impl From<sgx_status_t> for SealingError {
    fn from(status: sgx_status_t) -> Self {
        SealingError::Sgx(status)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rtc_types::enclave_messages::RecommendedAesGcmIv;
    use sgx_types::sgx_aes_gcm_128bit_tag_t;

    use super::test_helpers::*;
    use super::*;

    /// Roundtrip [`rkyv_seal_associated`] / [`rkyv_unseal_associated`]
    #[test]
    fn test_seal_unseal_associated_roundtrip() {
        let test = |key: [u8; 16], message: &DummyMessage, associated: &DummyAssociated| {
            let channel = &mut make_channel(key);

            let sealed = rkyv_seal_associated(channel, message, associated).unwrap();
            let (message2, associated2) =
                &unsafe { rkyv_unseal_associated(channel, sealed) }.unwrap();
            assert_eq!(message, message2);
            assert_eq!(associated, associated2);
        };
        proptest!(|(key: [u8; 16], message: DummyMessage, associated: DummyAssociated)| test(key, &message, &associated));
    }

    /// Roundtrip [`rkyv_seal`] / [`rkyv_unseal`]
    #[test]
    fn test_seal_unseal_roundtrip() {
        let test = |key: [u8; 16], message: &DummyMessage| {
            let channel = &mut make_channel(key);

            let sealed = rkyv_seal(channel, message).unwrap();
            let message2 = &unsafe { rkyv_unseal(channel, sealed) }.unwrap();
            assert_eq!(message, message2);
        };
        proptest!(|(key: [u8; 16], message: DummyMessage)| test(key, &message));
    }

    /// [`rkyv_seal_associated`] fails with zero-length message & associated data
    #[test]
    fn test_seal_associated_zero_length() {
        let test = |key: [u8; 16]| {
            let channel = &mut make_channel(key);
            let message = &DummyEmpty;
            let associated = &DummyEmpty;

            let err = rkyv_seal_associated::<DummyEmpty, DummyEmpty>(channel, message, associated)
                .unwrap_err();
            assert_eq!(format!("{:?}", err), "Sgx(SGX_ERROR_INVALID_PARAMETER)");
        };
        proptest!(|(key: [u8; 16])| test(key));
    }

    /// [`rkyv_seal`] fails with zero-length message
    #[test]
    fn test_seal_zero_length() {
        let test = |key: [u8; 16]| {
            let channel = &mut make_channel(key);
            let message = &DummyEmpty;

            let err = rkyv_seal::<DummyEmpty>(channel, message).unwrap_err();
            assert_eq!(format!("{:?}", err), "Sgx(SGX_ERROR_INVALID_PARAMETER)");
        };
        proptest!(|(key: [u8; 16])| test(key));
    }

    /// [`rkyv_unseal_associated`] fails with wrong channel
    #[test]
    fn test_unseal_associated_wrong_channel() {
        let test = |key1: [u8; 16],
                    key2: [u8; 16],
                    message: &DummyMessage,
                    associated: &DummyAssociated| {
            let channel1 = &mut make_channel(key1);
            let channel2 = &mut make_channel(key2);

            let sealed = rkyv_seal_associated(channel1, message, associated).unwrap();
            let err = unsafe {
                rkyv_unseal_associated::<DummyMessage, DummyAssociated>(channel2, sealed)
            }
            .unwrap_err();
            assert_eq!(format!("{:?}", err), "Sgx(SGX_ERROR_MAC_MISMATCH)");
        };
        proptest!(|(key1: [u8; 16], key2: [u8; 16], message: DummyMessage, associated: DummyAssociated)| {
            prop_assume!(key1 != key2);
            test(key1, key2, &message, &associated);
        });
    }

    /// [`rkyv_unseal`] fails with wrong channel
    #[test]
    fn test_unseal_wrong_channel() {
        let test = |key1: [u8; 16], key2: [u8; 16], message: &DummyMessage| {
            let channel1 = &mut make_channel(key1);
            let channel2 = &mut make_channel(key2);

            let sealed = rkyv_seal(channel1, message).unwrap();
            let err = unsafe { rkyv_unseal::<DummyMessage>(channel2, sealed) }.unwrap_err();
            assert_eq!(format!("{:?}", err), "Sgx(SGX_ERROR_MAC_MISMATCH)");
        };
        proptest!(|(key1: [u8; 16], key2: [u8; 16], message: DummyMessage)| {
            prop_assume!(key1 != key2);
            test(key1, key2, &message);
        });
    }

    /// [`rkyv_unseal_associated`] fails with a tampered MAC tag
    #[test]
    fn test_unseal_associated_tampered_tag() {
        let test = |key: [u8; 16],
                    tampered_tag: sgx_aes_gcm_128bit_tag_t,
                    message: &DummyMessage,
                    associated: &DummyAssociated|
         -> Result<_, _> {
            let channel = &mut make_channel(key);

            let mut sealed = rkyv_seal_associated(channel, message, associated).unwrap();
            prop_assume!(sealed.tag != tampered_tag);
            sealed.tag = tampered_tag;

            let err =
                unsafe { rkyv_unseal_associated::<DummyMessage, DummyAssociated>(channel, sealed) }
                    .unwrap_err();
            assert_eq!(format!("{:?}", err), "Sgx(SGX_ERROR_MAC_MISMATCH)");
            Ok(())
        };
        proptest!(|(key: [u8; 16], tampered_tag: sgx_aes_gcm_128bit_tag_t, message: DummyMessage, associated: DummyAssociated)| {
            test(key, tampered_tag, &message, &associated)?;
        });
    }

    /// [`rkyv_unseal`] fails with a tampered MAC tag
    #[test]
    fn test_unseal_tampered_tag() {
        let test = |key: [u8; 16],
                    tampered_tag: sgx_aes_gcm_128bit_tag_t,
                    message: &DummyMessage|
         -> Result<_, _> {
            let channel = &mut make_channel(key);

            let mut sealed = rkyv_seal(channel, message).unwrap();
            prop_assume!(sealed.tag != tampered_tag);
            sealed.tag = tampered_tag;

            let err = unsafe { rkyv_unseal::<DummyMessage>(channel, sealed) }.unwrap_err();
            assert_eq!(format!("{:?}", err), "Sgx(SGX_ERROR_MAC_MISMATCH)");
            Ok(())
        };
        proptest!(|(key: [u8; 16], tampered_tag: sgx_aes_gcm_128bit_tag_t, message: DummyMessage)| {
            test(key, tampered_tag, &message)?;
        });
    }

    /// [`rkyv_unseal_associated`] fails with a tampered nonce
    #[test]
    fn test_unseal_associated_tampered_nonce() {
        let test = |key: [u8; 16],
                    tampered_nonce: RecommendedAesGcmIv,
                    message: &DummyMessage,
                    associated: &DummyAssociated|
         -> Result<_, _> {
            let channel = &mut make_channel(key);

            let mut sealed = rkyv_seal_associated(channel, message, associated).unwrap();
            prop_assume!(sealed.nonce != tampered_nonce);
            sealed.nonce = tampered_nonce;

            let err =
                unsafe { rkyv_unseal_associated::<DummyMessage, DummyAssociated>(channel, sealed) }
                    .unwrap_err();
            assert_eq!(format!("{:?}", err), "Sgx(SGX_ERROR_MAC_MISMATCH)");
            Ok(())
        };
        proptest!(|(key: [u8; 16], tampered_nonce: RecommendedAesGcmIv, message: DummyMessage, associated: DummyAssociated)| {
            test(key, tampered_nonce, &message, &associated)?;
        });
    }

    /// [`rkyv_unseal`] fails with a tampered nonce
    #[test]
    fn test_unseal_tampered_nonce() {
        let test = |key: [u8; 16],
                    tampered_nonce: RecommendedAesGcmIv,
                    message: &DummyMessage|
         -> Result<_, _> {
            let channel = &mut make_channel(key);

            let mut sealed = rkyv_seal(channel, message).unwrap();
            prop_assume!(sealed.nonce != tampered_nonce);
            sealed.nonce = tampered_nonce;

            let err = unsafe { rkyv_unseal::<DummyMessage>(channel, sealed) }.unwrap_err();
            assert_eq!(format!("{:?}", err), "Sgx(SGX_ERROR_MAC_MISMATCH)");
            Ok(())
        };
        proptest!(|(key: [u8; 16], tampered_nonce: RecommendedAesGcmIv, message: DummyMessage)| {
            test(key, tampered_nonce, &message)?;
        });
    }

    /// [`rkyv_unseal_associated`] fails with tampered associated data
    #[test]
    fn test_unseal_associated_tampered_aad() {
        const AAD_SIZE: usize = size_of::<ArchivedDummyAssociated>();

        let test = |key: [u8; 16],
                    tampered_aad: [u8; AAD_SIZE],
                    message: &DummyMessage,
                    associated: &DummyAssociated| {
            let channel = &mut make_channel(key);

            let mut sealed = rkyv_seal_associated(channel, message, associated).unwrap();
            sealed.aad = tampered_aad;

            let err =
                unsafe { rkyv_unseal_associated::<DummyMessage, DummyAssociated>(channel, sealed) }
                    .unwrap_err();
            assert_eq!(format!("{:?}", err), "Sgx(SGX_ERROR_MAC_MISMATCH)");
        };
        proptest!(|(key: [u8; 16], tampered_aad: [u8; AAD_SIZE], message: DummyMessage, associated: DummyAssociated)| {
            let expected_aad = rkyv_format::write_array(&associated).unwrap();
            prop_assume!(expected_aad != tampered_aad);
            test(key, tampered_aad, &message, &associated);
        });
    }
}

/// Supporting structs and code for the tests.
#[cfg(test)]
pub(crate) mod test_helpers {
    use proptest_derive::Arbitrary;
    use rkyv::{Archive, Deserialize, Serialize};
    use sgx_types::sgx_align_key_128bit_t;

    use crate::dh::types::AlignedKey;
    use crate::dh::ProtectedChannel;

    #[derive(Clone, Debug, PartialEq)] // core
    #[derive(Archive, Deserialize, Serialize)] // rkyv
    #[derive(Arbitrary)] // proptest
    pub struct DummyMessage {
        code: u32,
        message: [u8; 16],
    }

    #[derive(Clone, Debug, PartialEq)] // core
    #[derive(Archive, Deserialize, Serialize)] // rkyv
    #[derive(Arbitrary)] // proptest
    pub struct DummyAssociated {
        flags: u8,
        data: [u8; 8],
    }

    #[derive(Clone, Debug, PartialEq)] // core
    #[derive(Archive, Deserialize, Serialize)] // rkyv
    pub struct DummyEmpty;

    /// Helper: Make a channel with the given key.
    pub fn make_channel(key: [u8; 16]) -> ProtectedChannel {
        let mut aligned_key = sgx_align_key_128bit_t::default();
        aligned_key.key = key;
        ProtectedChannel::init(AlignedKey::new(aligned_key))
    }
}

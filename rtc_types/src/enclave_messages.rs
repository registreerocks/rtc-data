use sgx_types::*;
use std::mem;

use rkyv::{Archive, Deserialize, Serialize};

// NIST AES-GCM recommended IV size
pub type RecommendedAesGcmIv = [u8; 12];

#[repr(C)]
pub struct EncryptedEnclaveMessage<const MESSAGE_SIZE: usize, const AAD_SIZE: usize> {
    pub tag: sgx_aes_gcm_128bit_tag_t,
    pub ciphertext: [u8; MESSAGE_SIZE],
    pub aad: [u8; AAD_SIZE],
    pub nonce: RecommendedAesGcmIv,
}

// TODO: Macro?
pub mod set_access_key {
    use super::*;

    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Clone)]
    pub struct Request {
        // XXX: Technically this only needs to be available inside of enclave contexts.
        //      It might make sense to conditionally export this as public.
        pub uuid: [u8; 16],       // TODO: Use UUID crate?
        pub access_key: [u8; 24], // [u8; ACCESS_KEY_BYTES]
    }

    pub const REQUEST_SIZE: usize = mem::size_of::<<Request as Archive>::Archived>();

    pub type EncryptedRequest = EncryptedEnclaveMessage<REQUEST_SIZE, 0>;

    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    pub struct Response {
        pub success: bool,
    }

    pub const RESPONSE_SIZE: usize = mem::size_of::<<Response as Archive>::Archived>();

    pub type EncryptedResponse = EncryptedEnclaveMessage<RESPONSE_SIZE, 0>;
}

/// FIXME: Non-generic version of [`set_access_key`], with conversions.
///
/// This is a workaround for cbindgen not supporting const generics in structs yet,
/// and should be removed once cbindgen implements that.
///
/// Tracking issue: <https://github.com/eqrion/cbindgen/issues/687>
pub mod ng_set_access_key {
    use sgx_types::sgx_aes_gcm_128bit_tag_t;

    use super::RecommendedAesGcmIv;

    use super::set_access_key;

    // These sizes should match the ones computed in `set_access_key`.
    // (The Rust compiler should report an error if these don't line up:
    // this can be used to update these if `set_access_key` changes.)
    pub const REQUEST_SIZE: usize = 40;
    pub const RESPONSE_SIZE: usize = 1;

    #[repr(C)]
    pub struct EncryptedRequest {
        pub tag: sgx_aes_gcm_128bit_tag_t,
        pub ciphertext: [u8; REQUEST_SIZE],
        pub aad: [u8; 0],
        pub nonce: RecommendedAesGcmIv,
    }

    impl From<set_access_key::EncryptedRequest> for EncryptedRequest {
        fn from(
            set_access_key::EncryptedRequest {
                tag,
                ciphertext,
                aad,
                nonce,
            }: set_access_key::EncryptedRequest,
        ) -> Self {
            return EncryptedRequest {
                tag,
                ciphertext,
                aad,
                nonce,
            };
        }
    }

    impl From<EncryptedRequest> for set_access_key::EncryptedRequest {
        fn from(
            EncryptedRequest {
                tag,
                ciphertext,
                aad,
                nonce,
            }: EncryptedRequest,
        ) -> Self {
            return set_access_key::EncryptedRequest {
                tag,
                ciphertext,
                aad,
                nonce,
            };
        }
    }

    #[derive(Default)]
    #[repr(C)]
    pub struct EncryptedResponse {
        pub tag: sgx_aes_gcm_128bit_tag_t,
        pub ciphertext: [u8; RESPONSE_SIZE],
        pub aad: [u8; 0],
        pub nonce: RecommendedAesGcmIv,
    }

    impl From<set_access_key::EncryptedResponse> for EncryptedResponse {
        fn from(
            set_access_key::EncryptedResponse {
                tag,
                ciphertext,
                aad,
                nonce,
            }: set_access_key::EncryptedResponse,
        ) -> Self {
            return EncryptedResponse {
                tag,
                ciphertext,
                aad,
                nonce,
            };
        }
    }

    impl From<EncryptedResponse> for set_access_key::EncryptedResponse {
        fn from(
            EncryptedResponse {
                tag,
                ciphertext,
                aad,
                nonce,
            }: EncryptedResponse,
        ) -> Self {
            return set_access_key::EncryptedResponse {
                tag,
                ciphertext,
                aad,
                nonce,
            };
        }
    }
}

#[cfg(test)]
mod test {
    use rkyv::{
        archived_root,
        ser::{serializers::BufferSerializer, Serializer},
        Aligned, Deserialize, Infallible,
    };

    use super::*;

    #[test]
    fn test_set_access_key_msg() {
        let request = set_access_key::Request {
            uuid: [5u8; 16],
            access_key: [2u8; 24],
        };

        let mut serializer = BufferSerializer::new(Aligned([0u8; set_access_key::REQUEST_SIZE]));
        serializer.serialize_value(&request.clone()).unwrap();
        let buf = serializer.into_inner();
        let archived = unsafe { archived_root::<set_access_key::Request>(buf.as_ref()) };
        let deserialized = archived.deserialize(&mut Infallible).unwrap();

        assert_eq!(
            request, deserialized,
            "Deserialized request should match initial request"
        );
    }
}

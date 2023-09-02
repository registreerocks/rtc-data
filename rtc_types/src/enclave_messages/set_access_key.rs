use core::mem;

use rkyv::{Archive, Deserialize, Serialize};

use crate::enclave_messages::errors::SealingError;
use crate::enclave_messages::{EncryptedEnclaveMessage, ARCHIVED_ENCLAVE_ID_SIZE};

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct Request {
    // XXX: Technically this only needs to be available inside of enclave contexts.
    //      It might make sense to conditionally export this as public.
    pub uuid: [u8; 16],       // TODO: Use UUID crate?
    pub access_key: [u8; 24], // [u8; ACCESS_KEY_BYTES]

    /// Size of the dataset in bytes, to be cached alongside the UUID.
    pub unsealed_size: u64,
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
pub struct Response {
    pub success: bool,
}

// Begin FFI types
// (Keep these FFI type comments in sync between set_access_key and ffi_set_access_key, for diffing!)

// FFI type: REQUEST_SIZE
pub const REQUEST_SIZE: usize = mem::size_of::<ArchivedRequest>();

// FFI type: EncryptedRequest
pub type EncryptedRequest = EncryptedEnclaveMessage<REQUEST_SIZE, ARCHIVED_ENCLAVE_ID_SIZE>;

// FFI type: RESPONSE_SIZE
pub const RESPONSE_SIZE: usize = mem::size_of::<ArchivedResponse>();

// FFI type: EncryptedResponse
pub type EncryptedResponse = EncryptedEnclaveMessage<RESPONSE_SIZE, 0>;

// FFI type: SetAccessKeyResult
pub type SetAccessKeyResult = Result<EncryptedResponse, SealingError>;

// End FFI types

#[cfg(test)]
mod test {
    use crate::byte_formats::rkyv_format;
    use crate::enclave_messages::*;

    #[test]
    fn test_set_access_key_msg() {
        let request = set_access_key::Request {
            uuid: [5u8; 16],
            access_key: [2u8; 24],
            unsealed_size: 42,
        };

        let buf = rkyv_format::write_array(&request).unwrap();
        let deserialized = unsafe { rkyv_format::read_array(&buf) };

        assert_eq!(
            request, deserialized,
            "Deserialized request should match initial request"
        );
    }
}

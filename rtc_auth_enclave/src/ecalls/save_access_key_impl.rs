//! Implementation for [`crate::ecalls::save_access_key`]

use std::println;

use rtc_types::enclave_messages::set_access_key;
use uuid::Uuid;

use crate::token_store;

pub(crate) fn save_access_key_impl(
    set_access_key::Request {
        uuid,
        access_key,
        unsealed_size,
    }: set_access_key::Request,
) -> set_access_key::Response {
    // TODO: Pass dataset size
    let success = token_store::save_access_key(Uuid::from_bytes(uuid), access_key, unsealed_size)
        .map_err(|err| {
            println!("token_store::save_access_key failed: {}", err);
            err
        })
        .is_ok();
    set_access_key::Response { success }
}

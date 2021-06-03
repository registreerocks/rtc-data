//! Implementation for [`crate::ecalls::save_access_key`]

use std::println;

use rtc_types::enclave_messages::set_access_key;

pub(crate) fn save_access_key_impl(request: set_access_key::Request) -> set_access_key::Response {
    println!("TODO: save_access_key_impl({:?})", request);
    set_access_key::Response { success: false }
}

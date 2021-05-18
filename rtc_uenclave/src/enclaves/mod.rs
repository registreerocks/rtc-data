#[cfg(feature = "auth_enclave")]
mod rtc_auth;
#[cfg(feature = "data_enclave")]
mod rtc_data;

#[cfg(feature = "auth_enclave")]
pub use self::rtc_auth::*;
#[cfg(feature = "data_enclave")]
pub use self::rtc_data::*;

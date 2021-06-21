//! Errors related to enclave messages and sealing.

use std::sync::PoisonError;

use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use thiserror::Error;

/// Failed to acquire session / protected channel.
///
/// See: `rtc_tenclave::dh::sessions::DhSessions`
#[derive(Debug, PartialEq)] // core
#[derive(Error)] // thiserror
pub enum AcquireSessionError {
    /// This should generally be treated as an unrecoverable error.
    #[error("Channel mutex poisoned")]
    ChannelMutexPoisoned, // see impl From<PoisonError>

    #[error("No active session for enclave ID {0}")]
    NoActiveSession(sgx_enclave_id_t),

    #[error("SGX error: {0:?}")]
    Sgx(sgx_status_t),
}

/// [`PoisonError`] contains a lock guard, which requires lifetime propagation,
/// but we're not interested in using or recovering from a poisoned lock,
/// so we discard the guard here.
impl<_Guard> From<PoisonError<_Guard>> for AcquireSessionError {
    fn from(_: PoisonError<_Guard>) -> Self {
        AcquireSessionError::ChannelMutexPoisoned
    }
}

impl From<sgx_status_t> for AcquireSessionError {
    fn from(err: sgx_status_t) -> Self {
        AcquireSessionError::Sgx(err)
    }
}

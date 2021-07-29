//! Errors related to enclave messages and sealing.

use std::sync::PoisonError;

use rkyv::ser::serializers::BufferSerializerError;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use thiserror::Error;

/// Failed to acquire session / protected channel.
///
/// See: `rtc_tenclave::dh::sessions::DhSessions`
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug)] // core
#[derive(Error)] // thiserror
#[repr(C)]
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

#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug)] // core
#[derive(Error)] // thiserror
#[repr(C)]
pub enum SealingError {
    #[error("Failed to acquire ProtectedChannel: {0}")]
    ChannelNotFound(#[from] AcquireSessionError),

    #[error("Failed to rkyv-serialize message (BufferSerializerError omitted)")]
    RkyvBufferSerializerError, // see impl From<BufferSerializerError>

    #[error("SGX error: {0:?}")]
    Sgx(sgx_status_t),
}

/// BufferSerializerError is not FFI-safe: ignore it, for now.
impl From<BufferSerializerError> for SealingError {
    fn from(_: BufferSerializerError) -> Self {
        SealingError::RkyvBufferSerializerError
    }
}

impl From<sgx_status_t> for SealingError {
    fn from(status: sgx_status_t) -> Self {
        SealingError::Sgx(status)
    }
}

//! OCALL definitions

mod save_access_key_impl;
mod save_sealed_blob_impl;

// Re-export the OCALL entry points we're interested in:

pub(crate) use save_access_key_impl::save_access_key;
pub(crate) use save_sealed_blob_impl::save_sealed_blob_u;

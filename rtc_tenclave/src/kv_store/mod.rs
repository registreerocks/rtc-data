//! Simple key-value store abstraction

use std::boxed::Box;
use std::error::Error;

type StoreResult<T> = Result<T, Box<dyn Error>>;

/// A key-value store.
///
/// These methods borrow key and value references,
/// to suit cloning / serialising implementations.
///
pub trait KvStore<V> {
    // TODO: Use associated type for V?

    /// Load the saved value for `key`, if any.
    ///
    /// Return [`None`] if `key` has no previous value.
    ///
    fn load(&self, key: &str) -> StoreResult<Option<V>>;

    /// Save a new value for `key`.
    ///
    /// This will replace any existing value.
    ///
    fn save(&mut self, key: &str, value: &V) -> StoreResult<()>;

    // TODO: add update()
}

mod fs;
mod in_memory;
mod inspect;

#[cfg(test)]
mod tests;

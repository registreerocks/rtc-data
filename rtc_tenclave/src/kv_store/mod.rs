//! Simple key-value store abstraction

mod fs;
mod in_memory;

/// A key-value store.
///
/// These methods borrow key and value references,
/// to suit cloning / serialising implementations.
///
pub trait KvStore<V> {
    type Error;

    /// Load the saved value for `key`, if any.
    ///
    /// Return [`None`] if `key` has no previous value.
    ///
    fn load(&self, key: &str) -> Result<Option<V>, Self::Error>;

    /// Save a new value for `key`.
    ///
    /// This will replace any existing value.
    ///
    fn save(&mut self, key: &str, value: &V) -> Result<(), Self::Error>;

    /// Delete the saved value for `key`.
    fn delete(&mut self, key: &str) -> Result<(), Self::Error>;

    /// Alter the value of `key`.
    ///
    /// This operation is a generalisation of [`Self::load`], [`Self::save`], and [`Self::delete`].
    ///
    fn alter<F>(&mut self, key: &str, alter_fn: F) -> Result<Option<V>, Self::Error>
    where
        F: FnOnce(Option<V>) -> Option<V>,
    {
        let loaded: Option<V> = self.load(key)?;
        let altered: Option<V> = alter_fn(loaded);
        match &altered {
            None => self.delete(key)?,
            Some(value) => self.save(key, value)?,
        };
        Ok(altered)
    }
}

#[cfg(test)]
mod inspect;

#[cfg(test)]
mod tests;

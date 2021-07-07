//! Simple key-value store abstraction

pub mod fs;
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

    /// Mutate the value of `key`.
    ///
    /// This is like [`Self::mutate`], but only operates on existing values.
    fn mutate<F>(&mut self, key: &str, mutate_fn: F) -> Result<Option<V>, Self::Error>
    where
        F: FnOnce(V) -> V,
    {
        self.alter(key, |opt_v| opt_v.map(mutate_fn))
    }

    /// Insert a value for `key`, if absent. If `key` already has a value, do nothing.
    ///
    /// Return the key's prior value (`None` if `value` was inserted)
    fn try_insert(&mut self, key: &str, value: &V) -> Result<Option<V>, Self::Error> {
        let loaded = self.load(key)?;
        if loaded.is_none() {
            self.save(key, value)?;
        }
        Ok(loaded)
    }
}

#[cfg(test)]
mod inspect;

#[cfg(test)]
mod tests;

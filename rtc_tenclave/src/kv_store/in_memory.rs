//! In-memory implementations of [`KvStore`] (for testing)

use std::collections::HashMap;
use std::prelude::v1::*;

use serde::de::DeserializeOwned;
use serde::Serialize;

use super::KvStore;

/// In-memory [`KvStore`] using [`HashMap`]
#[derive(Default)]
pub struct InMemoryStore<V> {
    pub(crate) map: HashMap<String, V>,
}

impl<V> KvStore<V> for InMemoryStore<V>
where
    V: Clone,
{
    type Error = Never;

    fn load(&self, key: &str) -> Result<Option<V>, Self::Error> {
        Ok(self.map.get(key).cloned())
    }

    fn save(&mut self, key: &str, value: &V) -> Result<(), Self::Error> {
        self.map.insert(key.to_string(), value.clone());
        Ok(())
    }

    fn delete(&mut self, key: &str) -> Result<(), Self::Error> {
        self.map.remove(key);
        Ok(())
    }
}

/// In-memory [`KvStore`] using [`HashMap`] and [`serde_json`] serialization
#[derive(Default)]
pub struct InMemoryJsonStore {
    pub(crate) map: HashMap<String, Vec<u8>>,
}

impl<V> KvStore<V> for InMemoryJsonStore
where
    V: Serialize + DeserializeOwned,
{
    type Error = serde_json::Error;

    fn load(&self, key: &str) -> Result<Option<V>, Self::Error> {
        let loaded: Option<&[u8]> = self.map.get(key).map(|v| v.as_slice());
        let deserialized: Option<V> = loaded.map(serde_json::from_slice).transpose()?;
        Ok(deserialized)
    }

    fn save(&mut self, key: &str, value: &V) -> Result<(), Self::Error> {
        let serialized = serde_json::to_vec(&value)?;
        self.map.insert(key.to_string(), serialized);
        Ok(())
    }

    fn delete(&mut self, key: &str) -> Result<(), Self::Error> {
        self.map.remove(key);
        Ok(())
    }
}

/// TODO: Replace with ! once stabilized.
///
/// See:
///
/// * https://doc.rust-lang.org/beta/unstable-book/language-features/never-type.html
/// * https://github.com/rust-lang/rfcs/blob/master/text/1216-bang-type.md
/// * https://github.com/rust-lang/rust/issues/35121
///
#[derive(Debug)]
pub enum Never {}

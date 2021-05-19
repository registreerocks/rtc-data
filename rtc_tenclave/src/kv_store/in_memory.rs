//! In-memory implementations of [`KvStore`] (for testing)

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::prelude::v1::*;

use super::{KvStore, StoreResult};

/// In-memory [`KvStore`] using [`HashMap`]
#[derive(Default)]
pub struct InMemoryStore<V> {
    pub(crate) map: HashMap<String, V>,
}

impl<V> KvStore<V> for InMemoryStore<V>
where
    V: Clone,
{
    fn load(&self, key: &str) -> StoreResult<Option<V>> {
        Ok(self.map.get(key).cloned())
    }

    fn save(&mut self, key: &str, value: &V) -> StoreResult<()> {
        self.map.insert(key.to_string(), value.clone());
        Ok(())
    }

    fn delete(&mut self, key: &str) -> StoreResult<()> {
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
    fn load(&self, key: &str) -> StoreResult<Option<V>> {
        let loaded: Option<&[u8]> = self.map.get(key).map(|v| v.as_slice());
        let deserialized: Option<V> = loaded.map(serde_json::from_slice).transpose()?;
        Ok(deserialized)
    }

    fn save(&mut self, key: &str, value: &V) -> StoreResult<()> {
        let serialized = serde_json::to_vec(&value)?;
        self.map.insert(key.to_string(), serialized);
        Ok(())
    }

    fn delete(&mut self, key: &str) -> StoreResult<()> {
        self.map.remove(key);
        Ok(())
    }
}

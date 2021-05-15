//! Support for inspecting [`KvStore`] instances (for testing and debugging)

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::borrow::ToOwned;
use std::collections::HashMap;
use std::iter::Iterator;

use super::in_memory::{InMemoryJsonStore, InMemoryStore};
use super::KvStore;

pub trait InspectStore<V> {
    fn as_map(&self) -> HashMap<String, V>;
}

impl<V> InspectStore<V> for InMemoryStore<V>
where
    V: Clone,
{
    fn as_map(&self) -> HashMap<String, V> {
        self.map.clone()
    }
}

impl<V> InspectStore<V> for InMemoryJsonStore
where
    V: Serialize + DeserializeOwned,
{
    fn as_map(&self) -> HashMap<String, V> {
        self.map
            .keys()
            .map(|k| {
                let loaded: Option<V> = self.load(&k).expect(&format!("load {:?} failed!", k));
                let v: V = loaded.expect(&format!("key missing! {:?}", k));
                (k.to_owned(), v)
            })
            .collect()
    }
}

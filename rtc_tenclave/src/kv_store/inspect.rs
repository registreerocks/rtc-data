//! Support for inspecting [`KvStore`] instances (for testing and debugging)

#[cfg(not(test))]
use std::prelude::v1::*;

use std::borrow::ToOwned;
use std::collections::HashMap;

use serde::de::DeserializeOwned;
use serde::Serialize;

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
                let loaded: Option<V> = self
                    .load(k)
                    .unwrap_or_else(|_| panic!("load {:?} failed!", k));
                let v: V = loaded.unwrap_or_else(|| panic!("key missing! {:?}", k));
                (k.to_owned(), v)
            })
            .collect()
    }
}

// sgx_tstd (v1.1.3) does not support `fs::read_dir`, so limit the following to tests, for now.
//
// See: https://github.com/apache/incubator-teaclave-sgx-sdk/blob/v1.1.3/release_notes.md#partially-supported-modstraits-in-sgx_tstd

#[cfg(test)]
use std::{ffi::OsStr, fs::DirEntry, io, iter::Iterator};

#[cfg(test)]
use super::fs::FsStore;

#[cfg(test)]
impl<V> InspectStore<V> for FsStore
where
    V: Serialize + DeserializeOwned,
{
    fn as_map(&self) -> HashMap<String, V> {
        let entries: impl Iterator<Item = io::Result<DirEntry>> = self
            .root_dir
            .read_dir()
            .expect(&format!("read_dir {:?} failed", self.root_dir));

        let keys: impl Iterator<Item = String> = entries.map(|entry: io::Result<DirEntry>| {
            let entry: DirEntry = entry.expect("read_dir entry failed");
            let file_path = entry.path();
            let os_file_name: &OsStr = file_path
                .file_name()
                .expect(&format!("directory entry lacks file_name: {:?}", file_path));
            let file_name: &str = os_file_name.to_str().expect("OsStr.to_str failed");
            FsStore::decode_key(file_name).expect("FsStore::decode_key failed")
        });

        keys.map(|k| {
            let loaded: Option<V> = self.load(&k).expect(&format!("load {:?} failed!", k));
            let v: V = loaded.expect(&format!("key missing! {:?}", k));
            (k, v)
        })
        .collect()
    }
}

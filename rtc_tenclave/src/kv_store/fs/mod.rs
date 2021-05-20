//! Filesystem-based [`KvStore`] implementation

pub mod std_filer;

#[cfg(not(test))]
pub mod sgx_filer;

// sgx_tstd (v1.1.3) does not support `fs::read_dir`, so limit the following to tests, for now.
//
// See: https://github.com/apache/incubator-teaclave-sgx-sdk/blob/v1.1.3/release_notes.md#partially-supported-modstraits-in-sgx_tstd

#[cfg(not(test))]
use std::prelude::v1::*;

use std::io;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use super::{KvStore, StoreResult};

/// Simplified interface for reading and writing files.
pub trait Filer {
    /// Read content of `path`, if any.
    ///
    /// Return [`None`] if `path` doesn't exist.
    ///
    fn get(&self, path: impl AsRef<Path>) -> io::Result<Option<Vec<u8>>>;

    /// Write `content` to `path`. Discard any existing content.
    fn put(&self, path: impl AsRef<Path>, content: impl AsRef<[u8]>) -> io::Result<()>;

    /// Delete `path`. Discard any existing content.
    fn delete(&self, path: impl AsRef<Path>) -> io::Result<()>;
}

/// [`KvStore`] using a file per key under `root_dir`.
pub struct FsStore<F: Filer> {
    pub(crate) root_dir: PathBuf,
    pub(crate) filer: F,
}

impl<F> FsStore<F>
where
    F: Filer,
{
    /// Validate that `root_dir` exists as a directory.
    #[cfg_attr(not(test), allow(dead_code))] // currently only referenced in tests
    pub fn new(root: impl AsRef<Path>, filer: F) -> StoreResult<Self> {
        let root_dir = root.as_ref().to_path_buf();
        Ok(FsStore { root_dir, filer })
    }

    /// Resolve file name for the value of `key`.
    fn value_path(&self, key: &str) -> PathBuf {
        let file_name = Self::encode_key(key);
        self.root_dir.join(file_name)
    }

    // Make keys filesystem-safe using hex (conservative, but effective):

    pub(crate) fn encode_key(key: &str) -> String {
        let encoded = hex::encode(key);
        format!("x{}", encoded)
    }

    #[cfg_attr(not(test), allow(dead_code))] // currently only referenced in tests
    pub(crate) fn decode_key(file_name: &str) -> StoreResult<String> {
        let encoded: &str = file_name
            .strip_prefix("x")
            .ok_or_else(|| format!("FsStore::decode_key: missing x prefix for {:?}", file_name))?;
        // FIXME: Dodgy err.to_string()
        let bytes: Vec<u8> = hex::decode(encoded).map_err(|err| err.to_string())?;
        String::from_utf8(bytes).map_err(|err| err.into())
    }
}

impl<F, V> KvStore<V> for FsStore<F>
where
    F: Filer,
    V: Serialize + DeserializeOwned,
{
    fn load(&self, key: &str) -> StoreResult<Option<V>> {
        let value_file_name = self.value_path(key);

        // Note: Read all the data into memory first, then deserialize, for efficiency.
        // See the docs for [`serde_json::de::from_reader`],
        // and https://github.com/serde-rs/json/issues/160
        let loaded: Option<Vec<u8>> = self
            .filer
            .get(&value_file_name)
            .map_err(|err| format!("FsStore: read from {:?} failed: {}", value_file_name, err))?;
        let value: Option<V> = loaded
            .map(|serialised: Vec<u8>| serde_json::from_slice(serialised.as_slice()))
            .transpose()?;
        Ok(value)
    }

    fn save(&mut self, key: &str, value: &V) -> StoreResult<()> {
        let value_file_name = self.value_path(key);
        let serialized: Vec<u8> = serde_json::to_vec(&value)?;
        self.filer
            .put(&value_file_name, serialized)
            .map_err(|err| format!("FsStore: write to {:?} failed: {}", value_file_name, err))?;
        Ok(())
    }

    fn delete(&mut self, key: &str) -> StoreResult<()> {
        let path = self.value_path(key);
        self.filer.delete(path)?;
        Ok(())
    }
}

#[cfg(test)]
mod inspect;

//!  [`KvStore`] implementation based on [`fs`]

#[cfg(not(test))]
use std::prelude::v1::*;

use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

#[cfg(not(test))]
use std::untrusted::{fs, fs::File};
#[cfg(test)]
use std::{fs, fs::File};

use super::{KvStore, StoreResult};

/// Filesystem-based [`KvStore`]
pub struct FsStore {
    pub(crate) root_dir: PathBuf,
}

impl FsStore {
    /// Validate that `root_dir` exists as a directory.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(root: impl AsRef<Path>) -> StoreResult<Self> {
        let root = root.as_ref();

        fs::create_dir_all(root)
            .map_err(|err| format!("FsStore: create_dir_all({:?}) failed: {:?}", root, err))?;

        Ok(FsStore {
            root_dir: root.to_path_buf(),
        })
    }

    /// Resolve file name for the value of `key`.
    fn value_path(&self, key: &str) -> PathBuf {
        // XXX: Escaping / encoding?
        let file_name = Self::encode_key(key);
        self.root_dir.join(file_name)
    }

    pub(crate) fn encode_key(key: &str) -> String {
        let encoded = hex::encode(key);
        format!("x{}", encoded)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn decode_key(file_name: &str) -> StoreResult<String> {
        let encoded: &str = file_name
            .strip_prefix("x")
            .ok_or_else(|| format!("FsStore::decode_key: missing x prefix for {:?}", file_name))?;
        // FIXME: Dodgy err.to_string()
        let bytes: Vec<u8> = hex::decode(encoded).map_err(|err| err.to_string())?;
        String::from_utf8(bytes).map_err(|err| err.into())
    }
}

impl<V> KvStore<V> for FsStore
where
    V: Serialize + DeserializeOwned,
{
    fn load(&self, key: &str) -> StoreResult<Option<V>> {
        let value_file_name = self.value_path(key);

        // TODO: Handle NotFound
        let value_file = File::open(&value_file_name)
            .map_err(|err| format!("FsStore: open {:?} failed: {}", value_file_name, err))?;

        // Note: Read all the data into memory first, then deserialize, for efficiency.
        // See the docs for [`serde_json::de::from_reader`],
        // and https://github.com/serde-rs/json/issues/160
        let serialised: Vec<u8> = read_all(value_file)
            .map_err(|err| format!("FsStore: read from {:?} failed: {}", value_file_name, err))?;

        let deserialized: V = serde_json::from_slice(serialised.as_slice())?;
        Ok(Some(deserialized))
    }

    fn save(&mut self, key: &str, value: V) -> StoreResult<()> {
        let serialized: Vec<u8> = serde_json::to_vec(&value)?;

        let value_file_name = self.value_path(key);

        let mut value_file = File::create(&value_file_name)
            .map_err(|err| format!("open {:?} failed: {}", value_file_name, err))?;

        value_file.write_all(serialized.as_slice()).map_err(|err| {
            format!(
                "FsStore: write_all to {:?} failed: {}",
                value_file_name, err
            )
        })?;
        Ok(())
    }
}

/// Helper: Like [`fs::read`], but take an open file.
fn read_all(mut file: File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(initial_buffer_size(&file));
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Indicates how large a buffer to pre-allocate before reading the entire file.
fn initial_buffer_size(file: &File) -> usize {
    // Allocate one extra byte so the buffer doesn't need to grow before the
    // final `read` call at the end of the file.  Don't worry about `usize`
    // overflow because reading will fail regardless in that case.
    file.metadata().map(|m| m.len() as usize + 1).unwrap_or(0)
}

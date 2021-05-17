//!  [`KvStore`] implementation based on [`sgx_tstd::sgxfs`] (using the Intel SGX Protected FS Library)

use std::prelude::v1::*;

use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;
use sgx_tstd::sgxfs::SgxFile;

use super::{KvStore, StoreResult};

/// Filesystem-based [`KvStore`], using [`SgxFile`]
///
/// TODO: Document security guarantees.
///
struct SgxFsStore {
    pub(crate) root_dir: PathBuf,
}

impl SgxFsStore {
    /// Validate that `root_dir` exists as a directory.
    pub fn new(root: impl AsRef<Path>) -> StoreResult<Self> {
        let root = root.as_ref();

        // XXX: no create_dir_all()

        Ok(SgxFsStore {
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
    pub(crate) fn decode_key(file_name: &str) -> StoreResult<String> {
        let encoded: &str = file_name
            .strip_prefix("x")
            .ok_or_else(|| format!("FsStore::decode_key: missing x prefix for {:?}", file_name))?;
        // FIXME: Dodgy err.to_string()
        let bytes: Vec<u8> = hex::decode(encoded).map_err(|err| err.to_string())?;
        String::from_utf8(bytes).map_err(|err| err.into())
    }
}

impl<V> KvStore<V> for SgxFsStore
where
    V: Serialize + DeserializeOwned,
{
    fn load(&self, key: &str) -> StoreResult<Option<V>> {
        let value_file_name = self.value_path(key);

        // TODO: Handle NotFound
        // TODO: open_ex() with key
        let value_file = SgxFile::open(&value_file_name)
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

        let mut value_file = SgxFile::create(&value_file_name)
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
fn read_all(mut file: SgxFile) -> io::Result<Vec<u8>> {
    // XXX: No metadata for initial_buffer_size in sgxfs
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

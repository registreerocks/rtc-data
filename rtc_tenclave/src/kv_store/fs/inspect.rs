//! [`InspectStore`] for [`FsStore`]

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::DirEntry;
use std::io;
use std::iter::Iterator;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::kv_store::inspect::InspectStore;
use crate::kv_store::KvStore;

use super::std_filer::StdFiler;
use super::FsStore;
use std::path::PathBuf;

impl<V> InspectStore<V> for FsStore<StdFiler>
where
    V: Serialize + DeserializeOwned,
{
    fn to_map(&self) -> HashMap<String, V> {
        let entries /* impl Iterator<Item = io::Result<DirEntry>> */ = self
            .root_dir
            .read_dir()
            .unwrap_or_else(|_| panic!("read_dir {:?} failed", self.root_dir));

        let keys /* impl Iterator<Item = String> */ = entries.map(|entry: io::Result<DirEntry>| {
            let entry: DirEntry = entry.expect("read_dir entry failed");
            let file_path: PathBuf = entry.path();
            let os_file_name: &OsStr = file_path
                .file_name()
                .unwrap_or_else(|| panic!("directory entry lacks file_name: {:?}", file_path));
            let file_name: &str = os_file_name.to_str().expect("OsStr.to_str failed");
            Self::decode_key(file_name).expect("FsStore::decode_key failed")
        });

        keys.map(|k| {
            let loaded: Option<V> = self
                .load(&k)
                .unwrap_or_else(|_| panic!("load {:?} failed!", k));
            let v: V = loaded.unwrap_or_else(|| panic!("key missing! {:?}", k));
            (k, v)
        })
        .collect()
    }
}

//! [`std::fs::File`] support

use std::prelude::v1::Vec;

use std::io::Result;
use std::io::Write;

use std::path::Path;

// Under sgx_tstd, fs needs the std::untrusted prefix:
#[cfg(not(test))]
use std::untrusted::{fs, fs::File};
#[cfg(test)]
use std::{fs, fs::File};

use super::Filer;

pub struct StdFiler;

impl Filer for StdFiler {
    fn get(&self, path: impl AsRef<Path>) -> Result<Vec<u8>> {
        fs::read(path)
    }

    fn put(&self, path: impl AsRef<Path>, content: impl AsRef<[u8]>) -> Result<()> {
        let contents: &[u8] = content.as_ref();
        let mut value_file = File::create(path)?;
        value_file.write_all(contents)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    // Helper: Run `f` with a non-existent file path inside a temporary directory.
    fn with_temp_path(f: impl FnOnce(&Path)) {
        let temp_dir = TempDir::new().unwrap();
        f(&temp_dir.path().join("foo"));
        temp_dir.close().unwrap()
    }

    #[test]
    fn get_empty() {
        with_temp_path(|path: &Path| {
            File::create(path).unwrap();
            assert_eq!(StdFiler.get(path).unwrap(), "".as_bytes());
        })
    }

    #[test]
    fn put_get() {
        with_temp_path(|path| {
            StdFiler.put(path, "spam").unwrap();
            assert_eq!(StdFiler.get(path).unwrap(), "spam".as_bytes())
        })
    }

    #[test]
    fn put_get_overwrite() {
        with_temp_path(|path| {
            StdFiler.put(path, "spam").unwrap();
            StdFiler.put(path, "ham").unwrap();
            assert_eq!(StdFiler.get(path).unwrap(), "ham".as_bytes())
        })
    }
}

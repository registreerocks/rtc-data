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

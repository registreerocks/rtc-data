//! [`SgxFile`] support

use std::prelude::v1::Vec;

use std::io::Read;
use std::io::Result;
use std::io::Write;
use std::path::Path;

use sgx_tstd::sgxfs::SgxFile;

use super::Filer;

/// TODO: key management policy
pub struct SgxFiler;

// Default key management:
//
// * `protected_fs_file::generate_random_meta_data_key`
//   https://github.com/intel/linux-sgx/blob/sgx_2.13.3/sdk/protected_fs/sgx_tprotected_fs/file_crypto.cpp#L197
//
impl Filer for SgxFiler {
    fn get(&self, path: impl AsRef<Path>) -> Result<Option<Vec<u8>>> {
        // TODO: open_ex with key
        let value_file = SgxFile::open(path)?;
        read_all(value_file).map(Some)
    }

    fn put(&self, path: impl AsRef<Path>, content: impl AsRef<[u8]>) -> Result<()> {
        let contents: &[u8] = content.as_ref();
        // TODO: create_ex with key
        let mut value_file = SgxFile::create(path)?;
        value_file.write_all(contents)
    }
}

/// Helper: Like [`fs::read`], but take an open file.
fn read_all(mut file: SgxFile) -> Result<Vec<u8>> {
    // XXX: No metadata for initial_buffer_size in sgxfs
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

use crate::types::*;
use core::slice;

pub(crate) trait SampleExecModule {
    fn call_safe(&self, dataset: &[u8]) -> ExecResult;
}

impl<T> ExecModule for T
where
    T: SampleExecModule,
{
    unsafe fn call(&self, dataset_ptr: *const u8, dataset_len: usize) -> ExecResult {
        let dataset = unsafe { slice::from_raw_parts(dataset_ptr, dataset_len) };
        self.call_safe(dataset)
    }
}

pub(crate) const SHA256_HASH_MODULE_ID: [u8; 32] = [1u8; 32];
pub(crate) struct Sha256HashModule;

impl SampleExecModule for Sha256HashModule {
    fn call_safe(&self, dataset: &[u8]) -> ExecResult {
        match sgx_tcrypto::rsgx_sha256_slice(dataset) {
            Ok(res) => Ok(res.to_vec().into_boxed_slice()),
            Err(_) => Err(()),
        }
    }
}

pub(crate) const MEDIAN_MODULE_ID: [u8; 32] = [2u8; 32];
pub(crate) struct MedianModule;

impl SampleExecModule for MedianModule {
    fn call_safe(&self, _dataset: &[u8]) -> ExecResult {
        todo!()
    }
}

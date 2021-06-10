use core::cmp::Ordering;
use core::mem::size_of;
use core::slice;
use std::boxed::Box;
use std::vec::Vec;

use crate::types::*;

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
    fn call_safe(&self, dataset: &[u8]) -> ExecResult {
        let mut float_dataset: Vec<f64> = if dataset.len() % size_of::<f64>() == 0 {
            // Safety: dataset.len() should be aligned with the size of f64,
            // so the array_chucks iterator should have no remainder().
            dataset
                .array_chunks()
                .map(|x| f64::from_ne_bytes(*x))
                .collect()
        } else {
            // Bail out: dataset.len() is not a multiple of the size of f64.
            return Err(());
        };

        let median = median(&mut float_dataset).ok_or(())?;
        let median_bytes = median.to_ne_bytes();

        Ok(Box::new(median_bytes))
    }
}

fn median(data: &mut [f64]) -> Option<f64> {
    let len = data.len();
    // If len is 0 we cannot calculate a median
    if len == 0 {
        return None;
    };

    // No well-defined median if data contains infinities or NaN.
    // TODO: Consider something like <https://crates.io/crates/ordered-float>?
    if !data.iter().all(|n| n.is_finite()) {
        return None;
    }

    let mid = len / 2;

    // Safety: is_finite checked above
    let (less, &mut m1, _) = data.select_nth_unstable_by(mid, |a, b| unsafe { finite_cmp(a, b) });

    let median = if len % 2 == 1 {
        m1
    } else {
        // Safety: is_finite checked above
        let (_, &mut m2, _) =
            less.select_nth_unstable_by(mid - 1, |a, b| unsafe { finite_cmp(a, b) });
        (m1 + m2) / 2.0
    };
    Some(median)
}

/// Compare finite floats.
/// # Safety
/// Caller must ensure values are finite (or at least not NaN).
unsafe fn finite_cmp(a: &f64, b: &f64) -> Ordering {
    a.partial_cmp(b)
        .unwrap_or_else(|| panic!("finite_cmp({:?}, {:?}): not comparable", a, b))
}

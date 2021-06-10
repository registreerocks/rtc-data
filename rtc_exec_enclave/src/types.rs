use std::boxed::Box;

pub(crate) type CallReturnValue = Box<[u8]>;

pub(crate) type ExecResult = core::result::Result<CallReturnValue, ()>;

pub(crate) trait ExecModule {
    /// Calls the entry function of a module with the provided dataset and return the result
    ///
    /// # Safety
    /// The caller must ensure that `dataset_ptr` is a valid pointer to a `u8` slice of `dataset_len`
    unsafe fn call(&self, dataset_ptr: *const u8, dataset_len: usize) -> ExecResult;
}

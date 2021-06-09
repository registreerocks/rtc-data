use std::boxed::Box;

pub(crate) type CallReturnValue = Box<[u8]>;

pub(crate) type ExecResult = core::result::Result<CallReturnValue, ()>;

pub(crate) trait ExecModule {
    unsafe fn call(&self, dataset_ptr: *const u8, dataset_len: usize) -> ExecResult;
}

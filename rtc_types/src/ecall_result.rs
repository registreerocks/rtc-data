use super::*;

/// FFI safe result type that can be converted to and from a rust result.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug)]
pub enum EcallResult<T, E> {
    Ok(T),
    Err(E),
}

impl<T, E> EcallResult<T, E> {
    /// See [`Result::map`]
    pub fn map<U, F: FnOnce(T) -> U>(self, op: F) -> EcallResult<U, E> {
        use EcallResult::{Err, Ok};
        match self {
            Ok(t) => Ok(op(t)),
            Err(e) => Err(e),
        }
    }
}

impl<T, E> EcallResult<T, E>
where
    E: 'static + std::error::Error + Display,
{
    pub fn to_ecall_err(self, sgx_result: sgx_status_t) -> EcallResult<T, EcallError<E>> {
        if sgx_result != sgx_status_t::SGX_SUCCESS {
            EcallResult::Err(EcallError::SgxRuntime(sgx_result))
        } else {
            match self {
                EcallResult::Ok(res) => EcallResult::Ok(res),
                EcallResult::Err(err) => EcallResult::Err(EcallError::RtcEnclave(err)),
            }
        }
    }
}

impl<T, E> From<EcallResult<T, E>> for Result<T, E> {
    fn from(result: EcallResult<T, E>) -> Self {
        match result {
            EcallResult::Ok(res) => Ok(res),
            EcallResult::Err(err) => Err(err),
        }
    }
}

impl<T, E> From<Result<T, E>> for EcallResult<T, E> {
    fn from(result: Result<T, E>) -> Self {
        match result {
            Ok(res) => EcallResult::Ok(res),
            Err(err) => EcallResult::Err(err),
        }
    }
}

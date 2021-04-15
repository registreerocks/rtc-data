#[cfg(test)]
use mockall::*;
use sgx_types::{sgx_quote3_error_t, sgx_report_t, sgx_target_info_t};

#[cfg_attr(test, automock)]
mod qe_functions {
    use sgx_types::{sgx_quote3_error_t, sgx_report_t, sgx_target_info_t, uint32_t, uint8_t};

    // This is causing issues with testing dependent packages locally.
    // TODO: test if this line is required for correct interaction
    // in the azure environment
    // #[cfg_attr(not(test), link(name = "sgx_dcap_ql"))]
    extern "C" {
        pub fn sgx_qe_get_target_info(
            p_qe_target_info: *mut sgx_target_info_t,
        ) -> sgx_quote3_error_t;
        pub fn sgx_qe_get_quote_size(p_quote_size: *mut uint32_t) -> sgx_quote3_error_t;
        pub fn sgx_qe_get_quote(
            p_app_report: *const sgx_report_t,
            quote_size: uint32_t,
            p_quote: *mut uint8_t,
        ) -> sgx_quote3_error_t;
    }
}

#[cfg(test)]
use self::mock_qe_functions::*;

#[cfg(not(test))]
use self::qe_functions::*;

pub(crate) struct QuotingEnclave;

#[cfg_attr(test, automock)]
impl QuotingEnclave {
    pub(crate) fn get_target_info(&self) -> Result<sgx_target_info_t, sgx_quote3_error_t> {
        let mut qe_target_info = sgx_target_info_t::default();
        let qe3_ret = unsafe { sgx_qe_get_target_info(&mut qe_target_info as *mut _) };
        match qe3_ret {
            sgx_quote3_error_t::SGX_QL_SUCCESS => Ok(qe_target_info),
            _ => Err(qe3_ret),
        }
    }

    pub(crate) fn request_quote(
        &self,
        report: sgx_report_t,
    ) -> Result<Vec<u8>, sgx_quote3_error_t> {
        let quote_size = self.get_quote_size()?;

        let mut quote_vec: Vec<u8> = vec![0; quote_size as usize];

        let qe3_ret =
            unsafe { sgx_qe_get_quote(&report as _, quote_size, quote_vec.as_mut_ptr() as _) };
        match qe3_ret {
            sgx_quote3_error_t::SGX_QL_SUCCESS => Ok(quote_vec),
            _ => Err(qe3_ret),
        }
    }

    pub(super) fn get_quote_size(&self) -> Result<u32, sgx_quote3_error_t> {
        let mut quote_size: u32 = 0;
        let qe3_ret = unsafe { sgx_qe_get_quote_size(&mut quote_size as _) };
        match qe3_ret {
            sgx_quote3_error_t::SGX_QL_SUCCESS => Ok(quote_size),
            _ => Err(qe3_ret),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_quote() {
        let quote_size = 132;
        let report = sgx_report_t::default();

        let ctx_get_quote = sgx_qe_get_quote_context();
        let ctx_get_quote_size = sgx_qe_get_quote_size_context();

        ctx_get_quote_size.expect().returning(move |size| {
            unsafe { *size = quote_size }
            sgx_quote3_error_t::SGX_QL_SUCCESS
        });

        ctx_get_quote
            .expect()
            .withf(move |rep, size, _| unsafe { **rep == report } && size == &quote_size)
            .return_const(sgx_quote3_error_t::SGX_QL_SUCCESS);

        let res = QuotingEnclave.request_quote(sgx_report_t::default());
        assert!(res.is_ok())
    }

    #[test]
    fn test_get_target_info() {
        let ctx = sgx_qe_get_target_info_context();
        ctx.expect()
            .return_const(sgx_quote3_error_t::SGX_QL_SUCCESS);
        let res = QuotingEnclave.get_target_info();
        assert!(res.is_ok())
    }
}

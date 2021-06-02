use secrecy::{Secret, Zeroize};
use sgx_types::*;

#[cfg(test)]
use mockall::automock;

pub struct AlignedKey(sgx_align_key_128bit_t);

impl AlignedKey {
    pub fn new(key: sgx_align_key_128bit_t) -> Secret<Self> {
        Secret::new(Self(key))
    }
    pub fn key(&self) -> &sgx_key_128bit_t {
        &self.0.key
    }
}

impl Zeroize for AlignedKey {
    fn zeroize(&mut self) {
        self.0.key.zeroize()
    }
}

pub struct DhValues {
    pub(crate) session_key: Secret<AlignedKey>,
    #[allow(dead_code)] // not used yet, but will be
    pub(crate) peer_identity: sgx_dh_session_enclave_identity_t,
}

#[cfg_attr(test, automock)]
pub trait RtcDhInitiator {
    fn init_session() -> Self;
    fn proc_msg1(&mut self, msg1: &sgx_dh_msg1_t) -> Result<sgx_dh_msg2_t, sgx_status_t>;

    /// Process msg3 and return the DhValues for the session
    ///
    /// We currently allow no additional prop data, and will return an error
    /// if `msg3.msg3_body.additional_prop_length` is greater than 0. This can be changed
    /// to a well known constant size in the future if the additional prop needs to be used.
    fn proc_msg3(&mut self, msg3: &mut sgx_dh_msg3_t) -> Result<DhValues, sgx_status_t>;
}
#[cfg_attr(test, automock)]
pub trait RtcDhResponder {
    fn init_session() -> Self;
    fn gen_msg1(&mut self) -> Result<sgx_dh_msg1_t, sgx_status_t>;

    /// Process msg3 and return the DhValues for the session
    fn proc_msg2(
        &mut self,
        msg2: &sgx_dh_msg2_t,
    ) -> Result<(sgx_dh_msg3_t, DhValues), sgx_status_t>;
}

#[cfg(not(test))]
pub mod impl_sgx {
    use super::*;
    use sgx_tdh::{SgxDhInitiator, SgxDhMsg3, SgxDhResponder};
    use sgx_tstd::mem;

    impl RtcDhInitiator for SgxDhInitiator {
        fn init_session() -> Self {
            SgxDhInitiator::init_session()
        }

        fn proc_msg1(&mut self, msg1: &sgx_dh_msg1_t) -> Result<sgx_dh_msg2_t, sgx_status_t> {
            let mut msg2 = sgx_dh_msg2_t::default();
            SgxDhInitiator::proc_msg1(self, msg1, &mut msg2)?;
            Ok(msg2)
        }

        fn proc_msg3(&mut self, msg3: &mut sgx_dh_msg3_t) -> Result<DhValues, sgx_status_t> {
            // Only allow msg3 values with no additional prop data
            if msg3.msg3_body.additional_prop_length > 0 {
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
            }
            let mut aek = sgx_align_key_128bit_t::default();
            let mut peer_identity = sgx_dh_session_enclave_identity_t::default();

            // Safety:
            // This should be safe since we don't allow additional prop data, so we don't have to
            // worry about memory allocations
            let msg3_full = unsafe {
                SgxDhMsg3::from_raw_dh_msg3_t(msg3, mem::size_of::<sgx_dh_msg3_t>() as u32)
            }
            .ok_or(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)?;

            SgxDhInitiator::proc_msg3(self, &msg3_full, &mut aek.key, &mut peer_identity)?;
            Ok(DhValues {
                session_key: AlignedKey::new(aek),
                peer_identity,
            })
        }
    }

    impl RtcDhResponder for SgxDhResponder {
        fn init_session() -> Self {
            SgxDhResponder::init_session()
        }

        fn gen_msg1(&mut self) -> Result<sgx_dh_msg1_t, sgx_status_t> {
            let mut msg1 = sgx_dh_msg1_t::default();
            SgxDhResponder::gen_msg1(self, &mut msg1)?;
            Ok(msg1)
        }

        fn proc_msg2(
            &mut self,
            msg2: &sgx_dh_msg2_t,
        ) -> Result<(sgx_dh_msg3_t, DhValues), sgx_status_t> {
            let mut msg3 = SgxDhMsg3::new();
            let mut aek = sgx_align_key_128bit_t::default();
            let mut peer_identity = sgx_dh_session_enclave_identity_t::default();

            SgxDhResponder::proc_msg2(self, msg2, &mut msg3, &mut aek.key, &mut peer_identity)?;

            let msg3_len = msg3.calc_raw_sealed_data_size();

            // Only allow messages with 0 additional prop size
            if msg3_len == (mem::size_of::<sgx_dh_msg3_t>() as u32) {
                // This branch should never be reached since we don't use additional prop
                // --
                // Normally unreachable code should panic but since this will open up a trivial
                // way for untrusted code to trigger a panic (and potentially UB if we unwind over
                // the ffi boundary) we should return with an `Err` instead.
                return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
            }

            let mut msg3_raw = sgx_dh_msg3_t::default();

            // Safety:
            // This function should be safe since we don't allow additional prop data, so we don't have
            // to worry about memory allocations. We also guard against cases where this does not uphold
            // to prevent UB.
            unsafe { msg3.to_raw_dh_msg3_t(&mut msg3_raw, msg3_len) }
                .ok_or(sgx_status_t::SGX_ERROR_UNEXPECTED)?;

            Ok((
                msg3_raw,
                DhValues {
                    session_key: AlignedKey::new(aek),
                    peer_identity,
                },
            ))
        }
    }
}

use sgx_tdh::SgxDhResponder;
use sgx_types::sgx_align_key_128bit_t;

pub enum DhSessionStatus {
    Closed,
    InProgress(SgxDhResponder),
    Active(sgx_align_key_128bit_t),
}

impl Default for DhSessionStatus {
    fn default() -> DhSessionStatus {
        DhSessionStatus::Closed
    }
}

#[derive(Default)]
pub struct DhSession {
    pub session_id: u32,
    pub session_status: DhSessionStatus,
}

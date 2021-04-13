use actix::prelude::*;
use rtc_uenclave::{AttestationError, EnclaveReportResult, RtcEnclave, SgxEnclave};
use sgx_types::*;
use std::cell::Cell;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

// TODO: Move functionality to rtc_uenclave
fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

#[derive(Default)]
pub(crate) struct CreateReport(sgx_target_info_t);

impl Message for CreateReport {
    type Result = Result<EnclaveReportResult, AttestationError>;
}

#[derive(Default)]
pub(crate) struct EnclaveActor(Cell<SgxEnclave>);

impl Actor for EnclaveActor {
    type Context = Context<EnclaveActor>;

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        self.0.take().destroy();
    }

    fn started(&mut self, _ctx: &mut Self::Context) {
        // TODO: Should we use expect here or handle the errors in some
        // other way?
        self.0
            .set(init_enclave().expect("Enclave to be initialized"));
    }
}

impl Handler<CreateReport> for EnclaveActor {
    type Result = Result<EnclaveReportResult, AttestationError>;

    fn handle(&mut self, msg: CreateReport, _ctx: &mut Self::Context) -> Self::Result {
        self.0.get_mut().create_report(&msg.0)
    }
}

// TODO: Investigate supervisor returning `Err(Cancelled)` (see supervisor docs on Actix)
impl actix::Supervised for EnclaveActor {
    fn restarting(&mut self, _ctx: &mut Context<EnclaveActor>) {
        self.0
            .replace(init_enclave().expect("enclave to be initialized"))
            .destroy()
    }
}

impl SystemService for EnclaveActor {}

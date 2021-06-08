use std::convert::Infallible;

use crate::exec_enclave_actor::ExecEnclaveActor;
use actix::{Handler, Message};

// TODO: Replace with types from rtc_types
pub(crate) type RequestExecutionResponse = ();
pub(crate) type RequestExecutionError = Infallible;

pub struct RequestExecutionMessage {
    pub metadata: (), // TODO: RequestExecutionMetadata
    pub payload: Box<[u8]>,
}

impl Message for RequestExecutionMessage {
    // TODO: RequestExecutionResponse and Request Execution Error
    type Result = Result<RequestExecutionResponse, RequestExecutionError>;
}

impl Handler<RequestExecutionMessage> for ExecEnclaveActor {
    type Result = <RequestExecutionMessage as Message>::Result;

    fn handle(&mut self, _msg: RequestExecutionMessage, _ctx: &mut Self::Context) -> Self::Result {
        Ok(()) // TODO
    }
}

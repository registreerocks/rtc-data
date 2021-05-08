use crate::data_enclave_actor::DataEnclaveActor;
use actix::{Handler, Message};
use rtc_types::{ExecTokenError, ExecTokenResponse};

// TODO : Change struct values to resemble request Body (add data access key, uuid, hash, keypair, nonce..)
pub struct ExecTokenMessage {
    pub metadata: Vec<u8>,
}

impl Message for ExecTokenMessage {
    type Result = Result<ExecTokenResponse, ExecTokenError>;
}

impl Handler<ExecTokenMessage> for DataEnclaveActor {
    type Result = <ExecTokenMessage as Message>::Result;

    fn handle(&mut self, msg: ExecTokenMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.get_enclave().get_exec_token()
    }
}

use actix::{Handler, Message};
use rtc_types::{DataUploadError, DataUploadResponse, EcallError, UploadMetadata};

use crate::data_enclave_actor::DataEnclaveActor;

pub struct DataUploadRequest {
    pub metadata: UploadMetadata,
    pub payload: Box<[u8]>,
}

pub struct DataUploadMessage {
    pub request: DataUploadRequest,
}

impl Message for DataUploadMessage {
    type Result = Result<DataUploadResponse, EcallError<DataUploadError>>;
}

/// Handle upload using [`rtc_uenclave::RtcDataEnclave::upload_data`].
impl Handler<DataUploadMessage> for DataEnclaveActor {
    type Result = <DataUploadMessage as Message>::Result;

    fn handle(&mut self, msg: DataUploadMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.get_enclave()
            .upload_data(&msg.request.payload, msg.request.metadata)
    }
}

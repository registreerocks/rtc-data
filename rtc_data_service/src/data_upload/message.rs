use actix::{Handler, Message};
use rtc_types::{DataUploadError, DataUploadResponse, EcallError, UploadMetadata};
use sgx_types::sgx_enclave_id_t;

use crate::data_enclave_actor::DataEnclaveActor;

/// Sealed request from a client to upload a new dataset.
///
/// See: [`crate::data_upload::service::models::RequestBody`]
pub struct DataUploadRequest {
    pub metadata: UploadMetadata,
    pub payload: Box<[u8]>,
}

/// [`Message`]: Process a [`DataUploadRequest`] sealed for [`auth_enclave_id`].
/// Return a sealed [`DataUploadResponse`].
///
/// See: [`rtc_uenclave::enclaves::rtc_data::upload_data`]
pub struct DataUploadMessage {
    pub auth_enclave_id: sgx_enclave_id_t,
    pub request: DataUploadRequest,
}

impl Message for DataUploadMessage {
    type Result = Result<DataUploadResponse, EcallError<DataUploadError>>;
}

/// Handle upload using [`rtc_uenclave::RtcDataEnclave::upload_data`].
impl Handler<DataUploadMessage> for DataEnclaveActor {
    type Result = <DataUploadMessage as Message>::Result;

    fn handle(&mut self, msg: DataUploadMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.get_enclave().upload_data(
            msg.auth_enclave_id,
            &msg.request.payload,
            msg.request.metadata,
        )
    }
}

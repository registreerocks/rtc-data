use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::string::String;

use jwt::EncodedExecutionToken;
use once_cell::sync::OnceCell;
use rtc_tenclave::kv_store::fs::{FsStore, SgxFiler};
use rtc_tenclave::kv_store::KvStore;
use serde::{Deserialize, Serialize};
use sgx_tstd::sync::{SgxMutex as Mutex, SgxMutexGuard as MutexGuard};
use sgx_tstd::untrusted::{fs as untrusted_fs, path as untrusted_path};
use uuid::Uuid;

use crate::{jwt, uuid_to_string};

#[derive(Serialize, Deserialize)]
struct ExecutionTokenRecord {
    exec_module_hash: [u8; 32],
    dataset_uuid: Uuid,
    allowed_uses: u32,
    current_uses: u32,
}

fn kv_store<'a>(
) -> MutexGuard<'a, impl KvStore<HashMap<Uuid, ExecutionTokenRecord>, Error = io::Error>> {
    static TOKEN_FS_STORE: OnceCell<Mutex<FsStore<SgxFiler>>> = OnceCell::new();
    let store = TOKEN_FS_STORE.get_or_init(|| {
        // TODO: Evaluate if this make sense, and what the possible attack vectors can be from relying on the
        // untrusted fs and path functions.
        let path = Path::new("./token_kv_store");
        if !untrusted_path::PathEx::exists(path) {
            untrusted_fs::create_dir_all(path).expect("Failed to create token kv store directory");
        }

        Mutex::new(FsStore::new(path, SgxFiler))
    });
    store.lock().expect("FS store mutex poisoned")
}

// Returns exec token hash
pub(crate) fn issue_token(
    dataset_uuid: Uuid,
    exec_module_hash: [u8; 32],
    number_of_allowed_uses: u32,
) -> Result<String, io::Error> {
    let EncodedExecutionToken { token, token_id } =
        EncodedExecutionToken::new(exec_module_hash, dataset_uuid);

    save_token(
        dataset_uuid,
        token_id,
        exec_module_hash,
        number_of_allowed_uses,
    )?;

    Ok(token)
}

fn save_token(
    dataset_uuid: Uuid,
    token_uuid: Uuid,
    exec_module_hash: [u8; 32],
    number_of_allowed_uses: u32,
) -> Result<(), io::Error> {
    let mut store = kv_store();
    let dataset_uuid_string = uuid_to_string(dataset_uuid);
    let new_record = ExecutionTokenRecord {
        dataset_uuid,
        exec_module_hash,
        allowed_uses: number_of_allowed_uses,
        current_uses: 0u32,
    };

    store.alter(&dataset_uuid_string, |records| {
        let mut records = records.unwrap_or_else(HashMap::new);
        records.insert(token_uuid, new_record);
        Some(records)
    })?;
    Ok(())
}

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

/// The set of execution tokens issued for a dataset.
#[derive(Serialize, Deserialize)]
struct ExecutionTokenSet {
    dataset_uuid: Uuid, // XXX(Pi): This may be redundant? Remove, or keep for self-integrity checking?

    /// The dataset's unsealed size in bytes.
    dataset_size: u64,

    /// Usage state of the issued execution tokens, by JWT ID (`jti`).
    issued_tokens: HashMap<Uuid, ExecutionTokenState>,
}

impl ExecutionTokenSet {
    #[allow(unused)]
    fn new(dataset_uuid: Uuid, dataset_size: u64) -> ExecutionTokenSet {
        ExecutionTokenSet {
            dataset_uuid,
            dataset_size,
            issued_tokens: HashMap::new(),
        }
    }
}

/// Usage state of a single execution token.
#[derive(Serialize, Deserialize)]
struct ExecutionTokenState {
    exec_module_hash: [u8; 32],
    allowed_uses: u32,
    current_uses: u32,
}

fn kv_store<'a>() -> MutexGuard<'a, impl KvStore<ExecutionTokenSet, Error = io::Error>> {
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
    dataset_size: u64,
) -> Result<String, io::Error> {
    let EncodedExecutionToken { token, token_id } =
        EncodedExecutionToken::new(exec_module_hash, dataset_uuid, dataset_size);

    save_token(
        dataset_uuid,
        token_id,
        exec_module_hash,
        number_of_allowed_uses,
    )?;

    Ok(token)
}

/// Save a newly-issued execution token's state to the store.
///
/// Fail with error for invalid `dataset_uuid`.
///
/// # Panics
///
/// If `token_uuid` was already issued.
fn save_token(
    dataset_uuid: Uuid,
    token_uuid: Uuid,
    exec_module_hash: [u8; 32],
    number_of_allowed_uses: u32,
) -> Result<(), io::Error> {
    let mut store = kv_store();
    let dataset_uuid_string = uuid_to_string(dataset_uuid);
    let new_token_state = ExecutionTokenState {
        exec_module_hash,
        allowed_uses: number_of_allowed_uses,
        current_uses: 0u32,
    };

    let mutated = store.mutate(&dataset_uuid_string, |mut token_set| {
        token_set.issued_tokens.insert(token_uuid, new_token_state);
        token_set
    })?;

    // Handle lookup failure
    match mutated {
        // TODO(Pi): Use something better than the io NotFound here?
        None => Err(io::ErrorKind::NotFound.into()),
        Some(_) => Ok(()),
    }
}

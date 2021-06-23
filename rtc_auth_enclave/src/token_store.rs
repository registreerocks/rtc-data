use std::collections::hash_map::Entry;
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

    /// The dataset's access key.
    access_key: [u8; 24],

    /// The dataset's unsealed size in bytes.
    dataset_size: u64,

    /// Usage state of the issued execution tokens, by JWT ID (`jti`).
    issued_tokens: HashMap<Uuid, ExecutionTokenState>,
}

impl ExecutionTokenSet {
    fn new(dataset_uuid: Uuid, access_key: [u8; 24], dataset_size: u64) -> ExecutionTokenSet {
        ExecutionTokenSet {
            dataset_uuid,
            access_key,
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

/// Save a new dataset access key and associated metadata to the store.
///
/// This must be called before [`issue_token`] can be called.
///
/// # Panics
///
/// If `dataset_uuid` already exists in the store. (This should not happen.)
#[allow(dead_code)] // TODO
pub(crate) fn save_access_key(
    dataset_uuid: Uuid,
    access_key: [u8; 24],
    dataset_size: u64,
) -> Result<(), io::Error> {
    let mut store = kv_store();
    let dataset_uuid_string = uuid_to_string(dataset_uuid);
    let empty_token_set = ExecutionTokenSet::new(dataset_uuid, access_key, dataset_size);

    match store.try_insert(&dataset_uuid_string, &empty_token_set)? {
        None => Ok(()),
        Some(_existing) => panic!(
            "token_store::save_access_key: access key for dateset_uuid={:?} already saved (this should not happen)",
            dataset_uuid,
        )
    }
}

// Returns exec token hash
pub(crate) fn issue_token(
    dataset_uuid: Uuid,
    access_key: [u8; 24],
    exec_module_hash: [u8; 32],
    number_of_allowed_uses: u32,
    dataset_size: u64,
) -> Result<String, io::Error> {
    let EncodedExecutionToken { token, token_id } =
        EncodedExecutionToken::new(exec_module_hash, dataset_uuid, dataset_size);

    let token_state = ExecutionTokenState {
        exec_module_hash,
        allowed_uses: number_of_allowed_uses,
        current_uses: 0u32,
    };

    save_token(dataset_uuid, access_key, token_id, token_state)?;

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
    access_key: [u8; 24],
    token_id: Uuid,
    token_state: ExecutionTokenState,
) -> Result<(), io::Error> {
    let mut store = kv_store();
    let dataset_uuid_string = uuid_to_string(dataset_uuid);

    let mut token_set = store
        .load(&dataset_uuid_string)?
        // TODO(Pi): Use something better than the io NotFound here?
        .ok_or_else(|| io::ErrorKind::NotFound)?;

    // Update if the access key matches.
    if token_set.access_key == access_key {
        // TODO: Use [`HashMap::try_insert`] once stable.
        // Unstable tracking issue: <https://github.com/rust-lang/rust/issues/82766>
        match token_set.issued_tokens.entry(token_id) {
            Entry::Occupied(_entry) => panic!(
                "token_store::save_token: token_uuid={:?} already issued (this should not happen)",
                token_id,
            ),
            Entry::Vacant(entry) => entry.insert(token_state),
        };
        store.save(&dataset_uuid_string, &token_set)?;
        Ok(())
    } else {
        Err(io::ErrorKind::NotFound.into())
    }
}

//! Tests for [`rtc_tenclave::kv_store`]

#[cfg(not(test))]
use std::prelude::v1::*;

use std::collections::HashMap;

use proptest::prelude::*;
use proptest::test_runner::TestCaseResult;
use tempfile::TempDir;

use super::fs::{std_filer::StdFiler, FsStore};
use super::in_memory::{InMemoryJsonStore, InMemoryStore};
use super::inspect::InspectStore;
use super::KvStore;

/// Verify that executing a sequence of store operations matches a simple model.
#[test]
fn prop_store_ops_match_model() {
    // Strategy to generate store operations: currently, just key / value pairs to save.
    let store_ops_strategy = {
        let keys = prop_oneof!(r"[a-z]{0,5}", ".*");
        let values = prop_oneof!(keys.clone()); // TODO: Non-string values

        // This strategy will generate key / value pairs with multiple values per key,
        // and shuffle them to have some interleaving, for bugs that depend on that.
        proptest::collection::hash_map(keys, proptest::collection::vec(values, 0..10), 0..10)
            .prop_map(flatten_key_values)
            .prop_shuffle()
    };

    fn test(store_ops_vec: Vec<(String, String)>) -> TestCaseResult {
        // FIXME: This value type parameter needs better handling.
        type V = String;

        // Init the models
        let mut store_model: InMemoryStore<V> = InMemoryStore::default();
        let mut store_model_json: InMemoryJsonStore = InMemoryJsonStore::default();

        // Init the store under test
        let temp_dir = TempDir::new().unwrap();
        let mut store_fs: FsStore<StdFiler> =
            FsStore::new(&temp_dir, StdFiler).expect("FsStore::new failed");

        for (k, v) in store_ops_vec {
            store_model
                .save(&k, &v)
                .expect("InMemoryStore save failed!");
            store_model_json
                .save(&k, &v)
                .expect("InMemoryJsonStore save failed!");
            store_fs.save(&k, &v).expect("FsStore save failed!");

            // Models match each other
            prop_assert_eq!(store_model.as_map(), store_model_json.as_map());
            // Models match store_fs
            prop_assert_eq!(store_model.as_map(), store_fs.as_map());
            // FIXME: explicit coercion for as_map()
            prop_assert_eq!(
                store_model_json.as_map() as HashMap<String, V>,
                store_fs.as_map()
            );
        }

        temp_dir.close()?;
        Ok(())
    }

    proptest!(|(store_ops_vec in store_ops_strategy)| {
        test(store_ops_vec)?;
    });
}

/// Helper: Flatten `{K => [V, …], …}` to `[(K, V), …]`, cloning `K` for each `V`.
fn flatten_key_values<K: Clone, V>(kvs: HashMap<K, Vec<V>>) -> Vec<(K, V)> {
    kvs.into_iter()
        .flat_map(|(k, vs)| vs.into_iter().map(move |v| (k.clone(), v)))
        .collect()
}

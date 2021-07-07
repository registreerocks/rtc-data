//! Tests for [`rtc_tenclave::kv_store`]

use std::collections::HashMap;
#[cfg(not(test))]
use std::prelude::v1::*;

use proptest::prelude::*;
use proptest::test_runner::TestCaseResult;
use tempfile::TempDir;

use super::fs::std_filer::StdFiler;
use super::fs::FsStore;
use super::in_memory::{InMemoryJsonStore, InMemoryStore, Never};
use super::inspect::InspectStore;
use super::KvStore;

#[test]
fn test_mutate() -> Result<(), Never> {
    let mut store = InMemoryStore::default();

    assert_eq!(store.mutate("missing", |n| n + 1)?, None);

    store.save("existing", &2)?;
    assert_eq!(store.mutate("existing", |n| n + 1)?, Some(3));
    assert_eq!(store.load("existing")?, Some(3));

    Ok(())
}
#[test]
fn test_try_insert() -> Result<(), Never> {
    let mut store = InMemoryStore::default();

    assert_eq!(store.try_insert("missing", &42)?, None);
    assert_eq!(store.load("missing")?, Some(42));

    store.save("existing", &5)?;
    assert_eq!(store.try_insert("existing", &42)?, Some(5));
    assert_eq!(store.load("existing")?, Some(5));

    Ok(())
}

/// Verify that executing a sequence of store operations matches a simple model.
#[test]
fn prop_store_ops_match_model() {
    // FIXME: This value type parameter needs better handling.
    type V = String;

    /// Helper: Represent store operations.
    #[derive(Debug)]
    enum StoreOp {
        Save { key: String, value: V },
        Delete { key: String },
        AlterId { key: String },
        AlterConst { key: String, replacement: Option<V> },
        AlterUpdate { key: String, new_value: V },
    }
    use StoreOp::*;
    impl StoreOp {
        /// Apply operation, and also check some invariants.
        fn apply<S>(&self, store: &mut S) -> Result<(), S::Error>
        where
            S: KvStore<V>,
        {
            match self {
                Save { key, value } => {
                    store.save(key, value)?;
                    assert_eq!(store.load(key)?.as_ref(), Some(value));
                }
                Delete { key } => {
                    store.delete(key)?;
                    assert_eq!(store.load(key)?, None);
                }
                AlterId { key } => {
                    let previous = store.load(key)?;
                    store.alter(key, |loaded| loaded)?;
                    assert_eq!(store.load(key)?, previous);
                }
                AlterConst { key, replacement } => {
                    store.alter(key, |_| replacement.clone())?;
                    assert_eq!(store.load(key)?.as_ref(), replacement.as_ref());
                }
                AlterUpdate { key, new_value } => {
                    let previous = store.load(key)?;
                    store.alter(key, |existing: Option<V>| {
                        existing.map(|_| new_value.clone())
                    })?;
                    assert_eq!(store.load(key)?.as_ref(), previous.map(|_| new_value));
                }
            };
            Ok(())
        }
    }

    // Strategy to generate lists of store operations.
    let store_ops_strategy = {
        let keys = prop_oneof!(r"[a-z]{0,5}", ".*");
        let values = prop_oneof!(keys.clone()); // TODO: Non-string values
        let half_ops = prop_oneof!(
            (Just("Save"), values.clone().prop_map(Some)),
            (Just("Delete"), Just(None)),
            (Just("AlterId"), Just(None)),
            (Just("AlterConst"), proptest::option::of(values.clone())),
            (Just("AlterUpdate"), values.clone().prop_map(Some)),
        );

        // This strategy will generate key / value pairs with multiple values per key,
        // and shuffle them to have some interleaving, for bugs that depend on that.
        proptest::collection::hash_map(keys, proptest::collection::vec(half_ops, 0..10), 0..10)
            .prop_map(flatten_key_values)
            .prop_map(|pairs: Vec<_>| -> Vec<StoreOp> {
                pairs
                    .into_iter()
                    .map(|(key, half_op)| -> StoreOp {
                        match half_op {
                            ("Save", Some(value)) => Save { key, value },
                            ("Delete", None) => Delete { key },
                            ("AlterId", None) => AlterId { key },
                            ("AlterConst", replacement) => AlterConst { key, replacement },
                            ("AlterUpdate", Some(new_value)) => AlterUpdate { key, new_value },
                            unexpected => panic!("unexpected: {:?}", unexpected),
                        }
                    })
                    .collect()
            })
            .prop_shuffle()
    };

    /// Helper: Check that store state matches model.
    fn check_state(store1: &impl InspectStore<V>, store2: &impl InspectStore<V>) -> TestCaseResult {
        prop_assert_eq!(store1.to_map(), store2.to_map());
        Ok(())
    }

    fn test(store_ops_vec: Vec<StoreOp>) -> TestCaseResult {
        // Init the models
        let store_model = &mut InMemoryStore::default();
        let store_model_json = &mut InMemoryJsonStore::default();

        // Init the store under test
        let temp_dir = TempDir::new().unwrap();
        let store_fs = &mut FsStore::new(&temp_dir, StdFiler);

        for ref op in store_ops_vec {
            op.apply(store_model).unwrap();
            op.apply(store_model_json).unwrap();
            op.apply(store_fs).unwrap();

            // Models match each other
            check_state(store_model, store_model_json)?;
            // Models match store_fs
            check_state(store_model, store_fs)?;
            check_state(store_model_json, store_fs)?;
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

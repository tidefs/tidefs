//! Catalog delta handlers for the cluster epoch commit path.
//!
//! Provides the concrete wiring between [`ClusterLeaseRuntime`] and the
//! cluster's epoch commit infrastructure:
//!
//! - [`make_coordinator_handler`] produces a `Box<dyn FnMut(&[u8])>` for
//!   [`CommitCoordinatorTransportBridge::with_catalog_delta_handler`] so
//!   the coordinator node applies committed catalog deltas directly.
//!
//! - [`CatalogDeltaSubscriber`] implements [`EpochCommitSubscriber`] for
//!   peer nodes, processing catalog deltas arriving through the
//!   [`EpochCommitBus`] subscriber dispatch.
//!
//! Both paths deserialize a [`CatalogDelta`] from raw bytes and apply it
//! via [`ClusterLeaseRuntime::apply_committed_catalog_delta`].

use std::sync::{Arc, Mutex};

use tidefs_membership_epoch::epoch_commit_subscriber::{
    EpochCommitNotification, EpochCommitSubscriber,
};

use crate::runtime::ClusterLeaseRuntime;

pub type CatalogDeltaHandler = Box<dyn FnMut(&[u8]) + Send>;

/// Create a coordinator-side catalog delta handler suitable for
/// [`CommitCoordinatorTransportBridge::with_catalog_delta_handler`].
///
/// The handler deserializes the raw bytes into a [`CatalogDelta`] and
/// applies it through the shared runtime. Errors are logged (via `eprintln`
/// for now; integration with a real logging framework is deferred to
/// the storage-node wiring).
///
/// The returned closure is `Send` so it can be stored in the bridge.
pub fn make_coordinator_handler(runtime: Arc<Mutex<ClusterLeaseRuntime>>) -> CatalogDeltaHandler {
    Box::new(move |delta_bytes: &[u8]| match runtime.lock() {
        Ok(mut guard) => match guard.apply_committed_catalog_delta(delta_bytes) {
            Some(Ok(version)) => {
                eprintln!(
                    "catalog delta applied: version={version} len={}",
                    guard.pool_catalog().map(|c| c.len()).unwrap_or(0)
                );
            }
            Some(Err(e)) => {
                eprintln!("catalog delta apply error: {e}");
            }
            None => {
                eprintln!("catalog delta ignored: no pool catalog configured");
            }
        },
        Err(_) => {
            eprintln!("catalog delta handler: runtime lock poisoned");
        }
    })
}

/// An [`EpochCommitSubscriber`] that applies committed catalog deltas
/// on peer nodes via the [`EpochCommitBus`] subscriber dispatch.
///
/// Register this with the bus after constructing the runtime:
///
/// ```ignore
/// use tidefs_cluster::catalog_commit_handler::CatalogDeltaSubscriber;
///
/// let sub = CatalogDeltaSubscriber::new(Arc::clone(&runtime_arc));
/// epoch_commit_bus.register(Box::new(sub));
/// ```
pub struct CatalogDeltaSubscriber {
    runtime: Arc<Mutex<ClusterLeaseRuntime>>,
}

impl CatalogDeltaSubscriber {
    /// Create a new subscriber backed by the shared runtime.
    pub fn new(runtime: Arc<Mutex<ClusterLeaseRuntime>>) -> Self {
        Self { runtime }
    }
}

impl EpochCommitSubscriber for CatalogDeltaSubscriber {
    fn on_epoch_committed(&self, notification: &EpochCommitNotification) {
        if let Some(ref delta_bytes) = notification.catalog_delta_bytes {
            match self.runtime.lock() {
                Ok(mut guard) => {
                    if let Some(Err(e)) = guard.apply_committed_catalog_delta(delta_bytes) {
                        eprintln!(
                            "catalog delta subscriber: apply error for epoch {:?}: {e}",
                            notification.epoch
                        );
                    }
                }
                Err(_) => {
                    eprintln!("catalog delta subscriber: runtime lock poisoned");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataset_catalog::{CatalogDelta, ClusterPoolCatalog};
    use tidefs_dataset_catalog::{DatasetFlags, DatasetType};
    use tidefs_membership_epoch::EpochId;
    use tokio::sync::mpsc;

    fn make_runtime() -> ClusterLeaseRuntime {
        let (tx, _rx) = mpsc::unbounded_channel();
        ClusterLeaseRuntime::new(1, EpochId(1), Default::default(), tx)
    }

    fn make_pool_catalog() -> ClusterPoolCatalog {
        let uuid = [0xAAu8; 16];
        let mut pc = ClusterPoolCatalog::new("testpool", uuid);
        // Seed root entry
        pc.apply_committed_delta(&CatalogDelta::Create {
            path: "testpool".into(),
            dataset_id_bytes: vec![0u8; 16],
            dataset_type_u8: DatasetType::Filesystem.to_u8(),
            creation_txg: 1,
            properties: vec![],
            flags_u16: 0,
        })
        .unwrap();
        pc
    }

    #[test]
    fn coordinator_handler_applies_delta() {
        let mut rt = make_runtime();
        let pool = make_pool_catalog();
        rt = rt.with_pool_catalog(pool);
        let rt = Arc::new(Mutex::new(rt));

        // Create a FS1 delta
        let delta = CatalogDelta::Create {
            path: "testpool/fs1".into(),
            dataset_id_bytes: vec![1u8; 16],
            dataset_type_u8: DatasetType::Filesystem.to_u8(),
            creation_txg: 100,
            properties: vec![],
            flags_u16: DatasetFlags::default_create().bits(),
        };
        let encoded = bincode::serialize(&delta).unwrap();

        let mut handler = make_coordinator_handler(Arc::clone(&rt));
        handler(&encoded);

        let guard = rt.lock().unwrap();
        let pool = guard.pool_catalog().unwrap();
        assert!(pool.catalog().catalog().contains("testpool/fs1"));
        assert_eq!(pool.version(), 2); // root (v1) + fs1 (v2)
    }

    #[test]
    fn coordinator_handler_no_catalog_no_panic() {
        let rt = make_runtime();
        let rt = Arc::new(Mutex::new(rt));

        let delta = CatalogDelta::Create {
            path: "testpool/fs1".into(),
            dataset_id_bytes: vec![1u8; 16],
            dataset_type_u8: DatasetType::Filesystem.to_u8(),
            creation_txg: 100,
            properties: vec![],
            flags_u16: 0,
        };
        let encoded = bincode::serialize(&delta).unwrap();

        let mut handler = make_coordinator_handler(Arc::clone(&rt));
        handler(&encoded); // should not panic, just eprintln

        // No catalog, no state change
        let guard = rt.lock().unwrap();
        assert!(guard.pool_catalog().is_none());
    }

    #[test]
    fn coordinator_handler_corrupt_bytes_is_safe() {
        let mut rt = make_runtime();
        rt = rt.with_pool_catalog(make_pool_catalog());
        let rt = Arc::new(Mutex::new(rt));

        let mut handler = make_coordinator_handler(Arc::clone(&rt));
        handler(&[0xFFu8; 10]); // corrupt — should not panic

        // Catalog version unchanged
        let guard = rt.lock().unwrap();
        assert_eq!(guard.pool_catalog().unwrap().version(), 1); // only root
    }

    #[test]
    fn subscriber_applies_delta_from_notification() {
        let mut rt = make_runtime();
        rt = rt.with_pool_catalog(make_pool_catalog());
        let rt = Arc::new(Mutex::new(rt));

        let delta = CatalogDelta::Create {
            path: "testpool/vol1".into(),
            dataset_id_bytes: vec![2u8; 16],
            dataset_type_u8: DatasetType::Volume.to_u8(),
            creation_txg: 200,
            properties: vec![],
            flags_u16: DatasetFlags::READONLY.bits(),
        };
        let encoded = bincode::serialize(&delta).unwrap();

        let sub = CatalogDeltaSubscriber::new(Arc::clone(&rt));
        let notification = EpochCommitNotification {
            epoch: EpochId(5),
            roster_hash: [0u8; 32],
            member_ids: vec![1, 2],
            commit_index: 3,
            catalog_delta_bytes: Some(encoded),
        };
        sub.on_epoch_committed(&notification);

        let guard = rt.lock().unwrap();
        let pool = guard.pool_catalog().unwrap();
        assert!(pool.catalog().catalog().contains("testpool/vol1"));
        assert_eq!(pool.version(), 2);
    }

    #[test]
    fn subscriber_no_delta_is_noop() {
        let mut rt = make_runtime();
        rt = rt.with_pool_catalog(make_pool_catalog());
        let rt = Arc::new(Mutex::new(rt));

        let sub = CatalogDeltaSubscriber::new(Arc::clone(&rt));
        let notification = EpochCommitNotification {
            epoch: EpochId(5),
            roster_hash: [0u8; 32],
            member_ids: vec![1, 2],
            commit_index: 3,
            catalog_delta_bytes: None,
        };
        sub.on_epoch_committed(&notification);

        // No catalog change
        let guard = rt.lock().unwrap();
        assert_eq!(guard.pool_catalog().unwrap().version(), 1);
    }

    #[test]
    fn send_trait_satisfied() {
        // Compile-time check: make_coordinator_handler returns Send
        fn _assert_send<T: Send>(_: T) {}
        let (tx, _rx) = mpsc::unbounded_channel();
        let rt = ClusterLeaseRuntime::new(1, EpochId(1), Default::default(), tx);
        let rt = Arc::new(Mutex::new(rt));
        let handler = make_coordinator_handler(rt);
        _assert_send(handler);
    }
}

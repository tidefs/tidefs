//! Object scanner that walks the live-object set from a committed root.
//!
//! [`ObjectScanner`] iterates over allocated objects in deterministic order
//! and respects the ledger's last-scanned position so incremental progress
//! is possible across crash-restart cycles.

use std::sync::Arc;

/// An allocated object as seen by the block allocator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedObject {
    /// Unique object identifier.
    pub object_id: u64,
    /// Total object size in bytes.
    pub size: u64,
    /// The BLAKE3-256 content hash stored at allocation time.
    pub stored_hash: [u8; 32],
}

/// Trait abstracting object enumeration from a block allocator anchored
/// at a committed root.
pub trait ObjectIndex: Send + Sync {
    /// Return all allocated objects reachable from the given committed root.
    ///
    /// Objects are returned in deterministic order (by object_id ascending).
    fn list_objects(&self, committed_root: u64) -> Vec<ScannedObject>;
}

/// Iterator-like scanner that walks the live-object set anchored at a
/// committed root, respecting a resume position from the scrub ledger.
pub struct ObjectScanner<I: ObjectIndex> {
    index: Arc<I>,
}

impl<I: ObjectIndex> ObjectScanner<I> {
    /// Create a new scanner wrapping the given object index.
    #[must_use]
    pub fn new(index: Arc<I>) -> Self {
        Self { index }
    }

    /// Return objects starting after `resume_from_id` (the last-scanned
    /// object ID from the ledger).
    ///
    /// Objects with `object_id <= resume_from_id` are skipped.
    /// An empty pool returns an empty vector.
    #[must_use]
    pub fn scan_from(&self, committed_root: u64, resume_from_id: u64) -> Vec<ScannedObject> {
        let all = self.index.list_objects(committed_root);
        all.into_iter()
            .filter(|obj| obj.object_id > resume_from_id)
            .collect()
    }

    /// Return all objects from the committed root (no resume position).
    #[must_use]
    pub fn scan_all(&self, committed_root: u64) -> Vec<ScannedObject> {
        self.scan_from(committed_root, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Mock ObjectIndex backed by an in-memory map.
    struct MockObjectIndex {
        objects: Mutex<HashMap<u64, Vec<ScannedObject>>>,
    }

    impl MockObjectIndex {
        fn new() -> Self {
            Self {
                objects: Mutex::new(HashMap::new()),
            }
        }

        fn set_objects(&self, root: u64, objs: Vec<ScannedObject>) {
            self.objects.lock().unwrap().insert(root, objs);
        }
    }

    impl ObjectIndex for MockObjectIndex {
        fn list_objects(&self, committed_root: u64) -> Vec<ScannedObject> {
            self.objects
                .lock()
                .unwrap()
                .get(&committed_root)
                .cloned()
                .unwrap_or_default()
        }
    }

    fn make_object(id: u64, size: u64) -> ScannedObject {
        ScannedObject {
            object_id: id,
            size,
            stored_hash: [id as u8; 32],
        }
    }

    #[test]
    fn scan_from_committed_root_returns_all() {
        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(1, vec![make_object(10, 100), make_object(20, 200)]);
        let scanner = ObjectScanner::new(index);

        let results = scanner.scan_all(1);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].object_id, 10);
        assert_eq!(results[1].object_id, 20);
    }

    #[test]
    fn incremental_resume_skips_already_scanned() {
        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(
            1,
            vec![
                make_object(10, 100),
                make_object(20, 200),
                make_object(30, 300),
            ],
        );
        let scanner = ObjectScanner::new(index);

        // resume_from_id=20 means skip 10 and 20, return 30 only
        let results = scanner.scan_from(1, 20);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].object_id, 30);
    }

    #[test]
    fn empty_pool_returns_no_objects() {
        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(1, vec![]);
        let scanner = ObjectScanner::new(index);

        let results = scanner.scan_all(1);
        assert!(results.is_empty());
    }

    #[test]
    fn fully_scanned_pool_returns_empty() {
        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(1, vec![make_object(10, 100), make_object(20, 200)]);
        let scanner = ObjectScanner::new(index);

        // resume past the last object
        let results = scanner.scan_from(1, 30);
        assert!(results.is_empty());
    }

    #[test]
    fn unknown_root_returns_empty() {
        let index = Arc::new(MockObjectIndex::new());
        let scanner = ObjectScanner::new(index);

        let results = scanner.scan_all(99);
        assert!(results.is_empty());
    }

    #[test]
    fn resume_at_zero_returns_all() {
        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(1, vec![make_object(5, 50), make_object(15, 150)]);
        let scanner = ObjectScanner::new(index);

        let results = scanner.scan_from(1, 0);
        assert_eq!(results.len(), 2);
    }
}

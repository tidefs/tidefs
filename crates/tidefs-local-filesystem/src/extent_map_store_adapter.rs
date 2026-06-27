// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! ExtentMapStore adapter that bridges the online-defrag crate's
//! [`tidefs_online_defrag::ExtentMapStore`] trait to live filesystem
//! extent maps.
//!
//! The adapter holds the shared extent-map handle used by the mounted
//! filesystem. On [`save_extent_map`], the adapter calls [`ExtentMap::defrag`]
//! directly on the production extent map, which merges adjacent same-locator
//! extents without changing logical offsets or locator assignments.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tidefs_extent_map::{ExtentMap, InlineExtentMap};
use tidefs_online_defrag::ExtentMapStore;
use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapError, ExtentMapV1};

/// Shared-handle adapter that connects the online-defrag service to
/// the filesystem's in-memory extent maps.
///
/// Reads produce a temporary [`InlineExtentMap`] for fragmentation scoring;
/// writes call [`ExtentMap::defrag`] directly on the production map.
pub struct FilesystemExtentMapStore {
    extent_maps: Arc<Mutex<BTreeMap<InodeId, ExtentMap>>>,
}

use tidefs_types_vfs_core::InodeId;

impl FilesystemExtentMapStore {
    /// Create a new adapter backed by the given shared handles.
    #[must_use]
    pub fn new(extent_maps: Arc<Mutex<BTreeMap<InodeId, ExtentMap>>>) -> Self {
        Self { extent_maps }
    }
}

impl ExtentMapStore for FilesystemExtentMapStore {
    fn list_inodes(&self) -> Vec<u64> {
        let em = match self.extent_maps.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        em.keys().map(|ino| ino.get()).collect()
    }

    fn load_extent_map(&self, ino: u64) -> Result<InlineExtentMap, ExtentMapError> {
        let em_guard = self
            .extent_maps
            .lock()
            .map_err(|_| ExtentMapError::Corrupt)?;

        let em = em_guard
            .get(&InodeId::new(ino))
            .ok_or(ExtentMapError::NotFound)?;

        let file_size = em.inner().file_size();

        let entries: Vec<ExtentMapEntryV2> = em
            .lookup_range(0, u64::MAX)
            .map_err(|_| ExtentMapError::Corrupt)?;

        drop(em_guard);

        let alloc_bytes: u64 = entries
            .iter()
            .filter(|e| {
                use tidefs_types_extent_map_core::ExtentType;
                matches!(e.extent_type(), ExtentType::Data | ExtentType::Unwritten)
            })
            .map(|e| e.length)
            .sum();

        let header = ExtentMapV1 {
            root: None,
            entry_count: entries.len() as u64,
            alloc_bytes,
            file_size,
            version: 1,
        };

        Ok(InlineExtentMap::from_parts(header, entries))
    }

    fn save_extent_map(&self, ino: u64, _map: &InlineExtentMap) -> Result<(), ExtentMapError> {
        // The OnlineDefragService has already computed the fragmentation
        // score and decided this inode needs defragmentation. We apply
        // the defrag directly on the production ExtentMap, which merges
        // adjacent same-locator extents via its own internal defrag
        // logic. The _map parameter is the InlineExtentMap produced by
        // defrag_inode(); we use it only as a defrag-trigger signal and
        // let ExtentMap::defrag() do the real work.
        let mut em_guard = self
            .extent_maps
            .lock()
            .map_err(|_| ExtentMapError::Corrupt)?;

        let em = em_guard
            .get_mut(&InodeId::new(ino))
            .ok_or(ExtentMapError::NotFound)?;

        let _ = em.defrag();
        Ok(())
    }
}

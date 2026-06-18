// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Concrete ObjectEnumerator and ObjectMover implementations backed by
//! [`tidefs_locator_table::LocatorTable`].
//!
//! These bridge the device-removal driver's trait abstractions to the
//! live locator table and its optional data-mover plugin.

use std::fmt;
use std::sync::Arc;

use tidefs_block_allocator::DeviceId;
use tidefs_locator_table::{ExtentId, LocatorTable, RelocationDataMover};

use crate::{DeviceRemovalError, ObjectEnumerator, ObjectMover};

// ---------------------------------------------------------------------------
// LocatorTableObjectEnumerator
// ---------------------------------------------------------------------------

/// [`ObjectEnumerator`] backed by a live [`LocatorTable`].
///
/// Uses `LocatorTable::known_inode_numbers()` and
/// `LocatorTable::find_extents_for_device()` to discover every object
/// resident on the target device.
pub struct LocatorTableObjectEnumerator {
    locator: Arc<LocatorTable>,
}

impl LocatorTableObjectEnumerator {
    /// Wrap an existing [`LocatorTable`].
    #[must_use]
    pub fn new(locator: Arc<LocatorTable>) -> Self {
        Self { locator }
    }
}

impl fmt::Debug for LocatorTableObjectEnumerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocatorTableObjectEnumerator")
            .field("locator", &"LocatorTable { .. }")
            .finish()
    }
}

impl ObjectEnumerator for LocatorTableObjectEnumerator {
    fn enumerate_objects_on_device(
        &self,
        device_id: DeviceId,
    ) -> Result<Vec<ExtentId>, DeviceRemovalError> {
        let inos: Vec<u64> = self.locator.known_inode_numbers().into_iter().collect();
        self.locator
            .find_extents_for_device(&inos, device_id.0 as u64)
            .map_err(|e| DeviceRemovalError::EvacuationFailed {
                object_id: ExtentId(0),
                reason: format!("locator enumeration: {e}"),
            })
    }

    fn object_size_bytes(&self, extent_id: ExtentId) -> Result<u64, DeviceRemovalError> {
        // We need the inode number to look up extent metadata.
        // The LocatorTable's lookup_extent requires an inode, but we
        // only have an extent_id.  Walk known inodes and try each.
        let inos: Vec<u64> = self.locator.known_inode_numbers().into_iter().collect();
        for ino in &inos {
            if let Ok(Some(entry)) = self.locator.lookup_extent(*ino, extent_id) {
                return Ok(entry.length as u64);
            }
        }
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// LocatorTableObjectMover
// ---------------------------------------------------------------------------

/// [`ObjectMover`] backed by a [`LocatorTable`] with an optional
/// [`RelocationDataMover`].
///
/// Reads object data via the locator table's configured data mover
/// (or metadata-only if none is configured), writes to a destination
/// device, and atomically swaps the locator-table entry.
pub struct LocatorTableObjectMover {
    locator: Arc<LocatorTable>,
    data_mover: Option<Arc<dyn RelocationDataMover>>,
}

impl LocatorTableObjectMover {
    /// Wrap a [`LocatorTable`] without a data mover.
    ///
    /// Evacuation will be metadata-only: the locator entry is moved
    /// but actual data bytes are not transferred by the mover.
    /// Callers should ensure data is copied by another mechanism.
    #[must_use]
    pub fn new(locator: Arc<LocatorTable>) -> Self {
        Self {
            locator,
            data_mover: None,
        }
    }

    /// Wrap a [`LocatorTable`] with a configured data mover for
    /// actual byte-level data transfer.
    #[must_use]
    pub fn with_data_mover(
        locator: Arc<LocatorTable>,
        data_mover: Arc<dyn RelocationDataMover>,
    ) -> Self {
        Self {
            locator,
            data_mover: Some(data_mover),
        }
    }
}

impl fmt::Debug for LocatorTableObjectMover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocatorTableObjectMover")
            .field("locator", &"LocatorTable { .. }")
            .field("has_data_mover", &self.data_mover.is_some())
            .finish()
    }
}

impl ObjectMover for LocatorTableObjectMover {
    fn read_object(
        &self,
        extent_id: ExtentId,
        source_device_id: DeviceId,
    ) -> Result<Vec<u8>, DeviceRemovalError> {
        let dm = self
            .data_mover
            .as_ref()
            .ok_or_else(|| DeviceRemovalError::EvacuationFailed {
                object_id: extent_id,
                reason: "read_object requires a data mover".into(),
            })?;

        // Walk known inodes to find physical offset and length.
        let inos: Vec<u64> = self.locator.known_inode_numbers().into_iter().collect();
        for ino in &inos {
            if let Ok(Some(entry)) = self.locator.lookup_extent(*ino, extent_id) {
                // Validate source device matches expectation.
                if entry.device_id != source_device_id.0 as u64 {
                    return Err(DeviceRemovalError::EvacuationFailed {
                        object_id: extent_id,
                        reason: format!(
                            "extent on device {} but expected {}",
                            entry.device_id, source_device_id.0
                        ),
                    });
                }

                return dm
                    .read_extent(entry.device_id, entry.physical_offset, entry.length)
                    .map_err(|e| DeviceRemovalError::EvacuationFailed {
                        object_id: extent_id,
                        reason: format!("read_extent: {e}"),
                    });
            }
        }

        Err(DeviceRemovalError::EvacuationFailed {
            object_id: extent_id,
            reason: "extent not found in locator table".into(),
        })
    }

    fn write_object(
        &self,
        extent_id: ExtentId,
        dest_device_id: DeviceId,
        data: &[u8],
    ) -> Result<u64, DeviceRemovalError> {
        let len = data.len() as u64;
        let dest_device_u64 = dest_device_id.0 as u64;

        // 1. Look up the extent to find which inode holds it and its
        //    current physical offset (for the relocate call).
        let inos: Vec<u64> = self.locator.known_inode_numbers().into_iter().collect();
        let mut target_ino: Option<u64> = None;
        let mut old_physical: u64 = 0;

        for ino in &inos {
            if let Ok(Some(entry)) = self.locator.lookup_extent(*ino, extent_id) {
                target_ino = Some(*ino);
                old_physical = entry.physical_offset;
                break;
            }
        }

        let ino = target_ino.ok_or_else(|| DeviceRemovalError::EvacuationFailed {
            object_id: extent_id,
            reason: "extent not found for relocation".into(),
        })?;

        // 2. If a data mover is configured, write the data blob.
        if let Some(ref dm) = self.data_mover {
            // Use a different physical offset on the destination device.
            // For simplicity we preserve the same physical offset.
            dm.write_extent(dest_device_u64, old_physical, data)
                .map_err(|e| DeviceRemovalError::EvacuationFailed {
                    object_id: extent_id,
                    reason: format!("write_extent: {e}"),
                })?;
        }

        // 3. Update the locator-table entry to point to the new device.
        self.locator
            .relocate_extent(ino, extent_id, dest_device_u64, old_physical)
            .map_err(|e| DeviceRemovalError::EvacuationFailed {
                object_id: extent_id,
                reason: format!("relocate_extent: {e}"),
            })?;

        Ok(len)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_block_allocator::DeviceId;
    use tidefs_local_object_store::LocalObjectStore;
    use tidefs_locator_table::{ExtentId, LocatorEntry, LocatorTable};

    fn make_locator() -> LocatorTable {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(dir.path()).unwrap();
        LocatorTable::new(store, 1)
    }

    #[test]
    fn enumerator_finds_objects_on_device() {
        let locator = Arc::new(make_locator());
        let enumr = LocatorTableObjectEnumerator::new(locator.clone());

        // Insert some objects on device 7.
        locator
            .insert(
                100,
                LocatorEntry {
                    logical_offset: 0,
                    extent_id: ExtentId::from(1000u64),
                    device_id: 7,
                    physical_offset: 0,
                    length: 4096,
                    flags: 0,
                    checksum: [0u8; 32],
                },
            )
            .unwrap();
        locator
            .insert(
                100,
                LocatorEntry {
                    logical_offset: 4096,
                    extent_id: ExtentId::from(1001u64),
                    device_id: 7,
                    physical_offset: 4096,
                    length: 8192,
                    flags: 0,
                    checksum: [0u8; 32],
                },
            )
            .unwrap();
        // Object on a different device (should not be returned).
        locator
            .insert(
                200,
                LocatorEntry {
                    logical_offset: 0,
                    extent_id: ExtentId::from(2000u64),
                    device_id: 3,
                    physical_offset: 0,
                    length: 1024,
                    flags: 0,
                    checksum: [0u8; 32],
                },
            )
            .unwrap();

        let found = enumr.enumerate_objects_on_device(DeviceId(7)).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.contains(&ExtentId::from(1000u64)));
        assert!(found.contains(&ExtentId::from(1001u64)));
        assert!(!found.contains(&ExtentId::from(2000u64)));

        // Size lookup.
        let sz = enumr.object_size_bytes(ExtentId::from(1001u64)).unwrap();
        assert_eq!(sz, 8192);
    }

    #[test]
    fn mover_read_write_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(temp_dir.path()).unwrap();
        let locator = Arc::new(LocatorTable::new(store, 1));

        // Insert an object.
        locator
            .insert(
                42,
                LocatorEntry {
                    logical_offset: 0,
                    extent_id: ExtentId::from(500u64),
                    device_id: 1,
                    physical_offset: 0,
                    length: 64,
                    flags: 0,
                    checksum: [0u8; 32],
                },
            )
            .unwrap();

        // Use a simple in-memory data mover for testing.
        use std::sync::Mutex;
        struct MemDataMover {
            data: Mutex<std::collections::HashMap<(u64, u64), Vec<u8>>>,
        }
        impl MemDataMover {
            fn new() -> Self {
                Self {
                    data: Mutex::new(std::collections::HashMap::new()),
                }
            }
        }
        impl RelocationDataMover for MemDataMover {
            fn read_extent(
                &self,
                device_id: u64,
                physical_offset: u64,
                _length: u32,
            ) -> Result<Vec<u8>, tidefs_locator_table::LocatorError> {
                self.data
                    .lock()
                    .unwrap()
                    .get(&(device_id, physical_offset))
                    .cloned()
                    .ok_or(tidefs_locator_table::LocatorError::NotFound)
            }
            fn write_extent(
                &self,
                device_id: u64,
                physical_offset: u64,
                data: &[u8],
            ) -> Result<(), tidefs_locator_table::LocatorError> {
                self.data
                    .lock()
                    .unwrap()
                    .insert((device_id, physical_offset), data.to_vec());
                Ok(())
            }
        }

        let mover = LocatorTableObjectMover::with_data_mover(
            locator.clone(),
            Arc::new(MemDataMover::new()),
        );

        // Write object.
        let payload = b"hello device removal evacuation test payload";
        let written = mover
            .write_object(ExtentId::from(500u64), DeviceId(3), payload)
            .unwrap();
        assert_eq!(written, payload.len() as u64);

        // Read it back from the new device.
        let read_back = mover
            .read_object(ExtentId::from(500u64), DeviceId(3))
            .unwrap();
        assert_eq!(read_back, payload);

        // Verify the locator entry was updated.
        let entry = locator
            .lookup_extent(42, ExtentId::from(500u64))
            .unwrap()
            .unwrap();
        assert_eq!(entry.device_id, 3);
    }
}

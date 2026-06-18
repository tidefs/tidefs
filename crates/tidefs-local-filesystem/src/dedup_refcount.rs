// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Durable reference-count authority for canonical content-addressed dedup
//! objects (#6167).
//!
//! # Design
//!
//! Each canonical dedup object (stored at `content_dedup_object_key(fp)`)
//! has a sibling refcount object (stored at `content_dedup_refcount_key(fp)`)
//! that tracks the number of live per-inode chunk redirects pointing to it.
//!
//! The refcount is the production authority that owns canonical dedup object
//! lifetime:
//!
//! - `init` is called when a NEW canonical dedup object is first stored.
//! - `increment` is called when an additional dedup redirect is created
//!   (write hit, reflink, cross-session hit, overlay path).
//! - `decrement` is called when a per-inode chunk key containing a dedup
//!   redirect is being reclaimed (file deletion, truncation).
//! - When the refcount reaches zero, the caller must delete both the
//!   canonical data object and the refcount object.
//!
//! The in-memory `DedupIndex` remains a session-local lookup cache; the
//! durable refcount is the cross-session reclaimable-lifetime authority.
//!
//! # Crash / reopen safety
//!
//! Refcount objects are ordinary object-store entries. A crash after
//! increment but before the per-inode chunk redirect is committed leaves
//! the refcount temporarily high — the canonical object is retained longer
//! than strictly necessary but no data loss occurs. A crash after decrement
//! but before the reclaim drain deletes the chunk redirect leaves the
//! refcount temporarily low. Both drifts are bounded: the next refcount
//! operation on that fingerprint corrects the count through normal
//! increment/decrement paths, and any permanent drift is repaired by a
//! mount-time full-store scan (see `RebuildStats`).
//!
//! # Comparison
//!
//! - **ZFS**: on-disk DDT refcount table stored in the MOS config; ZFS
//!   dedup table entries track birth txg + refcount.
//! - **Ceph**: refcount objects in the metadata pool for each chunk.
//! - **Btrfs**: extent reference counts in the extent allocation tree.
//! - **TideFS**: lightweight per-canonical-key u64 refcount objects in the
//!   object store, rebuilt on mount if drift is detected.

//! # Nonclaim boundary (#6538)
//!
//! This module provides durable per-fingerprint refcount authority. The
//! following surfaces are intentionally not owned here and must not be
//! claimed as release validation from this crate alone:
//!
//! - `delete_canonical` is `#[allow(dead_code)]`. Actual canonical-object
//!   deletion is routed through the reclaim queue (`ReclaimQueueEntry`),
//!   not through direct `delete_canonical` calls.
//! - The reclaim drain in `drain_local_reclaim_queue_into_store` inspects
//!   per-inode chunk keys and decrements `DedupRefCount` only when entries
//!   are dequeued from the B+tree reclaim queue. A file deletion that does
//!   not trigger a reclaim drain (e.g., between `unlink` and
//!   `tick_background_services`) will leave the durable refcount unchanged
//!   until the next drain or mount-time orphan cleanup.
//! - Mount-time orphan cleanup (`orphan_cleanup::cleanup_orphans`) is a
//!   separate path that handles dedup refcount decrement for inodes that
//!   reached nlink==0 before an unclean shutdown. It is not a live-runtime
//!   reclaim path.
//! - The production dedup refcount authority is validated at Tier 1 via the
//!   `dedup_retention_gc` and `dedup_crash_reopen` integration tests, not via
//!   unit tests in this module. Mounted-FUSE, ublk, QEMU, multi-node, and
//!   full-kernel tiers require separate runtime validation output.
//!

use tidefs_local_object_store::LocalObjectStore;

use crate::object_keys;
use crate::types::ContentFingerprint;

/// Persistent reference-count authority for canonical dedup objects.
///
/// Stateless helper that reads/writes little-endian u64 refcounts in the
/// object store under `content_dedup_refcount_key(fp)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct DedupRefCount;

impl DedupRefCount {
    /// Read the current refcount. Returns 0 when no refcount entry exists.
    pub fn read(store: &LocalObjectStore, fingerprint: &ContentFingerprint) -> crate::Result<u64> {
        let key = object_keys::content_dedup_refcount_key(fingerprint);
        match store.get(key)? {
            Some(bytes) if bytes.len() >= 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[..8]);
                Ok(u64::from_le_bytes(buf))
            }
            Some(_) => Ok(0), // corrupt or truncated
            None => Ok(0),
        }
    }

    /// Initialize a refcount to 1 — called when a brand-new canonical
    /// dedup object is stored.
    pub fn init(
        store: &mut LocalObjectStore,
        fingerprint: &ContentFingerprint,
    ) -> crate::Result<()> {
        let key = object_keys::content_dedup_refcount_key(fingerprint);
        store.put(key, &1u64.to_le_bytes())?;
        Ok(())
    }

    /// Increment the refcount by 1. Returns the new count.
    ///
    /// Called when a new dedup redirect is created that points to this
    /// canonical object.
    pub fn increment(
        store: &mut LocalObjectStore,
        fingerprint: &ContentFingerprint,
    ) -> crate::Result<u64> {
        let current = Self::read(store, fingerprint)?;
        let new_count = current.saturating_add(1);
        let key = object_keys::content_dedup_refcount_key(fingerprint);
        store.put(key, &new_count.to_le_bytes())?;
        Ok(new_count)
    }

    /// Decrement the refcount by 1.
    ///
    /// Returns `Ok(true)` when the count reaches zero — the caller must
    /// delete both the canonical data and refcount objects.
    /// Returns `Ok(false)` when the count is still positive or the
    /// refcount entry does not exist (already reclaimed / never created).
    pub fn decrement(
        store: &mut LocalObjectStore,
        fingerprint: &ContentFingerprint,
    ) -> crate::Result<bool> {
        let current = Self::read(store, fingerprint)?;
        if current == 0 {
            return Ok(false);
        }
        let new_count = current.saturating_sub(1);
        let key = object_keys::content_dedup_refcount_key(fingerprint);
        if new_count == 0 {
            let _ = store.delete(key);
            Ok(true)
        } else {
            store.put(key, &new_count.to_le_bytes())?;
            Ok(false)
        }
    }

    /// Delete a canonical dedup object and its refcount entry together.
    /// Call when the refcount has reached zero.
    #[allow(dead_code)] // INTENT: available for direct deletion; reclaim drain uses queue
    pub fn delete_canonical(
        store: &mut LocalObjectStore,
        fingerprint: &ContentFingerprint,
    ) -> crate::Result<()> {
        let data_key = object_keys::content_dedup_object_key(fingerprint);
        let ref_key = object_keys::content_dedup_refcount_key(fingerprint);
        let _ = store.delete(data_key);
        let _ = store.delete(ref_key);
        Ok(())
    }
}

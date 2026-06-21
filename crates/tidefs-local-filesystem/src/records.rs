// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;
use std::string::String;
use std::vec::Vec;

use tidefs_local_object_store::{IntegrityDigest64, ObjectKey};
use tidefs_types_vfs_core::InodeId;

use crate::types::*;
use crate::FileSystemState;
/// Distinguishes the purpose of a snapshot catalog entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotKind {
    /// Standard named snapshot: retains data, blocks can be reclaimed after deletion.
    Snapshot,
    /// Writable fork of a snapshot: shares blocks with origin, tracks lineage.
    Clone,
    /// Lightweight reference: no data retention, used as an anchor for incremental replication.
    Bookmark,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SnapshotRecord {
    pub(crate) name: Vec<u8>,
    pub(crate) root: CommittedRootSummary,
    pub(crate) created_at_generation: u64,
    pub(crate) kind: SnapshotKind,
    /// For clones: name of the origin snapshot. None for regular snapshots and bookmarks.
    pub(crate) origin: Option<Vec<u8>>,
    /// Deletion is blocked while hold_count > 0.
    pub(crate) hold_count: u32,
}

impl SnapshotRecord {
    pub(crate) fn summary(&self) -> SnapshotSummary {
        SnapshotSummary {
            name: String::from_utf8_lossy(&self.name).into_owned(),
            source_transaction_id: self.root.transaction_id,
            source_generation: self.root.generation,
            created_at_generation: self.created_at_generation,
            source_root: self.root.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SuperblockRecord {
    pub(crate) next_inode_id: u64,
    pub(crate) generation: u64,
    pub(crate) inode_count: u64,
    /// Compact allocation bitmap: bit i corresponds to inode (i+1).
    /// ceil(next_inode_id / 64) words.
    pub(crate) inode_allocation_bitmap: Vec<u64>,
    /// Minimum code format version that can mount this filesystem.
    pub(crate) format_version_min: u16,
    /// Format version of the most recent writer (downgrade fence).
    pub(crate) format_version_max: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RootCommitRecord {
    pub(crate) slot: u64,
    pub(crate) transaction_id: u64,
    pub(crate) generation: u64,
    pub(crate) next_inode_id: u64,
    pub(crate) inode_count: u64,
    pub(crate) superblock_checksum: IntegrityDigest64,
    pub(crate) manifest_checksum: IntegrityDigest64,
    pub(crate) manifest_entry_count: u64,
    pub(crate) root_authentication: Option<RootAuthenticationRecord>,
}

impl RootCommitRecord {
    pub(crate) fn has_manifest(&self) -> bool {
        !self.manifest_checksum.is_zero() || self.manifest_entry_count != 0
    }

    pub(crate) fn summary(&self) -> CommittedRootSummary {
        CommittedRootSummary {
            slot: self.slot,
            transaction_id: self.transaction_id,
            generation: self.generation,
            next_inode_id: self.next_inode_id,
            inode_count: self.inode_count,
            superblock_checksum: self.superblock_checksum,
            has_transaction_manifest: self.has_manifest(),
            manifest_checksum: self.manifest_checksum,
            manifest_entry_count: self.manifest_entry_count,
            has_root_authentication: self.root_authentication.is_some(),
            root_authentication_policy_epoch: self
                .root_authentication
                .as_ref()
                .map(|record| record.policy_epoch),
            root_authentication_algorithm_suite_id: self
                .root_authentication
                .as_ref()
                .map(|record| record.algorithm_suite_id),
            superblock_digest: self
                .root_authentication
                .as_ref()
                .map(|record| record.superblock_digest),
            manifest_digest: self
                .root_authentication
                .as_ref()
                .map(|record| record.manifest_digest),
            root_authentication_code: self
                .root_authentication
                .as_ref()
                .map(|record| record.authentication_code),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContentObject {
    pub(crate) inode_id: InodeId,
    pub(crate) data_version: u64,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContentChunkRef {
    pub(crate) chunk_index: u64,
    pub(crate) data_version: u64,
    pub(crate) len: u32,
    pub(crate) checksum: IntegrityDigest64,
    /// Pool placement receipt generation that made this chunk durable.
    ///
    /// Zero means no receipt was captured (pre-v6 format, hole chunks,
    /// or writes that predate receipt capture).  When non-zero, the
    /// (object_key, generation) pair uniquely identifies the pool
    /// placement receipt that locates this extent.
    pub(crate) placement_receipt_generation: u64,
}

impl ContentChunkRef {
    /// Data-version sentinel that marks a hole (sparse) chunk.
    /// ZFS uses hole birth times in block pointers to achieve O(1) sparse truncation;
    /// TideFS uses data_version == 0 because data versions start at 1.
    pub(crate) const HOLE_SENTINEL: u64 = 0;

    /// Create a hole (sparse) chunk reference that represents zero-filled data
    /// without consuming any object-store space.
    pub(crate) fn hole(chunk_index: u64, len: u32) -> Self {
        Self {
            chunk_index,
            data_version: Self::HOLE_SENTINEL,
            len,
            checksum: IntegrityDigest64(0),
            placement_receipt_generation: 0,
        }
    }

    /// Returns true when this chunk reference represents a hole.
    ///
    /// Hole chunks carry no backing object-store data and must have
    /// placement_receipt_generation == 0.
    pub(crate) fn is_hole(&self) -> bool {
        self.data_version == Self::HOLE_SENTINEL
            && self.checksum == IntegrityDigest64(0)
            && self.placement_receipt_generation == 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContentManifestObject {
    pub(crate) inode_id: InodeId,
    pub(crate) data_version: u64,
    pub(crate) file_size: u64,
    pub(crate) chunk_size: u32,
    pub(crate) chunks: Vec<ContentChunkRef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContentChunkObject {
    pub(crate) inode_id: InodeId,
    pub(crate) data_version: u64,
    pub(crate) chunk_index: u64,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ContentLayout {
    Inline(ContentObject),
    Chunked(ContentManifestObject),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct RootIdentity {
    pub(crate) transaction_id: u64,
    pub(crate) generation: u64,
    pub(crate) superblock_checksum: u64,
}

impl RootIdentity {
    pub(crate) fn from_summary(summary: &CommittedRootSummary) -> Self {
        Self {
            transaction_id: summary.transaction_id,
            generation: summary.generation,
            superblock_checksum: summary.superblock_checksum.get(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceCreateIntentRecord {
    pub(crate) parent_inode_id: InodeId,
    pub(crate) entry: NamespaceEntry,
    pub(crate) inode: InodeRecord,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedChangedRecordRoot {
    pub(crate) source_root: CommittedRootSummary,
    pub(crate) state: FileSystemState,
    pub(crate) records: BTreeMap<ObjectKey, ChangedObjectRecord>,
}

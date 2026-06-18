// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_local_object_store::ObjectKey;
use tidefs_types_vfs_core::InodeId;

use crate::constants::*;
pub fn superblock_object_key() -> ObjectKey {
    ObjectKey::from_name(FILESYSTEM_SUPERBLOCK_OBJECT_NAME)
}

pub fn dataset_catalog_object_key() -> ObjectKey {
    ObjectKey::from_name(DATASET_CATALOG_OBJECT_NAME)
}

pub fn pool_properties_object_key() -> ObjectKey {
    ObjectKey::from_name(POOL_PROPERTIES_OBJECT_NAME)
}

pub fn inode_object_key(inode_id: InodeId) -> ObjectKey {
    ObjectKey::from_name(format!(
        "{FILESYSTEM_INODE_OBJECT_PREFIX}/{:016x}",
        inode_id.get()
    ))
}

pub fn directory_object_key(inode_id: InodeId) -> ObjectKey {
    ObjectKey::from_name(format!(
        "{FILESYSTEM_DIRECTORY_OBJECT_PREFIX}/{:016x}",
        inode_id.get()
    ))
}

pub fn content_object_key(inode_id: InodeId) -> ObjectKey {
    ObjectKey::from_name(format!(
        "{FILESYSTEM_CONTENT_OBJECT_PREFIX}/{:016x}",
        inode_id.get()
    ))
}

// Review debt TFR-005: data_version is storage key material, not just mtime.
pub fn content_object_key_for_version(inode_id: InodeId, data_version: u64) -> ObjectKey {
    ObjectKey::from_name(format!(
        "{FILESYSTEM_CONTENT_OBJECT_PREFIX}/{:016x}/v{data_version:016x}",
        inode_id.get()
    ))
}

pub fn content_chunk_object_key_for_version(
    inode_id: InodeId,
    data_version: u64,
    chunk_index: u64,
) -> ObjectKey {
    ObjectKey::from_name(format!(
        "{FILESYSTEM_CONTENT_OBJECT_PREFIX}/{:016x}/v{data_version:016x}/chunk/{chunk_index:016x}",
        inode_id.get()
    ))
}

pub fn root_slot_object_key(slot: u64) -> ObjectKey {
    ObjectKey::from_name(format!("{FILESYSTEM_ROOT_OBJECT_PREFIX}/{slot:02x}"))
}

pub fn transaction_superblock_object_key(transaction_id: u64) -> ObjectKey {
    ObjectKey::from_name(format!(
        "{FILESYSTEM_TRANSACTION_OBJECT_PREFIX}/{transaction_id:016x}/superblock"
    ))
}

pub fn transaction_manifest_object_key(transaction_id: u64) -> ObjectKey {
    ObjectKey::from_name(format!(
        "{FILESYSTEM_TRANSACTION_OBJECT_PREFIX}/{transaction_id:016x}/manifest"
    ))
}

pub fn transaction_inode_object_key(transaction_id: u64, inode_id: InodeId) -> ObjectKey {
    ObjectKey::from_name(format!(
        "{FILESYSTEM_TRANSACTION_OBJECT_PREFIX}/{transaction_id:016x}/inode/{:016x}",
        inode_id.get()
    ))
}

pub fn transaction_directory_object_key(transaction_id: u64, inode_id: InodeId) -> ObjectKey {
    ObjectKey::from_name(format!(
        "{FILESYSTEM_TRANSACTION_OBJECT_PREFIX}/{transaction_id:016x}/directory/{:016x}",
        inode_id.get()
    ))
}

pub fn intent_log_entry_object_key(entry_id: u64) -> ObjectKey {
    ObjectKey::from_name(format!(
        "{FILESYSTEM_INTENT_LOG_OBJECT_PREFIX}/entry/{entry_id:016x}"
    ))
}

/// Intent-log data payload for a given entry (stores write data for crash replay).
pub fn intent_log_data_object_key(entry_id: u64) -> ObjectKey {
    ObjectKey::from_name(format!(
        "{FILESYSTEM_INTENT_LOG_OBJECT_PREFIX}/data/{entry_id:016x}"
    ))
}

pub fn intent_log_head_object_key() -> ObjectKey {
    ObjectKey::from_name(format!("{FILESYSTEM_INTENT_LOG_OBJECT_PREFIX}/head"))
}

pub fn content_dedup_object_key(fingerprint: &crate::types::ContentFingerprint) -> ObjectKey {
    ObjectKey::from_name(format!(
        "tidefs.local-filesystem.v1.content-dedup/{fingerprint}"
    ))
}

/// Refcount key for a canonical dedup object.
///
/// Stores a little-endian u64 reference count in a dedicated object-store
/// key so the reclaim authority can determine when a canonical dedup object
/// has no remaining file references and can be freed.
pub fn content_dedup_refcount_key(fingerprint: &crate::types::ContentFingerprint) -> ObjectKey {
    ObjectKey::from_name(format!(
        "tidefs.local-filesystem.v1.content-dedup-refcount/{fingerprint}"
    ))
}

pub fn transaction_snapshot_catalog_entry_object_key(
    transaction_id: u64,
    name: &[u8],
) -> ObjectKey {
    let prefix = format!("{FILESYSTEM_SNAPSHOT_CATALOG_OBJECT_PREFIX}/{transaction_id:016x}/");
    let mut name_hex = String::new();
    for byte in name {
        use std::fmt::Write;
        write!(&mut name_hex, "{byte:02x}").unwrap();
    }
    ObjectKey::from_name(format!("{prefix}{name_hex}"))
}

/// Object key for the dataset space counters (logical used, reserved, etc.).
pub fn space_counters_object_key() -> ObjectKey {
    ObjectKey::from_name("tidefs:space:counters:v0")
}

/// Object key for the persisted orphan index B+tree.
pub fn orphan_index_object_key() -> ObjectKey {
    ObjectKey::from_name(crate::constants::FILESYSTEM_ORPHAN_INDEX_OBJECT_NAME)
}

/// Object key for the orphan index B+tree root pointer (u64).
/// Stored separately so the root survives independently of the full-log encoding.
pub fn orphan_index_root_object_key() -> ObjectKey {
    ObjectKey::from_name("tidefs:orphan-index-root:v0")
}

/// Object key for persisted dataset feature flags roots.
pub fn feature_flags_roots_object_key() -> ObjectKey {
    ObjectKey::from_name("tidefs:dataset:feature-flags-roots:v0")
}
/// Object key for the extent map of a specific inode within a transaction.
pub fn transaction_extent_map_object_key(transaction_id: u64, inode_id: InodeId) -> ObjectKey {
    ObjectKey::from_name(format!(
        "{FILESYSTEM_TRANSACTION_OBJECT_PREFIX}/{transaction_id:016x}/extent-map/{:016x}",
        inode_id.get()
    ))
}

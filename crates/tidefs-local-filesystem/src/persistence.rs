// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;
use std::path::Path;

use tidefs_local_object_store::{checksum64, pool::Pool, LocalObjectStore, StoreError};
use tidefs_types_vfs_core::InodeId;

use crate::constants::*;
use crate::content::MountedContentReadAuthority;
use crate::decode_content_layout;
use crate::dedup::DedupIndex;
use crate::encoding::*;
use crate::error::FileSystemError;
use crate::object_keys::*;
use crate::read_content_chunk_from_store;
use crate::read_content_from_store;
use crate::records::*;
use crate::types::*;
use crate::validate_content_layout;
use crate::write_chunked_content;
use crate::FileSystemState;
use crate::Result;
#[cfg(test)]
pub(crate) fn persist_state(
    store: &mut LocalObjectStore,
    state: &FileSystemState,
    root_authentication_key: RootAuthenticationKey,
) -> Result<()> {
    let _ = persist_state_until_boundary(store, state, root_authentication_key, None)?;
    Ok(())
}

/// Persist a mounted transaction with file content validated through Pool
/// placement authority and transaction metadata retained on the raw primary.
pub(crate) fn persist_state_with_pool(
    pool: &mut Pool,
    state: &FileSystemState,
    root_authentication_key: RootAuthenticationKey,
) -> Result<()> {
    let _ = persist_state_with_pool_until_boundary(pool, state, root_authentication_key, None)?;
    Ok(())
}

pub(crate) fn persist_state_with_pool_until_boundary(
    pool: &mut Pool,
    state: &FileSystemState,
    root_authentication_key: RootAuthenticationKey,
    stop_after: Option<FilesystemCommitBoundary>,
) -> Result<FilesystemCommitBoundary> {
    let transaction_id = state.generation.max(ROOT_COMMIT_MIN_TRANSACTION_ID);
    let content_entries = pool_content_manifest_entries_for_state(pool, state)?;
    let root = persist_transaction_objects_with_precomputed_content(
        pool.raw_primary_store_mut(),
        state,
        transaction_id,
        &content_entries,
    )?;
    if stop_after == Some(FilesystemCommitBoundary::TransactionObjectsWritten) {
        return Ok(FilesystemCommitBoundary::TransactionObjectsWritten);
    }
    sync_pool_after_commit_boundary(pool, FilesystemCommitBoundary::TransactionObjectsWritten)
        .map_err(FileSystemError::from)?;
    if stop_after == Some(FilesystemCommitBoundary::TransactionObjectsSynced) {
        return Ok(FilesystemCommitBoundary::TransactionObjectsSynced);
    }
    publish_root_commit(pool.raw_primary_store_mut(), &root, root_authentication_key)?;
    if stop_after == Some(FilesystemCommitBoundary::RootCommitWritten) {
        return Ok(FilesystemCommitBoundary::RootCommitWritten);
    }
    sync_pool_after_commit_boundary(pool, FilesystemCommitBoundary::RootCommitWritten).map_err(
        |source| FileSystemError::PublishOutcomeUncertain {
            completed_boundary: FilesystemCommitBoundary::RootCommitWritten,
            recovery_expectation: CrashRecoveryExpectation::OldOrNewCommittedRoot,
            live_state_reconciled: true,
            source,
        },
    )?;
    Ok(FilesystemCommitBoundary::RootCommitSynced)
}

pub(crate) fn persist_state_until_boundary(
    store: &mut LocalObjectStore,
    state: &FileSystemState,
    root_authentication_key: RootAuthenticationKey,
    stop_after: Option<FilesystemCommitBoundary>,
) -> Result<FilesystemCommitBoundary> {
    let transaction_id = state.generation.max(ROOT_COMMIT_MIN_TRANSACTION_ID);
    let root = persist_transaction_objects(store, state, transaction_id)?;
    if stop_after == Some(FilesystemCommitBoundary::TransactionObjectsWritten) {
        return Ok(FilesystemCommitBoundary::TransactionObjectsWritten);
    }
    sync_store_after_commit_boundary(store, FilesystemCommitBoundary::TransactionObjectsWritten)
        .map_err(FileSystemError::from)?;
    if stop_after == Some(FilesystemCommitBoundary::TransactionObjectsSynced) {
        return Ok(FilesystemCommitBoundary::TransactionObjectsSynced);
    }
    publish_root_commit(store, &root, root_authentication_key)?;
    if stop_after == Some(FilesystemCommitBoundary::RootCommitWritten) {
        return Ok(FilesystemCommitBoundary::RootCommitWritten);
    }
    sync_store_after_commit_boundary(store, FilesystemCommitBoundary::RootCommitWritten).map_err(
        |source| FileSystemError::PublishOutcomeUncertain {
            completed_boundary: FilesystemCommitBoundary::RootCommitWritten,
            recovery_expectation: CrashRecoveryExpectation::OldOrNewCommittedRoot,
            live_state_reconciled: true,
            source,
        },
    )?;
    Ok(FilesystemCommitBoundary::RootCommitSynced)
}

pub(crate) fn sync_store_after_commit_boundary(
    store: &mut LocalObjectStore,
    boundary: FilesystemCommitBoundary,
) -> std::result::Result<(), StoreError> {
    maybe_inject_sync_failure_after_boundary(store, boundary)?;
    store.sync_all()
}

fn sync_pool_after_commit_boundary(
    pool: &mut Pool,
    boundary: FilesystemCommitBoundary,
) -> std::result::Result<(), StoreError> {
    maybe_inject_sync_failure_after_boundary(pool.raw_primary_store(), boundary)?;
    pool.sync_all()
}

#[cfg(not(test))]
pub(crate) fn maybe_inject_sync_failure_after_boundary(
    _store: &LocalObjectStore,
    _boundary: FilesystemCommitBoundary,
) -> std::result::Result<(), StoreError> {
    Ok(())
}

#[cfg(test)]
thread_local! {
    static TEST_SYNC_FAILURE_AFTER_BOUNDARY: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn inject_next_sync_failure_after_boundary(boundary: FilesystemCommitBoundary) {
    TEST_SYNC_FAILURE_AFTER_BOUNDARY
        .with(|failure| failure.set(test_sync_failure_boundary_code(boundary)));
}

#[cfg(test)]
pub(crate) fn maybe_inject_sync_failure_after_boundary(
    store: &LocalObjectStore,
    boundary: FilesystemCommitBoundary,
) -> std::result::Result<(), StoreError> {
    let expected = test_sync_failure_boundary_code(boundary);
    let should_fail = TEST_SYNC_FAILURE_AFTER_BOUNDARY.with(|failure| {
        if failure.get() == expected {
            failure.set(0);
            true
        } else {
            false
        }
    });
    if should_fail {
        return Err(StoreError::Io {
            operation: "sync_all",
            path: store.root().join("<injected filesystem sync failure>"),
            source: std::io::Error::other("injected filesystem sync failure"),
        });
    }
    Ok(())
}

#[cfg(test)]
const fn test_sync_failure_boundary_code(boundary: FilesystemCommitBoundary) -> u8 {
    match boundary {
        FilesystemCommitBoundary::TransactionObjectsWritten => 1,
        FilesystemCommitBoundary::TransactionObjectsSynced => 2,
        FilesystemCommitBoundary::RootCommitWritten => 3,
        FilesystemCommitBoundary::RootCommitSynced => 4,
    }
}

pub(crate) fn ensure_versioned_content_object(
    store: &mut LocalObjectStore,
    inode: &InodeRecord,
    compression_policy: &ContentCompressionPolicy,
) -> Result<()> {
    let content_key = content_object_key_for_version(inode.inode_id, inode.data_version);
    if store.get(content_key)?.is_some() {
        return Ok(());
    }
    if inode.size == 0 {
        return Ok(());
    }
    let content = read_content_from_store(store, inode.inode_id, inode, true, None)?;
    write_chunked_content(
        false,
        store,
        inode,
        &content,
        &mut DedupIndex::new(),
        None,
        compression_policy,
    )
}

pub(crate) fn transaction_manifest_entries_for_existing_content(
    store: &LocalObjectStore,
    inode: &InodeRecord,
) -> Result<Vec<TransactionManifestEntry>> {
    transaction_manifest_entries_for_content(store, inode, true)
}

pub(crate) fn transaction_manifest_entries_for_content(
    store: &LocalObjectStore,
    inode: &InodeRecord,
    verify_chunk_payloads: bool,
) -> Result<Vec<TransactionManifestEntry>> {
    let content_key = content_object_key_for_version(inode.inode_id, inode.data_version);
    let Some(content_bytes) = store.get(content_key)? else {
        if inode.size == 0 {
            return Ok(Vec::new());
        }
        return Err(FileSystemError::CorruptState {
            reason: "transaction manifest validation expected a missing content object",
        });
    };
    let layout = decode_content_layout(&content_bytes)?;
    validate_content_layout(inode.inode_id, inode, &layout)?;

    let mut entries = vec![TransactionManifestEntry {
        role: TransactionManifestObjectRole::VersionedContent,
        object_key: content_key,
        checksum: checksum64(&content_bytes),
    }];
    if let ContentLayout::Chunked(manifest) = layout {
        for chunk_ref in &manifest.chunks {
            // Hole (sparse) chunks have no backing object-store data.
            if chunk_ref.is_hole() {
                continue;
            }
            let object_key = content_chunk_object_key_for_version(
                manifest.inode_id,
                chunk_ref.data_version,
                chunk_ref.chunk_index,
            );
            if verify_chunk_payloads {
                // Check stored bytes to determine if this is a dedup redirect.
                // For dedup-resolved chunks the canonical data carries a
                // different chunk_index, inode_id, and data_version than the
                // redirect reference (#841). The checksum validation in
                // read_content_chunk_from_store already ensures data integrity;
                // only verify chunk_index for non-dedup chunks.
                let stored_bytes = store
                    .get(object_key)?
                    .ok_or(FileSystemError::CorruptState {
                        reason: "transaction manifest references a missing content chunk",
                    })?;
                let is_dedup = crate::encoding::is_dedup_redirect(&stored_bytes);
                let chunk =
                    read_content_chunk_from_store(store, manifest.inode_id, chunk_ref, None)?;
                if !is_dedup && chunk.chunk_index != chunk_ref.chunk_index {
                    return Err(FileSystemError::CorruptState {
                        reason: "content chunk does not match manifest",
                    });
                }
            } else if !store.contains_key(object_key) {
                return Err(FileSystemError::CorruptState {
                    reason: "transaction manifest references a missing content chunk",
                });
            }
            entries.push(TransactionManifestEntry {
                role: TransactionManifestObjectRole::VersionedContentChunk,
                object_key,
                checksum: chunk_ref.checksum,
            });
        }
    }
    Ok(entries)
}

/// Build committed-root content entries exclusively from Pool-authorized
/// reads. Raw-primary bytes cannot satisfy this mounted persistence boundary.
pub(crate) fn transaction_manifest_entries_for_pool_content(
    pool: &Pool,
    inode: &InodeRecord,
) -> Result<Vec<TransactionManifestEntry>> {
    let authority = MountedContentReadAuthority::new(pool);
    let content_key = content_object_key_for_version(inode.inode_id, inode.data_version);
    let Some(content_bytes) = authority.read_current_object(content_key)? else {
        if inode.size == 0 {
            return Ok(Vec::new());
        }
        return Err(FileSystemError::ReceiptAuthorityMissing {
            object_key: content_key,
            expected_generation: 0,
        });
    };
    let layout = decode_content_layout(&content_bytes)?;
    validate_content_layout(inode.inode_id, inode, &layout)?;

    let mut entries = vec![TransactionManifestEntry {
        role: TransactionManifestObjectRole::VersionedContent,
        object_key: content_key,
        checksum: checksum64(&content_bytes),
    }];
    if let ContentLayout::Chunked(manifest) = layout {
        for chunk_ref in &manifest.chunks {
            if chunk_ref.is_hole() {
                continue;
            }
            let _ = authority.read_current_chunk(manifest.inode_id, chunk_ref)?;
            entries.push(TransactionManifestEntry {
                role: TransactionManifestObjectRole::VersionedContentChunk,
                object_key: content_chunk_object_key_for_version(
                    manifest.inode_id,
                    chunk_ref.data_version,
                    chunk_ref.chunk_index,
                ),
                checksum: chunk_ref.checksum,
            });
        }
    }
    Ok(entries)
}

fn pool_content_manifest_entries_for_state(
    pool: &Pool,
    state: &FileSystemState,
) -> Result<BTreeMap<InodeId, Vec<TransactionManifestEntry>>> {
    let mut entries = BTreeMap::new();
    for inode in state.inodes.values().filter(|inode| inode.is_file_like()) {
        entries.insert(
            inode.inode_id,
            transaction_manifest_entries_for_pool_content(pool, inode)?,
        );
    }
    Ok(entries)
}

pub(crate) fn fs_io_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> FileSystemError {
    FileSystemError::Store(StoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    })
}

pub(crate) fn persist_transaction_objects(
    store: &mut LocalObjectStore,
    state: &FileSystemState,
    transaction_id: u64,
) -> Result<RootCommitRecord> {
    persist_transaction_objects_impl(store, state, transaction_id, None)
}

fn persist_transaction_objects_with_precomputed_content(
    store: &mut LocalObjectStore,
    state: &FileSystemState,
    transaction_id: u64,
    content_entries: &BTreeMap<InodeId, Vec<TransactionManifestEntry>>,
) -> Result<RootCommitRecord> {
    persist_transaction_objects_impl(store, state, transaction_id, Some(content_entries))
}

fn persist_transaction_objects_impl(
    store: &mut LocalObjectStore,
    state: &FileSystemState,
    transaction_id: u64,
    precomputed_content_entries: Option<&BTreeMap<InodeId, Vec<TransactionManifestEntry>>>,
) -> Result<RootCommitRecord> {
    let mut manifest_entries = Vec::new();
    for inode in state.inodes.values() {
        let is_dirty = state.dirty_inodes.contains(&inode.inode_id);
        let needs_inode_write =
            is_dirty || !state.last_inode_write_tx.contains_key(&inode.inode_id);

        if inode.is_file_like() && precomputed_content_entries.is_some() {
            let entries = precomputed_content_entries
                .and_then(|entries| entries.get(&inode.inode_id))
                .ok_or(FileSystemError::CorruptState {
                    reason: "mounted transaction is missing prevalidated content entries",
                })?;
            manifest_entries.extend(entries.iter().cloned());
        } else if inode.is_file_like() && needs_inode_write {
            ensure_versioned_content_object(store, inode, &state.content_compression_policy)?;
            manifest_entries.extend(transaction_manifest_entries_for_content(
                store, inode, false,
            )?);
        } else if inode.is_file_like() {
            manifest_entries.extend(transaction_manifest_entries_for_existing_content(
                store, inode,
            )?);
        }

        if needs_inode_write {
            let inode_key = transaction_inode_object_key(transaction_id, inode.inode_id);
            let inode_bytes = try_encode_inode(inode)?;
            store.put(inode_key, &inode_bytes)?;
            manifest_entries.push(TransactionManifestEntry {
                role: TransactionManifestObjectRole::TransactionInode,
                object_key: inode_key,
                checksum: checksum64(&inode_bytes),
            });
        } else {
            let last_tx = state.last_inode_write_tx[&inode.inode_id];
            let last_key = transaction_inode_object_key(last_tx, inode.inode_id);
            let current_bytes = try_encode_inode(inode)?;
            let existing_bytes = store.get(last_key)?.ok_or(FileSystemError::CorruptState {
                reason: "clean inode reference points to missing object",
            })?;
            if current_bytes != existing_bytes {
                if inode.is_file_like() && precomputed_content_entries.is_none() {
                    ensure_versioned_content_object(
                        store,
                        inode,
                        &state.content_compression_policy,
                    )?;
                    manifest_entries.extend(transaction_manifest_entries_for_content(
                        store, inode, false,
                    )?);
                }
                let inode_key = transaction_inode_object_key(transaction_id, inode.inode_id);
                store.put(inode_key, &current_bytes)?;
                manifest_entries.push(TransactionManifestEntry {
                    role: TransactionManifestObjectRole::TransactionInode,
                    object_key: inode_key,
                    checksum: checksum64(&current_bytes),
                });
            } else {
                manifest_entries.push(TransactionManifestEntry {
                    role: TransactionManifestObjectRole::TransactionInode,
                    object_key: last_key,
                    checksum: checksum64(&existing_bytes),
                });
            }
        }

        if inode.carries_child_namespace() {
            let is_dir_dirty = state.dirty_dirs.contains(&inode.inode_id);
            let needs_dir_write =
                is_dir_dirty || !state.last_dir_write_tx.contains_key(&inode.inode_id);

            if needs_dir_write {
                let directory = state.directories.get(&inode.inode_id).ok_or(
                    FileSystemError::CorruptState {
                        reason: "directory inode has no directory table",
                    },
                )?;
                let directory_key =
                    transaction_directory_object_key(transaction_id, inode.inode_id);
                let directory_bytes = encode_directory(inode, directory);
                store.put(directory_key, &directory_bytes)?;
                manifest_entries.push(TransactionManifestEntry {
                    role: TransactionManifestObjectRole::TransactionDirectory,
                    object_key: directory_key,
                    checksum: checksum64(&directory_bytes),
                });
            } else {
                let last_tx = state.last_dir_write_tx[&inode.inode_id];
                let last_key = transaction_directory_object_key(last_tx, inode.inode_id);
                let directory = state.directories.get(&inode.inode_id).ok_or(
                    FileSystemError::CorruptState {
                        reason: "directory inode has no directory table",
                    },
                )?;
                let current_bytes = encode_directory(inode, directory);
                let existing_bytes = store.get(last_key)?.ok_or(FileSystemError::CorruptState {
                    reason: "clean directory reference points to missing object",
                })?;
                if current_bytes != existing_bytes {
                    let directory_key =
                        transaction_directory_object_key(transaction_id, inode.inode_id);
                    store.put(directory_key, &current_bytes)?;
                    manifest_entries.push(TransactionManifestEntry {
                        role: TransactionManifestObjectRole::TransactionDirectory,
                        object_key: directory_key,
                        checksum: checksum64(&current_bytes),
                    });
                } else {
                    manifest_entries.push(TransactionManifestEntry {
                        role: TransactionManifestObjectRole::TransactionDirectory,
                        object_key: last_key,
                        checksum: checksum64(&existing_bytes),
                    });
                }
            }
        }
    }
    let inode_count = state.inodes.len() as u64;
    let bitmap_words = state.next_inode_id_raw().div_ceil(64) as usize;
    let mut inode_allocation_bitmap = vec![0u64; bitmap_words];
    for inode_id in state.inodes.keys() {
        let idx = (inode_id.get() - 1) as usize;
        inode_allocation_bitmap[idx / 64] |= 1u64 << (idx % 64);
    }
    // Persist dirty extent maps for file-like inodes.
    let extent_maps = state.extent_maps.lock().unwrap();
    for inode_id in &state.dirty_extent_maps {
        let Some(inode) = state.inodes.get(inode_id) else {
            continue;
        };
        if !inode.is_file_like() {
            continue;
        }
        if let Some(extent_map) = extent_maps.get(inode_id) {
            let ext_key = transaction_extent_map_object_key(transaction_id, *inode_id);
            let mut ext_bytes = Vec::new();
            extent_map
                .serialize(&mut ext_bytes)
                .map_err(|_| FileSystemError::CorruptState {
                    reason: "extent map serialization failed",
                })?;
            store.put(ext_key, &ext_bytes)?;
            manifest_entries.push(TransactionManifestEntry {
                role: TransactionManifestObjectRole::TransactionExtentMap,
                object_key: ext_key,
                checksum: checksum64(&ext_bytes),
            });
        }
    }

    let superblock = SuperblockRecord {
        next_inode_id: state.next_inode_id_raw(),
        generation: state.generation,
        inode_count,
        inode_allocation_bitmap,
        format_version_min: CURRENT_FORMAT_VERSION,
        format_version_max: CURRENT_FORMAT_VERSION,
    };
    let superblock_bytes = encode_superblock(&superblock);
    let superblock_checksum = checksum64(&superblock_bytes);
    let superblock_key = transaction_superblock_object_key(transaction_id);
    store.put(superblock_key, &superblock_bytes)?;
    manifest_entries.push(TransactionManifestEntry {
        role: TransactionManifestObjectRole::TransactionSuperblock,
        object_key: superblock_key,
        checksum: superblock_checksum,
    });

    // Write snapshot catalog entries as separate transaction objects.
    for snapshot in state.snapshots.values() {
        let snap_key =
            transaction_snapshot_catalog_entry_object_key(transaction_id, &snapshot.name);
        let snap_bytes = encode_snapshot_record(snapshot);
        store.put(snap_key, &snap_bytes)?;
        manifest_entries.push(TransactionManifestEntry {
            role: TransactionManifestObjectRole::TransactionSnapshotCatalogEntry,
            object_key: snap_key,
            checksum: checksum64(&snap_bytes),
        });
    }

    let manifest = TransactionManifestRecord {
        transaction_id,
        generation: state.generation,
        entries: manifest_entries,
    };
    let manifest_entry_count = manifest.entries.len() as u64;
    let manifest_bytes = encode_transaction_manifest(&manifest);
    let manifest_checksum = checksum64(&manifest_bytes);
    store.put(
        transaction_manifest_object_key(transaction_id),
        &manifest_bytes,
    )?;

    Ok(RootCommitRecord {
        slot: root_slot_for_transaction(transaction_id),
        transaction_id,
        generation: state.generation,
        next_inode_id: state.next_inode_id_raw(),
        inode_count: superblock.inode_count,
        superblock_checksum,
        manifest_checksum,
        manifest_entry_count,
        root_authentication: Some(root_authentication_record_for_bytes(
            &superblock_bytes,
            Some(&manifest_bytes),
        )),
    })
}

pub(crate) fn publish_root_commit(
    store: &mut LocalObjectStore,
    root: &RootCommitRecord,
    root_authentication_key: RootAuthenticationKey,
) -> Result<()> {
    let signed = sign_root_commit(root, root_authentication_key)?;
    store.put(
        root_slot_object_key(signed.slot),
        &encode_root_commit(&signed),
    )?;
    Ok(())
}

pub(crate) fn root_slot_for_transaction(transaction_id: u64) -> u64 {
    transaction_id % FILESYSTEM_ROOT_SLOT_COUNT
}

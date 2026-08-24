// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use tidefs_dataset_lifecycle::DatasetId;
use tidefs_local_object_store::{
    checksum64, pool::Pool, DeviceIoClass, LocalObjectStore, ObjectKey, StoreError,
};
use tidefs_pool_runtime::{DatasetRootKind, DatasetRootUpdate, PoolRuntime};
use tidefs_types_vfs_core::InodeId;

use crate::constants::*;
use crate::content::MountedContentReadAuthority;
use crate::decode_content_layout;
#[cfg(any(test, feature = "replication-io"))]
use crate::dedup::DedupIndex;
use crate::encoding::*;
use crate::error::FileSystemError;
use crate::object_keys::*;
use crate::read_content_chunk_from_store;
#[cfg(any(test, feature = "replication-io"))]
use crate::read_content_from_store;
use crate::records::*;
use crate::types::*;
use crate::validate_content_layout;
#[cfg(any(test, feature = "replication-io"))]
use crate::write_chunked_content;
use crate::FileSystemState;
use crate::Result;

trait TransactionMetadataStore {
    fn get_transaction_metadata(&self, key: ObjectKey) -> Result<Option<Vec<u8>>>;

    fn put_transaction_metadata(&mut self, key: ObjectKey, payload: &[u8]) -> Result<()>;
}

impl TransactionMetadataStore for LocalObjectStore {
    fn get_transaction_metadata(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        Ok(self.get(key)?)
    }

    fn put_transaction_metadata(&mut self, key: ObjectKey, payload: &[u8]) -> Result<()> {
        self.put(key, payload)?;
        Ok(())
    }
}

fn get_pool_transaction_metadata(pool: &Pool, key: ObjectKey) -> Result<Option<Vec<u8>>> {
    Ok(pool
        .get_with_current_receipt(DeviceIoClass::Metadata, key)?
        .map(|(payload, _receipt)| payload))
}

struct PoolTransactionMetadataBatch<'a> {
    pool: &'a mut Pool,
    pending: BTreeMap<ObjectKey, Vec<u8>>,
}

impl<'a> PoolTransactionMetadataBatch<'a> {
    fn new(pool: &'a mut Pool) -> Self {
        Self {
            pool,
            pending: BTreeMap::new(),
        }
    }

    fn finish(self) -> Result<()> {
        maybe_inject_sync_failure_after_boundary(
            self.pool.raw_primary_store(),
            FilesystemCommitBoundary::TransactionObjectsWritten,
        )?;
        let entries = self.pending.into_iter().collect::<Vec<_>>();
        self.pool.put_prepublication_metadata_batch(&entries)?;
        Ok(())
    }
}

impl TransactionMetadataStore for PoolTransactionMetadataBatch<'_> {
    fn get_transaction_metadata(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        if let Some(payload) = self.pending.get(&key) {
            return Ok(Some(payload.clone()));
        }
        get_pool_transaction_metadata(self.pool, key)
    }

    fn put_transaction_metadata(&mut self, key: ObjectKey, payload: &[u8]) -> Result<()> {
        if let Some(current) = self.pending.get(&key) {
            if current.as_slice() != payload {
                return Err(FileSystemError::CorruptState {
                    reason: "filesystem transaction metadata repeats a key with different payload",
                });
            }
            return Ok(());
        }
        self.pending.insert(key, payload.to_vec());
        Ok(())
    }
}

/// Authenticated COW source for one successor transaction manifest.
///
/// A mounted commit must validate and write every changed object, but it must
/// not turn a per-inode durability barrier into a filesystem-wide scrub. Clean
/// objects retain their immutable key and checksum from the canonical prior
/// root. Reopen and the scrub path remain responsible for reading and checking
/// every retained payload.
struct PriorTransactionManifestIndex<'a> {
    manifest: &'a TransactionManifestRecord,
    positions: BTreeMap<ObjectKey, usize>,
}

impl<'a> PriorTransactionManifestIndex<'a> {
    fn new(manifest: &'a TransactionManifestRecord) -> Result<Self> {
        let mut positions = BTreeMap::new();
        for (position, entry) in manifest.entries.iter().enumerate() {
            if positions.insert(entry.object_key, position).is_some() {
                return Err(FileSystemError::CorruptState {
                    reason: "committed transaction manifest repeats an object key",
                });
            }
        }
        Ok(Self {
            manifest,
            positions,
        })
    }

    fn matching_metadata_entry(
        &self,
        key: ObjectKey,
        role: TransactionManifestObjectRole,
        current_bytes: &[u8],
        missing_reason: &'static str,
    ) -> Result<Option<TransactionManifestEntry>> {
        let position = self
            .positions
            .get(&key)
            .copied()
            .ok_or(FileSystemError::CorruptState {
                reason: missing_reason,
            })?;
        let entry = &self.manifest.entries[position];
        if entry.role != role {
            return Err(FileSystemError::CorruptState {
                reason: "clean metadata key has the wrong committed manifest role",
            });
        }
        Ok((entry.checksum == checksum64(current_bytes)).then(|| entry.clone()))
    }

    fn contains_metadata_entry(
        &self,
        key: ObjectKey,
        role: TransactionManifestObjectRole,
    ) -> Result<bool> {
        let Some(position) = self.positions.get(&key).copied() else {
            return Ok(false);
        };
        if self.manifest.entries[position].role != role {
            return Err(FileSystemError::CorruptState {
                reason: "current transaction metadata key has the wrong manifest role",
            });
        }
        Ok(true)
    }

    fn content_entries(
        &self,
        inode: &InodeRecord,
        last_inode_transaction: u64,
        keyspace: FilesystemObjectKeyspace,
    ) -> Result<Vec<TransactionManifestEntry>> {
        if inode.size == 0 {
            return Ok(Vec::new());
        }

        let content_key = keyspace.scope(content_object_key_for_version(
            inode.inode_id,
            inode.data_version,
        ));
        let inode_key = keyspace.transaction_inode(last_inode_transaction, inode.inode_id);
        self.content_entries_between(content_key, inode_key)
    }

    fn content_entries_between(
        &self,
        content_key: ObjectKey,
        inode_key: ObjectKey,
    ) -> Result<Vec<TransactionManifestEntry>> {
        let position =
            self.positions
                .get(&content_key)
                .copied()
                .ok_or(FileSystemError::CorruptState {
                    reason: "clean inode has no committed content manifest entry",
                })?;
        let first = &self.manifest.entries[position];
        if first.role != TransactionManifestObjectRole::VersionedContent {
            return Err(FileSystemError::CorruptState {
                reason: "clean inode content key has the wrong committed manifest role",
            });
        }

        let mut entries = vec![first.clone()];
        let mut cursor = position + 1;
        while self
            .manifest
            .entries
            .get(cursor)
            .is_some_and(|entry| entry.role == TransactionManifestObjectRole::VersionedContentChunk)
        {
            entries.push(self.manifest.entries[cursor].clone());
            cursor += 1;
        }

        let terminator =
            self.manifest
                .entries
                .get(cursor)
                .ok_or(FileSystemError::CorruptState {
                    reason: "clean inode content entries have no owning inode entry",
                })?;
        if terminator.role != TransactionManifestObjectRole::TransactionInode
            || terminator.object_key != inode_key
        {
            return Err(FileSystemError::CorruptState {
                reason: "clean inode content entries do not terminate at their owning inode",
            });
        }
        Ok(entries)
    }
}

fn load_authenticated_runtime_manifest(
    runtime: &PoolRuntime,
    dataset_id: DatasetId,
    root_authentication_key: RootAuthenticationKey,
) -> Result<TransactionManifestRecord> {
    let root_bytes = runtime.load_dataset_root(dataset_id, DatasetRootKind::Filesystem)?;
    let root = decode_root_commit(&root_bytes)?;
    let authentication = validate_root_authentication_record(&root, root_authentication_key)?;
    if !root.has_manifest() {
        return Err(FileSystemError::CorruptState {
            reason: "canonical filesystem root has no transaction manifest",
        });
    }

    let keyspace = FilesystemObjectKeyspace::new(dataset_id);
    let manifest_bytes = get_pool_transaction_metadata(
        runtime.pool(),
        keyspace.transaction_manifest(root.transaction_id),
    )?
    .ok_or(FileSystemError::CorruptState {
        reason: "canonical filesystem transaction manifest is missing",
    })?;
    if checksum64(&manifest_bytes) != root.manifest_checksum
        || root_authentication_digest(ROOT_AUTHENTICATION_MANIFEST_DOMAIN, &manifest_bytes)
            != authentication.manifest_digest
    {
        return Err(FileSystemError::CorruptState {
            reason: "canonical filesystem transaction manifest failed root authentication",
        });
    }
    let manifest = decode_transaction_manifest(&manifest_bytes)?;
    if manifest.transaction_id != root.transaction_id
        || manifest.generation != root.generation
        || manifest.entries.len() as u64 != root.manifest_entry_count
    {
        return Err(FileSystemError::CorruptState {
            reason: "canonical filesystem transaction manifest does not match its root",
        });
    }
    Ok(manifest)
}

fn validate_prepared_runtime_successor(
    pool: &Pool,
    dataset_id: DatasetId,
    root: &RootCommitRecord,
    root_authentication_key: RootAuthenticationKey,
    prior_manifest: &TransactionManifestRecord,
) -> Result<TransactionManifestRecord> {
    let authentication = validate_root_authentication_record(root, root_authentication_key)?;
    let keyspace = FilesystemObjectKeyspace::new(dataset_id);

    let superblock_bytes =
        get_pool_transaction_metadata(pool, keyspace.transaction_superblock(root.transaction_id))?
            .ok_or(FileSystemError::CorruptState {
                reason: "prepared filesystem transaction superblock is missing",
            })?;
    if checksum64(&superblock_bytes) != root.superblock_checksum
        || root_authentication_digest(ROOT_AUTHENTICATION_SUPERBLOCK_DOMAIN, &superblock_bytes)
            != authentication.superblock_digest
    {
        return Err(FileSystemError::CorruptState {
            reason: "prepared filesystem transaction superblock failed root authentication",
        });
    }
    let superblock = decode_superblock(&superblock_bytes)?;
    if superblock.generation != root.generation
        || superblock.next_inode_id != root.next_inode_id
        || superblock.inode_count != root.inode_count
    {
        return Err(FileSystemError::CorruptState {
            reason: "prepared filesystem transaction superblock does not match its root",
        });
    }

    let manifest_bytes =
        get_pool_transaction_metadata(pool, keyspace.transaction_manifest(root.transaction_id))?
            .ok_or(FileSystemError::CorruptState {
                reason: "prepared filesystem transaction manifest is missing",
            })?;
    if checksum64(&manifest_bytes) != root.manifest_checksum
        || root_authentication_digest(ROOT_AUTHENTICATION_MANIFEST_DOMAIN, &manifest_bytes)
            != authentication.manifest_digest
    {
        return Err(FileSystemError::CorruptState {
            reason: "prepared filesystem transaction manifest failed root authentication",
        });
    }
    let manifest = decode_transaction_manifest(&manifest_bytes)?;
    if manifest.transaction_id != root.transaction_id
        || manifest.generation != root.generation
        || manifest.entries.len() as u64 != root.manifest_entry_count
    {
        return Err(FileSystemError::CorruptState {
            reason: "prepared filesystem transaction manifest does not match its root",
        });
    }

    let prior_entries = prior_manifest
        .entries
        .iter()
        .map(|entry| (entry.role, entry.object_key, entry.checksum))
        .collect::<BTreeSet<_>>();
    for entry in &manifest.entries {
        if prior_entries.contains(&(entry.role, entry.object_key, entry.checksum)) {
            continue;
        }
        match entry.role {
            TransactionManifestObjectRole::TransactionSuperblock => {
                if entry.object_key != keyspace.transaction_superblock(root.transaction_id)
                    || entry.checksum != root.superblock_checksum
                {
                    return Err(FileSystemError::CorruptState {
                        reason: "prepared manifest superblock entry does not match its root",
                    });
                }
            }
            TransactionManifestObjectRole::TransactionInode
            | TransactionManifestObjectRole::TransactionDirectory
            | TransactionManifestObjectRole::TransactionSnapshotCatalogEntry
            | TransactionManifestObjectRole::TransactionExtentMap => {
                let bytes = get_pool_transaction_metadata(pool, entry.object_key)?.ok_or(
                    FileSystemError::CorruptState {
                        reason: "prepared manifest metadata entry is missing",
                    },
                )?;
                if checksum64(&bytes) != entry.checksum {
                    return Err(FileSystemError::CorruptState {
                        reason: "prepared manifest metadata entry checksum mismatch",
                    });
                }
            }
            TransactionManifestObjectRole::VersionedContent
            | TransactionManifestObjectRole::VersionedContentChunk => {
                // Changed content was strictly read through current Pool
                // receipts before the transaction objects were prepared.
                // Clean content retains its authenticated prior-root entry.
            }
        }
    }
    Ok(manifest)
}

#[derive(Debug)]
pub(crate) struct FilesystemStatePublication {
    pub(crate) root: RootCommitRecord,
    pub(crate) inode_write_ids: BTreeSet<InodeId>,
    pub(crate) directory_write_ids: BTreeSet<InodeId>,
}

fn current_transaction_metadata_writes(
    state: &FileSystemState,
    manifest: &TransactionManifestRecord,
    keyspace: FilesystemObjectKeyspace,
) -> Result<(BTreeSet<InodeId>, BTreeSet<InodeId>)> {
    let index = PriorTransactionManifestIndex::new(manifest)?;
    let mut inode_write_ids = BTreeSet::new();
    let mut directory_write_ids = BTreeSet::new();
    for inode in state.inodes.values() {
        if index.contains_metadata_entry(
            keyspace.transaction_inode(manifest.transaction_id, inode.inode_id),
            TransactionManifestObjectRole::TransactionInode,
        )? {
            inode_write_ids.insert(inode.inode_id);
        }
        if inode.carries_child_namespace()
            && index.contains_metadata_entry(
                keyspace.transaction_directory(manifest.transaction_id, inode.inode_id),
                TransactionManifestObjectRole::TransactionDirectory,
            )?
        {
            directory_write_ids.insert(inode.inode_id);
        }
    }
    Ok((inode_write_ids, directory_write_ids))
}
#[cfg(test)]
pub(crate) fn persist_state(
    store: &mut LocalObjectStore,
    state: &FileSystemState,
    root_authentication_key: RootAuthenticationKey,
) -> Result<()> {
    let _ = persist_state_until_boundary(store, state, root_authentication_key, None)?;
    Ok(())
}

/// Persist a mounted transaction only after every nonempty file-like inode's
/// content is readable through current Pool placement authority.
#[cfg(test)]
pub(crate) fn persist_state_with_pool(
    pool: &mut Pool,
    state: &FileSystemState,
    root_authentication_key: RootAuthenticationKey,
) -> Result<()> {
    let _ = persist_state_with_pool_until_boundary(pool, state, root_authentication_key, None)?;
    Ok(())
}

/// Persist mounted state under an explicit transaction identity.
///
/// Filesystem generation describes the newest logical state mutation, while
/// transaction id identifies one durable publication in the root-slot ring.
/// A batched commit may therefore need a later transaction id without
/// inventing mutations or changing the generation exposed after recovery.
pub(crate) fn persist_state_with_pool_at_transaction(
    pool: &mut Pool,
    state: &FileSystemState,
    transaction_id: u64,
    root_authentication_key: RootAuthenticationKey,
) -> Result<()> {
    let _ = persist_state_with_pool_at_transaction_until_boundary(
        pool,
        state,
        transaction_id,
        root_authentication_key,
        None,
    )?;
    Ok(())
}

/// Persist filesystem transaction objects, then publish the authenticated
/// filesystem semantic root together with any staged Pool metadata.
pub(crate) fn persist_state_with_runtime_at_transaction(
    runtime: &mut PoolRuntime,
    state: &FileSystemState,
    transaction_id: u64,
    root_authentication_key: RootAuthenticationKey,
) -> Result<RootCommitRecord> {
    Ok(
        persist_state_with_runtime_at_transaction_and_snapshot_rewrites(
            runtime,
            state,
            transaction_id,
            root_authentication_key,
            &BTreeMap::new(),
        )?
        .root,
    )
}

/// Persist filesystem state while authorizing exact typed snapshot-root
/// successors for a Pool device-lifecycle transaction.
///
/// Ordinary commits pass no predecessors and continue to fail closed if live
/// snapshot state disagrees with the canonical Pool composition. Device
/// removal/replacement supplies the exact roots authenticated before receipt
/// relocation; only those roots may advance to references containing the new
/// placement-receipt generations.
pub(crate) fn persist_state_with_runtime_at_transaction_and_snapshot_rewrites(
    runtime: &mut PoolRuntime,
    state: &FileSystemState,
    transaction_id: u64,
    root_authentication_key: RootAuthenticationKey,
    expected_snapshot_predecessors: &BTreeMap<DatasetId, tidefs_pool_runtime::SnapshotRoot>,
) -> Result<FilesystemStatePublication> {
    let source_dataset_id = state.dataset_id();
    let prior_manifest =
        load_authenticated_runtime_manifest(runtime, source_dataset_id, root_authentication_key)?;
    let signed = prepare_state_with_pool_at_transaction_reusing_manifest(
        runtime.pool_mut(),
        state,
        transaction_id,
        root_authentication_key,
        &prior_manifest,
    )?;
    let successor_manifest = validate_prepared_runtime_successor(
        runtime.pool(),
        source_dataset_id,
        &signed,
        root_authentication_key,
        &prior_manifest,
    )?;
    let (inode_write_ids, directory_write_ids) = current_transaction_metadata_writes(
        state,
        &successor_manifest,
        FilesystemObjectKeyspace::new(source_dataset_id),
    )?;
    let bytes = encode_root_commit(&signed);
    let mut snapshot_roots = Vec::new();
    let mut consumed_snapshot_predecessors = BTreeSet::new();
    for record in state
        .snapshots
        .values()
        .filter(|record| crate::snapshot::snapshot_record_retains_data(record))
    {
        let snapshot_dataset_id =
            crate::snapshot::snapshot_record_dataset_id_for_dataset(record, source_dataset_id);
        let root =
            crate::snapshot::snapshot_record_typed_root_for_dataset(record, source_dataset_id)?;
        if runtime.dataset_root(snapshot_dataset_id).is_some() {
            let stored = runtime.load_snapshot_root(snapshot_dataset_id)?;
            if stored != root {
                if expected_snapshot_predecessors.get(&snapshot_dataset_id) != Some(&stored) {
                    return Err(FileSystemError::CorruptState {
                        reason:
                            "canonical Pool snapshot root differs from filesystem snapshot state",
                    });
                }
                consumed_snapshot_predecessors.insert(snapshot_dataset_id);
                snapshot_roots.push((snapshot_dataset_id, root.snapshot_generation, root.encode()));
            } else if expected_snapshot_predecessors.contains_key(&snapshot_dataset_id) {
                return Err(FileSystemError::CorruptState {
                    reason: "device lifecycle snapshot predecessor did not advance",
                });
            }
        } else {
            if expected_snapshot_predecessors.contains_key(&snapshot_dataset_id) {
                return Err(FileSystemError::CorruptState {
                    reason: "device lifecycle snapshot predecessor is missing",
                });
            }
            snapshot_roots.push((snapshot_dataset_id, root.snapshot_generation, root.encode()));
        }
    }
    if consumed_snapshot_predecessors.len() != expected_snapshot_predecessors.len() {
        return Err(FileSystemError::CorruptState {
            reason: "device lifecycle snapshot predecessor is not retained by filesystem state",
        });
    }
    let mut updates = Vec::with_capacity(snapshot_roots.len().saturating_add(1));
    updates.push(DatasetRootUpdate {
        dataset_id: source_dataset_id,
        kind: DatasetRootKind::Filesystem,
        semantic_generation: signed.generation,
        bytes: &bytes,
    });
    updates.extend(snapshot_roots.iter().map(
        |(dataset_id, semantic_generation, snapshot_bytes)| DatasetRootUpdate {
            dataset_id: *dataset_id,
            kind: DatasetRootKind::Snapshot,
            semantic_generation: *semantic_generation,
            bytes: snapshot_bytes,
        },
    ));
    runtime.publish_metadata_with_roots(&updates)?;
    Ok(FilesystemStatePublication {
        root: signed,
        inode_write_ids,
        directory_write_ids,
    })
}

/// Write and sync a complete filesystem transaction without choosing its
/// canonical Pool reachability. Fresh-pool creation uses the returned signed
/// root in the same catalog/root publication.
pub(crate) fn prepare_state_with_pool_at_transaction(
    pool: &mut Pool,
    state: &FileSystemState,
    transaction_id: u64,
    root_authentication_key: RootAuthenticationKey,
) -> Result<RootCommitRecord> {
    prepare_state_with_pool_at_transaction_inner(
        pool,
        state,
        transaction_id,
        root_authentication_key,
        None,
    )
}

fn prepare_state_with_pool_at_transaction_reusing_manifest(
    pool: &mut Pool,
    state: &FileSystemState,
    transaction_id: u64,
    root_authentication_key: RootAuthenticationKey,
    prior_manifest: &TransactionManifestRecord,
) -> Result<RootCommitRecord> {
    prepare_state_with_pool_at_transaction_inner(
        pool,
        state,
        transaction_id,
        root_authentication_key,
        Some(prior_manifest),
    )
}

fn prepare_state_with_pool_at_transaction_inner(
    pool: &mut Pool,
    state: &FileSystemState,
    transaction_id: u64,
    root_authentication_key: RootAuthenticationKey,
    prior_manifest: Option<&TransactionManifestRecord>,
) -> Result<RootCommitRecord> {
    if transaction_id < state.generation.max(ROOT_COMMIT_MIN_TRANSACTION_ID) {
        return Err(FileSystemError::CorruptState {
            reason: "mounted transaction id precedes filesystem state generation",
        });
    }
    let keyspace = FilesystemObjectKeyspace::new(state.dataset_id());
    let prior_index = prior_manifest
        .map(PriorTransactionManifestIndex::new)
        .transpose()?;
    let content_entries =
        pool_content_manifest_entries_for_state(pool, state, prior_index.as_ref())?;
    let mut batch = PoolTransactionMetadataBatch::new(pool);
    let root = persist_transaction_objects_with_precomputed_content(
        &mut batch,
        state,
        transaction_id,
        &content_entries,
        keyspace,
        prior_index.as_ref(),
    )?;
    batch.finish()?;
    sign_root_commit(&root, root_authentication_key)
}

pub(crate) fn persist_state_with_pool_until_boundary(
    pool: &mut Pool,
    state: &FileSystemState,
    root_authentication_key: RootAuthenticationKey,
    stop_after: Option<FilesystemCommitBoundary>,
) -> Result<FilesystemCommitBoundary> {
    let transaction_id = state.generation.max(ROOT_COMMIT_MIN_TRANSACTION_ID);
    persist_state_with_pool_at_transaction_until_boundary(
        pool,
        state,
        transaction_id,
        root_authentication_key,
        stop_after,
    )
}

pub(crate) fn persist_state_with_pool_at_transaction_until_boundary(
    pool: &mut Pool,
    state: &FileSystemState,
    transaction_id: u64,
    root_authentication_key: RootAuthenticationKey,
    stop_after: Option<FilesystemCommitBoundary>,
) -> Result<FilesystemCommitBoundary> {
    if transaction_id < state.generation.max(ROOT_COMMIT_MIN_TRANSACTION_ID) {
        return Err(FileSystemError::CorruptState {
            reason: "mounted transaction id precedes filesystem state generation",
        });
    }
    let content_entries = pool_content_manifest_entries_for_state(pool, state, None)?;
    let root = persist_transaction_objects_with_precomputed_content(
        pool.raw_primary_store_mut(),
        state,
        transaction_id,
        &content_entries,
        FilesystemObjectKeyspace::new(state.dataset_id()),
        None,
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(any(test, feature = "replication-io"))]
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
    let content = read_content_from_store(store, inode.inode_id, inode, None)?;
    write_chunked_content(
        false,
        store,
        inode,
        &content,
        &mut DedupIndex::new(),
        #[cfg(feature = "quorum-write")]
        None,
        compression_policy,
    )
}

/// Validate that mounted content is complete and readable through the Pool
/// authority that published its placement receipts.
///
/// Data-only durability paths call this after draining buffered writes. They
/// must not reconstruct receipt-backed content in the raw primary metadata
/// store when the Pool already owns the current logical objects.
pub(crate) fn validate_versioned_content_with_pool_in_keyspace(
    pool: &Pool,
    inode: &InodeRecord,
    keyspace: FilesystemObjectKeyspace,
) -> Result<()> {
    let _ = MountedContentReadAuthority::for_dataset(pool, keyspace.dataset_id())
        .read_all(inode.inode_id, inode)?;
    Ok(())
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

/// Build mounted committed-root entries from strict, current Pool reads.
/// Receiptless raw-primary bytes cannot satisfy this boundary.
pub(crate) fn transaction_manifest_entries_for_pool_content_in_keyspace(
    pool: &Pool,
    inode: &InodeRecord,
    keyspace: FilesystemObjectKeyspace,
) -> Result<Vec<TransactionManifestEntry>> {
    if inode.size == 0 {
        return Ok(Vec::new());
    }

    let authority = MountedContentReadAuthority::for_dataset(pool, keyspace.dataset_id());
    let logical_content_key = content_object_key_for_version(inode.inode_id, inode.data_version);
    let content_key = keyspace.scope(logical_content_key);
    let (content_bytes, _receipt) = authority.read_current_object(logical_content_key)?.ok_or(
        FileSystemError::ReceiptAuthorityMissing {
            object_key: content_key,
            expected_generation: 0,
        },
    )?;
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
            let _ = authority.read_chunk(manifest.inode_id, chunk_ref)?;
            entries.push(TransactionManifestEntry {
                role: TransactionManifestObjectRole::VersionedContentChunk,
                object_key: keyspace.content_chunk(
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
    prior_manifest: Option<&PriorTransactionManifestIndex<'_>>,
) -> Result<BTreeMap<InodeId, Vec<TransactionManifestEntry>>> {
    let keyspace = FilesystemObjectKeyspace::new(state.dataset_id());
    let mut entries = BTreeMap::new();
    for inode in state.inodes.values().filter(|inode| inode.is_file_like()) {
        let prior_clean_transaction = if !state.dirty_content.contains(&inode.inode_id)
            && !state.dirty_inodes.contains(&inode.inode_id)
        {
            if let (Some(prior), Some(last_transaction)) = (
                prior_manifest,
                state.last_inode_write_tx.get(&inode.inode_id).copied(),
            ) {
                let inode_key = keyspace.transaction_inode(last_transaction, inode.inode_id);
                let inode_bytes = try_encode_inode(inode)?;
                prior
                    .matching_metadata_entry(
                        inode_key,
                        TransactionManifestObjectRole::TransactionInode,
                        &inode_bytes,
                        "clean inode reference is missing from committed manifest",
                    )?
                    .map(|_| last_transaction)
            } else {
                None
            }
        } else {
            None
        };
        let inode_entries = match (prior_manifest, prior_clean_transaction) {
            (Some(prior), Some(last_transaction)) => {
                prior.content_entries(inode, last_transaction, keyspace)?
            }
            _ => transaction_manifest_entries_for_pool_content_in_keyspace(pool, inode, keyspace)?,
        };
        entries.insert(inode.inode_id, inode_entries);
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

#[cfg(any(test, feature = "replication-io"))]
pub(crate) fn persist_transaction_objects(
    store: &mut LocalObjectStore,
    state: &FileSystemState,
    transaction_id: u64,
) -> Result<RootCommitRecord> {
    let content_entries = raw_content_manifest_entries_for_state(store, state)?;
    persist_transaction_objects_impl(
        store,
        state,
        transaction_id,
        &content_entries,
        FilesystemObjectKeyspace::new(tidefs_pool_runtime::ROOT_DATASET_ID),
        None,
    )
}

#[cfg(any(test, feature = "replication-io"))]
fn raw_content_manifest_entries_for_state(
    store: &mut LocalObjectStore,
    state: &FileSystemState,
) -> Result<BTreeMap<InodeId, Vec<TransactionManifestEntry>>> {
    let mut entries = BTreeMap::new();
    for inode in state.inodes.values().filter(|inode| inode.is_file_like()) {
        let needs_inode_write = state.dirty_inodes.contains(&inode.inode_id)
            || !state.last_inode_write_tx.contains_key(&inode.inode_id);
        let inode_entries = if needs_inode_write {
            ensure_versioned_content_object(store, inode, &state.content_compression_policy)?;
            transaction_manifest_entries_for_content(store, inode, false)?
        } else {
            transaction_manifest_entries_for_existing_content(store, inode)?
        };
        entries.insert(inode.inode_id, inode_entries);
    }
    Ok(entries)
}

fn persist_transaction_objects_with_precomputed_content<S: TransactionMetadataStore>(
    store: &mut S,
    state: &FileSystemState,
    transaction_id: u64,
    content_entries: &BTreeMap<InodeId, Vec<TransactionManifestEntry>>,
    keyspace: FilesystemObjectKeyspace,
    prior_manifest: Option<&PriorTransactionManifestIndex<'_>>,
) -> Result<RootCommitRecord> {
    persist_transaction_objects_impl(
        store,
        state,
        transaction_id,
        content_entries,
        keyspace,
        prior_manifest,
    )
}

fn persist_transaction_objects_impl<S: TransactionMetadataStore>(
    store: &mut S,
    state: &FileSystemState,
    transaction_id: u64,
    content_entries: &BTreeMap<InodeId, Vec<TransactionManifestEntry>>,
    keyspace: FilesystemObjectKeyspace,
    prior_manifest: Option<&PriorTransactionManifestIndex<'_>>,
) -> Result<RootCommitRecord> {
    let mut manifest_entries = Vec::new();
    for inode in state.inodes.values() {
        let is_dirty = state.dirty_inodes.contains(&inode.inode_id);
        let needs_inode_write =
            is_dirty || !state.last_inode_write_tx.contains_key(&inode.inode_id);

        if inode.is_file_like() {
            let entries =
                content_entries
                    .get(&inode.inode_id)
                    .ok_or(FileSystemError::CorruptState {
                        reason: "mounted transaction is missing prevalidated content entries",
                    })?;
            manifest_entries.extend(entries.iter().cloned());
        }

        if needs_inode_write {
            let inode_key = keyspace.transaction_inode(transaction_id, inode.inode_id);
            let inode_bytes = try_encode_inode(inode)?;
            store.put_transaction_metadata(inode_key, &inode_bytes)?;
            manifest_entries.push(TransactionManifestEntry {
                role: TransactionManifestObjectRole::TransactionInode,
                object_key: inode_key,
                checksum: checksum64(&inode_bytes),
            });
        } else {
            let last_tx = state.last_inode_write_tx[&inode.inode_id];
            let last_key = keyspace.transaction_inode(last_tx, inode.inode_id);
            let current_bytes = try_encode_inode(inode)?;
            if let Some(prior) = prior_manifest {
                if let Some(entry) = prior.matching_metadata_entry(
                    last_key,
                    TransactionManifestObjectRole::TransactionInode,
                    &current_bytes,
                    "clean inode reference is missing from committed manifest",
                )? {
                    manifest_entries.push(entry);
                } else {
                    let inode_key = keyspace.transaction_inode(transaction_id, inode.inode_id);
                    store.put_transaction_metadata(inode_key, &current_bytes)?;
                    manifest_entries.push(TransactionManifestEntry {
                        role: TransactionManifestObjectRole::TransactionInode,
                        object_key: inode_key,
                        checksum: checksum64(&current_bytes),
                    });
                }
            } else {
                let existing_bytes = store.get_transaction_metadata(last_key)?.ok_or(
                    FileSystemError::CorruptState {
                        reason: "clean inode reference points to missing object",
                    },
                )?;
                if current_bytes != existing_bytes {
                    let inode_key = keyspace.transaction_inode(transaction_id, inode.inode_id);
                    store.put_transaction_metadata(inode_key, &current_bytes)?;
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
                let directory_key = keyspace.transaction_directory(transaction_id, inode.inode_id);
                let directory_bytes = encode_directory(inode, directory);
                store.put_transaction_metadata(directory_key, &directory_bytes)?;
                manifest_entries.push(TransactionManifestEntry {
                    role: TransactionManifestObjectRole::TransactionDirectory,
                    object_key: directory_key,
                    checksum: checksum64(&directory_bytes),
                });
            } else {
                let last_tx = state.last_dir_write_tx[&inode.inode_id];
                let last_key = keyspace.transaction_directory(last_tx, inode.inode_id);
                let directory = state.directories.get(&inode.inode_id).ok_or(
                    FileSystemError::CorruptState {
                        reason: "directory inode has no directory table",
                    },
                )?;
                let current_bytes = encode_directory(inode, directory);
                if let Some(prior) = prior_manifest {
                    if let Some(entry) = prior.matching_metadata_entry(
                        last_key,
                        TransactionManifestObjectRole::TransactionDirectory,
                        &current_bytes,
                        "clean directory reference is missing from committed manifest",
                    )? {
                        manifest_entries.push(entry);
                    } else {
                        let directory_key =
                            keyspace.transaction_directory(transaction_id, inode.inode_id);
                        store.put_transaction_metadata(directory_key, &current_bytes)?;
                        manifest_entries.push(TransactionManifestEntry {
                            role: TransactionManifestObjectRole::TransactionDirectory,
                            object_key: directory_key,
                            checksum: checksum64(&current_bytes),
                        });
                    }
                } else {
                    let existing_bytes = store.get_transaction_metadata(last_key)?.ok_or(
                        FileSystemError::CorruptState {
                            reason: "clean directory reference points to missing object",
                        },
                    )?;
                    if current_bytes != existing_bytes {
                        let directory_key =
                            keyspace.transaction_directory(transaction_id, inode.inode_id);
                        store.put_transaction_metadata(directory_key, &current_bytes)?;
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
            let ext_key = keyspace.transaction_extent_map(transaction_id, *inode_id);
            let mut ext_bytes = Vec::new();
            extent_map
                .serialize(&mut ext_bytes)
                .map_err(|_| FileSystemError::CorruptState {
                    reason: "extent map serialization failed",
                })?;
            store.put_transaction_metadata(ext_key, &ext_bytes)?;
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
    let superblock_key = keyspace.transaction_superblock(transaction_id);
    store.put_transaction_metadata(superblock_key, &superblock_bytes)?;
    manifest_entries.push(TransactionManifestEntry {
        role: TransactionManifestObjectRole::TransactionSuperblock,
        object_key: superblock_key,
        checksum: superblock_checksum,
    });

    // Write snapshot catalog entries as separate transaction objects.
    for snapshot in state.snapshots.values() {
        let snap_key = keyspace.transaction_snapshot(transaction_id, &snapshot.name);
        let snap_bytes = encode_snapshot_record(snapshot);
        store.put_transaction_metadata(snap_key, &snap_bytes)?;
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
    store.put_transaction_metadata(
        keyspace.transaction_manifest(transaction_id),
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
        FilesystemObjectKeyspace::new(tidefs_pool_runtime::ROOT_DATASET_ID).root_slot(signed.slot),
        &encode_root_commit(&signed),
    )?;
    Ok(())
}

pub(crate) fn root_slot_for_transaction(transaction_id: u64) -> u64 {
    transaction_id % FILESYSTEM_ROOT_SLOT_COUNT
}

/// Choose the transaction id for the next mounted commit so root-slot
/// retention advances by one committed root, independent of how many
/// mutations the commit contains.
///
/// Transaction id is publication order; filesystem generation is logical
/// mutation order. A mutation burst may advance `state.generation` by several
/// complete turns of the root ring, so round the transaction floor forward to
/// the successor slot without rewriting the state's generation.
pub(crate) fn next_mounted_commit_transaction_id(
    state_generation: u64,
    previous_root: &CommittedRootSummary,
) -> Result<u64> {
    if previous_root.slot >= FILESYSTEM_ROOT_SLOT_COUNT
        || previous_root.slot != root_slot_for_transaction(previous_root.transaction_id)
    {
        return Err(FileSystemError::CorruptState {
            reason: "selected committed root does not match the root-slot ring",
        });
    }

    let previous_successor =
        previous_root
            .transaction_id
            .checked_add(1)
            .ok_or(FileSystemError::CorruptState {
                reason: "committed-root transaction id space is exhausted",
            })?;
    let lower_bound = state_generation
        .max(previous_successor)
        .max(ROOT_COMMIT_MIN_TRANSACTION_ID);
    let successor_slot = (previous_root.slot + 1) % FILESYSTEM_ROOT_SLOT_COUNT;
    let lower_slot = root_slot_for_transaction(lower_bound);
    let slot_adjustment = if lower_slot <= successor_slot {
        successor_slot - lower_slot
    } else {
        FILESYSTEM_ROOT_SLOT_COUNT - (lower_slot - successor_slot)
    };

    lower_bound
        .checked_add(slot_adjustment)
        .ok_or(FileSystemError::CorruptState {
            reason: "committed-root transaction id space is exhausted",
        })
}

#[cfg(test)]
mod prior_manifest_tests {
    use super::*;

    fn manifest_entry(
        role: TransactionManifestObjectRole,
        object_key: ObjectKey,
        payload: &[u8],
    ) -> TransactionManifestEntry {
        TransactionManifestEntry {
            role,
            object_key,
            checksum: checksum64(payload),
        }
    }

    #[test]
    fn clean_metadata_reuse_skips_live_state_divergence() {
        let inode_key = ObjectKey::from_name("prior-clean-inode");
        let committed = b"committed inode bytes";
        let manifest = TransactionManifestRecord {
            transaction_id: 7,
            generation: 9,
            entries: vec![manifest_entry(
                TransactionManifestObjectRole::TransactionInode,
                inode_key,
                committed,
            )],
        };
        let index = PriorTransactionManifestIndex::new(&manifest).expect("index prior manifest");

        let reused = index
            .matching_metadata_entry(
                inode_key,
                TransactionManifestObjectRole::TransactionInode,
                committed,
                "missing",
            )
            .expect("check matching committed inode")
            .expect("reuse matching committed inode");
        assert_eq!(reused, manifest.entries[0]);

        let divergent = index
            .matching_metadata_entry(
                inode_key,
                TransactionManifestObjectRole::TransactionInode,
                b"untracked live mutation",
                "missing",
            )
            .expect("check divergent committed inode");
        assert!(divergent.is_none(), "divergent metadata must be rewritten");
    }

    #[test]
    fn clean_content_reuse_stops_at_its_committed_inode() {
        let content_key = ObjectKey::from_name("prior-content");
        let chunk_key = ObjectKey::from_name("prior-content-chunk");
        let inode_key = ObjectKey::from_name("prior-content-inode");
        let other_inode_key = ObjectKey::from_name("other-inode");
        let manifest = TransactionManifestRecord {
            transaction_id: 11,
            generation: 13,
            entries: vec![
                manifest_entry(
                    TransactionManifestObjectRole::VersionedContent,
                    content_key,
                    b"content manifest",
                ),
                manifest_entry(
                    TransactionManifestObjectRole::VersionedContentChunk,
                    chunk_key,
                    b"content chunk",
                ),
                manifest_entry(
                    TransactionManifestObjectRole::TransactionInode,
                    inode_key,
                    b"inode",
                ),
                manifest_entry(
                    TransactionManifestObjectRole::TransactionInode,
                    other_inode_key,
                    b"other inode",
                ),
            ],
        };
        let index = PriorTransactionManifestIndex::new(&manifest).expect("index prior manifest");

        let entries = index
            .content_entries_between(content_key, inode_key)
            .expect("reuse exact content span");
        assert_eq!(entries, manifest.entries[..2]);

        let error = index
            .content_entries_between(content_key, other_inode_key)
            .expect_err("content span must not cross its owning inode");
        assert!(matches!(
            error,
            FileSystemError::CorruptState {
                reason: "clean inode content entries do not terminate at their owning inode"
            }
        ));
    }
}

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::vec;

use tidefs_local_object_store::{checksum64, IntegrityDigest64, LocalObjectStore, ObjectKey, StoredObject};
use tidefs_local_object_store::pool::{PlacementReceipt, PoolStoreMut};
use tidefs_types_vfs_core::InodeId;

use crate::constants::*;
use crate::dedup::DedupIndex;
use crate::encoding::{
    decode_content, decode_content_chunk, decode_content_manifest, decode_dedup_redirect,
    encode_content, encode_content_chunk, encode_content_manifest, encode_content_manifest_sparse,
    is_dedup_redirect,
};
use crate::error::FileSystemError;
use crate::object_keys::{
    content_chunk_object_key_for_version, content_object_key, content_object_key_for_version,
};
use crate::types::*;
use crate::{ContentChunkObject, ContentChunkRef, ContentLayout, ContentManifestObject, Result};

/// Trait abstracting content-store writes so that write functions can
/// accept either a receipt-producing [`PoolStoreMut`] (VFS write path) or
/// a raw [`LocalObjectStore`] (transaction serialisation path).
pub(crate) trait ContentWriteStore {
    fn put_with_receipt(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
    ) -> Result<(StoredObject, PlacementReceipt)>;

    fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject>;

    fn contains_key(&self, key: ObjectKey) -> bool;

    fn raw_store(&self) -> &LocalObjectStore;
    fn raw_store_mut(&mut self) -> &mut LocalObjectStore;
}

impl<'a> ContentWriteStore for PoolStoreMut<'a> {
    fn put_with_receipt(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
    ) -> Result<(StoredObject, PlacementReceipt)> {
        Ok(PoolStoreMut::put_with_receipt(self, key, payload)?)
    }
    fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        Ok(PoolStoreMut::put(self, key, payload)?)
    }
    fn contains_key(&self, key: ObjectKey) -> bool {
        PoolStoreMut::raw_store(self).contains_key(key)
    }
    fn raw_store(&self) -> &LocalObjectStore {
        PoolStoreMut::raw_store(self)
    }
    fn raw_store_mut(&mut self) -> &mut LocalObjectStore {
        PoolStoreMut::raw_store_mut(self)
    }
}

impl<'a> ContentWriteStore for &'a mut LocalObjectStore {
    fn put_with_receipt(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
    ) -> Result<(StoredObject, PlacementReceipt)> {
        let stored = LocalObjectStore::put(self, key, payload)?;
        let receipt = PlacementReceipt {
            object_key: key,
            epoch: 0,
            generation: 0,
            policy: Default::default(),
            failure_domain_level: tidefs_durability_layout::FailureDomainLevel::Device,
            payload_len: payload.len() as u64,
            shard_len: 0,
            payload_digest: [0u8; 32],
            targets: Vec::new(),
            planner_replay_receipt: None,
        };
        Ok((stored, receipt))
    }
    fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        Ok(LocalObjectStore::put(self, key, payload)?)
    }
    fn contains_key(&self, key: ObjectKey) -> bool {
        LocalObjectStore::contains_key(self, key)
    }
    fn raw_store(&self) -> &LocalObjectStore {
        self
    }
    fn raw_store_mut(&mut self) -> &mut LocalObjectStore {
        self
    }
}

impl ContentWriteStore for LocalObjectStore {
    fn put_with_receipt(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
    ) -> Result<(StoredObject, PlacementReceipt)> {
        let stored = LocalObjectStore::put(self, key, payload)?;
        let receipt = PlacementReceipt {
            object_key: key,
            epoch: 0,
            generation: 0,
            policy: Default::default(),
            failure_domain_level: tidefs_durability_layout::FailureDomainLevel::Device,
            payload_len: payload.len() as u64,
            shard_len: 0,
            payload_digest: [0u8; 32],
            targets: Vec::new(),
            planner_replay_receipt: None,
        };
        Ok((stored, receipt))
    }
    fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        Ok(LocalObjectStore::put(self, key, payload)?)
    }
    fn contains_key(&self, key: ObjectKey) -> bool {
        LocalObjectStore::contains_key(self, key)
    }
    fn raw_store(&self) -> &LocalObjectStore {
        self
    }
    fn raw_store_mut(&mut self) -> &mut LocalObjectStore {
        self
    }
}

pub(crate) struct WriteChunkedContentOverlay<'a, S: ContentWriteStore> {
    pub dedup_enabled: bool,
    pub store: &'a mut S,
    pub inode_id: InodeId,
    pub old_record: &'a InodeRecord,
    pub new_record: &'a InodeRecord,
    pub overlay_offset: u64,
    pub overlay_bytes: &'a [u8],
    pub allow_holes: bool,
    pub dedup_index: &'a mut DedupIndex,
    pub quorum_store: Option<&'a mut tidefs_quorum_write_runtime::QuorumObjectStore>,
    pub compression_policy: &'a ContentCompressionPolicy,
}

#[derive(Clone, Copy)]
pub(crate) struct ContentOverlayPatch<'a> {
    pub offset: u64,
    pub bytes: &'a [u8],
}

pub(crate) struct WriteChunkedContentPatchBatch<'a, S: ContentWriteStore> {
    pub dedup_enabled: bool,
    pub store: &'a mut S,
    pub inode_id: InodeId,
    pub old_record: &'a InodeRecord,
    pub new_record: &'a InodeRecord,
    pub patches: &'a [ContentOverlayPatch<'a>],
    pub allow_holes: bool,
    pub dedup_index: &'a mut DedupIndex,
    pub quorum_store: Option<&'a mut tidefs_quorum_write_runtime::QuorumObjectStore>,
    pub compression_policy: &'a ContentCompressionPolicy,
}

pub(crate) struct PunchHoleContent<'a, S: ContentWriteStore> {
    pub store: &'a mut S,
    pub inode_id: InodeId,
    pub old_record: &'a InodeRecord,
    pub new_record: &'a InodeRecord,
    pub hole_offset: u64,
    pub hole_length: u64,
    pub quorum_store: Option<&'a mut tidefs_quorum_write_runtime::QuorumObjectStore>,
    pub compression_policy: &'a ContentCompressionPolicy,
}

pub(crate) fn read_content_from_store(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
    allow_v0390_fixed_content: bool,
) -> Result<Vec<u8>> {
    let layout =
        read_content_layout_from_store(store, inode_id, record, allow_v0390_fixed_content)?;
    match &layout {
        ContentLayout::Inline(content) => Ok(content.bytes.clone()),
        ContentLayout::Chunked(manifest) => read_chunked_content(store, manifest, record.size),
    }
}

pub(crate) fn read_content_layout_from_store(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
    allow_v0390_fixed_content: bool,
) -> Result<ContentLayout> {
    let bytes = match store.get(content_object_key_for_version(
        inode_id,
        record.data_version,
    ))? {
        Some(bytes) => bytes,
        None if allow_v0390_fixed_content => match store.get(content_object_key(inode_id))? {
            Some(bytes) => bytes,
            None if record.size == 0 => {
                return Ok(empty_chunked_layout(inode_id, record.data_version));
            }
            None => {
                return Err(FileSystemError::CorruptState {
                    reason: "file-like inode is missing its content object",
                })
            }
        },
        None if record.size == 0 => {
            return Ok(empty_chunked_layout(inode_id, record.data_version));
        }
        None => {
            return Err(FileSystemError::CorruptState {
                reason: "file-like inode is missing its versioned content object",
            })
        }
    };
    let layout = decode_content_layout(&bytes)?;
    validate_content_layout(inode_id, record, &layout)?;
    Ok(layout)
}

fn empty_chunked_layout(inode_id: InodeId, data_version: u64) -> ContentLayout {
    ContentLayout::Chunked(ContentManifestObject {
        inode_id,
        data_version,
        file_size: 0,
        chunk_size: content_chunk_size(),
        chunks: Vec::new(),
    })
}

pub(crate) fn decode_content_layout(bytes: &[u8]) -> Result<ContentLayout> {
    if bytes.starts_with(&CONTENT_MANIFEST_MAGIC)
        || bytes.starts_with(&CONTENT_MANIFEST_SPARSE_MAGIC)
    {
        decode_content_manifest(bytes).map(ContentLayout::Chunked)
    } else {
        decode_content(bytes).map(ContentLayout::Inline)
    }
}

pub(crate) fn validate_content_layout(
    inode_id: InodeId,
    record: &InodeRecord,
    layout: &ContentLayout,
) -> Result<()> {
    match layout {
        ContentLayout::Inline(content) => {
            if content.inode_id != inode_id {
                return Err(FileSystemError::CorruptState {
                    reason: "content object belongs to a different inode",
                });
            }
            if content.data_version != record.data_version {
                return Err(FileSystemError::CorruptState {
                    reason: "content object data version does not match inode",
                });
            }
            if u64::try_from(content.bytes.len()).unwrap_or(u64::MAX) != record.size {
                return Err(FileSystemError::CorruptState {
                    reason: "content object size does not match inode",
                });
            }
        }
        ContentLayout::Chunked(manifest) => {
            validate_content_manifest(inode_id, record, manifest)?;
        }
    }
    Ok(())
}

pub(crate) fn validate_content_manifest(
    inode_id: InodeId,
    record: &InodeRecord,
    manifest: &ContentManifestObject,
) -> Result<()> {
    if manifest.inode_id != inode_id {
        return Err(FileSystemError::CorruptState {
            reason: "content manifest belongs to a different inode",
        });
    }
    if manifest.data_version != record.data_version {
        return Err(FileSystemError::CorruptState {
            reason: "content manifest data version does not match inode",
        });
    }
    if manifest.file_size != record.size {
        return Err(FileSystemError::CorruptState {
            reason: "content manifest size does not match inode",
        });
    }

    if !is_valid_content_chunk_size(manifest.chunk_size) {
        return Err(FileSystemError::CorruptState {
            reason: "content manifest chunk size is invalid (must be power of two, 512..1048576)",
        });
    }
    if manifest.chunk_size != FILESYSTEM_CONTENT_CHUNK_SIZE as u32 {
        // Non-default chunk size: accept but note for future compatibility
    }
    let expected_chunks = if record.size == 0 {
        0
    } else {
        (record.size - 1) / manifest.chunk_size as u64 + 1
    };
    if manifest.chunks.len() as u64 > expected_chunks {
        return Err(FileSystemError::CorruptState {
            reason: "content manifest has more chunks than file size allows",
        });
    }
    let mut prev_index: Option<u64> = None;
    for chunk_ref in &manifest.chunks {
        if let Some(pi) = prev_index {
            if chunk_ref.chunk_index <= pi {
                return Err(FileSystemError::CorruptState {
                    reason: "content manifest chunk indices are not strictly increasing",
                });
            }
        }
        prev_index = Some(chunk_ref.chunk_index);
        if chunk_ref.chunk_index >= expected_chunks {
            return Err(FileSystemError::CorruptState {
                reason: "content manifest chunk index beyond file size",
            });
        }
        if chunk_ref.is_hole() {
            // Hole (sparse) chunk: data_version is the sentinel.
            // Validate structural fields; no object-store read needed.
            let hole_chunk_start = chunk_ref
                .chunk_index
                .checked_mul(manifest.chunk_size as u64)
                .ok_or(FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })?;
            let hole_remaining = record.size.saturating_sub(hole_chunk_start);
            let hole_expected_len = hole_remaining.min(manifest.chunk_size as u64) as u32;
            if chunk_ref.len != hole_expected_len {
                return Err(FileSystemError::CorruptState {
                    reason: "content manifest hole chunk length does not match file size",
                });
            }
            if chunk_ref.checksum != IntegrityDigest64(0) {
                return Err(FileSystemError::CorruptState {
                    reason: "content manifest hole chunk checksum is non-zero",
                });
            }
            continue;
        }
        if chunk_ref.data_version > manifest.data_version {
            return Err(FileSystemError::CorruptState {
                reason: "content manifest chunk data version is invalid",
            });
        }
        let chunk_start = chunk_ref
            .chunk_index
            .checked_mul(manifest.chunk_size as u64)
            .ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })?;
        let remaining = record.size.saturating_sub(chunk_start);
        let expected_chunk_len = remaining.min(manifest.chunk_size as u64) as u32;
        if chunk_ref.len != expected_chunk_len {
            return Err(FileSystemError::CorruptState {
                reason: "content manifest chunk length does not match file size",
            });
        }
    }
    Ok(())
}

/// Validate raw chunk bytes: resolve dedup redirect, verify checksum,
/// decode, and check structural fields. Returns decoded chunk or `None`.
fn try_validate_chunk_bytes(
    store: &LocalObjectStore,
    inode_id: InodeId,
    chunk_ref: &ContentChunkRef,
    raw_bytes: &[u8],
) -> Option<(ContentChunkObject, bool)> {
    // Checksum the raw stored bytes first. For dedup redirects this is
    // the redirect payload, not the resolved canonical data, matching
    // how checksum is computed in all write paths.
    if checksum64(raw_bytes) != chunk_ref.checksum {
        return None;
    }
    let resolved_vec;
    let (chunk_bytes, resolved_via_dedup) = if is_dedup_redirect(raw_bytes) {
        let canonical_key = decode_dedup_redirect(raw_bytes).ok()?;
        resolved_vec = store.get(canonical_key).ok()??;
        (resolved_vec.as_slice(), true)
    } else {
        (raw_bytes, false)
    };
    let chunk = decode_content_chunk(chunk_bytes).ok()?;
    // For dedup-resolved chunks, skip inode_id, data_version, and
    // chunk_index checks: the canonical data may have been written by
    // a different inode, with a different data version, and at a
    // different chunk offset (cross-file and intra-file dedup, #841).
    if (!resolved_via_dedup
        && (chunk.inode_id != inode_id
            || chunk.data_version != chunk_ref.data_version
            || chunk.chunk_index != chunk_ref.chunk_index))
        || chunk.bytes.len() != chunk_ref.len as usize
    {
        return None;
    }
    Some((chunk, resolved_via_dedup))
}

/// Single-disk self-healing: try historical versions of a corrupt chunk.
///
/// The append-only object store preserves old copies of chunk keys in
/// segments not yet reclaimed by compaction.  When the current version
/// fails checksum, older copies may still be intact.  TideFS can self-heal
/// on a single disk — ZFS requires mirrors or PARITY_RAID, Ceph requires at
/// least one intact replica.
fn try_self_heal_chunk(
    store: &LocalObjectStore,
    inode_id: InodeId,
    chunk_ref: &ContentChunkRef,
    key: ObjectKey,
) -> Option<ContentChunkObject> {
    for location in store.version_locations_of(key).into_iter().rev() {
        let candidate = store.get_at_location(location).ok()?;
        if let Some((chunk, _dedup)) =
            try_validate_chunk_bytes(store, inode_id, chunk_ref, &candidate)
        {
            return Some(chunk);
        }
    }
    None
}

pub(crate) fn read_content_chunk_from_store(
    store: &LocalObjectStore,
    inode_id: InodeId,
    chunk_ref: &ContentChunkRef,
) -> Result<ContentChunkObject> {
    // Hole (sparse) chunks have no backing object-store data; synthesize zeros.
    if chunk_ref.is_hole() {
        let bytes = vec![0_u8; chunk_ref.len as usize];
        return Ok(ContentChunkObject {
            inode_id,
            data_version: 0,
            chunk_index: chunk_ref.chunk_index,
            bytes,
        });
    }
    let key = content_chunk_object_key_for_version(
        inode_id,
        chunk_ref.data_version,
        chunk_ref.chunk_index,
    );
    let bytes = store.get(key)?.ok_or(FileSystemError::CorruptState {
        reason: "content manifest references a missing chunk object",
    })?;
    // Validate the chunk bytes. try_validate_chunk_bytes handles dedup
    // redirect resolution internally, including cross-file inode_id
    // validation skip for reflinked chunks (#841).
    if let Some((chunk, _dedup)) = try_validate_chunk_bytes(store, inode_id, chunk_ref, &bytes) {
        return Ok(chunk);
    }

    // Self-healing fallback: the current version failed integrity checks.
    // Because the object store is append-only, older copies of the same
    // chunk key may still exist in segments not yet reclaimed.  TideFS
    // can self-heal on a single disk — ZFS requires mirrors/PARITY_RAID,
    // Ceph requires at least one intact replica.
    if let Some(chunk) = try_self_heal_chunk(store, inode_id, chunk_ref, key) {
        return Ok(chunk);
    }

    Err(FileSystemError::CorruptState {
        reason: "content chunk checksum mismatch (all historical versions also corrupt)",
    })
}

pub(crate) fn write_chunked_content<S: ContentWriteStore>(
    dedup_enabled: bool,
    store: &mut S,
    record: &InodeRecord,
    bytes: &[u8],
    dedup_index: &mut DedupIndex,
    mut quorum_store: Option<&mut tidefs_quorum_write_runtime::QuorumObjectStore>,
    compression_policy: &ContentCompressionPolicy,
) -> Result<()> {
    let actual_size = u64::try_from(bytes.len()).map_err(|_| FileSystemError::SizeOverflow {
        requested: u64::MAX,
    })?;
    if actual_size != record.size {
        return Err(FileSystemError::CorruptState {
            reason: "content byte length does not match inode size",
        });
    }
    let mut chunks = Vec::new();
    for (position, chunk_bytes) in bytes.chunks(content_chunk_size() as usize).enumerate() {
        let chunk_index = position as u64;
        let per_inode_key =
            content_chunk_object_key_for_version(record.inode_id, record.data_version, chunk_index);
        let encoded = if dedup_enabled {
            let fingerprint = crate::encoding::compute_content_fingerprint(chunk_bytes);
            if let Some(canonical_key) = dedup_index.lookup(&fingerprint) {
                // Verify the canonical object still exists; compaction may have
                // reclaimed it (#841 content-addressed dedup).
                if store.contains_key(canonical_key) {
                    dedup_index.record_dedup_hit(u64::from(content_chunk_size()));
                    let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fingerprint);
                    crate::encoding::encode_dedup_redirect(canonical_key)
                } else {
                    dedup_index.remove(&fingerprint);
                    let canon_key = crate::object_keys::content_dedup_object_key(&fingerprint);
                    let enc =
                        encode_content_chunk(record, chunk_index, chunk_bytes, compression_policy);
                    let _ = store.put_with_receipt(canon_key, &enc)?;
                    dedup_index.insert(fingerprint, canon_key);
                    crate::dedup_refcount::DedupRefCount::init(store.raw_store_mut(), &fingerprint)?;
                    crate::encoding::encode_dedup_redirect(canon_key)
                }
            } else {
                let canon_key = crate::object_keys::content_dedup_object_key(&fingerprint);
                // Cross-session dedup: if the canonical object already exists from a
                // prior mount, use it instead of writing duplicate content.
                if store.contains_key(canon_key) {
                    dedup_index.insert(fingerprint, canon_key);
                    dedup_index.record_dedup_hit(u64::from(content_chunk_size()));
                    let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fingerprint);
                    crate::encoding::encode_dedup_redirect(canon_key)
                } else {
                    let enc =
                        encode_content_chunk(record, chunk_index, chunk_bytes, compression_policy);
                    let _ = store.put_with_receipt(canon_key, &enc)?;
                    if let Some(ref mut qs) = quorum_store {
                        let _ = qs.quorum_put(canon_key, &enc);
                    }
                    dedup_index.insert(fingerprint, canon_key);
                    crate::dedup_refcount::DedupRefCount::init(store.raw_store_mut(), &fingerprint)?;
                    crate::encoding::encode_dedup_redirect(canon_key)
                }
            }
        } else {
            // Dedup disabled: inline chunk data only, no fingerprint computation,
            // no DedupIndex lookup, no cross-session canonical-object probing.

            encode_content_chunk(record, chunk_index, chunk_bytes, compression_policy)
        };
        dedup_index.record_chunk_written();
        let checksum = checksum64(&encoded);
        let chunk_receipt = store.put_with_receipt(per_inode_key, &encoded)?.1;
        if let Some(ref mut qs) = quorum_store {
            let _ = qs.quorum_put(per_inode_key, &encoded);
        }
        chunks.push(ContentChunkRef {
            chunk_index,
            data_version: record.data_version,
            len: chunk_bytes.len() as u32,
            checksum,
                    placement_receipt_generation: chunk_receipt.generation,
});
    }
    let manifest = ContentManifestObject {
        inode_id: record.inode_id,
        data_version: record.data_version,
        file_size: record.size,
        chunk_size: content_chunk_size(),
        chunks,
    };
    let _ = store.put_with_receipt(
        content_object_key_for_version(record.inode_id, record.data_version),
        &encode_content_manifest(&manifest),
    )?;
    Ok(())
}

fn write_same_size_sparse_overlay<S: ContentWriteStore>(
    dedup_enabled: bool,
    store: &mut S,
    old_layout: &ContentLayout,
    old_manifest: &ContentManifestObject,
    old_record: &InodeRecord,
    new_record: &InodeRecord,
    overlay_offset: u64,
    overlay_bytes: &[u8],
    dedup_index: &mut DedupIndex,
    mut quorum_store: Option<&mut tidefs_quorum_write_runtime::QuorumObjectStore>,
    compression_policy: &ContentCompressionPolicy,
) -> Result<()> {
    let chunk_count = content_chunk_count(new_record.size)?;
    let mut chunks_by_index = BTreeMap::new();
    for old_ref in &old_manifest.chunks {
        if old_ref.chunk_index >= chunk_count {
            continue;
        }
        let new_len = content_chunk_len(new_record.size, old_ref.chunk_index)?;
        if old_ref.len != new_len {
            continue;
        }
        let chunk_start = content_chunk_start(old_ref.chunk_index)?;
        let chunk_end =
            chunk_start
                .checked_add(u64::from(new_len))
                .ok_or(FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })?;
        if range_intersects_overlay(chunk_start, chunk_end, overlay_offset, overlay_bytes)? {
            continue;
        }
        chunks_by_index.insert(old_ref.chunk_index, old_ref.clone());
    }

    let Some((first_overlay_chunk, last_overlay_chunk)) =
        overlay_chunk_index_bounds(new_record.size, overlay_offset, overlay_bytes.len())?
    else {
        return Ok(());
    };

    for chunk_index in first_overlay_chunk..=last_overlay_chunk {
        let chunk_len = content_chunk_len(new_record.size, chunk_index)? as usize;
        let old_chunk_is_sparse_zero = match find_chunk_in_manifest(old_manifest, chunk_index) {
            Some(chunk_ref) => chunk_ref.is_hole(),
            None => true,
        };
        if old_chunk_is_sparse_zero
            && overlay_chunk_writes_only_zeros(
                chunk_index,
                chunk_len as u32,
                overlay_offset,
                overlay_bytes,
            )?
        {
            continue;
        }

        let mut chunk_bytes = vec![0_u8; chunk_len];
        copy_old_content_into_chunk(
        store.raw_store(),
            old_layout,
            old_record.size,
            chunk_index,
            &mut chunk_bytes,
        )?;
        overlay_chunk_bytes(chunk_index, overlay_offset, overlay_bytes, &mut chunk_bytes)?;

        let per_inode_key = content_chunk_object_key_for_version(
            new_record.inode_id,
            new_record.data_version,
            chunk_index,
        );
        let encoded = if dedup_enabled {
            let fingerprint = crate::encoding::compute_content_fingerprint(&chunk_bytes);
            if let Some(canonical_key) = dedup_index.lookup(&fingerprint) {
                if store.contains_key(canonical_key) {
                    dedup_index.record_dedup_hit(u64::from(content_chunk_size()));
                    let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fingerprint);
                    crate::encoding::encode_dedup_redirect(canonical_key)
                } else {
                    dedup_index.remove(&fingerprint);
                    let canon_key = crate::object_keys::content_dedup_object_key(&fingerprint);
                    let enc = encode_content_chunk(
                        new_record,
                        chunk_index,
                        &chunk_bytes,
                        compression_policy,
                    );
                    let _ = store.put_with_receipt(canon_key, &enc)?;
                    dedup_index.insert(fingerprint, canon_key);
                    crate::dedup_refcount::DedupRefCount::init(store.raw_store_mut(), &fingerprint)?;
                    crate::encoding::encode_dedup_redirect(canon_key)
                }
            } else {
                let canon_key = crate::object_keys::content_dedup_object_key(&fingerprint);
                if store.contains_key(canon_key) {
                    dedup_index.insert(fingerprint, canon_key);
                    dedup_index.record_dedup_hit(u64::from(content_chunk_size()));
                    let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fingerprint);
                    crate::encoding::encode_dedup_redirect(canon_key)
                } else {
                    let enc = encode_content_chunk(
                        new_record,
                        chunk_index,
                        &chunk_bytes,
                        compression_policy,
                    );
                    let _ = store.put_with_receipt(canon_key, &enc)?;
                    if let Some(ref mut qs) = quorum_store {
                        let _ = qs.quorum_put(canon_key, &enc);
                    }
                    dedup_index.insert(fingerprint, canon_key);
                    crate::dedup_refcount::DedupRefCount::init(store.raw_store_mut(), &fingerprint)?;
                    crate::encoding::encode_dedup_redirect(canon_key)
                }
            }
        } else {
            encode_content_chunk(new_record, chunk_index, &chunk_bytes, compression_policy)
        };
        dedup_index.record_chunk_written();
        let checksum = checksum64(&encoded);
        let chunk_receipt = store.put_with_receipt(per_inode_key, &encoded)?.1;
        if let Some(ref mut qs) = quorum_store {
            let _ = qs.quorum_put(per_inode_key, &encoded);
        }
        chunks_by_index.insert(
            chunk_index,
            ContentChunkRef {
                chunk_index,
                data_version: new_record.data_version,
                len: chunk_bytes.len() as u32,
                checksum,
                        placement_receipt_generation: chunk_receipt.generation,
},
        );
    }

    let manifest = ContentManifestObject {
        inode_id: new_record.inode_id,
        data_version: new_record.data_version,
        file_size: new_record.size,
        chunk_size: content_chunk_size(),
        chunks: chunks_by_index.into_values().collect(),
    };
    let manifest_key = content_object_key_for_version(new_record.inode_id, new_record.data_version);
    let manifest_encoded = encode_content_manifest_sparse(&manifest);
    let _ = store.put_with_receipt(manifest_key, &manifest_encoded)?;
    if let Some(ref mut qs) = quorum_store {
        let _ = qs.quorum_put(manifest_key, &manifest_encoded);
    }
    Ok(())
}

fn write_same_size_sparse_patch_batch<S: ContentWriteStore>(
    dedup_enabled: bool,
    store: &mut S,
    old_layout: &ContentLayout,
    old_manifest: &ContentManifestObject,
    old_record: &InodeRecord,
    new_record: &InodeRecord,
    patches: &[ContentOverlayPatch<'_>],
    dedup_index: &mut DedupIndex,
    mut quorum_store: Option<&mut tidefs_quorum_write_runtime::QuorumObjectStore>,
    compression_policy: &ContentCompressionPolicy,
) -> Result<()> {
    let chunk_count = content_chunk_count(new_record.size)?;
    let mut patches_by_chunk: BTreeMap<u64, Vec<ContentOverlayPatch<'_>>> = BTreeMap::new();
    for patch in patches {
        let Some((first_chunk, last_chunk)) =
            overlay_chunk_index_bounds(new_record.size, patch.offset, patch.bytes.len())?
        else {
            continue;
        };
        for chunk_index in first_chunk..=last_chunk {
            patches_by_chunk
                .entry(chunk_index)
                .or_default()
                .push(*patch);
        }
    }

    let mut chunks_by_index = BTreeMap::new();
    for old_ref in &old_manifest.chunks {
        if old_ref.chunk_index >= chunk_count {
            continue;
        }
        if old_ref.is_hole() {
            let new_len = content_chunk_len(new_record.size, old_ref.chunk_index)?;
            chunks_by_index.insert(
                old_ref.chunk_index,
                ContentChunkRef::hole(old_ref.chunk_index, new_len),
            );
            continue;
        }

        if patches_by_chunk.contains_key(&old_ref.chunk_index) {
            continue;
        }
        let new_len = content_chunk_len(new_record.size, old_ref.chunk_index)?;
        if old_ref.len == new_len {
            chunks_by_index.insert(old_ref.chunk_index, old_ref.clone());
            continue;
        }

        let mut chunk_bytes = vec![0_u8; new_len as usize];
        copy_old_content_into_chunk(
        store.raw_store(),
            old_layout,
            old_record.size,
            old_ref.chunk_index,
            &mut chunk_bytes,
        )?;
        let per_inode_key = content_chunk_object_key_for_version(
            new_record.inode_id,
            new_record.data_version,
            old_ref.chunk_index,
        );
        let encoded = if dedup_enabled {
            let fingerprint = crate::encoding::compute_content_fingerprint(&chunk_bytes);
            if let Some(canonical_key) = dedup_index.lookup(&fingerprint) {
                if store.contains_key(canonical_key) {
                    dedup_index.record_dedup_hit(u64::from(content_chunk_size()));
                    let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fingerprint);
                    crate::encoding::encode_dedup_redirect(canonical_key)
                } else {
                    dedup_index.remove(&fingerprint);
                    let canon_key = crate::object_keys::content_dedup_object_key(&fingerprint);
                    let enc = encode_content_chunk(
                        new_record,
                        old_ref.chunk_index,
                        &chunk_bytes,
                        compression_policy,
                    );
                    let _ = store.put_with_receipt(canon_key, &enc)?;
                    dedup_index.insert(fingerprint, canon_key);
                    crate::dedup_refcount::DedupRefCount::init(store.raw_store_mut(), &fingerprint)?;
                    crate::encoding::encode_dedup_redirect(canon_key)
                }
            } else {
                let canon_key = crate::object_keys::content_dedup_object_key(&fingerprint);
                if store.contains_key(canon_key) {
                    dedup_index.insert(fingerprint, canon_key);
                    dedup_index.record_dedup_hit(u64::from(content_chunk_size()));
                    let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fingerprint);
                    crate::encoding::encode_dedup_redirect(canon_key)
                } else {
                    let enc = encode_content_chunk(
                        new_record,
                        old_ref.chunk_index,
                        &chunk_bytes,
                        compression_policy,
                    );
                    let _ = store.put_with_receipt(canon_key, &enc)?;
                    if let Some(ref mut qs) = quorum_store {
                        let _ = qs.quorum_put(canon_key, &enc);
                    }
                    dedup_index.insert(fingerprint, canon_key);
                    crate::dedup_refcount::DedupRefCount::init(store.raw_store_mut(), &fingerprint)?;
                    crate::encoding::encode_dedup_redirect(canon_key)
                }
            }
        } else {
            encode_content_chunk(
                new_record,
                old_ref.chunk_index,
                &chunk_bytes,
                compression_policy,
            )
        };
        dedup_index.record_chunk_written();
        let checksum = checksum64(&encoded);
        let chunk_receipt = store.put_with_receipt(per_inode_key, &encoded)?.1;
        if let Some(ref mut qs) = quorum_store {
            let _ = qs.quorum_put(per_inode_key, &encoded);
        }
        chunks_by_index.insert(
            old_ref.chunk_index,
            ContentChunkRef {
                chunk_index: old_ref.chunk_index,
                data_version: new_record.data_version,
                len: chunk_bytes.len() as u32,
                checksum,
                        placement_receipt_generation: chunk_receipt.generation,
},
        );
    }

    for (chunk_index, chunk_patches) in patches_by_chunk {
        let chunk_len = content_chunk_len(new_record.size, chunk_index)? as usize;
        let old_chunk_is_sparse_zero = match find_chunk_in_manifest(old_manifest, chunk_index) {
            Some(chunk_ref) => chunk_ref.is_hole(),
            None => true,
        };
        let patch_bytes_all_zero = chunk_patches.iter().try_fold(true, |all_zero, patch| {
            Ok::<bool, FileSystemError>(
                all_zero
                    && overlay_chunk_writes_only_zeros(
                        chunk_index,
                        chunk_len as u32,
                        patch.offset,
                        patch.bytes,
                    )?,
            )
        })?;
        if old_chunk_is_sparse_zero && patch_bytes_all_zero {
            continue;
        }

        let mut chunk_bytes = vec![0_u8; chunk_len];
        copy_old_content_into_chunk(
        store.raw_store(),
            old_layout,
            old_record.size,
            chunk_index,
            &mut chunk_bytes,
        )?;
        for patch in chunk_patches {
            overlay_chunk_bytes(chunk_index, patch.offset, patch.bytes, &mut chunk_bytes)?;
        }
        if old_chunk_is_sparse_zero && chunk_bytes.iter().all(|byte| *byte == 0) {
            continue;
        }

        let per_inode_key = content_chunk_object_key_for_version(
            new_record.inode_id,
            new_record.data_version,
            chunk_index,
        );
        let encoded = if dedup_enabled {
            let fingerprint = crate::encoding::compute_content_fingerprint(&chunk_bytes);
            if let Some(canonical_key) = dedup_index.lookup(&fingerprint) {
                if store.contains_key(canonical_key) {
                    dedup_index.record_dedup_hit(u64::from(content_chunk_size()));
                    let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fingerprint);
                    crate::encoding::encode_dedup_redirect(canonical_key)
                } else {
                    dedup_index.remove(&fingerprint);
                    let canon_key = crate::object_keys::content_dedup_object_key(&fingerprint);
                    let enc = encode_content_chunk(
                        new_record,
                        chunk_index,
                        &chunk_bytes,
                        compression_policy,
                    );
                    let _ = store.put_with_receipt(canon_key, &enc)?;
                    dedup_index.insert(fingerprint, canon_key);
                    crate::dedup_refcount::DedupRefCount::init(store.raw_store_mut(), &fingerprint)?;
                    crate::encoding::encode_dedup_redirect(canon_key)
                }
            } else {
                let canon_key = crate::object_keys::content_dedup_object_key(&fingerprint);
                if store.contains_key(canon_key) {
                    dedup_index.insert(fingerprint, canon_key);
                    dedup_index.record_dedup_hit(u64::from(content_chunk_size()));
                    let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fingerprint);
                    crate::encoding::encode_dedup_redirect(canon_key)
                } else {
                    let enc = encode_content_chunk(
                        new_record,
                        chunk_index,
                        &chunk_bytes,
                        compression_policy,
                    );
                    let _ = store.put_with_receipt(canon_key, &enc)?;
                    if let Some(ref mut qs) = quorum_store {
                        let _ = qs.quorum_put(canon_key, &enc);
                    }
                    dedup_index.insert(fingerprint, canon_key);
                    crate::dedup_refcount::DedupRefCount::init(store.raw_store_mut(), &fingerprint)?;
                    crate::encoding::encode_dedup_redirect(canon_key)
                }
            }
        } else {
            encode_content_chunk(new_record, chunk_index, &chunk_bytes, compression_policy)
        };
        dedup_index.record_chunk_written();
        let checksum = checksum64(&encoded);
        let chunk_receipt = store.put_with_receipt(per_inode_key, &encoded)?.1;
        if let Some(ref mut qs) = quorum_store {
            let _ = qs.quorum_put(per_inode_key, &encoded);
        }
        chunks_by_index.insert(
            chunk_index,
            ContentChunkRef {
                chunk_index,
                data_version: new_record.data_version,
                len: chunk_bytes.len() as u32,
                checksum,
                        placement_receipt_generation: chunk_receipt.generation,
},
        );
    }

    let manifest = ContentManifestObject {
        inode_id: new_record.inode_id,
        data_version: new_record.data_version,
        file_size: new_record.size,
        chunk_size: content_chunk_size(),
        chunks: chunks_by_index.into_values().collect(),
    };
    let manifest_key = content_object_key_for_version(new_record.inode_id, new_record.data_version);
    let manifest_encoded = encode_content_manifest_sparse(&manifest);
    let _ = store.put_with_receipt(manifest_key, &manifest_encoded)?;
    if let Some(ref mut qs) = quorum_store {
        let _ = qs.quorum_put(manifest_key, &manifest_encoded);
    }
    Ok(())
}

fn write_sparse_size_change<S: ContentWriteStore>(
    dedup_enabled: bool,
    store: &mut S,
    old_manifest: &ContentManifestObject,
    new_record: &InodeRecord,
    dedup_index: &mut DedupIndex,
    mut quorum_store: Option<&mut tidefs_quorum_write_runtime::QuorumObjectStore>,
    compression_policy: &ContentCompressionPolicy,
) -> Result<()> {
    let new_chunk_count = content_chunk_count(new_record.size)?;
    let max_retained_chunks = usize::try_from(new_chunk_count).unwrap_or(usize::MAX);
    let mut chunks = Vec::with_capacity(old_manifest.chunks.len().min(max_retained_chunks));

    for old_ref in &old_manifest.chunks {
        if old_ref.chunk_index >= new_chunk_count {
            continue;
        }
        let expected_len = content_chunk_len(new_record.size, old_ref.chunk_index)?;
        if old_ref.len == expected_len {
            chunks.push(old_ref.clone());
            continue;
        }
        if old_ref.is_hole() {
            chunks.push(ContentChunkRef::hole(old_ref.chunk_index, expected_len));
            continue;
        }

        let old_chunk = read_content_chunk_from_store(store.raw_store(), new_record.inode_id, old_ref)?;
        let mut chunk_bytes = old_chunk.bytes.to_vec();
        chunk_bytes.resize(expected_len as usize, 0);

        let per_inode_key = content_chunk_object_key_for_version(
            new_record.inode_id,
            new_record.data_version,
            old_ref.chunk_index,
        );
        let encoded = if dedup_enabled {
            let fingerprint = crate::encoding::compute_content_fingerprint(&chunk_bytes);
            if let Some(canonical_key) = dedup_index.lookup(&fingerprint) {
                if store.contains_key(canonical_key) {
                    dedup_index.record_dedup_hit(u64::from(content_chunk_size()));
                    let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fingerprint);
                    crate::encoding::encode_dedup_redirect(canonical_key)
                } else {
                    dedup_index.remove(&fingerprint);
                    let canon_key = crate::object_keys::content_dedup_object_key(&fingerprint);
                    let enc = encode_content_chunk(
                        new_record,
                        old_ref.chunk_index,
                        &chunk_bytes,
                        compression_policy,
                    );
                    let _ = store.put_with_receipt(canon_key, &enc)?;
                    dedup_index.insert(fingerprint, canon_key);
                    crate::dedup_refcount::DedupRefCount::init(store.raw_store_mut(), &fingerprint)?;
                    crate::encoding::encode_dedup_redirect(canon_key)
                }
            } else {
                let canon_key = crate::object_keys::content_dedup_object_key(&fingerprint);
                if store.contains_key(canon_key) {
                    dedup_index.insert(fingerprint, canon_key);
                    dedup_index.record_dedup_hit(u64::from(content_chunk_size()));
                    let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fingerprint);
                    crate::encoding::encode_dedup_redirect(canon_key)
                } else {
                    let enc = encode_content_chunk(
                        new_record,
                        old_ref.chunk_index,
                        &chunk_bytes,
                        compression_policy,
                    );
                    let _ = store.put_with_receipt(canon_key, &enc)?;
                    if let Some(ref mut qs) = quorum_store {
                        let _ = qs.quorum_put(canon_key, &enc);
                    }
                    dedup_index.insert(fingerprint, canon_key);
                    crate::dedup_refcount::DedupRefCount::init(store.raw_store_mut(), &fingerprint)?;
                    crate::encoding::encode_dedup_redirect(canon_key)
                }
            }
        } else {
            encode_content_chunk(
                new_record,
                old_ref.chunk_index,
                &chunk_bytes,
                compression_policy,
            )
        };
        dedup_index.record_chunk_written();
        let checksum = checksum64(&encoded);
        let chunk_receipt = store.put_with_receipt(per_inode_key, &encoded)?.1;
        if let Some(ref mut qs) = quorum_store {
            let _ = qs.quorum_put(per_inode_key, &encoded);
        }
        chunks.push(ContentChunkRef {
            chunk_index: old_ref.chunk_index,
            data_version: new_record.data_version,
            len: expected_len,
            checksum,
                    placement_receipt_generation: chunk_receipt.generation,
});
    }

    let manifest = ContentManifestObject {
        inode_id: new_record.inode_id,
        data_version: new_record.data_version,
        file_size: new_record.size,
        chunk_size: content_chunk_size(),
        chunks,
    };
    let manifest_key = content_object_key_for_version(new_record.inode_id, new_record.data_version);
    let manifest_encoded = encode_content_manifest_sparse(&manifest);
    let _ = store.put_with_receipt(manifest_key, &manifest_encoded)?;
    if let Some(ref mut qs) = quorum_store {
        let _ = qs.quorum_put(manifest_key, &manifest_encoded);
    }
    Ok(())
}

pub(crate) fn write_chunked_content_with_overlay<S: ContentWriteStore>(
    request: WriteChunkedContentOverlay<'_, S>,
) -> Result<()> {
    let WriteChunkedContentOverlay {
        dedup_enabled,
        store,
        inode_id,
        old_record,
        new_record,
        overlay_offset,
        overlay_bytes,
        allow_holes,
        dedup_index,
        mut quorum_store,
        compression_policy,
    } = request;
    let old_layout = read_content_layout_from_store(store.raw_store(), inode_id, old_record, true)?;
    if allow_holes && overlay_bytes.is_empty() {
        if let ContentLayout::Chunked(ref old_manifest) = old_layout {
            return write_sparse_size_change(
                dedup_enabled,
                store,
                old_manifest,
                new_record,
                dedup_index,
                quorum_store,
                compression_policy,

            );
        }
    }
    if allow_holes && old_record.size == new_record.size && !overlay_bytes.is_empty() {
        if let ContentLayout::Chunked(ref old_manifest) = old_layout {
            return write_same_size_sparse_overlay(
                dedup_enabled,
                store,
                &old_layout,
                old_manifest,
                old_record,
                new_record,
                overlay_offset,
                overlay_bytes,
                dedup_index,
                quorum_store,
                compression_policy,

            );
        }
    }
    let chunk_count = content_chunk_count(new_record.size)?;
    let mut chunks = Vec::new();
    for chunk_index in 0..chunk_count {
        if let Some(retained) = retained_content_chunk_ref(
            &old_layout,
            old_record.size,
            new_record.size,
            overlay_offset,
            overlay_bytes,
            chunk_index,
        )? {
            chunks.push(retained);
            continue;
        }

        if allow_holes {
            // Preserve sparse holes that the write doesn't touch. Chunks that
            // have no old data and no overlay stay absent from the manifest and
            // consume no capacity.
            let cstart = content_chunk_start(chunk_index)?;
            let cend = cstart
                .checked_add(u64::from(content_chunk_len(new_record.size, chunk_index)?))
                .ok_or(FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })?;
            if !range_intersects_overlay(cstart, cend, overlay_offset, overlay_bytes)? {
                let can_skip_hole = match old_layout {
                    ContentLayout::Chunked(ref manifest) => {
                        find_chunk_in_manifest(manifest, chunk_index).is_none()
                            || cstart >= old_record.size
                    }
                    ContentLayout::Inline(_) => cstart >= old_record.size,
                };
                if can_skip_hole {
                    continue;
                }
            }
        }

        let chunk_len = content_chunk_len(new_record.size, chunk_index)? as usize;
        let mut chunk_bytes = vec![0_u8; chunk_len];
        copy_old_content_into_chunk(
        store.raw_store(),
            &old_layout,
            old_record.size,
            chunk_index,
            &mut chunk_bytes,
        )?;
        overlay_chunk_bytes(chunk_index, overlay_offset, overlay_bytes, &mut chunk_bytes)?;
        // Hole (sparse) chunk detection: if the entire chunk lies beyond the old
        // file size and no overlay touches it, record a hole instead of storing zeros.
        // ZFS uses hole birth times in block pointers for the same O(1) sparse truncation.
        let chunk_start = content_chunk_start(chunk_index)?;
        let is_beyond_old = chunk_start >= old_record.size;
        let is_overlay_empty = overlay_bytes.is_empty()
            || !range_intersects_overlay(
                chunk_start,
                chunk_start + chunk_bytes.len() as u64,
                overlay_offset,
                overlay_bytes,
            )?;
        if allow_holes && is_beyond_old && is_overlay_empty {
            debug_assert!(
                chunk_bytes.iter().all(|&b| b == 0),
                "hole chunk must be all zeros"
            );
            chunks.push(ContentChunkRef::hole(chunk_index, chunk_bytes.len() as u32));
            continue;
        }
        let per_inode_key = content_chunk_object_key_for_version(
            new_record.inode_id,
            new_record.data_version,
            chunk_index,
        );
        let encoded = if dedup_enabled {
            let fingerprint = crate::encoding::compute_content_fingerprint(&chunk_bytes);
            if let Some(canonical_key) = dedup_index.lookup(&fingerprint) {
                if store.contains_key(canonical_key) {
                    dedup_index.record_dedup_hit(u64::from(content_chunk_size()));
                    let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fingerprint);
                    crate::encoding::encode_dedup_redirect(canonical_key)
                } else {
                    dedup_index.remove(&fingerprint);
                    let canon_key = crate::object_keys::content_dedup_object_key(&fingerprint);
                    let enc = encode_content_chunk(
                        new_record,
                        chunk_index,
                        &chunk_bytes,
                        compression_policy,
                    );
                    let _ = store.put_with_receipt(canon_key, &enc)?;
                    dedup_index.insert(fingerprint, canon_key);
                    crate::dedup_refcount::DedupRefCount::init(store.raw_store_mut(), &fingerprint)?;
                    crate::encoding::encode_dedup_redirect(canon_key)
                }
            } else {
                let canon_key = crate::object_keys::content_dedup_object_key(&fingerprint);
                if store.contains_key(canon_key) {
                    dedup_index.insert(fingerprint, canon_key);
                    dedup_index.record_dedup_hit(u64::from(content_chunk_size()));
                    let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fingerprint);
                    crate::encoding::encode_dedup_redirect(canon_key)
                } else {
                    let enc = encode_content_chunk(
                        new_record,
                        chunk_index,
                        &chunk_bytes,
                        compression_policy,
                    );
                    let _ = store.put_with_receipt(canon_key, &enc)?;
                    if let Some(ref mut qs) = quorum_store {
                        let _ = qs.quorum_put(canon_key, &enc);
                    }
                    dedup_index.insert(fingerprint, canon_key);
                    crate::dedup_refcount::DedupRefCount::init(store.raw_store_mut(), &fingerprint)?;
                    crate::encoding::encode_dedup_redirect(canon_key)
                }
            }
        } else {
            encode_content_chunk(new_record, chunk_index, &chunk_bytes, compression_policy)
        };
        dedup_index.record_chunk_written();
        let checksum = checksum64(&encoded);
        let chunk_receipt = store.put_with_receipt(per_inode_key, &encoded)?.1;
        if let Some(ref mut qs) = quorum_store {
            let _ = qs.quorum_put(per_inode_key, &encoded);
        }
        chunks.push(ContentChunkRef {
            chunk_index,
            data_version: new_record.data_version,
            len: chunk_bytes.len() as u32,
            checksum,
                    placement_receipt_generation: chunk_receipt.generation,
});
    }
    let manifest = ContentManifestObject {
        inode_id: new_record.inode_id,
        data_version: new_record.data_version,
        file_size: new_record.size,
        chunk_size: content_chunk_size(),
        chunks,
    };
    let manifest_key = content_object_key_for_version(new_record.inode_id, new_record.data_version);
    let manifest_encoded = encode_content_manifest_sparse(&manifest);
    let _ = store.put_with_receipt(manifest_key, &manifest_encoded)?;
    if let Some(ref mut qs) = quorum_store {
        let _ = qs.quorum_put(manifest_key, &manifest_encoded);
    }
    Ok(())
}

pub(crate) fn write_chunked_content_with_patch_batch<S: ContentWriteStore>(
    request: WriteChunkedContentPatchBatch<'_, S>,
) -> Result<()> {
    let WriteChunkedContentPatchBatch {
        dedup_enabled,
        store,
        inode_id,
        old_record,
        new_record,
        patches,
        allow_holes,
        dedup_index,
        quorum_store,
        compression_policy,
    } = request;
    let old_layout = read_content_layout_from_store(store.raw_store(), inode_id, old_record, true)?;
    if allow_holes && old_record.size <= new_record.size {
        if let ContentLayout::Chunked(ref old_manifest) = old_layout {
            return write_same_size_sparse_patch_batch(
                dedup_enabled,
                store,
                &old_layout,
                old_manifest,
                old_record,
                new_record,
                patches,
                dedup_index,
                quorum_store,
                compression_policy,

            );
        }
    }
    Err(FileSystemError::Unsupported {
        operation: "chunked content patch batch",
        reason: "batch writeback optimization requires non-shrinking chunked content",
    })
}

pub(crate) fn punch_hole_content<S: ContentWriteStore>(request: PunchHoleContent<'_, S>) -> Result<()> {
    let PunchHoleContent {
        store,
        inode_id,
        old_record,
        new_record,
        hole_offset,
        hole_length,
        mut quorum_store,
        compression_policy,
    } = request;
    let old_layout = read_content_layout_from_store(store.raw_store(), inode_id, old_record, true)?;

    // Handle inline content: zero the hole range in-place and re-encode.
    if let ContentLayout::Inline(ref content) = old_layout {
        let mut bytes = content.bytes.clone();
        let hole_start = usize::try_from(hole_offset).unwrap_or(bytes.len());
        let hole_end =
            usize::try_from(hole_offset.saturating_add(hole_length)).unwrap_or(bytes.len());
        let hole_start = hole_start.min(bytes.len());
        let hole_end = hole_end.min(bytes.len());
        if hole_start < hole_end {
            bytes[hole_start..hole_end].fill(0);
        }
        let key = content_object_key_for_version(new_record.inode_id, new_record.data_version);
        let encoded = encode_content(new_record, &bytes);
        let _ = store.put_with_receipt(key, &encoded)?;
        return Ok(());
    }

    let ContentLayout::Chunked(ref old_manifest) = old_layout else {
        unreachable!("punch_hole: expected Chunked layout after handling Inline");
    };

    let chunk_size = content_chunk_size() as u64;
    let hole_end = hole_offset.saturating_add(hole_length);
    let total_chunks = content_chunk_count(new_record.size)?;

    // Retain materialized chunks that do NOT overlap the hole range, or adjust
    // partial overlaps. Missing manifest entries are already sparse zeroes, so
    // walking only live entries avoids an O(total file chunks) scan for tiny
    // holes in large sparse files.
    let mut chunks = Vec::new();
    for old_ref in &old_manifest.chunks {
        if old_ref.chunk_index >= total_chunks {
            continue;
        }
        let chunk_index = old_ref.chunk_index;
        let chunk_start = chunk_index * chunk_size;
        let chunk_end = (chunk_start + u64::from(old_ref.len)).min(new_record.size);

        if chunk_end <= hole_offset || chunk_start >= hole_end {
            chunks.push(old_ref.clone());
        } else if chunk_start >= hole_offset && chunk_end <= hole_end {
            // Chunk is entirely within the hole: drop it entirely.
            // The read path will return zeros for this missing chunk.
        } else if !old_ref.is_hole() {
            // Chunk partially overlaps the hole: read the chunk, zero the
            // hole bytes, and write a modified chunk under the new data version.
            let old_chunk = read_content_chunk_from_store(store.raw_store(), inode_id, old_ref)?;
            let mut modified = old_chunk.bytes.to_vec();
            let zero_start = hole_offset.saturating_sub(chunk_start);
            let zero_start_idx = usize::try_from(zero_start).unwrap_or(0);
            let zero_end = (hole_end.saturating_sub(chunk_start)).min(modified.len() as u64);
            let modified_len = modified.len();
            let zero_end_idx = usize::try_from(zero_end).unwrap_or(modified_len);
            if zero_start_idx < zero_end_idx && zero_start_idx < modified_len {
                for b in &mut modified[zero_start_idx..zero_end_idx.min(modified_len)] {
                    *b = 0;
                }
            }
            let encoded =
                encode_content_chunk(new_record, chunk_index, &modified, compression_policy);
            let checksum = checksum64(&encoded);
            let key = content_chunk_object_key_for_version(
                new_record.inode_id,
                new_record.data_version,
                chunk_index,
            );
            let chunk_receipt = store.put_with_receipt(key, &encoded)?.1;
            if let Some(ref mut qs) = quorum_store {
                let _ = qs.quorum_put(key, &encoded);
            }
            chunks.push(ContentChunkRef {
                chunk_index,
                data_version: new_record.data_version,
                len: modified.len() as u32,
                checksum,
                        placement_receipt_generation: chunk_receipt.generation,
});
        } else {
            // Existing sparse marker partially overlaps the hole. Keep the
            // marker so sparse tail-length metadata survives unchanged.
            chunks.push(old_ref.clone());
        }
    }

    let manifest = ContentManifestObject {
        inode_id: new_record.inode_id,
        data_version: new_record.data_version,
        file_size: new_record.size,
        chunk_size: content_chunk_size(),
        chunks,
    };
    let manifest_key = content_object_key_for_version(new_record.inode_id, new_record.data_version);
    let manifest_encoded = encode_content_manifest_sparse(&manifest);
    let _ = store.put_with_receipt(manifest_key, &manifest_encoded)?;
    if let Some(ref mut qs) = quorum_store {
        let _ = qs.quorum_put(manifest_key, &manifest_encoded);
    }
    Ok(())
}

pub(crate) fn retained_content_chunk_ref(
    old_layout: &ContentLayout,
    old_size: u64,
    new_size: u64,
    overlay_offset: u64,
    overlay_bytes: &[u8],
    chunk_index: u64,
) -> Result<Option<ContentChunkRef>> {
    let ContentLayout::Chunked(manifest) = old_layout else {
        return Ok(None);
    };
    let Some(old_ref) = find_chunk_in_manifest(manifest, chunk_index) else {
        return Ok(None);
    };
    let new_len = content_chunk_len(new_size, chunk_index)?;
    if old_ref.len != new_len {
        return Ok(None);
    }
    let chunk_start = content_chunk_start(chunk_index)?;
    let chunk_end =
        chunk_start
            .checked_add(u64::from(new_len))
            .ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })?;
    if chunk_end > old_size {
        return Ok(None);
    }
    if range_intersects_overlay(chunk_start, chunk_end, overlay_offset, overlay_bytes)? {
        return Ok(None);
    }
    Ok(Some(old_ref.clone()))
}

pub(crate) fn copy_old_content_into_chunk(
    store: &LocalObjectStore,
    old_layout: &ContentLayout,
    old_size: u64,
    chunk_index: u64,
    chunk_bytes: &mut [u8],
) -> Result<()> {
    let chunk_start = content_chunk_start(chunk_index)?;
    if chunk_start >= old_size || chunk_bytes.is_empty() {
        return Ok(());
    }
    let available = old_size.saturating_sub(chunk_start);
    let copy_len = chunk_bytes
        .len()
        .min(usize::try_from(available).unwrap_or(usize::MAX));
    let old_bytes = read_content_range_from_layout(store, old_layout, chunk_start, copy_len)?;
    chunk_bytes[..old_bytes.len()].copy_from_slice(&old_bytes);
    Ok(())
}

pub(crate) fn overlay_chunk_bytes(
    chunk_index: u64,
    overlay_offset: u64,
    overlay_bytes: &[u8],
    chunk_bytes: &mut [u8],
) -> Result<()> {
    if overlay_bytes.is_empty() || chunk_bytes.is_empty() {
        return Ok(());
    }
    let chunk_start = content_chunk_start(chunk_index)?;
    let chunk_end =
        chunk_start
            .checked_add(chunk_bytes.len() as u64)
            .ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })?;
    let overlay_end = overlay_offset
        .checked_add(overlay_bytes.len() as u64)
        .ok_or(FileSystemError::SizeOverflow {
            requested: u64::MAX,
        })?;
    let start = chunk_start.max(overlay_offset);
    let end = chunk_end.min(overlay_end);
    if start >= end {
        return Ok(());
    }
    let chunk_dst =
        usize::try_from(start - chunk_start).map_err(|_| FileSystemError::SizeOverflow {
            requested: start - chunk_start,
        })?;
    let overlay_src =
        usize::try_from(start - overlay_offset).map_err(|_| FileSystemError::SizeOverflow {
            requested: start - overlay_offset,
        })?;
    let len = usize::try_from(end - start).map_err(|_| FileSystemError::SizeOverflow {
        requested: end - start,
    })?;
    chunk_bytes[chunk_dst..chunk_dst + len]
        .copy_from_slice(&overlay_bytes[overlay_src..overlay_src + len]);
    Ok(())
}

pub(crate) fn overlay_chunk_writes_only_zeros(
    chunk_index: u64,
    chunk_len: u32,
    overlay_offset: u64,
    overlay_bytes: &[u8],
) -> Result<bool> {
    if overlay_bytes.is_empty() || chunk_len == 0 {
        return Ok(true);
    }
    let chunk_start = content_chunk_start(chunk_index)?;
    let chunk_end =
        chunk_start
            .checked_add(u64::from(chunk_len))
            .ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })?;
    let overlay_end = overlay_offset
        .checked_add(overlay_bytes.len() as u64)
        .ok_or(FileSystemError::SizeOverflow {
            requested: u64::MAX,
        })?;
    let start = chunk_start.max(overlay_offset);
    let end = chunk_end.min(overlay_end);
    if start >= end {
        return Ok(true);
    }
    let overlay_src =
        usize::try_from(start - overlay_offset).map_err(|_| FileSystemError::SizeOverflow {
            requested: start - overlay_offset,
        })?;
    let len = usize::try_from(end - start).map_err(|_| FileSystemError::SizeOverflow {
        requested: end - start,
    })?;
    Ok(overlay_bytes[overlay_src..overlay_src + len]
        .iter()
        .all(|byte| *byte == 0))
}

pub(crate) fn read_chunked_content(
    store: &LocalObjectStore,
    manifest: &ContentManifestObject,
    file_size: u64,
) -> Result<Vec<u8>> {
    let capacity = usize::try_from(file_size).map_err(|_| FileSystemError::SizeOverflow {
        requested: file_size,
    })?;
    let mut out = Vec::with_capacity(capacity);
    let chunk_size = manifest.chunk_size as u64;
    let mut expected_pos: u64 = 0;
    for chunk_ref in &manifest.chunks {
        let chunk_start = chunk_ref.chunk_index * chunk_size;
        if chunk_start > expected_pos {
            let hole_len = usize::try_from(chunk_start - expected_pos).map_err(|_| {
                FileSystemError::SizeOverflow {
                    requested: chunk_start - expected_pos,
                }
            })?;
            out.resize(out.len() + hole_len, 0);
        }
        let chunk = read_content_chunk_from_store(store, manifest.inode_id, chunk_ref)?;
        out.extend_from_slice(&chunk.bytes);
        expected_pos = chunk_start + chunk_ref.len as u64;
    }
    if expected_pos < file_size {
        let tail_len = usize::try_from(file_size - expected_pos).map_err(|_| {
            FileSystemError::SizeOverflow {
                requested: file_size - expected_pos,
            }
        })?;
        out.resize(out.len() + tail_len, 0);
    }
    Ok(out)
}

pub(crate) fn read_content_range_from_store(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
    offset: u64,
    len: usize,
    allow_v0390_fixed_content: bool,
) -> Result<Vec<u8>> {
    if len == 0 || offset >= record.size {
        return Ok(Vec::new());
    }
    let len_u64 = u64::try_from(len).map_err(|_| FileSystemError::SizeOverflow {
        requested: u64::MAX,
    })?;
    let available = record.size - offset;
    let clipped_len =
        usize::try_from(available.min(len_u64)).map_err(|_| FileSystemError::SizeOverflow {
            requested: available,
        })?;
    let layout =
        read_content_layout_from_store(store, inode_id, record, allow_v0390_fixed_content)?;
    read_content_range_from_layout(store, &layout, offset, clipped_len)
}

pub(crate) fn read_content_range_from_layout(
    store: &LocalObjectStore,
    layout: &ContentLayout,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    match layout {
        ContentLayout::Inline(content) => {
            let start = usize::try_from(offset)
                .map_err(|_| FileSystemError::SizeOverflow { requested: offset })?;
            let end = start
                .checked_add(len)
                .ok_or(FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })?;
            if end > content.bytes.len() {
                return Err(FileSystemError::CorruptState {
                    reason: "inline content range exceeds object size",
                });
            }
            Ok(content.bytes[start..end].to_vec())
        }
        ContentLayout::Chunked(manifest) => {
            let mut out = Vec::with_capacity(len);
            let mut remaining = len;
            let mut cursor = offset;
            while remaining > 0 {
                let chunk_size = manifest.chunk_size as u64;
                let chunk_index = cursor / chunk_size;
                let in_chunk = usize::try_from(cursor % chunk_size)
                    .map_err(|_| FileSystemError::SizeOverflow { requested: cursor })?;
                let chunk_ref = find_chunk_in_manifest(manifest, chunk_index);
                if let Some(chunk_ref) = chunk_ref {
                    let chunk_available = chunk_ref.len as usize;
                    if chunk_ref.is_hole() {
                        if in_chunk > chunk_available {
                            return Err(FileSystemError::CorruptState {
                                reason: "content range starts beyond hole chunk length",
                            });
                        }
                        let take = remaining.min(chunk_available.saturating_sub(in_chunk));
                        if take == 0 {
                            return Err(FileSystemError::CorruptState {
                                reason: "content range made no progress",
                            });
                        }
                        out.resize(out.len() + take, 0);
                        remaining -= take;
                        cursor = cursor.checked_add(take as u64).ok_or(
                            FileSystemError::SizeOverflow {
                                requested: u64::MAX,
                            },
                        )?;
                        continue;
                    }

                    let chunk = read_content_chunk_from_store(store, manifest.inode_id, chunk_ref)?;
                    if in_chunk > chunk.bytes.len() {
                        return Err(FileSystemError::CorruptState {
                            reason: "content range starts beyond chunk length",
                        });
                    }
                    let take = remaining.min(chunk.bytes.len().saturating_sub(in_chunk));
                    if take == 0 {
                        return Err(FileSystemError::CorruptState {
                            reason: "content range made no progress",
                        });
                    }
                    out.extend_from_slice(&chunk.bytes[in_chunk..in_chunk + take]);
                    remaining -= take;
                    cursor =
                        cursor
                            .checked_add(take as u64)
                            .ok_or(FileSystemError::SizeOverflow {
                                requested: u64::MAX,
                            })?;
                } else {
                    let chunk_start = chunk_index.checked_mul(chunk_size).ok_or(
                        FileSystemError::SizeOverflow {
                            requested: u64::MAX,
                        },
                    )?;
                    let chunk_remaining = manifest.file_size.saturating_sub(chunk_start);
                    let chunk_len = chunk_remaining.min(chunk_size) as usize;
                    if in_chunk > chunk_len {
                        return Err(FileSystemError::CorruptState {
                            reason: "content range starts beyond sparse chunk length",
                        });
                    }
                    let take = remaining.min(chunk_len.saturating_sub(in_chunk));
                    if take == 0 {
                        return Err(FileSystemError::CorruptState {
                            reason: "content range made no progress",
                        });
                    }
                    out.resize(out.len() + take, 0);
                    remaining -= take;
                    cursor =
                        cursor
                            .checked_add(take as u64)
                            .ok_or(FileSystemError::SizeOverflow {
                                requested: u64::MAX,
                            })?;
                }
            }
            Ok(out)
        }
    }
}

pub(crate) fn range_intersects_overlay(
    start: u64,
    end: u64,
    overlay_offset: u64,
    overlay_bytes: &[u8],
) -> Result<bool> {
    let overlay_end = overlay_offset
        .checked_add(overlay_bytes.len() as u64)
        .ok_or(FileSystemError::SizeOverflow {
            requested: u64::MAX,
        })?;
    Ok(!overlay_bytes.is_empty() && start < overlay_end && overlay_offset < end)
}

pub(crate) fn overlay_chunk_index_bounds(
    file_size: u64,
    overlay_offset: u64,
    overlay_len: usize,
) -> Result<Option<(u64, u64)>> {
    if file_size == 0 || overlay_len == 0 || overlay_offset >= file_size {
        return Ok(None);
    }
    let overlay_len = u64::try_from(overlay_len).map_err(|_| FileSystemError::SizeOverflow {
        requested: u64::MAX,
    })?;
    let overlay_end = overlay_offset
        .checked_add(overlay_len)
        .ok_or(FileSystemError::SizeOverflow {
            requested: u64::MAX,
        })?
        .min(file_size);
    if overlay_end <= overlay_offset {
        return Ok(None);
    }
    let chunk_size = content_chunk_size() as u64;
    Ok(Some((
        overlay_offset / chunk_size,
        (overlay_end - 1) / chunk_size,
    )))
}

/// Find a chunk reference in a (possibly sparse) manifest by chunk_index.
pub(crate) fn find_chunk_in_manifest(
    manifest: &ContentManifestObject,
    chunk_index: u64,
) -> Option<&ContentChunkRef> {
    manifest
        .chunks
        .binary_search_by_key(&chunk_index, |chunk| chunk.chunk_index)
        .ok()
        .map(|index| &manifest.chunks[index])
}

/// Returns true if `chunk_size` is a power of two in [512, 1048576].
pub(crate) fn is_valid_content_chunk_size(chunk_size: u32) -> bool {
    (512..=1_048_576).contains(&chunk_size) && chunk_size.is_power_of_two()
}

pub(crate) fn content_chunk_count(size: u64) -> Result<u64> {
    if size == 0 {
        Ok(0)
    } else {
        Ok((size - 1) / content_chunk_size() as u64 + 1)
    }
}

pub(crate) fn content_chunk_len(file_size: u64, chunk_index: u64) -> Result<u32> {
    let chunk_start = content_chunk_start(chunk_index)?;
    if chunk_start >= file_size {
        return Err(FileSystemError::CorruptState {
            reason: "content chunk starts beyond file size",
        });
    }
    let remaining = file_size - chunk_start;
    let len = remaining.min(content_chunk_size() as u64);
    u32::try_from(len).map_err(|_| FileSystemError::SizeOverflow { requested: len })
}

pub(crate) fn content_chunk_start(chunk_index: u64) -> Result<u64> {
    chunk_index
        .checked_mul(content_chunk_size() as u64)
        .ok_or(FileSystemError::SizeOverflow {
            requested: u64::MAX,
        })
}

// ── Reflink (cross-file zero-copy clone via content-addressed dedup) ──

/// Share all content chunks from `source_record` with `dest_record` by storing
/// dedup redirects at the destination's per-inode chunk keys.  No data bytes
/// are read, copied, or re-encoded — the destination's chunk entries point
/// directly to the same canonical (fingerprint-addressed) chunks as the source.
///
/// This is the storage-level primitive that powers FICLONE/copy_file_range
/// same-filesystem reflink and snapshot-clone writable forks.
pub(crate) fn reflink_chunked_content<S: ContentWriteStore>(
    dedup_enabled: bool,
    store: &mut S,
    source_inode_id: InodeId,
    source_record: &InodeRecord,
    dest_record: &InodeRecord,
    dedup_index: &mut DedupIndex,
) -> Result<()> {
    let source_layout =
        read_content_layout_from_store(store.raw_store(), source_inode_id, source_record, true)?;
    match source_layout {
        ContentLayout::Inline(content) => {
            // Inline content cannot be shared at the chunk level; write the
            // entire content as a new inline object for the destination.
            let dest_content = crate::records::ContentObject {
                inode_id: dest_record.inode_id,
                data_version: dest_record.data_version,
                bytes: content.bytes.clone(),
            };
            store.put(
                content_object_key_for_version(dest_record.inode_id, dest_record.data_version),
                &crate::encoding::encode_content(dest_record, &dest_content.bytes),
            )?;
        }
        ContentLayout::Chunked(ref manifest) => {
            // For every chunk in the source manifest, store a dedup redirect
            // at the destination's per-inode chunk key.  We read the raw
            // encoded bytes from each source chunk key — these are *already*
            // either a dedup redirect or actual chunk data stored at the
            // canonical key from the original write path.
            let mut dest_chunks: Vec<ContentChunkRef> = Vec::with_capacity(manifest.chunks.len());

            if !dedup_enabled {
                // Dedup disabled: copy source chunk bytes directly to
                // destination per-inode keys without fingerprint computation,
                // canonical-object storage, or DedupIndex insertion.
                for src_chunk_ref in &manifest.chunks {
                    let src_chunk_key = content_chunk_object_key_for_version(
                        source_inode_id,
                        src_chunk_ref.data_version,
                        src_chunk_ref.chunk_index,
                    );
                    let src_encoded =
                        store.raw_store()
                            .get(src_chunk_key)?
                            .ok_or(FileSystemError::CorruptState {
                                reason: "reflink: source chunk object missing",
                            })?;
                    let dest_chunk_key = content_chunk_object_key_for_version(
                        dest_record.inode_id,
                        dest_record.data_version,
                        src_chunk_ref.chunk_index,
                    );
                    let chunk_receipt = store.put_with_receipt(dest_chunk_key, &src_encoded)?.1;
                    dest_chunks.push(ContentChunkRef {
                        chunk_index: src_chunk_ref.chunk_index,
                        data_version: dest_record.data_version,
                        len: src_chunk_ref.len,
                        checksum: checksum64(&src_encoded),
                                placement_receipt_generation: chunk_receipt.generation,
});
                }
                let dest_manifest = ContentManifestObject {
                    inode_id: dest_record.inode_id,
                    data_version: dest_record.data_version,
                    file_size: dest_record.size,
                    chunk_size: manifest.chunk_size,
                    chunks: dest_chunks,
                };
                store.put(
                    content_object_key_for_version(dest_record.inode_id, dest_record.data_version),
                    &encode_content_manifest(&dest_manifest),
                )?;
                return Ok(());
            }

            // Dedup enabled: use content-addressed redirects as the clone
            // primitive.
            for src_chunk_ref in &manifest.chunks {
                let src_chunk_key = content_chunk_object_key_for_version(
                    source_inode_id,
                    src_chunk_ref.data_version,
                    src_chunk_ref.chunk_index,
                );
                let src_encoded =
                    store.raw_store()
                        .get(src_chunk_key)?
                        .ok_or(FileSystemError::CorruptState {
                            reason: "reflink: source chunk object missing",
                        })?;

                let (canonical_key, fingerprint) = if is_dedup_redirect(&src_encoded) {
                    // Source already has a dedup redirect; chain to the same
                    // canonical key and add the fingerprint to the local index.
                    let ck = decode_dedup_redirect(&src_encoded)?;
                    let canon_bytes = store.raw_store().get(ck)?.ok_or(FileSystemError::CorruptState {
                        reason: "reflink: dedup redirect references missing canonical chunk",
                    })?;
                    let chunk = decode_content_chunk(&canon_bytes)?;
                    let fp = crate::encoding::compute_content_fingerprint(&chunk.bytes);
                    // Existing canonical: increment refcount for this new redirect.
                    let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fp);
                    (ck, fp)
                } else {
                    // Source chunk is stored inline (no previous dedup).
                    // Compute its fingerprint, store at the canonical key if
                    // not already present, then redirect.
                    let chunk = decode_content_chunk(&src_encoded)?;
                    let fp = crate::encoding::compute_content_fingerprint(&chunk.bytes);
                    let ck = crate::object_keys::content_dedup_object_key(&fp);
                    // Only store the canonical chunk if it's not already there
                    let canonical_existed = store.raw_store().get(ck)?.is_some();
                    if !canonical_existed {
                        store.put(ck, &src_encoded)?;
                        crate::dedup_refcount::DedupRefCount::init(store.raw_store_mut(), &fp)?;
                    } else {
                        let _ = crate::dedup_refcount::DedupRefCount::increment(store.raw_store_mut(), &fp);
                    }
                    (ck, fp)
                };

                // Record the fingerprint in the local dedup index so future
                // writes within this session can also share it.
                dedup_index.insert(fingerprint, canonical_key);

                // Write the redirect at the destination's per-inode key.
                let dest_chunk_key = content_chunk_object_key_for_version(
                    dest_record.inode_id,
                    dest_record.data_version,
                    src_chunk_ref.chunk_index,
                );
                let redirect = crate::encoding::encode_dedup_redirect(canonical_key);
                let chunk_receipt = store.put_with_receipt(dest_chunk_key, &redirect)?.1;

                // The destination stores a dedup redirect at its per-inode
                // key. The checksum must reflect the redirect bytes, not the
                // source chunk's bytes, so that transaction manifest
                // validation passes.
                dest_chunks.push(ContentChunkRef {
                    chunk_index: src_chunk_ref.chunk_index,
                    data_version: dest_record.data_version,
                    len: src_chunk_ref.len,
                    checksum: checksum64(&redirect),
                            placement_receipt_generation: chunk_receipt.generation,
});
            }

            let dest_manifest = ContentManifestObject {
                inode_id: dest_record.inode_id,
                data_version: dest_record.data_version,
                file_size: dest_record.size,
                chunk_size: manifest.chunk_size,
                chunks: dest_chunks,
            };
            store.put(
                content_object_key_for_version(dest_record.inode_id, dest_record.data_version),
                &encode_content_manifest(&dest_manifest),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_store(label: &str) -> LocalObjectStore {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tidefs-content-{label}-{nanos}-{}",
            std::process::id()
        ));
        LocalObjectStore::open(root).expect("open temp object store")
    }

    #[test]
    fn sparse_range_read_from_hole_ref_only_materializes_requested_bytes() {
        let store = temp_store("hole-ref-range");
        let layout = ContentLayout::Chunked(ContentManifestObject {
            inode_id: InodeId::new(1),
            data_version: 1,
            file_size: u32::MAX as u64,
            chunk_size: u32::MAX,
            chunks: vec![ContentChunkRef::hole(0, u32::MAX)],
        });

        let bytes = read_content_range_from_layout(&store, &layout, u32::MAX as u64 - 1, 1)
            .expect("read tail byte from sparse hole ref");

        assert_eq!(bytes, vec![0]);
    }

    #[test]
    fn sparse_range_read_from_missing_chunk_only_materializes_requested_bytes() {
        let store = temp_store("missing-hole-range");
        let layout = ContentLayout::Chunked(ContentManifestObject {
            inode_id: InodeId::new(2),
            data_version: 1,
            file_size: u32::MAX as u64,
            chunk_size: u32::MAX,
            chunks: Vec::new(),
        });

        let bytes = read_content_range_from_layout(&store, &layout, u32::MAX as u64 - 1, 1)
            .expect("read tail byte from implicit sparse chunk");

        assert_eq!(bytes, vec![0]);
    }
}

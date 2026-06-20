// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;

use tidefs_local_object_store::{LocalObjectStore, ObjectKey};
use tidefs_types_vfs_core::{InodeId, ROOT_INODE_ID};

use crate::constants::*;
use crate::content::{
    content_chunk_count, content_chunk_len, content_chunk_start, decode_content_layout,
    find_chunk_in_manifest, overlay_chunk_index_bounds, overlay_chunk_writes_only_zeros,
    range_intersects_overlay, read_content_layout_from_store, retained_content_chunk_ref,
    validate_content_layout, ContentOverlayPatch,
};
use crate::error::FileSystemError;
use crate::object_keys::{content_chunk_object_key_for_version, content_object_key_for_version};
use crate::records::ContentLayout;
use crate::types::*;
use crate::{FileSystemState, Result};
pub(crate) fn content_allocation_entries_for_state(
    store: &LocalObjectStore,
    state: &FileSystemState,
) -> Result<BTreeMap<ObjectKey, u64>> {
    let mut entries = BTreeMap::new();
    for inode in state.inodes.values() {
        if inode.is_file_like() {
            merge_allocation_entries(
                &mut entries,
                content_allocation_entries_for_inode(store, inode)?,
            );
        }
    }
    Ok(entries)
}

pub(crate) fn content_allocation_entries_for_inode(
    store: &LocalObjectStore,
    inode: &InodeRecord,
) -> Result<BTreeMap<ObjectKey, u64>> {
    let content_key = content_object_key_for_version(inode.inode_id, inode.data_version);
    let Some(bytes) = store.get(content_key)? else {
        if inode.size == 0 {
            return Ok(BTreeMap::new());
        }
        return Err(FileSystemError::CorruptState {
            reason: "allocator expected a missing content object",
        });
    };
    let layout = decode_content_layout(&bytes)?;
    validate_content_layout(inode.inode_id, inode, &layout)?;
    content_allocation_entries_for_layout(inode.inode_id, &layout)
}

pub(crate) fn content_allocation_entries_for_layout(
    inode_id: InodeId,
    layout: &ContentLayout,
) -> Result<BTreeMap<ObjectKey, u64>> {
    let mut entries = BTreeMap::new();
    match layout {
        ContentLayout::Inline(content) => {
            let grains = allocation_grains_for_len(content.bytes.len() as u64)?;
            debug_assert!(
                grains == 0 || grains % content_chunk_size() as u64 == 0,
                "inline content allocation grains must be grain-aligned"
            );
            entries.insert(
                content_object_key_for_version(inode_id, content.data_version),
                grains,
            );
        }
        ContentLayout::Chunked(manifest) => {
            for chunk_ref in &manifest.chunks {
                // Hole (sparse) chunks consume no storage.
                if chunk_ref.is_hole() {
                    continue;
                }
                let grains = allocation_grains_for_len(u64::from(chunk_ref.len))?;
                debug_assert!(
                    grains % content_chunk_size() as u64 == 0,
                    "chunk allocation grains must be grain-aligned"
                );
                entries.insert(
                    content_chunk_object_key_for_version(
                        manifest.inode_id,
                        chunk_ref.data_version,
                        chunk_ref.chunk_index,
                    ),
                    grains,
                );
            }
        }
    }
    Ok(entries)
}

pub(crate) fn planned_chunk_allocation_entries_for_full_content(
    record: &InodeRecord,
) -> Result<BTreeMap<ObjectKey, u64>> {
    let mut entries = BTreeMap::new();
    for chunk_index in 0..content_chunk_count(record.size)? {
        let len = content_chunk_len(record.size, chunk_index)?;
        let grains = allocation_grains_for_len(u64::from(len))?;
        debug_assert!(
            grains % content_chunk_size() as u64 == 0,
            "planned chunk allocation grains must be grain-aligned"
        );
        entries.insert(
            content_chunk_object_key_for_version(record.inode_id, record.data_version, chunk_index),
            grains,
        );
    }
    Ok(entries)
}

pub(crate) fn planned_reflink_allocation_entries_for_source_layout(
    dest_record: &InodeRecord,
    source_layout: &ContentLayout,
) -> Result<BTreeMap<ObjectKey, u64>> {
    let mut entries = BTreeMap::new();
    match source_layout {
        ContentLayout::Inline(content) => {
            let len =
                u64::try_from(content.bytes.len()).map_err(|_| FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })?;
            let grains = allocation_grains_for_len(len)?;
            if grains > 0 {
                entries.insert(
                    content_object_key_for_version(dest_record.inode_id, dest_record.data_version),
                    grains,
                );
            }
        }
        ContentLayout::Chunked(manifest) => {
            for chunk_ref in &manifest.chunks {
                if chunk_ref.is_hole() {
                    continue;
                }
                let grains = allocation_grains_for_len(u64::from(chunk_ref.len))?;
                if grains > 0 {
                    entries.insert(
                        content_chunk_object_key_for_version(
                            dest_record.inode_id,
                            dest_record.data_version,
                            chunk_ref.chunk_index,
                        ),
                        grains,
                    );
                }
            }
        }
    }
    Ok(entries)
}

pub(crate) fn materialized_content_bytes_for_layout(layout: &ContentLayout) -> Result<u64> {
    match layout {
        ContentLayout::Inline(content) => {
            u64::try_from(content.bytes.len()).map_err(|_| FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })
        }
        ContentLayout::Chunked(manifest) => manifest
            .chunks
            .iter()
            .filter(|chunk_ref| !chunk_ref.is_hole())
            .try_fold(0_u64, |sum, chunk_ref| {
                sum.checked_add(u64::from(chunk_ref.len))
                    .ok_or(FileSystemError::SizeOverflow {
                        requested: u64::MAX,
                    })
            }),
    }
}

pub(crate) fn planned_chunk_allocation_entries_for_overlay(
    store: &LocalObjectStore,
    old_record: &InodeRecord,
    new_record: &InodeRecord,
    overlay_offset: u64,
    overlay_bytes: &[u8],
    allow_holes: bool,
) -> Result<BTreeMap<ObjectKey, u64>> {
    let old_layout = read_content_layout_from_store(store, old_record.inode_id, old_record, true)?;
    let mut entries = BTreeMap::new();
    if allow_holes && overlay_bytes.is_empty() {
        if let crate::records::ContentLayout::Chunked(ref manifest) = old_layout {
            let new_chunk_count = content_chunk_count(new_record.size)?;
            for old_ref in &manifest.chunks {
                if old_ref.is_hole() || old_ref.chunk_index >= new_chunk_count {
                    continue;
                }
                let expected_len = content_chunk_len(new_record.size, old_ref.chunk_index)?;
                let data_version = if old_ref.len == expected_len {
                    old_ref.data_version
                } else {
                    new_record.data_version
                };
                let grains = allocation_grains_for_len(u64::from(expected_len))?;
                debug_assert!(
                    grains % content_chunk_size() as u64 == 0,
                    "sparse size-change chunk allocation grains must be grain-aligned"
                );
                entries.insert(
                    content_chunk_object_key_for_version(
                        new_record.inode_id,
                        data_version,
                        old_ref.chunk_index,
                    ),
                    grains,
                );
            }
            return Ok(entries);
        }
    }
    if allow_holes && old_record.size == new_record.size && !overlay_bytes.is_empty() {
        if let crate::records::ContentLayout::Chunked(ref manifest) = old_layout {
            for old_ref in &manifest.chunks {
                if old_ref.is_hole() {
                    continue;
                }
                let new_len = content_chunk_len(new_record.size, old_ref.chunk_index)?;
                if old_ref.len != new_len {
                    continue;
                }
                let chunk_start = content_chunk_start(old_ref.chunk_index)?;
                let chunk_end = chunk_start.checked_add(u64::from(new_len)).ok_or(
                    FileSystemError::SizeOverflow {
                        requested: u64::MAX,
                    },
                )?;
                if range_intersects_overlay(chunk_start, chunk_end, overlay_offset, overlay_bytes)?
                {
                    continue;
                }
                let grains = allocation_grains_for_len(u64::from(old_ref.len))?;
                debug_assert!(
                    grains % content_chunk_size() as u64 == 0,
                    "retained sparse overlay chunk allocation grains must be grain-aligned"
                );
                entries.insert(
                    content_chunk_object_key_for_version(
                        new_record.inode_id,
                        old_ref.data_version,
                        old_ref.chunk_index,
                    ),
                    grains,
                );
            }
            if let Some((first_overlay_chunk, last_overlay_chunk)) =
                overlay_chunk_index_bounds(new_record.size, overlay_offset, overlay_bytes.len())?
            {
                for chunk_index in first_overlay_chunk..=last_overlay_chunk {
                    let len = content_chunk_len(new_record.size, chunk_index)?;
                    let old_chunk_is_sparse_zero =
                        match find_chunk_in_manifest(manifest, chunk_index) {
                            Some(chunk_ref) => chunk_ref.is_hole(),
                            None => true,
                        };
                    if old_chunk_is_sparse_zero
                        && overlay_chunk_writes_only_zeros(
                            chunk_index,
                            len,
                            overlay_offset,
                            overlay_bytes,
                        )?
                    {
                        continue;
                    }

                    let grains = allocation_grains_for_len(u64::from(len))?;
                    debug_assert!(
                        grains % content_chunk_size() as u64 == 0,
                        "new sparse overlay chunk allocation grains must be grain-aligned"
                    );
                    entries.insert(
                        content_chunk_object_key_for_version(
                            new_record.inode_id,
                            new_record.data_version,
                            chunk_index,
                        ),
                        grains,
                    );
                }
            }
            return Ok(entries);
        }
    }
    for chunk_index in 0..content_chunk_count(new_record.size)? {
        if let Some(retained) = retained_content_chunk_ref(
            &old_layout,
            old_record.size,
            new_record.size,
            overlay_offset,
            overlay_bytes,
            chunk_index,
        )? {
            if retained.is_hole() {
                continue;
            }
            let grains = allocation_grains_for_len(u64::from(retained.len))?;
            debug_assert!(
                grains % content_chunk_size() as u64 == 0,
                "retained overlay chunk allocation grains must be grain-aligned"
            );
            entries.insert(
                content_chunk_object_key_for_version(
                    new_record.inode_id,
                    retained.data_version,
                    retained.chunk_index,
                ),
                grains,
            );
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
                    crate::records::ContentLayout::Chunked(ref manifest) => {
                        find_chunk_in_manifest(manifest, chunk_index).is_none()
                            || cstart >= old_record.size
                    }
                    crate::records::ContentLayout::Inline(_) => cstart >= old_record.size,
                };
                if can_skip_hole {
                    continue;
                }
            }
        }
        let len = content_chunk_len(new_record.size, chunk_index)?;
        let grains = allocation_grains_for_len(u64::from(len))?;
        debug_assert!(
            grains % content_chunk_size() as u64 == 0,
            "new overlay chunk allocation grains must be grain-aligned"
        );
        entries.insert(
            content_chunk_object_key_for_version(
                new_record.inode_id,
                new_record.data_version,
                chunk_index,
            ),
            grains,
        );
    }
    Ok(entries)
}

pub(crate) fn planned_chunk_allocation_entries_for_patch_batch(
    store: &LocalObjectStore,
    old_record: &InodeRecord,
    new_record: &InodeRecord,
    patches: &[ContentOverlayPatch<'_>],
    allow_holes: bool,
) -> Result<BTreeMap<ObjectKey, u64>> {
    let old_layout = read_content_layout_from_store(store, old_record.inode_id, old_record, true)?;
    let mut entries = BTreeMap::new();
    if !allow_holes || old_record.size > new_record.size {
        return Err(FileSystemError::Unsupported {
            operation: "patch batch allocation planning",
            reason: "batch writeback optimization requires non-shrinking sparse content",
        });
    }
    let crate::records::ContentLayout::Chunked(ref manifest) = old_layout else {
        return Err(FileSystemError::Unsupported {
            operation: "patch batch allocation planning",
            reason: "batch writeback optimization requires chunked content",
        });
    };

    let mut patched_chunks: BTreeMap<u64, Vec<ContentOverlayPatch<'_>>> = BTreeMap::new();
    for patch in patches {
        let Some((first_chunk, last_chunk)) =
            overlay_chunk_index_bounds(new_record.size, patch.offset, patch.bytes.len())?
        else {
            continue;
        };
        for chunk_index in first_chunk..=last_chunk {
            patched_chunks.entry(chunk_index).or_default().push(*patch);
        }
    }

    let chunk_count = content_chunk_count(new_record.size)?;
    for old_ref in &manifest.chunks {
        if old_ref.chunk_index >= chunk_count
            || old_ref.is_hole()
            || patched_chunks.contains_key(&old_ref.chunk_index)
        {
            continue;
        }
        let new_len = content_chunk_len(new_record.size, old_ref.chunk_index)?;
        let (data_version, len) = if old_ref.len == new_len {
            (old_ref.data_version, old_ref.len)
        } else {
            (new_record.data_version, new_len)
        };
        let grains = allocation_grains_for_len(u64::from(len))?;
        debug_assert!(
            grains % content_chunk_size() as u64 == 0,
            "retained patch-batch chunk allocation grains must be grain-aligned"
        );
        entries.insert(
            content_chunk_object_key_for_version(
                new_record.inode_id,
                data_version,
                old_ref.chunk_index,
            ),
            grains,
        );
    }

    for (chunk_index, chunk_patches) in patched_chunks {
        let len = content_chunk_len(new_record.size, chunk_index)?;
        let old_chunk_is_sparse_zero = match find_chunk_in_manifest(manifest, chunk_index) {
            Some(chunk_ref) => chunk_ref.is_hole(),
            None => true,
        };
        let patch_bytes_all_zero = chunk_patches.iter().try_fold(true, |all_zero, patch| {
            Ok::<bool, FileSystemError>(
                all_zero
                    && overlay_chunk_writes_only_zeros(
                        chunk_index,
                        len,
                        patch.offset,
                        patch.bytes,
                    )?,
            )
        })?;
        if old_chunk_is_sparse_zero && patch_bytes_all_zero {
            continue;
        }

        let grains = allocation_grains_for_len(u64::from(len))?;
        debug_assert!(
            grains % content_chunk_size() as u64 == 0,
            "new patch-batch chunk allocation grains must be grain-aligned"
        );
        entries.insert(
            content_chunk_object_key_for_version(
                new_record.inode_id,
                new_record.data_version,
                chunk_index,
            ),
            grains,
        );
    }
    Ok(entries)
}

pub(crate) fn dirty_overlay_allocation_bytes(
    new_size: u64,
    overlay_offset: u64,
    overlay_bytes: &[u8],
) -> Result<u64> {
    if overlay_bytes.is_empty() || new_size == 0 {
        return Ok(0);
    }

    let mut total = 0_u64;
    let Some((first_overlay_chunk, last_overlay_chunk)) =
        overlay_chunk_index_bounds(new_size, overlay_offset, overlay_bytes.len())?
    else {
        return Ok(0);
    };
    for chunk_index in first_overlay_chunk..=last_overlay_chunk {
        let chunk_start = content_chunk_start(chunk_index)?;
        let chunk_len = content_chunk_len(new_size, chunk_index)?;
        let chunk_end =
            chunk_start
                .checked_add(u64::from(chunk_len))
                .ok_or(FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })?;
        if range_intersects_overlay(chunk_start, chunk_end, overlay_offset, overlay_bytes)? {
            total = total
                .checked_add(allocation_grains_for_len(u64::from(chunk_len))?)
                .ok_or(FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })?;
        }
    }
    Ok(total)
}

pub(crate) fn allocation_grains_for_len(len: u64) -> Result<u64> {
    if len == 0 {
        return Ok(0);
    }
    let rounded =
        len.checked_add(content_chunk_size() as u64 - 1)
            .ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })?
            / content_chunk_size() as u64
            * content_chunk_size() as u64;
    debug_assert_eq!(
        rounded % content_chunk_size() as u64,
        0,
        "allocation grains must be a multiple of content chunk size"
    );
    debug_assert!(
        rounded >= len,
        "allocation grains ({rounded}) must cover at least the requested length ({len})"
    );
    Ok(rounded)
}

pub(crate) fn merge_allocation_entries(
    target: &mut BTreeMap<ObjectKey, u64>,
    source: BTreeMap<ObjectKey, u64>,
) {
    for (key, bytes) in source {
        target
            .entry(key)
            .and_modify(|existing| *existing = (*existing).max(bytes))
            .or_insert(bytes);
    }
}

pub(crate) fn allocation_bytes(entries: &BTreeMap<ObjectKey, u64>) -> Result<u64> {
    entries.values().try_fold(0_u64, |sum, bytes| {
        sum.checked_add(*bytes)
            .ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })
    })
}

pub(crate) fn next_generation_after(generation: u64) -> u64 {
    generation.saturating_add(1).max(1)
}

pub(crate) fn next_allocated_inode_id(state: &FileSystemState) -> u64 {
    state
        .next_inode_id_raw()
        .max(ROOT_INODE_ID.get().saturating_add(1))
}

/// Returns true when the placement receipt generation recorded in a chunk ref
/// is durable (matches the pool receipt for the same key).
///
/// A receipt is durable when the pool holds a matching receipt with the same
/// generation and the receipt is not synthetic (generation > 0). This is the
/// receipt-authority gate that prevents reclaim from freeing chunks whose
/// placement receipt has not been committed.
///
/// Hole chunks (data_version == 0, no receipt) are always durable-trivial:
/// they consume no storage and have no receipt to validate.
pub(crate) fn chunk_receipt_is_durable(
    pool: &tidefs_local_object_store::pool::Pool,
    chunk_ref: &crate::records::ContentChunkRef,
    object_key: tidefs_local_object_store::ObjectKey,
) -> bool {
    use tidefs_local_object_store::DeviceIoClass;

    // Hole chunks never need receipt validation.
    if chunk_ref.is_hole() {
        return true;
    }

    // Zero generation means no receipt was captured (pre-v6 format or legacy
    // write).  These chunks may be reclaimed without receipt gating.
    if chunk_ref.placement_receipt_generation == 0 {
        return true;
    }

    // Look up the pool's current receipt for this key.
    let Ok(Some(receipt)) = pool.placement_receipt_for_key(DeviceIoClass::Data, object_key) else {
        // No receipt found in pool: the chunk's receipt is not yet durable.
        return false;
    };

    // The chunk ref's receipt generation must match or be less than the pool receipt.
    // A higher pool generation means a replacement was written; the old
    // receipt is no longer authoritative but the replacement must be durable
    // before the old chunk is freed (checked separately by the caller).
    receipt.generation >= chunk_ref.placement_receipt_generation
}

/// Check whether a content object has a durable replacement receipt.
///
/// Returns `true` when the pool holds a receipt for `object_key` with a
/// generation strictly greater than `old_generation`. This means the
/// replacement data is durably placed and the old chunk may be reclaimed
/// once no readers depend on the old receipt.
pub(crate) fn replacement_receipt_is_durable(
    pool: &tidefs_local_object_store::pool::Pool,
    object_key: tidefs_local_object_store::ObjectKey,
    old_generation: u64,
) -> bool {
    use tidefs_local_object_store::DeviceIoClass;

    if old_generation == 0 {
        return true;
    }

    let Ok(Some(receipt)) = pool.placement_receipt_for_key(DeviceIoClass::Data, object_key) else {
        return false;
    };

    receipt.generation > old_generation
}

/// Check whether a content chunk object key has a durable placement receipt
/// in the pool.  Returns true when the chunk can be reclaimed (receipt is
/// committed and stable) or when no receipt gating is needed (metadata keys,
/// legacy pre-v6 objects).
///
/// This is the authority gate used by the reclaim drain to decide whether
/// a content chunk is safe to delete.  Queries the pool placement receipt
/// for the key and verifies that the receipt generation has been committed.
/// A missing receipt is treated as durable (backward compatibility with
/// pre-receipt writes), and a pool error conservatively retains the entry.
pub(crate) fn chunk_content_key_receipt_stable(
    pool: &tidefs_local_object_store::pool::Pool,
    object_key: tidefs_local_object_store::ObjectKey,
) -> bool {
    use tidefs_local_object_store::DeviceIoClass;

    match pool.placement_receipt_for_key(DeviceIoClass::Data, object_key) {
        Ok(Some(receipt)) => receipt.generation > 0,
        Ok(None) => true,
        Err(_) => false,
    }
}

/// Check whether a replacement object key has a durable placement receipt.
///
/// Unlike [`chunk_content_key_receipt_stable`], a missing receipt is not
/// treated as legacy-durable here: this gate protects old extents until the
/// replacement side of a rewrite has an explicit pool receipt.
pub(crate) fn replacement_key_receipt_is_durable(
    pool: &tidefs_local_object_store::pool::Pool,
    object_key: tidefs_local_object_store::ObjectKey,
) -> bool {
    use tidefs_local_object_store::DeviceIoClass;

    match pool.placement_receipt_for_key(DeviceIoClass::Data, object_key) {
        Ok(Some(receipt)) => receipt.generation > 0,
        Ok(None) | Err(_) => false,
    }
}

/// Classify old extent keys from a chunked rewrite into trimmable and
/// deferred sets, gated on replacement receipt durability.
///
/// For each non-hole old chunk in `old_manifest`, we decide whether its
/// object-store key can be reclaimed now or must be deferred:
///
/// - When a replacement chunk exists in `new_chunks` with a different
///   `data_version`, the old chunk is only safe to trim once the
///   replacement's placement receipt is durable (generation > 0 and
///   present in the pool).
/// - When no replacement exists (file shrunk past the chunk), the old
///   chunk is trimmable unconditionally — the file no longer needs it.
/// - When the same chunk is retained (identical `data_version`), it is
///   not obsolete at all and is excluded.
///
/// Returns `(trimmable_keys, deferred_pairs)` where trimmable entries
/// can be queued for immediate reclaim and deferred entries carry
/// `(old_key, replacement_key)` pairs for a future receipt-durability check.
/// INTENT: wired into rewrite path in lib.rs (issue #377)
pub(crate) fn obsolete_extent_keys_for_chunked_rewrite(
    pool: &tidefs_local_object_store::pool::Pool,
    inode_id: InodeId,
    old_manifest: &crate::records::ContentManifestObject,
    new_chunks: &[crate::records::ContentChunkRef],
) -> (Vec<ObjectKey>, Vec<(ObjectKey, ObjectKey)>) {
    let mut trimmable = Vec::new();
    let mut deferred = Vec::new();

    // Build a lookup of new chunks by chunk_index for replacement checks.
    let new_by_index: BTreeMap<u64, &crate::records::ContentChunkRef> =
        new_chunks.iter().map(|c| (c.chunk_index, c)).collect();

    for old_chunk in &old_manifest.chunks {
        if old_chunk.is_hole() {
            continue;
        }

        let old_key = content_chunk_object_key_for_version(
            inode_id,
            old_chunk.data_version,
            old_chunk.chunk_index,
        );

        match new_by_index.get(&old_chunk.chunk_index) {
            Some(new_chunk) if new_chunk.data_version != old_chunk.data_version => {
                // Replacement exists; gate on its receipt durability.
                let new_key = content_chunk_object_key_for_version(
                    inode_id,
                    new_chunk.data_version,
                    new_chunk.chunk_index,
                );
                if chunk_receipt_is_durable(pool, new_chunk, new_key) {
                    trimmable.push(old_key);
                } else {
                    deferred.push((old_key, new_key));
                }
            }
            Some(_new_chunk) => {
                // Same data_version: chunk was retained, not obsolete.
            }
            None => {
                // No replacement: chunk is beyond new file size.
                // The old chunk is trimmable unconditionally.
                trimmable.push(old_key);
            }
        }
    }

    (trimmable, deferred)
}

/// Compute obsolete extent keys for a chunked content rewrite.
///
/// Each old chunk key is classified by
/// [`obsolete_extent_keys_for_chunked_rewrite`].  The old manifest object is
/// also obsolete because the inode now points at the new data version; it is
/// gated on the new manifest object's replacement receipt.
///
/// Also returns the old versioned content-manifest key, similarly gated.
/// INTENT: wired into replace_content in lib.rs (issue #377)
pub(crate) fn obsolete_extent_keys_for_full_replace(
    pool: &tidefs_local_object_store::pool::Pool,
    inode_id: InodeId,
    old_manifest: &crate::records::ContentManifestObject,
    new_chunks: &[crate::records::ContentChunkRef],
    new_data_version: u64,
) -> (Vec<ObjectKey>, Vec<(ObjectKey, ObjectKey)>) {
    // For a full replace, the old manifest key is always obsolete.
    let old_manifest_key = content_object_key_for_version(inode_id, old_manifest.data_version);

    let new_manifest_key = content_object_key_for_version(inode_id, new_data_version);

    let (mut trimmable, mut deferred) =
        obsolete_extent_keys_for_chunked_rewrite(pool, inode_id, old_manifest, new_chunks);

    // Gate old manifest key on new manifest receipt durability.
    if replacement_key_receipt_is_durable(pool, new_manifest_key) {
        trimmable.push(old_manifest_key);
    } else {
        deferred.push((old_manifest_key, new_manifest_key));
    }

    (trimmable, deferred)
}

/// Classify old extent keys for an inline content replacement.
///
/// The old inline content object is obsolete.  Trimming is gated on
/// the replacement receipt for the new inline content key.
/// INTENT: wired into replace_content inline path in lib.rs (issue #377)
pub(crate) fn obsolete_extent_keys_for_inline_replace(
    pool: &tidefs_local_object_store::pool::Pool,
    inode_id: InodeId,
    old_data_version: u64,
    new_data_version: u64,
) -> (Vec<ObjectKey>, Vec<(ObjectKey, ObjectKey)>) {
    let old_key = content_object_key_for_version(inode_id, old_data_version);
    let new_key = content_object_key_for_version(inode_id, new_data_version);

    if replacement_key_receipt_is_durable(pool, new_key) {
        (vec![old_key], Vec::new())
    } else {
        (Vec::new(), vec![(old_key, new_key)])
    }
}

/// Queue extent keys into the reclaim queue for the next drain cycle.
/// INTENT: wired into rewrite reclaim queuing in lib.rs (issue #377)
pub(crate) fn queue_extent_keys_for_reclaim(
    queue: &std::sync::Arc<std::sync::Mutex<tidefs_reclaim_queue_core::BPlusTreeReclaimQueue>>,
    keys: &[ObjectKey],
) {
    use tidefs_types_reclaim_queue_core::{QueueFamily, ReclaimQueueEntry};
    let mut q = queue.lock().unwrap();
    for key in keys {
        q.insert(ReclaimQueueEntry::new(
            tidefs_types_reclaim_queue_core::ObjectKey(*key.as_bytes()),
            -1,
            QueueFamily::Extent,
        ));
    }
}

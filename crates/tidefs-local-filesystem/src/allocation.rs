// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;

#[cfg(test)]
use tidefs_local_object_store::LocalObjectStore;
use tidefs_local_object_store::{pool::Pool, ObjectKey};
use tidefs_types_vfs_core::{InodeId, ROOT_INODE_ID};

use crate::constants::*;
#[cfg(test)]
use crate::content::read_content_layout_from_store;
use crate::content::{
    content_chunk_count, content_chunk_len, content_chunk_start, find_chunk_in_manifest,
    is_valid_content_chunk_size, overlay_chunk_index_bounds, overlay_chunk_writes_only_zeros,
    range_intersects_overlay, retained_content_chunk_ref, ContentOverlayPatch,
    MountedContentReadAuthority,
};
use crate::encoding::{
    compute_content_fingerprint, decode_content, decode_content_chunk, decode_content_manifest,
    decode_dedup_redirect, is_dedup_redirect, split_inline_checksum,
};
use crate::error::FileSystemError;
use crate::object_keys::{
    content_chunk_object_key_for_version, content_dedup_object_key, content_object_key_for_version,
};
use crate::records::ContentLayout;
use crate::types::*;
use crate::{FileSystemState, Result};
pub(crate) fn content_allocation_entries_for_state_pool(
    pool: &Pool,
    state: &FileSystemState,
) -> Result<BTreeMap<ObjectKey, u64>> {
    let mut entries = BTreeMap::new();
    for inode in state.inodes.values() {
        if inode.is_file_like() {
            merge_allocation_entries(
                &mut entries,
                content_allocation_entries_for_inode_pool(pool, inode)?,
            );
        }
    }
    Ok(entries)
}

pub(crate) fn content_allocation_entries_for_inode_pool(
    pool: &Pool,
    inode: &InodeRecord,
) -> Result<BTreeMap<ObjectKey, u64>> {
    let reader = MountedContentReadAuthority::new(pool);
    let layout = reader.read_layout(inode.inode_id, inode)?;
    if let ContentLayout::Chunked(manifest) = &layout {
        for chunk_ref in &manifest.chunks {
            if !chunk_ref.is_hole() {
                let _ = reader.read_chunk(inode.inode_id, chunk_ref)?;
            }
        }
    }
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

#[cfg(test)]
pub(crate) fn planned_chunk_allocation_entries_for_overlay(
    store: &LocalObjectStore,
    old_record: &InodeRecord,
    new_record: &InodeRecord,
    overlay_offset: u64,
    overlay_bytes: &[u8],
    allow_holes: bool,
) -> Result<BTreeMap<ObjectKey, u64>> {
    let old_layout = read_content_layout_from_store(store, old_record.inode_id, old_record)?;
    planned_chunk_allocation_entries_for_overlay_layout(
        &old_layout,
        old_record,
        new_record,
        overlay_offset,
        overlay_bytes,
        allow_holes,
    )
}

pub(crate) fn planned_chunk_allocation_entries_for_overlay_layout(
    old_layout: &ContentLayout,
    old_record: &InodeRecord,
    new_record: &InodeRecord,
    overlay_offset: u64,
    overlay_bytes: &[u8],
    allow_holes: bool,
) -> Result<BTreeMap<ObjectKey, u64>> {
    let mut entries = BTreeMap::new();
    if allow_holes && overlay_bytes.is_empty() {
        if let crate::records::ContentLayout::Chunked(manifest) = old_layout {
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
        if let crate::records::ContentLayout::Chunked(manifest) = old_layout {
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
                    let old_chunk_is_sparse_zero = find_chunk_in_manifest(manifest, chunk_index)
                        .is_none_or(crate::records::ContentChunkRef::is_hole);
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
    if allow_holes && old_record.size != new_record.size && !overlay_bytes.is_empty() {
        if let crate::records::ContentLayout::Chunked(manifest) = old_layout {
            let new_chunk_count = content_chunk_count(new_record.size)?;
            for old_ref in &manifest.chunks {
                if old_ref.is_hole() || old_ref.chunk_index >= new_chunk_count {
                    continue;
                }
                let new_len = content_chunk_len(new_record.size, old_ref.chunk_index)?;
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

                let data_version = if old_ref.len == new_len {
                    old_ref.data_version
                } else {
                    new_record.data_version
                };
                let grains = allocation_grains_for_len(u64::from(new_len))?;
                debug_assert!(
                    grains % content_chunk_size() as u64 == 0,
                    "retained sparse size-changing overlay chunk allocation grains must be grain-aligned"
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
                        "new sparse size-changing overlay chunk allocation grains must be grain-aligned"
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
            old_layout,
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
                    crate::records::ContentLayout::Chunked(manifest) => {
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

pub(crate) fn planned_chunk_allocation_entries_for_patch_batch_layout(
    old_layout: &ContentLayout,
    old_record: &InodeRecord,
    new_record: &InodeRecord,
    patches: &[ContentOverlayPatch<'_>],
    allow_holes: bool,
) -> Result<BTreeMap<ObjectKey, u64>> {
    let mut entries = BTreeMap::new();
    if !allow_holes || old_record.size > new_record.size {
        return Err(FileSystemError::Unsupported {
            operation: "patch batch allocation planning",
            reason: "batch writeback optimization requires non-shrinking sparse content",
        });
    }
    let crate::records::ContentLayout::Chunked(manifest) = old_layout else {
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

fn dedup_canonical_chunk_is_current(
    pool: &tidefs_local_object_store::pool::Pool,
    canonical_key: ObjectKey,
    expected_len: Option<usize>,
) -> bool {
    use tidefs_local_object_store::DeviceIoClass;

    let Ok(Some((canonical_bytes, receipt))) =
        pool.get_with_current_receipt(DeviceIoClass::Data, canonical_key)
    else {
        return false;
    };
    if receipt.generation == 0 {
        return false;
    }
    let Ok(chunk) = decode_content_chunk(&canonical_bytes) else {
        return false;
    };
    if expected_len.is_some_and(|len| chunk.bytes.len() != len) {
        return false;
    }
    let fingerprint = compute_content_fingerprint(&chunk.bytes);
    content_dedup_object_key(&fingerprint) == canonical_key
}

fn chunk_payload_matches_ref(
    pool: &tidefs_local_object_store::pool::Pool,
    chunk_ref: &crate::records::ContentChunkRef,
    object_key: ObjectKey,
    bytes: &[u8],
) -> bool {
    if chunk_ref.data_version == 0
        || chunk_ref.len == 0
        || tidefs_local_object_store::checksum64(bytes) != chunk_ref.checksum
    {
        return false;
    }

    if is_dedup_redirect(bytes) {
        let Ok(canonical_key) = decode_dedup_redirect(bytes) else {
            return false;
        };
        return dedup_canonical_chunk_is_current(pool, canonical_key, Some(chunk_ref.len as usize));
    }

    let Ok(chunk) = decode_content_chunk(bytes) else {
        return false;
    };
    chunk.data_version == chunk_ref.data_version
        && chunk.chunk_index == chunk_ref.chunk_index
        && chunk.bytes.len() == chunk_ref.len as usize
        && content_chunk_object_key_for_version(
            chunk.inode_id,
            chunk.data_version,
            chunk.chunk_index,
        ) == object_key
}

/// Returns true when the placement receipt generation recorded in a chunk ref
/// is durable (matches the pool receipt for the same key).
///
/// A receipt is durable only when a strict current Pool read returns the exact
/// nonzero generation recorded by the chunk ref and the receipted payload
/// matches the ref's checksum, length, and content identity. Dedup redirects
/// additionally require a strict current read of a canonical chunk whose
/// plaintext fingerprint matches its content-addressed key.
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

    if chunk_ref.placement_receipt_generation == 0 {
        return false;
    }

    let Ok(Some((bytes, receipt))) = pool.get_with_current_receipt(DeviceIoClass::Data, object_key)
    else {
        return false;
    };

    receipt.generation == chunk_ref.placement_receipt_generation
        && receipt.generation > 0
        && chunk_payload_matches_ref(pool, chunk_ref, object_key, &bytes)
}

fn content_manifest_replacement_is_current(
    pool: &tidefs_local_object_store::pool::Pool,
    object_key: ObjectKey,
    bytes: &[u8],
) -> bool {
    let Ok(manifest) = decode_content_manifest(bytes) else {
        return false;
    };
    if manifest.inode_id.get() == 0
        || manifest.data_version == 0
        || content_object_key_for_version(manifest.inode_id, manifest.data_version) != object_key
        || !is_valid_content_chunk_size(manifest.chunk_size)
    {
        return false;
    }

    let expected_chunks = if manifest.file_size == 0 {
        0
    } else {
        (manifest.file_size - 1) / u64::from(manifest.chunk_size) + 1
    };
    let mut previous_index = None;
    for chunk_ref in &manifest.chunks {
        if previous_index.is_some_and(|index| chunk_ref.chunk_index <= index)
            || chunk_ref.chunk_index >= expected_chunks
        {
            return false;
        }
        previous_index = Some(chunk_ref.chunk_index);

        let chunk_start = match chunk_ref
            .chunk_index
            .checked_mul(u64::from(manifest.chunk_size))
        {
            Some(start) => start,
            None => return false,
        };
        let expected_len =
            (manifest.file_size - chunk_start).min(u64::from(manifest.chunk_size)) as u32;
        if chunk_ref.len != expected_len {
            return false;
        }
        if chunk_ref.is_hole() {
            continue;
        }
        if chunk_ref.data_version == 0 || chunk_ref.data_version > manifest.data_version {
            return false;
        }
        let chunk_key = content_chunk_object_key_for_version(
            manifest.inode_id,
            chunk_ref.data_version,
            chunk_ref.chunk_index,
        );
        if !chunk_receipt_is_durable(pool, chunk_ref, chunk_key) {
            return false;
        }
    }
    true
}

fn replacement_payload_matches_key(
    pool: &tidefs_local_object_store::pool::Pool,
    object_key: ObjectKey,
    bytes: &[u8],
) -> bool {
    if is_dedup_redirect(bytes) {
        let Ok(canonical_key) = decode_dedup_redirect(bytes) else {
            return false;
        };
        return dedup_canonical_chunk_is_current(pool, canonical_key, None);
    }
    if bytes.starts_with(&CONTENT_MANIFEST_MAGIC)
        || bytes.starts_with(&CONTENT_MANIFEST_SPARSE_MAGIC)
    {
        return content_manifest_replacement_is_current(pool, object_key, bytes);
    }
    if bytes.starts_with(&CONTENT_CHUNK_MAGIC) {
        let Ok(chunk) = decode_content_chunk(bytes) else {
            return false;
        };
        return chunk.inode_id.get() != 0
            && chunk.data_version != 0
            && content_chunk_object_key_for_version(
                chunk.inode_id,
                chunk.data_version,
                chunk.chunk_index,
            ) == object_key;
    }
    if !bytes.starts_with(&CONTENT_MAGIC)
        || !matches!(split_inline_checksum(bytes), Ok((_, Some(_))))
    {
        return false;
    }
    let Ok(content) = decode_content(bytes) else {
        return false;
    };
    content.inode_id.get() != 0
        && content.data_version != 0
        && content_object_key_for_version(content.inode_id, content.data_version) == object_key
}

/// Check whether a replacement object key has a durable placement receipt.
///
/// The key is durable only when a strict current Pool read returns a nonzero
/// receipt and a decodable filesystem content payload whose identity projects
/// back to the same key. Manifests recursively require exact current receipt
/// authority for every non-hole chunk they reference.
pub(crate) fn replacement_key_receipt_is_durable(
    pool: &tidefs_local_object_store::pool::Pool,
    object_key: tidefs_local_object_store::ObjectKey,
) -> bool {
    use tidefs_local_object_store::DeviceIoClass;

    let Ok(Some((bytes, receipt))) = pool.get_with_current_receipt(DeviceIoClass::Data, object_key)
    else {
        return false;
    };
    receipt.generation > 0 && replacement_payload_matches_key(pool, object_key, &bytes)
}

/// Classify old extent keys from a chunked rewrite into trimmable and
/// deferred sets, gated on replacement receipt durability.
///
/// For each non-hole old chunk in `old_manifest`, we decide whether its
/// object-store key can be reclaimed now or must be deferred:
///
/// - When a replacement chunk exists in `new_chunks` with a different
///   `data_version`, the old chunk is only safe to trim once the
///   replacement's exact recorded placement generation and payload are
///   current under strict Pool authority.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContentChunkRef, ContentManifestObject};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tidefs_local_object_store::pool::{Pool, PoolConfig, PoolProperties};
    use tidefs_local_object_store::{
        checksum64, DeviceBacking, DeviceClass, DeviceConfig, DeviceIoClass, DeviceKind,
        StoreOptions,
    };
    use tidefs_types_vfs_core::{Generation, NodeKind};

    fn temp_store(label: &str) -> LocalObjectStore {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tidefs-allocation-{label}-{nanos}-{}",
            std::process::id()
        ));
        LocalObjectStore::open(root).expect("open temp object store")
    }

    fn temp_pool(label: &str) -> Pool {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tidefs-allocation-pool-{label}-{nanos}-{}",
            std::process::id()
        ));
        let data_dir = root.join("data");
        Pool::create(
            PoolConfig {
                name: "allocation-test".into(),
                root_path: root,
                devices: vec![DeviceConfig {
                    media_class: Default::default(),
                    path: data_dir.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: data_dir },
                    encryption: None,
                    compression: None,
                }],
            },
            PoolProperties::default(),
            &StoreOptions::test_fast(),
        )
        .expect("create temp pool")
    }

    fn test_record(inode_id: u64, data_version: u64, size: u64) -> InodeRecord {
        InodeRecord {
            dir_storage_kind: 0,
            inode_id: InodeId::new(inode_id),
            generation: Generation(1),
            facets: NodeKind::File.to_facets(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            nlink: 1,
            size,
            data_version,
            metadata_version: data_version,
            posix_time: PosixTimeRecord::now(),
            xattr_storage_kind: 0,
            xattrs: BTreeMap::new(),
            dir_rev: 0,
            subtree_rev: 0,
            rdev: 0,
        }
    }

    fn receipted_chunk(
        pool: &mut Pool,
        inode_id: u64,
        data_version: u64,
        chunk_index: u64,
        payload: &[u8],
    ) -> (ObjectKey, Vec<u8>, ContentChunkRef) {
        let record = test_record(inode_id, data_version, payload.len() as u64);
        let encoded = crate::encoding::encode_content_chunk(
            &record,
            chunk_index,
            payload,
            &ContentCompressionPolicy::off(),
        );
        let key = content_chunk_object_key_for_version(record.inode_id, data_version, chunk_index);
        let (_, receipt) = pool
            .put_with_receipt(DeviceIoClass::Data, key, &encoded)
            .expect("write receipted chunk");
        let chunk_ref = ContentChunkRef {
            chunk_index,
            data_version,
            len: payload.len() as u32,
            checksum: checksum64(&encoded),
            placement_receipt_generation: receipt.generation,
        };
        (key, encoded, chunk_ref)
    }

    #[test]
    fn reclaim_receipt_chunk_requires_exact_generation_and_payload() {
        let mut pool = temp_pool("chunk-exact");
        let (key, encoded, chunk_ref) = receipted_chunk(&mut pool, 100, 7, 0, b"exact chunk");

        assert!(chunk_receipt_is_durable(&pool, &chunk_ref, key));

        let mut zero_generation = chunk_ref.clone();
        zero_generation.placement_receipt_generation = 0;
        assert!(!chunk_receipt_is_durable(&pool, &zero_generation, key));

        let mut future_generation = chunk_ref.clone();
        future_generation.placement_receipt_generation += 1;
        assert!(!chunk_receipt_is_durable(&pool, &future_generation, key));

        let (_, newer_receipt) = pool
            .put_with_receipt(DeviceIoClass::Data, key, &encoded)
            .expect("republish identical chunk");
        assert!(newer_receipt.generation > chunk_ref.placement_receipt_generation);
        assert!(
            !chunk_receipt_is_durable(&pool, &chunk_ref, key),
            "a newer current receipt must not satisfy an older recorded generation"
        );

        let mut current_ref = chunk_ref;
        current_ref.placement_receipt_generation = newer_receipt.generation;
        assert!(chunk_receipt_is_durable(&pool, &current_ref, key));
        current_ref.checksum = checksum64(b"different raw payload");
        assert!(!chunk_receipt_is_durable(&pool, &current_ref, key));
    }

    #[test]
    fn reclaim_receipt_chunk_rejects_receiptless_corrupt_and_wrong_identity() {
        let mut pool = temp_pool("chunk-invalid");
        let record = test_record(101, 3, 5);
        let expected_key =
            content_chunk_object_key_for_version(record.inode_id, record.data_version, 0);
        let encoded = crate::encoding::encode_content_chunk(
            &record,
            0,
            b"bytes",
            &ContentCompressionPolicy::off(),
        );
        pool.raw_primary_store_mut()
            .put(expected_key, &encoded)
            .expect("write receiptless raw chunk");
        let receiptless_ref = ContentChunkRef {
            chunk_index: 0,
            data_version: 3,
            len: 5,
            checksum: checksum64(&encoded),
            placement_receipt_generation: 1,
        };
        assert!(!chunk_receipt_is_durable(
            &pool,
            &receiptless_ref,
            expected_key
        ));

        let wrong_record = test_record(102, 3, 5);
        let wrong_encoded = crate::encoding::encode_content_chunk(
            &wrong_record,
            0,
            b"bytes",
            &ContentCompressionPolicy::off(),
        );
        let wrong_key =
            content_chunk_object_key_for_version(record.inode_id, record.data_version, 1);
        let (_, receipt) = pool
            .put_with_receipt(DeviceIoClass::Data, wrong_key, &wrong_encoded)
            .expect("write wrong-identity chunk");
        let wrong_identity_ref = ContentChunkRef {
            chunk_index: 1,
            data_version: 3,
            len: 5,
            checksum: checksum64(&wrong_encoded),
            placement_receipt_generation: receipt.generation,
        };
        assert!(!chunk_receipt_is_durable(
            &pool,
            &wrong_identity_ref,
            wrong_key
        ));

        pool.raw_primary_store_mut()
            .put(wrong_key, b"corrupt current bytes")
            .expect("corrupt current physical payload");
        assert!(!chunk_receipt_is_durable(
            &pool,
            &wrong_identity_ref,
            wrong_key
        ));
    }

    #[test]
    fn reclaim_receipt_chunk_validates_dedup_canonical_authority() {
        let mut pool = temp_pool("chunk-dedup");
        let payload = b"dedup replacement bytes";
        let canonical_record = test_record(900, 90, payload.len() as u64);
        let canonical_encoded = crate::encoding::encode_content_chunk(
            &canonical_record,
            12,
            payload,
            &ContentCompressionPolicy::off(),
        );
        let fingerprint = compute_content_fingerprint(payload);
        let canonical_key = content_dedup_object_key(&fingerprint);
        pool.put_with_receipt(DeviceIoClass::Data, canonical_key, &canonical_encoded)
            .expect("write canonical chunk");

        let logical_inode = InodeId::new(103);
        let logical_key = content_chunk_object_key_for_version(logical_inode, 4, 2);
        let redirect = crate::encoding::encode_dedup_redirect(canonical_key);
        let (_, receipt) = pool
            .put_with_receipt(DeviceIoClass::Data, logical_key, &redirect)
            .expect("write logical redirect");
        let chunk_ref = ContentChunkRef {
            chunk_index: 2,
            data_version: 4,
            len: payload.len() as u32,
            checksum: checksum64(&redirect),
            placement_receipt_generation: receipt.generation,
        };
        assert!(chunk_receipt_is_durable(&pool, &chunk_ref, logical_key));

        pool.raw_primary_store_mut()
            .put(canonical_key, b"unreadable canonical bytes")
            .expect("corrupt canonical payload");
        assert!(!chunk_receipt_is_durable(&pool, &chunk_ref, logical_key));
    }

    #[test]
    fn reclaim_receipt_replacement_validates_content_and_manifest_identity() {
        let mut pool = temp_pool("replacement");
        let inline_record = test_record(104, 5, 6);
        let inline_key =
            content_object_key_for_version(inline_record.inode_id, inline_record.data_version);
        let inline = crate::encoding::encode_content(&inline_record, b"inline");
        pool.put_with_receipt(DeviceIoClass::Data, inline_key, &inline)
            .expect("write inline replacement");
        assert!(replacement_key_receipt_is_durable(&pool, inline_key));

        let wrong_record = test_record(105, 5, 6);
        let wrong_key = content_object_key_for_version(InodeId::new(106), 5);
        let wrong_inline = crate::encoding::encode_content(&wrong_record, b"inline");
        pool.put_with_receipt(DeviceIoClass::Data, wrong_key, &wrong_inline)
            .expect("write wrong-identity inline replacement");
        assert!(!replacement_key_receipt_is_durable(&pool, wrong_key));

        let malformed_key = content_object_key_for_version(InodeId::new(109), 5);
        pool.put_with_receipt(
            DeviceIoClass::Data,
            malformed_key,
            b"not filesystem content",
        )
        .expect("write malformed replacement");
        assert!(!replacement_key_receipt_is_durable(&pool, malformed_key));

        let receiptless_record = test_record(107, 5, 6);
        let receiptless_key = content_object_key_for_version(receiptless_record.inode_id, 5);
        let receiptless_inline = crate::encoding::encode_content(&receiptless_record, b"inline");
        pool.raw_primary_store_mut()
            .put(receiptless_key, &receiptless_inline)
            .expect("write receiptless inline replacement");
        assert!(!replacement_key_receipt_is_durable(&pool, receiptless_key));

        let (chunk_key, chunk_bytes, chunk_ref) =
            receipted_chunk(&mut pool, 108, 6, 0, b"manifest chunk");
        let manifest = ContentManifestObject {
            inode_id: InodeId::new(108),
            data_version: 6,
            file_size: b"manifest chunk".len() as u64,
            chunk_size: content_chunk_size(),
            chunks: vec![chunk_ref],
        };
        let manifest_key = content_object_key_for_version(manifest.inode_id, 6);
        let manifest_bytes = crate::encoding::encode_content_manifest_sparse(&manifest);
        pool.put_with_receipt(DeviceIoClass::Data, manifest_key, &manifest_bytes)
            .expect("write replacement manifest");
        assert!(replacement_key_receipt_is_durable(&pool, manifest_key));

        pool.put_with_receipt(DeviceIoClass::Data, chunk_key, &chunk_bytes)
            .expect("advance referenced chunk generation");
        assert!(
            !replacement_key_receipt_is_durable(&pool, manifest_key),
            "a manifest must not authorize reclaim after a referenced receipt advances"
        );
    }

    #[test]
    fn sparse_size_changing_overlay_allocation_plans_only_touched_far_chunk() {
        let store = temp_store("far-sparse-overlay-plan");
        let old_record = test_record(42, 1, 0);
        let far_chunk_index = 100_000_000_u64;
        let chunk_size = u64::from(content_chunk_size());
        let offset_in_chunk = 123_u64;
        let overlay_offset = far_chunk_index * chunk_size + offset_in_chunk;
        let payload = b"generic-013-fsstress-write".to_vec();
        let new_record = test_record(42, 2, overlay_offset + payload.len() as u64);

        let entries = planned_chunk_allocation_entries_for_overlay(
            &store,
            &old_record,
            &new_record,
            overlay_offset,
            &payload,
            true,
        )
        .expect("plan far sparse overlay allocation");

        let expected_key =
            content_chunk_object_key_for_version(new_record.inode_id, 2, far_chunk_index);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries.get(&expected_key).copied(),
            Some(u64::from(content_chunk_size()))
        );
    }
}

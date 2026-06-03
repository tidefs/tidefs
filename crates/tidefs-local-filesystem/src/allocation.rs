use std::collections::BTreeMap;

use tidefs_local_object_store::{LocalObjectStore, ObjectKey};
use tidefs_types_vfs_core::{InodeId, ROOT_INODE_ID};

use crate::constants::*;
use crate::content::{
    content_chunk_count, content_chunk_len, content_chunk_start, decode_content_layout,
    find_chunk_in_manifest, range_intersects_overlay, read_content_layout_from_store,
    retained_content_chunk_ref, validate_content_layout,
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
    let bytes = store
        .get(content_key)?
        .ok_or(FileSystemError::CorruptState {
            reason: "allocator expected a missing content object",
        })?;
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
    for chunk_index in 0..content_chunk_count(new_record.size)? {
        if let Some(retained) = retained_content_chunk_ref(
            &old_layout,
            old_record.size,
            new_record.size,
            overlay_offset,
            overlay_bytes,
            chunk_index,
        )? {
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
            // Preserve pre-existing holes that the write doesn't touch (#873).
            // A chunk that was absent from the old manifest (hole) and lies
            // entirely outside the overlay region stays absent.  This avoids
            // over-counting capacity that won't be used.
            {
                let cstart = content_chunk_start(chunk_index)?;
                let cend = cstart
                    .checked_add(u64::from(content_chunk_len(new_record.size, chunk_index)?))
                    .ok_or(FileSystemError::SizeOverflow {
                        requested: u64::MAX,
                    })?;
                if !range_intersects_overlay(cstart, cend, overlay_offset, overlay_bytes)? {
                    if let crate::records::ContentLayout::Chunked(ref manifest) = old_layout {
                        if find_chunk_in_manifest(manifest, chunk_index).is_none() {
                            continue;
                        }
                    }
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

pub(crate) fn dirty_overlay_allocation_bytes(
    new_size: u64,
    overlay_offset: u64,
    overlay_bytes: &[u8],
) -> Result<u64> {
    if overlay_bytes.is_empty() || new_size == 0 {
        return Ok(0);
    }

    let mut total = 0_u64;
    for chunk_index in 0..content_chunk_count(new_size)? {
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
        .next_inode_id
        .max(ROOT_INODE_ID.get().saturating_add(1))
}

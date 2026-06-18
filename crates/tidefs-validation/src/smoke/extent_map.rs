// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Extent-map smoke: deterministic sequence of insert, lookup, sparse
//! boundary, adjacency merge, split-overwrite, and validation operations
//! against `InlineExtentMap`.
//!
//! Gated on `feature = "extent-map"`.

use crate::smoke::SmokeHarness;
use crate::trace::TraceEvent;
use tidefs_extent_map::InlineExtentMap;
use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapOps, ExtentType, LocatorId};

fn data_extent(offset: u64, length: u64, locator: u64) -> ExtentMapEntryV2 {
    let mut checksum = [0u8; 32];
    checksum[0] = (locator & 0xFF) as u8;
    checksum[1] = ((locator >> 8) & 0xFF) as u8;
    ExtentMapEntryV2::new_data(offset, length, LocatorId(locator), checksum, locator)
}

fn unwritten_extent(offset: u64, length: u64, birth_commit_group: u64) -> ExtentMapEntryV2 {
    ExtentMapEntryV2::new_unwritten(offset, length, birth_commit_group)
}

fn record_insert(h: &mut SmokeHarness, entry: &ExtentMapEntryV2) {
    h.record(TraceEvent::ExtentInsert {
        logical_offset: entry.logical_offset,
        length: entry.length,
        locator_id: entry.locator_id.0,
        flags: u32::from(entry.flags),
    });
}

/// Run the full extent-map smoke sequence and return the harness.
#[must_use]
pub fn run_extent_map_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();
    let mut em = InlineExtentMap::new();

    h.scenario_begin("extent-map/smoke");

    h.assert_ev("empty map validates", em.validate().is_ok());
    h.assert_ev("empty map has no entries", em.entries.is_empty());
    h.assert_eq_ev("empty map file_size == 0", em.header.file_size, 0);
    h.assert_eq_ev("empty map alloc_bytes == 0", em.header.alloc_bytes, 0);
    h.assert_eq_ev("empty map seek_data(0) is none", em.seek_data(0), None);
    h.assert_eq_ev("empty map seek_hole(0) is none", em.seek_hole(0), None);

    let first = data_extent(0, 4096, 7);
    let second = data_extent(8192, 4096, 7);
    record_insert(&mut h, &first);
    record_insert(&mut h, &second);
    em.insert_extent(&[first, second])
        .expect("sparse data extent insert should succeed");

    h.record(TraceEvent::ExtentLookup {
        offset: 0,
        length: 12288,
    });
    let results = em
        .lookup_range(0, 12288)
        .expect("sparse extent lookup should succeed");
    h.assert_eq_ev("sparse lookup returns two data extents", results.len(), 2);
    h.assert_eq_ev(
        "hole begins at sparse gap boundary",
        em.seek_hole(4096),
        Some((4096, 4096)),
    );
    h.assert_eq_ev(
        "data after sparse gap begins at second extent",
        em.seek_data(4096),
        Some((8192, 4096)),
    );

    let bridge = data_extent(4096, 4096, 7);
    record_insert(&mut h, &bridge);
    em.insert_extent(&[bridge])
        .expect("bridge insert should merge adjacent data extents");
    h.assert_eq_ev(
        "adjacent data extents merged into one entry",
        em.entries.len(),
        1,
    );
    h.assert_eq_ev(
        "merged data extent starts at zero",
        em.entries[0].logical_offset,
        0,
    );
    h.assert_eq_ev(
        "merged data extent length spans original gap",
        em.entries[0].length,
        12288,
    );
    h.assert_eq_ev(
        "merged data extent keeps locator",
        em.entries[0].locator_id,
        LocatorId(7),
    );
    h.assert_eq_ev(
        "no hole remains inside merged extent",
        em.seek_hole(0),
        None,
    );

    let unwritten = unwritten_extent(16384, 4096, 20);
    record_insert(&mut h, &unwritten);
    em.insert_extent(&[unwritten])
        .expect("unwritten extent insert should succeed");
    h.assert_eq_ev("unwritten insert adds second entry", em.entries.len(), 2);
    h.assert_eq_ev(
        "unwritten entry has unwritten type",
        em.entries[1].extent_type(),
        ExtentType::Unwritten,
    );
    h.assert_eq_ev(
        "hole before unwritten begins at data boundary",
        em.seek_hole(0),
        Some((12288, 4096)),
    );
    h.assert_eq_ev(
        "seek_data treats unwritten as data",
        em.seek_data(12288),
        Some((16384, 4096)),
    );

    let overwrite = data_extent(2048, 8192, 9);
    record_insert(&mut h, &overwrite);
    em.insert_extent(&[overwrite])
        .expect("overlapping data overwrite should split existing edges");

    h.record(TraceEvent::ExtentLookup {
        offset: 0,
        length: 20480,
    });
    let ordered = em
        .lookup_range(0, 20480)
        .expect("full lookup after split should succeed");
    let offsets: Vec<u64> = ordered.iter().map(|entry| entry.logical_offset).collect();
    let lengths: Vec<u64> = ordered.iter().map(|entry| entry.length).collect();
    let kinds: Vec<ExtentType> = ordered.iter().map(ExtentMapEntryV2::extent_type).collect();
    h.assert_eq_ev(
        "split overwrite preserves iteration ordering",
        offsets,
        vec![0, 2048, 10240, 16384],
    );
    h.assert_eq_ev(
        "split overwrite preserves edge lengths",
        lengths,
        vec![2048, 8192, 2048, 4096],
    );
    h.assert_eq_ev(
        "split overwrite preserves data and unwritten kinds",
        kinds,
        vec![
            ExtentType::Data,
            ExtentType::Data,
            ExtentType::Data,
            ExtentType::Unwritten,
        ],
    );
    h.assert_eq_ev(
        "split overwrite middle locator is replacement",
        ordered[1].locator_id,
        LocatorId(9),
    );
    h.assert_eq_ev(
        "hole after split remains before unwritten",
        em.seek_hole(0),
        Some((12288, 4096)),
    );
    h.assert_eq_ev("seek_hole at eof is none", em.seek_hole(20480), None);
    h.assert_ev("validate after split overwrite", em.validate().is_ok());

    h.scenario_end("extent-map/smoke");
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_extent_map_passes() {
        let h = run_extent_map_smoke();
        for event in &h.trace {
            if let TraceEvent::Assert {
                passed,
                ref condition,
            } = event
            {
                assert!(passed, "assertion failed: {condition}");
            }
        }

        let data = crate::trace::serialize_trace(&h.trace).expect("serialize extent-map trace");
        let back = crate::trace::deserialize_trace(&data).expect("deserialize extent-map trace");
        assert_eq!(h.trace, back);
    }
}

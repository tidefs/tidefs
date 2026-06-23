// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for tidefs-pool-scan.
//!
//! These tests exercise the public API across module boundaries: label
//! reading, segment enumeration, committed-root discovery, and full
//! PoolScanner orchestration.

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use tidefs_pool_scan::{
    committed_root::write_committed_root_entry,
    label::{
        validate_pool_membership, LabelReadOutcome, LabelReader, MembershipError, PoolScanConfig,
    },
    result::PoolScanner,
    segment::{
        build_system_area, SegmentDescriptor, SegmentScanError, SegmentState, SegmentTableReader,
        SEGMENT_TABLE_ENTRY_SIZE, SYSTEM_AREA_HEADER_SIZE,
    },
    DeviceScanEntry, DeviceScanReport,
};

use tidefs_types_pool_label_core::{
    encode_label, seal_label, PoolLabelV1, POOL_LABEL_V1_EXT_WIRE_SIZE,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a valid sealed label for a device.
fn make_label(
    pool_guid: [u8; 16],
    device_guid: [u8; 16],
    name: &str,
    device_index: u32,
    device_count: u32,
) -> PoolLabelV1 {
    let mut label = PoolLabelV1::new(pool_guid, device_guid, name);
    label.device_index = device_index;
    label.device_count = device_count;
    seal_label(label).unwrap()
}

/// Write a label to a device file at path.
fn write_label(path: &Path, label: &PoolLabelV1) {
    let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
    encode_label(label, &mut buf).unwrap();
    std::fs::write(path, buf).unwrap();
}

/// Write a label plus padded system area at a given offset.
fn write_label_with_system_area(path: &Path, label: &PoolLabelV1, sys_buf: &[u8], sys_offset: u64) {
    let mut label_buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
    encode_label(label, &mut label_buf).unwrap();

    let mut file = std::fs::File::create(path).unwrap();
    file.write_all(&label_buf).unwrap();
    let cur = file.stream_position().unwrap();
    if cur < sys_offset {
        let pad = vec![0u8; (sys_offset - cur) as usize];
        file.write_all(&pad).unwrap();
    }
    file.write_all(sys_buf).unwrap();
}

/// Write label copy 0 at offset 0 and label copy 1 at the given offset.

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

// — Label reader + dual-copy recovery —

#[test]
fn read_label_from_copy1_when_copy0_corrupted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dual");

    let label = make_label([0xAAu8; 16], [0xBBu8; 16], "dualpool", 0, 1);

    // Write copy 0 with corrupted magic and copy 1 as valid label.
    let copy1_offset = POOL_LABEL_V1_EXT_WIRE_SIZE as u64 + 512;
    {
        let mut file = std::fs::File::create(&path).unwrap();

        // Copy 0: corrupted magic.
        let mut buf0 = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&label, &mut buf0).unwrap();
        buf0[0] = 0x00;
        buf0[1] = 0x00;
        file.write_all(&buf0).unwrap();

        // Pad to copy 1.
        let cur = file.stream_position().unwrap();
        let pad = vec![0u8; (copy1_offset - cur) as usize];
        file.write_all(&pad).unwrap();

        // Copy 1: valid label.
        let mut buf1 = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&label, &mut buf1).unwrap();
        file.write_all(&buf1).unwrap();
    }

    // Read with config that specifies both offsets.
    let cfg = PoolScanConfig::new(vec![path.clone()]).with_label_offsets(0, copy1_offset);
    let reader = LabelReader::new(cfg);
    let outcome = reader.read_label(&path);

    assert!(
        outcome.is_valid(),
        "expected valid label from copy 1, got {outcome:?}"
    );
    let parsed = outcome.label().unwrap();
    assert_eq!(parsed.pool_guid, [0xAAu8; 16]);
}

#[test]
fn read_label_fails_when_both_copies_corrupted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bothbad");

    let label = make_label([0xCCu8; 16], [0xDDu8; 16], "doomed", 0, 1);

    // Copy 0: bad magic.
    {
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&label, &mut buf).unwrap();
        buf[0..4].copy_from_slice(b"JUNK");
        std::fs::write(&path, buf).unwrap();
    }

    // Copy 1: valid magic but corrupted checksum (tampered field).
    let copy1_offset = 8192u64;
    {
        let mut bad_label = label.clone();
        bad_label.pool_state = tidefs_types_pool_label_core::PoolState::Destroyed;
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&bad_label, &mut buf).unwrap();
        // Re-seal to get a valid checksum but with Destroyed state.
        // Tamper a byte in the payload to break checksum.
        buf[16] ^= 0xFF;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        let cur = file.seek(SeekFrom::End(0)).unwrap();
        let pad = vec![0u8; (copy1_offset - cur) as usize];
        file.write_all(&pad).unwrap();
        file.write_all(&buf).unwrap();
    }

    let cfg = PoolScanConfig::new(vec![path.clone()]).with_label_offsets(0, copy1_offset);
    let reader = LabelReader::new(cfg);
    let outcome = reader.read_label(&path);

    assert!(
        matches!(outcome, LabelReadOutcome::Corrupted { .. }),
        "expected Corrupted, got {outcome:?}"
    );
}

// — Full PoolScanner integration —

#[test]
fn pool_scanner_single_device_full_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let pool_guid = [0x10u8; 16];
    let device_guid = [0x20u8; 16];
    let dev_path = dir.path().join("dev0");

    let segments = vec![
        SegmentDescriptor::new(0, 0x100000, 0x400000, SegmentState::Sealed),
        SegmentDescriptor::new(1, 0x500000, 0x400000, SegmentState::Active),
    ];
    let mut sys_buf = build_system_area(&segments, 1);
    let root_offset = SYSTEM_AREA_HEADER_SIZE + segments.len() * SEGMENT_TABLE_ENTRY_SIZE;
    write_committed_root_entry(&mut sys_buf, root_offset, 42, 999, 1, 0x500000);

    let mut label = PoolLabelV1::new(pool_guid, device_guid, "fulldev");
    label.device_index = 0;
    label.device_count = 1;
    label.system_area_pointer = 4096;
    label.system_area_size = sys_buf.len() as u64;
    let label = seal_label(label).unwrap();

    write_label_with_system_area(&dev_path, &label, &sys_buf, 4096);

    let cfg = PoolScanConfig::new(vec![dev_path]);
    let result = PoolScanner::scan(&cfg).unwrap();

    assert_eq!(result.pool_guid, pool_guid);
    assert_eq!(result.pool_name, "fulldev");
    assert!(result.has_valid_devices());
    assert_eq!(result.devices.len(), 1);
    assert!(result.has_committed_root());
    assert_eq!(result.committed_txg(), Some(42));
    assert_eq!(result.total_segment_count(), 2);
    assert!(result.warnings.is_empty());
}

#[test]
fn pool_scanner_two_devices_segments_dedup() {
    let dir = tempfile::tempdir().unwrap();
    let pool_guid = [0x30u8; 16];

    // Device A: segment 0.
    let dev_a = dir.path().join("devA");
    let seg_a = vec![SegmentDescriptor::new(
        0,
        0x100000,
        0x200000,
        SegmentState::Sealed,
    )];
    let sys_a = build_system_area(&seg_a, 0);

    // Device B: segments 0 (same) and 1.
    let dev_b = dir.path().join("devB");
    let seg_b = vec![
        SegmentDescriptor::new(0, 0x100000, 0x200000, SegmentState::Sealed),
        SegmentDescriptor::new(1, 0x300000, 0x200000, SegmentState::Active),
    ];
    let sys_b = build_system_area(&seg_b, 0);

    let label_a = {
        let mut l = PoolLabelV1::new(pool_guid, [0x01u8; 16], "dedup");
        l.device_index = 0;
        l.device_count = 2;
        l.system_area_pointer = 4096;
        l.system_area_size = sys_a.len() as u64;
        seal_label(l).unwrap()
    };
    let label_b = {
        let mut l = PoolLabelV1::new(pool_guid, [0x02u8; 16], "dedup");
        l.device_index = 1;
        l.device_count = 2;
        l.system_area_pointer = 4096;
        l.system_area_size = sys_b.len() as u64;
        seal_label(l).unwrap()
    };

    write_label_with_system_area(&dev_a, &label_a, &sys_a, 4096);
    write_label_with_system_area(&dev_b, &label_b, &sys_b, 4096);

    let cfg = PoolScanConfig::new(vec![dev_a, dev_b]);
    let result = PoolScanner::scan(&cfg).unwrap();

    // Segment 0 appears on both devices but should be deduplicated.
    assert_eq!(result.total_segment_count(), 2);
    assert_eq!(result.devices.len(), 2);
    assert!(result.devices.iter().all(|d| d.label_valid));
}

#[test]
fn pool_scanner_unlabeled_device_produces_warning() {
    let dir = tempfile::tempdir().unwrap();
    let pool_guid = [0x40u8; 16];
    let dev = dir.path().join("good");

    let label = make_label(pool_guid, [0xAAu8; 16], "warncase", 0, 1);
    write_label(&dev, &label);

    let junk = dir.path().join("junk");
    std::fs::write(&junk, b"not a TideFS label at all, just random bytes").unwrap();

    let cfg = PoolScanConfig::new(vec![dev, junk]);
    let result = PoolScanner::scan(&cfg).unwrap();

    assert_eq!(result.devices.len(), 2);
    assert!(!result.warnings.is_empty());
    let has_no_label_warning = result
        .warnings
        .iter()
        .any(|w| w.contains("no TideFS label"));
    assert!(has_no_label_warning);
}

#[test]
fn pool_scanner_corrupted_label_reported_as_warning() {
    let dir = tempfile::tempdir().unwrap();
    let pool_guid = [0x50u8; 16];

    // Good device.
    let good = dir.path().join("good");
    let label = make_label(pool_guid, [0x01u8; 16], "corruptcase", 0, 2);
    write_label(&good, &label);

    // Bad device: valid magic but corrupted checksum.
    let bad = dir.path().join("bad");
    {
        let label2 = make_label(pool_guid, [0x02u8; 16], "corruptcase", 1, 2);
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&label2, &mut buf).unwrap();
        // Corrupt a byte after magic but before checksum.
        buf[20] ^= 0xFF;
        std::fs::write(&bad, buf).unwrap();
    }

    let cfg = PoolScanConfig::new(vec![good, bad]);
    let result = PoolScanner::scan(&cfg);

    // Membership validation rejects pools containing corrupted labels.
    assert!(result.is_err());
    match result.unwrap_err() {
        MembershipError::CorruptedLabel {
            device_path,
            reason: _,
        } => {
            assert!(device_path.to_string_lossy().contains("bad"));
        }
        other => panic!("expected CorruptedLabel, got {other:?}"),
    }
}

#[test]
fn pool_scanner_guid_mismatch_returns_error() {
    let dir = tempfile::tempdir().unwrap();

    let dev_a = dir.path().join("poolA");
    let label_a = make_label([0x11u8; 16], [0xA1u8; 16], "poolA", 0, 1);
    write_label(&dev_a, &label_a);

    let dev_b = dir.path().join("poolB");
    let label_b = make_label([0x22u8; 16], [0xB2u8; 16], "poolB", 0, 1);
    write_label(&dev_b, &label_b);

    let cfg = PoolScanConfig::new(vec![dev_a, dev_b]);
    let result = PoolScanner::scan(&cfg);

    assert!(result.is_err());
    match result.unwrap_err() {
        MembershipError::PoolGuidMismatch { .. } => {}
        other => panic!("expected PoolGuidMismatch, got {other:?}"),
    }
}

#[test]
fn pool_scanner_empty_device_list_returns_error() {
    let cfg = PoolScanConfig::new(vec![]);
    let result = PoolScanner::scan(&cfg);

    assert!(result.is_err());
    match result.unwrap_err() {
        MembershipError::NoValidLabels => {}
        other => panic!("expected NoValidLabels, got {other:?}"),
    }
}

#[test]
fn pool_scanner_all_unlabeled_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let p1 = dir.path().join("plain1");
    let p2 = dir.path().join("plain2");
    std::fs::write(&p1, b"nothing").unwrap();
    std::fs::write(&p2, b"also nothing").unwrap();

    let cfg = PoolScanConfig::new(vec![p1, p2]);
    let result = PoolScanner::scan(&cfg);

    assert!(result.is_err());
}

// — Segment table enumeration edge cases —

#[test]
fn enumerate_segments_from_device_with_no_system_area() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nosys");

    let label = {
        let mut l = PoolLabelV1::new([0x60u8; 16], [0x61u8; 16], "nosys");
        l.system_area_pointer = 0;
        l.system_area_size = 0;
        seal_label(l).unwrap()
    };
    write_label(&path, &label);

    let result = SegmentTableReader::read_from_device(&path, &label);
    assert!(matches!(result, Err(SegmentScanError::NoSystemArea { .. })));
}

#[test]
fn enumerate_segments_bad_system_area_magic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("badmagic");

    let mut sys_buf = vec![0u8; 512];
    // Write bad magic instead of VBSA.
    sys_buf[0..4].copy_from_slice(b"BADC");

    let mut label = PoolLabelV1::new([0x70u8; 16], [0x71u8; 16], "badmagic");
    label.system_area_pointer = 4096;
    label.system_area_size = sys_buf.len() as u64;
    let label = seal_label(label).unwrap();

    write_label_with_system_area(&path, &label, &sys_buf, 4096);

    let result = SegmentTableReader::read_from_device(&path, &label);
    assert!(matches!(
        result,
        Err(SegmentScanError::BadSystemAreaMagic { .. })
    ));
}

#[test]
fn enumerate_segments_system_area_checksum_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("badcksum");

    let segments = vec![SegmentDescriptor::new(
        0,
        0x100000,
        0x200000,
        SegmentState::Sealed,
    )];
    let mut sys_buf = build_system_area(&segments, 0);
    // Corrupt a byte in the header after magic but before checksum to trigger
    // system-area checksum mismatch.
    sys_buf[8] ^= 0xFF;

    let mut label = PoolLabelV1::new([0x80u8; 16], [0x81u8; 16], "badcksum");
    label.system_area_pointer = 4096;
    label.system_area_size = sys_buf.len() as u64;
    let label = seal_label(label).unwrap();

    write_label_with_system_area(&path, &label, &sys_buf, 4096);

    let result = SegmentTableReader::read_from_device(&path, &label);
    assert!(matches!(
        result,
        Err(SegmentScanError::SystemAreaChecksumMismatch { .. })
    ));
}

#[test]
fn enumerate_segments_truncated_system_area() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("truncsys");

    // System area truncated to less than HEADER_SIZE.
    let sys_buf = vec![0u8; 32];

    let mut label = PoolLabelV1::new([0x90u8; 16], [0x91u8; 16], "truncsys");
    label.system_area_pointer = 4096;
    label.system_area_size = sys_buf.len() as u64;
    let label = seal_label(label).unwrap();

    write_label_with_system_area(&path, &label, &sys_buf, 4096);

    let result = SegmentTableReader::read_from_device(&path, &label);
    assert!(result.is_err());
}

// — Committed root cross-device selection —

#[test]
fn committed_root_highest_txg_selected_across_devices() {
    let dir = tempfile::tempdir().unwrap();
    let pool_guid = [0xA0u8; 16];

    // Device A: segments + root at txg=10.
    let dev_a = dir.path().join("devA");
    let seg_a = vec![SegmentDescriptor::new(
        0,
        0x100000,
        0x200000,
        SegmentState::Sealed,
    )];
    let mut sys_a = build_system_area(&seg_a, 1);
    let cr_offset_a = SYSTEM_AREA_HEADER_SIZE + seg_a.len() * SEGMENT_TABLE_ENTRY_SIZE;
    write_committed_root_entry(&mut sys_a, cr_offset_a, 10, 100, 0, 0x100000);
    let label_a = {
        let mut l = PoolLabelV1::new(pool_guid, [0xA1u8; 16], "txgtest");
        l.device_index = 0;
        l.device_count = 2;
        l.system_area_pointer = 4096;
        l.system_area_size = sys_a.len() as u64;
        seal_label(l).unwrap()
    };
    write_label_with_system_area(&dev_a, &label_a, &sys_a, 4096);

    // Device B: root at txg=25 (higher, should win).
    let dev_b = dir.path().join("devB");
    let seg_b = vec![SegmentDescriptor::new(
        1,
        0x300000,
        0x200000,
        SegmentState::Sealed,
    )];
    let mut sys_b = build_system_area(&seg_b, 1);
    let cr_offset_b = SYSTEM_AREA_HEADER_SIZE + seg_b.len() * SEGMENT_TABLE_ENTRY_SIZE;
    write_committed_root_entry(&mut sys_b, cr_offset_b, 25, 200, 1, 0x300000);
    let label_b = {
        let mut l = PoolLabelV1::new(pool_guid, [0xA2u8; 16], "txgtest");
        l.device_index = 1;
        l.device_count = 2;
        l.system_area_pointer = 4096;
        l.system_area_size = sys_b.len() as u64;
        seal_label(l).unwrap()
    };
    write_label_with_system_area(&dev_b, &label_b, &sys_b, 4096);

    let cfg = PoolScanConfig::new(vec![dev_a, dev_b]);
    let result = PoolScanner::scan(&cfg).unwrap();

    assert_eq!(result.committed_txg(), Some(25));
}

#[test]
fn committed_root_none_when_no_roots_exist() {
    let dir = tempfile::tempdir().unwrap();
    let pool_guid = [0xB0u8; 16];
    let dev = dir.path().join("noroot");

    let segments = vec![SegmentDescriptor::new(
        0,
        0x100000,
        0x200000,
        SegmentState::Active,
    )];
    let sys_buf = build_system_area(&segments, 0); // 0 committed roots.

    let mut label = PoolLabelV1::new(pool_guid, [0xB1u8; 16], "noroot");
    label.device_index = 0;
    label.device_count = 1;
    label.system_area_pointer = 4096;
    label.system_area_size = sys_buf.len() as u64;
    let label = seal_label(label).unwrap();

    write_label_with_system_area(&dev, &label, &sys_buf, 4096);

    let cfg = PoolScanConfig::new(vec![dev]);
    let result = PoolScanner::scan(&cfg).unwrap();

    assert!(!result.has_committed_root());
    let has_no_root_warn = result
        .warnings
        .iter()
        .any(|w| w.contains("no committed root"));
    assert!(has_no_root_warn);
}

// — Label reader boundary conditions —

#[test]
fn label_reader_empty_file_returns_no_label() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty");
    std::fs::write(&path, []).unwrap();

    let cfg = PoolScanConfig::new(vec![path.clone()]);
    let reader = LabelReader::new(cfg);
    let outcome = reader.read_label(&path);

    assert!(matches!(outcome, LabelReadOutcome::NoLabel));
}

#[test]
fn label_reader_too_short_for_magic_returns_no_label() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("short");
    std::fs::write(&path, [0u8; 2]).unwrap(); // shorter than magic

    let cfg = PoolScanConfig::new(vec![path.clone()]);
    let reader = LabelReader::new(cfg);
    let outcome = reader.read_label(&path);

    assert!(matches!(outcome, LabelReadOutcome::NoLabel));
}

#[test]
fn label_reader_non_existent_file_returns_corrupted() {
    let path = PathBuf::from("/tmp/nonexistent_tidefs_test_device_xyz");

    let cfg = PoolScanConfig::new(vec![path.clone()]);
    let reader = LabelReader::new(cfg);
    let outcome = reader.read_label(&path);

    assert!(matches!(outcome, LabelReadOutcome::Corrupted { .. }));
}

// — validate_pool_membership edge cases —

#[test]
fn validate_membership_many_devices_same_pool() {
    let dir = tempfile::tempdir().unwrap();
    let pool_guid = [0xC0u8; 16];
    let device_count: u32 = 20;

    let mut paths = Vec::new();
    for i in 0..device_count {
        let path = dir.path().join(format!("dev{i}"));
        let mut dg = [0u8; 16];
        dg[0..4].copy_from_slice(&i.to_le_bytes());
        let label = make_label(pool_guid, dg, "manydevs", i, device_count);
        write_label(&path, &label);
        paths.push(path);
    }

    let cfg = PoolScanConfig::new(paths);
    let reader = LabelReader::new(cfg);
    let result = validate_pool_membership(&reader).unwrap();
    assert_eq!(result, pool_guid);
}

#[test]
fn validate_membership_duplicate_device_guid_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let pool_guid = [0xD0u8; 16];
    let device_guid = [0xD1u8; 16];

    // Two distinct devices with the same device GUID — must be rejected.
    let dev0 = dir.path().join("dev0");
    let label0 = make_label(pool_guid, device_guid, "dupdevs", 0, 2);
    write_label(&dev0, &label0);

    let dev1 = dir.path().join("dev1");
    let label1 = make_label(pool_guid, device_guid, "dupdevs", 1, 2);
    write_label(&dev1, &label1);

    let cfg = PoolScanConfig::new(vec![dev0, dev1]);
    let reader = LabelReader::new(cfg);
    let err = validate_pool_membership(&reader).unwrap_err();
    match err {
        MembershipError::DuplicateMemberIdentity {
            kind,
            identity_value,
            observations,
        } => {
            assert!(matches!(
                kind,
                tidefs_pool_scan::label::DuplicateIdentityKind::DeviceGuid
            ));
            assert_eq!(identity_value, "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1");
            assert_eq!(observations.len(), 2);
        }
        other => panic!("expected DuplicateMemberIdentity, got {other:?}"),
    }
}

#[test]
fn validate_membership_single_foreign_device_reported() {
    let dir = tempfile::tempdir().unwrap();

    let dev0 = dir.path().join("home");
    let label0 = make_label([0xE0u8; 16], [0xE1u8; 16], "homepool", 0, 2);
    write_label(&dev0, &label0);

    let dev1 = dir.path().join("foreign");
    let label1 = make_label([0xFFu8; 16], [0xEEu8; 16], "alienpool", 0, 1);
    write_label(&dev1, &label1);

    let cfg = PoolScanConfig::new(vec![dev0, dev1]);
    let reader = LabelReader::new(cfg);
    let err = validate_pool_membership(&reader).unwrap_err();

    match err {
        MembershipError::PoolGuidMismatch {
            expected,
            found,
            device_path,
        } => {
            assert_eq!(expected, [0xE0u8; 16]);
            assert_eq!(found, [0xFFu8; 16]);
            assert!(device_path.to_string_lossy().contains("foreign"));
        }
        other => panic!("expected PoolGuidMismatch, got {other:?}"),
    }
}

// — Duplicate member identity tests —

#[test]
fn validate_membership_duplicate_device_index_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let pool_guid = [0x50u8; 16];

    // Two distinct devices claiming the same device_index=0.
    let dev0 = dir.path().join("dev0");
    let label0 = make_label(pool_guid, [0x01u8; 16], "dupindex", 0, 2);
    write_label(&dev0, &label0);

    let dev1 = dir.path().join("dev1");
    let label1 = make_label(pool_guid, [0x02u8; 16], "dupindex", 0, 2);
    write_label(&dev1, &label1);

    let cfg = PoolScanConfig::new(vec![dev0, dev1]);
    let reader = LabelReader::new(cfg);
    let err = validate_pool_membership(&reader).unwrap_err();

    match err {
        MembershipError::DuplicateMemberIdentity {
            kind,
            identity_value,
            observations,
        } => {
            assert!(matches!(
                kind,
                tidefs_pool_scan::label::DuplicateIdentityKind::DeviceIndex
            ));
            assert_eq!(identity_value, "0");
            assert_eq!(observations.len(), 2);
            // Observations mention different device GUIDs.
            let details: Vec<&str> = observations.iter().map(|(_, d)| d.as_str()).collect();
            assert!(details
                .iter()
                .any(|d| d.contains("01010101010101010101010101010101")));
            assert!(details
                .iter()
                .any(|d| d.contains("02020202020202020202020202020202")));
        }
        other => panic!("expected DuplicateMemberIdentity, got {other:?}"),
    }
}

#[test]
fn validate_membership_same_path_twice_is_benign() {
    let dir = tempfile::tempdir().unwrap();
    let pool_guid = [0x60u8; 16];

    let dev = dir.path().join("onlydev");
    let label = make_label(pool_guid, [0x01u8; 16], "benign", 0, 1);
    write_label(&dev, &label);

    // Scan the same path twice — must succeed (benign repeated scan).
    let cfg = PoolScanConfig::new(vec![dev.clone(), dev.clone()]);
    let reader = LabelReader::new(cfg);
    let guid = validate_pool_membership(&reader).unwrap();
    assert_eq!(guid, pool_guid);
}

#[test]
fn validate_membership_healthy_unique_members() {
    let dir = tempfile::tempdir().unwrap();
    let pool_guid = [0x70u8; 16];

    let dev0 = dir.path().join("dev0");
    let label0 = make_label(pool_guid, [0x01u8; 16], "healthy", 0, 2);
    write_label(&dev0, &label0);

    let dev1 = dir.path().join("dev1");
    let label1 = make_label(pool_guid, [0x02u8; 16], "healthy", 1, 2);
    write_label(&dev1, &label1);

    let cfg = PoolScanConfig::new(vec![dev0, dev1]);
    let reader = LabelReader::new(cfg);
    let guid = validate_pool_membership(&reader).unwrap();
    assert_eq!(guid, pool_guid);
}

#[test]
fn duplicate_member_identity_error_display() {
    use tidefs_pool_scan::label::DuplicateIdentityKind;
    let err = MembershipError::DuplicateMemberIdentity {
        kind: DuplicateIdentityKind::DeviceGuid,
        identity_value: "abcdef".into(),
        observations: vec![
            (PathBuf::from("/dev/sda"), "device_index=0".into()),
            (PathBuf::from("/dev/sdb"), "device_index=1".into()),
        ],
    };
    let msg = format!("{err}");
    assert!(msg.contains("duplicate device GUID identity"));
    assert!(msg.contains("abcdef"));
    assert!(msg.contains("/dev/sda"));
    assert!(msg.contains("/dev/sdb"));
    assert!(msg.contains("device_index=0"));
    assert!(msg.contains("device_index=1"));
}

#[test]
fn duplicate_member_identity_error_display_device_index() {
    use tidefs_pool_scan::label::DuplicateIdentityKind;
    let err = MembershipError::DuplicateMemberIdentity {
        kind: DuplicateIdentityKind::DeviceIndex,
        identity_value: "3".into(),
        observations: vec![
            (PathBuf::from("/dev/nvme0n1"), "device_guid=aaa".into()),
            (PathBuf::from("/dev/nvme1n1"), "device_guid=bbb".into()),
        ],
    };
    let msg = format!("{err}");
    assert!(msg.contains("duplicate device index identity"));
    assert!(msg.contains("\"3\""));
    assert!(msg.contains("/dev/nvme0n1"));
    assert!(msg.contains("/dev/nvme1n1"));
}

// — PoolScanConfig edge cases —

#[test]
fn scan_config_has_devices_detects_empty() {
    let cfg = PoolScanConfig::new(vec![]);
    assert!(!cfg.has_devices());

    let cfg = PoolScanConfig::new(vec![PathBuf::from("/dev/sda")]);
    assert!(cfg.has_devices());
}

#[test]
fn scan_config_explicit_label_area() {
    let cfg = PoolScanConfig::new(vec![PathBuf::from("/dev/sda")]).with_label_area(128 * 1024);
    assert_eq!(cfg.label_area_bytes, 128 * 1024);
}

#[test]
fn scan_config_default_label_area_is_pool_label_size() {
    let cfg = PoolScanConfig::default();
    assert_eq!(
        cfg.label_area_bytes,
        tidefs_types_pool_label_core::POOL_LABEL_SIZE as u64
    );
}

// — SegmentState and error Display coverage —

#[test]
fn segment_scan_error_io_variant_display() {
    let err = SegmentScanError::Io {
        device_path: PathBuf::from("/dev/sdx"),
        msg: "permission denied".into(),
    };
    let s = format!("{err}");
    assert!(s.contains("I/O error"));
    assert!(s.contains("/dev/sdx"));
    assert!(s.contains("permission denied"));
}

#[test]
fn membership_error_display_no_valid_labels() {
    assert_eq!(
        format!("{}", MembershipError::NoValidLabels),
        "no valid TideFS labels found on any device"
    );
}

// — Large segment table —

#[test]
fn large_segment_table_enumeration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("largeseg");

    let segments: Vec<SegmentDescriptor> = (0..100)
        .map(|i| {
            let state = match i % 3 {
                0 => SegmentState::Active,
                1 => SegmentState::Sealed,
                _ => SegmentState::Obsolete,
            };
            SegmentDescriptor::new(i, i * 0x100000, 0x100000, state)
        })
        .collect();

    let sys_buf = build_system_area(&segments, 0);

    let mut label = PoolLabelV1::new([0xF0u8; 16], [0xF1u8; 16], "largeseg");
    label.device_index = 0;
    label.device_count = 1;
    label.system_area_pointer = 4096;
    label.system_area_size = sys_buf.len() as u64;
    let label = seal_label(label).unwrap();

    write_label_with_system_area(&path, &label, &sys_buf, 4096);

    let table = SegmentTableReader::read_from_device(&path, &label).unwrap();
    assert_eq!(table.len(), 100);
    assert_eq!(table.live_segments().len(), 67); // 100 - 33 obsolete = 67 live
    assert!(table.get(0).is_some());
    assert!(table.get(99).is_some());
    assert!(table.get(100).is_none());
}

// — DeviceScanReport integration —

#[test]
fn device_scan_entry_construction() {
    let entry = DeviceScanEntry {
        device_path: PathBuf::from("/dev/test"),
        size_bytes: 1024 * 1024 * 1024,
        kind: tidefs_pool_scan::DeviceKind::Ssd,
        model: Some("Samsung EVO".into()),
        serial: Some("S123456".into()),
        has_tidefs_label: true,
        pool_guid: Some([0x42u8; 16]),
        pool_name: Some("testpool".into()),
        pool_state: Some(tidefs_types_pool_label_core::PoolState::Active),
        device_guid: Some([0x24u8; 16]),
        label_valid: true,
        label_status: "ok".into(),
        device_index: Some(0),
        device_count: Some(4),
        topology_generation: Some(1),
        device_class: Some(tidefs_types_pool_label_core::DeviceClass::Ssd),
        redundancy_policy: Some(tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1)),
        device_capacity_bytes: Some(1024 * 1024 * 1024),
        device_health: Some(tidefs_pool_scan::DeviceHealth::Online),
        device_read_errors: Some(0),
        device_write_errors: Some(0),
        device_checksum_errors: Some(0),
        completed_evacuations: vec![],
    };

    assert_eq!(entry.device_count, Some(4));
    assert!(entry.has_tidefs_label);
    assert!(entry.label_valid);
}

// — Empty scan report —

#[test]
fn empty_scan_report() {
    let report = DeviceScanReport::default();
    assert!(report.devices.is_empty());
    assert!(report.devices.is_empty());
}

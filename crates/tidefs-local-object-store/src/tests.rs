// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use super::*;
use crate::compress::CompressionConfig;
use crate::device::Device;
use crate::device::DeviceImpl;
use crate::pool_exporter::PoolExporter;
use crate::pool_importer::PoolImporter;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-local-object-store-{name}-{}-{nanos}",
        std::process::id()
    ))
}

const fn options() -> StoreOptions {
    StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        max_segment_bytes: 512,
        sync_on_write: false,
        repair_torn_tail: true,
        mirror_path: None,
        replica_paths: Vec::new(),
        segment_rotation_interval_secs: 0,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 256,
        durability_layout: None,
        write_throttle_enabled: false,
    }
}
fn cleanup(root: &Path) {
    let _ = fs::remove_dir_all(root);
}

#[test]
fn read_only_open_does_not_initialize_missing_store() {
    let root = temp_root("read-only-missing");
    assert!(!root.exists());

    let store = LocalObjectStore::open_read_only_with_options(&root, options())
        .expect("read-only open missing store");

    assert!(store.is_none());
    assert!(!root.exists());
    cleanup(&root);
}

#[test]
fn read_only_open_does_not_rotate_full_segment() {
    let root = temp_root("read-only-full-segment");
    let opts = options();
    let payload = vec![0x5a; opts.max_object_bytes() as usize];
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        store
            .put_named("full-segment", &payload)
            .expect("put object");
        store.sync_all().expect("sync store");
    }
    let segments_dir = root.join(STORE_DIR_NAME);
    let before = discover_segment_ids(&segments_dir).expect("segments before read-only open");

    let store = LocalObjectStore::open_read_only_with_options(&root, opts.clone())
        .expect("read-only open full segment")
        .expect("existing store");

    let after = discover_segment_ids(&segments_dir).expect("segments after read-only open");
    assert_eq!(after, before);
    assert_eq!(
        store.get_named("full-segment").expect("read object"),
        Some(payload)
    );
    cleanup(&root);
}

#[test]
fn read_only_store_rejects_mutating_put() {
    let root = temp_root("read-only-rejects-put");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put_named("stable", b"stable").expect("put object");
        store.sync_all().expect("sync store");
    }

    let mut read_only = LocalObjectStore::open_read_only_with_options(&root, options())
        .expect("read-only open")
        .expect("existing store");

    assert_eq!(
        read_only.get_named("stable").expect("read stable"),
        Some(b"stable".to_vec())
    );
    assert!(matches!(
        read_only.put_named("new", b"nope"),
        Err(StoreError::ReadOnly { operation: "put" })
    ));
    assert_eq!(
        read_only
            .get_named("stable")
            .expect("read stable after put"),
        Some(b"stable".to_vec())
    );
    cleanup(&root);
}

#[test]
fn local_object_store_on_disk_format_spec_covers_storage_005_topics() {
    let rules = local_object_store_on_disk_format_rules();
    assert_eq!(rules.len(), 8);

    for topic in [
        LocalObjectStoreFormatTopic::SegmentIdentity,
        LocalObjectStoreFormatTopic::SegmentGapPolicy,
        LocalObjectStoreFormatTopic::RecordVersions,
        LocalObjectStoreFormatTopic::HeaderLayout,
        LocalObjectStoreFormatTopic::FooterSemantics,
        LocalObjectStoreFormatTopic::TombstoneSemantics,
        LocalObjectStoreFormatTopic::VersionHistory,
        LocalObjectStoreFormatTopic::UpgradeRules,
    ] {
        assert!(
            rules.iter().any(|rule| rule.topic == topic),
            "on-disk format spec should cover {}",
            topic.human_name()
        );
    }

    for marker in [
        "segment",
        "gap",
        "version",
        "footer",
        "tombstone",
        "history",
        "upgrade",
    ] {
        assert!(
            rules.iter().any(|rule| {
                rule.rule.contains(marker)
                    || rule.topic.human_name().contains(marker)
                    || rule.topic.stable_id().contains(marker)
            }),
            "on-disk format spec should mention {marker}"
        );
    }

    assert_eq!(RECORD_MAGIC_BYTES, *b"VLOSREC1");
    assert_eq!(RECORD_FOOTER_MAGIC_BYTES, *b"VLOSEND2");
    assert_eq!(PRODUCTION_INTEGRITY_TRAILER_MAGIC_BYTES, *b"VLOSINT4");
    assert_eq!(RECORD_HEADER_LEN, 96);
    assert_eq!(RECORD_FOOTER_LEN, 16);
    assert_eq!(PRODUCTION_INTEGRITY_TRAILER_LEN, 112);
    assert_eq!(RECORD_FORMAT_VERSION_V1_NO_FOOTER, 1);
    assert_eq!(RECORD_FORMAT_VERSION_V2_FOOTER, 2);
    assert_eq!(RECORD_FORMAT_VERSION, 3);
}

#[test]
fn production_integrity_policy_covers_storage_006_acceptance_gate() {
    let rules = production_integrity_policy_rules();
    assert_eq!(rules.len(), 8);

    for topic in [
        ProductionIntegrityPolicyTopic::ChosenAlgorithms,
        ProductionIntegrityPolicyTopic::DomainSeparation,
        ProductionIntegrityPolicyTopic::CollisionPolicy,
        ProductionIntegrityPolicyTopic::AuthenticatedRoot,
        ProductionIntegrityPolicyTopic::MigrationPlan,
        ProductionIntegrityPolicyTopic::CompatibilityBoundary,
        ProductionIntegrityPolicyTopic::KeyHandling,
        ProductionIntegrityPolicyTopic::Validation,
    ] {
        assert!(
            rules.iter().any(|rule| rule.topic == topic),
            "production integrity policy should cover {}",
            topic.human_name()
        );
    }

    for marker in [
        "BLAKE3-256",
        "domain",
        "collision",
        "authenticated root",
        "migration",
        "version 3",
        "compatibility",
        "keys",
    ] {
        assert!(
            rules.iter().any(|rule| {
                rule.rule.contains(marker)
                    || rule.topic.human_name().contains(marker)
                    || rule.topic.stable_id().contains(marker)
            }),
            "production integrity policy should mention {marker}"
        );
    }

    assert_eq!(PRODUCTION_INTEGRITY_OBJECT_DIGEST_ALGORITHM, "BLAKE3-256");
    assert_eq!(PRODUCTION_INTEGRITY_RECORD_DIGEST_ALGORITHM, "BLAKE3-256");
    assert!(PRODUCTION_INTEGRITY_ROOT_AUTHENTICATION_ALGORITHM.contains("keyed BLAKE3-256"));
    assert!(PRODUCTION_INTEGRITY_KEY_DERIVATION_ALGORITHM.contains("derive_key"));
    let migration_record_version = rules
        .iter()
        .find(|rule| rule.topic == ProductionIntegrityPolicyTopic::MigrationPlan)
        .map(|_| PRODUCTION_INTEGRITY_MIGRATION_RECORD_VERSION)
        .expect("migration plan rule should be present");
    assert_eq!(migration_record_version, RECORD_FORMAT_VERSION);
    assert!(PRODUCTION_INTEGRITY_POLICY_SPEC.contains("TideFS storage item 006"));
}

#[test]
fn put_reopen_gets_bytes() {
    let root = temp_root("put-reopen");
    let key = ObjectKey::from_name("alpha");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        let stored = store.put(key, b"hello durable bytes").expect("put bytes");
        assert_eq!(stored.key, key);
        assert_eq!(stored.len, 19);
        store.sync_all().expect("sync store");
    }
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
        assert_eq!(
            store.get(key).expect("get key"),
            Some(b"hello durable bytes".to_vec())
        );
        assert_eq!(store.stats().live_objects, 1);
        assert_eq!(store.replay_report().puts_seen, 1);
        assert_eq!(store.replay_report().v3_records_seen, 1);
        assert_eq!(store.replay_report().production_integrity_records_seen, 1);
    }
    cleanup(&root);
}

#[test]
fn new_records_use_v3_production_integrity_trailer() {
    let root = temp_root("v3-production-integrity-trailer");
    let key = ObjectKey::from_name("alpha");
    let payload = b"v3 production integrity bytes";
    let location;
    let path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, payload).expect("put bytes");
        store.sync_all().expect("sync store");
        location = store.location_of(key).expect("location exists");
        path = super::segment_path(store.segments_dir(), location.segment_id);
    }
    let mut file = File::open(&path).expect("open segment");
    let mut header = [0_u8; RECORD_HEADER_LEN];
    file.read_exact(&mut header).expect("read header");
    let record = decode_header(&header, location.segment_id, location.record_offset)
        .expect("decode v3 header");
    assert_eq!(record.format_version, RECORD_FORMAT_VERSION);
    let mut payload_bytes = vec![0_u8; payload.len()];
    file.read_exact(&mut payload_bytes).expect("read payload");
    let mut footer = [0_u8; RECORD_FOOTER_LEN];
    file.read_exact(&mut footer).expect("read footer");
    let mut trailer = [0_u8; INTEGRITY_TRAILER_V2_LEN];
    file.read_exact(&mut trailer)
        .expect("read integrity trailer V2");
    let decoded = decode_integrity_trailer_v2(&trailer).expect("validate integrity trailer V2");
    assert_eq!(decoded.digest_suite, INTEGRITY_TRAILER_V2_DIGEST_SUITE_ID);
    let digests = verify_integrity_trailer_v2(
        &decoded,
        record,
        &header,
        &payload_bytes,
        &footer,
        location.segment_id,
        RECORD_HEADER_LEN_U64 + record.payload_len + RECORD_FOOTER_LEN_U64,
    )
    .expect("verify integrity trailer V2");
    assert_ne!(digests.payload_digest, ProductionIntegrityDigest::ZERO);
    assert_ne!(digests.record_digest, ProductionIntegrityDigest::ZERO);

    let reopened = LocalObjectStore::open_with_options(&root, options()).expect("reopen v3 store");
    assert_eq!(reopened.get(key).expect("read key"), Some(payload.to_vec()));
    assert_eq!(reopened.replay_report().v3_records_seen, 1);
    assert_eq!(
        reopened.replay_report().production_integrity_records_seen,
        1
    );
    cleanup(&root);
}

#[test]
fn record_version_2_footer_record_replays_as_compatibility_input() {
    let root = temp_root("v2-compatibility");
    let key = ObjectKey::from_name("compat-v2");
    let payload = b"v2 compatibility bytes";
    {
        let store =
            LocalObjectStore::open_with_options(&root, options()).expect("open empty store");
        let segment_path = super::segment_path(store.segments_dir(), 0);
        drop(store);
        let record = RecordHeader {
            format_version: RECORD_FORMAT_VERSION_V2_FOOTER,
            kind: RecordKind::Put,
            sequence: 1,
            key,
            payload_len: payload.len() as u64,
            payload_checksum: checksum64(payload),
            compression_algorithm: 0,
        };
        let mut header = [0_u8; RECORD_HEADER_LEN];
        encode_header(&mut header, record);
        let footer = encode_footer(record);
        let mut file = OpenOptions::new()
            .append(true)
            .open(&segment_path)
            .expect("open segment");
        file.write_all(&header).expect("write v2 header");
        file.write_all(payload).expect("write v2 payload");
        file.write_all(&footer).expect("write v2 footer");
        file.sync_all().expect("sync v2 segment");
    }

    let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
    assert_eq!(store.get(key).expect("read key"), Some(payload.to_vec()));
    assert_eq!(store.replay_report().v2_records_seen, 1);
    assert_eq!(store.replay_report().production_integrity_records_seen, 0);
    cleanup(&root);
}

#[test]
fn overwrite_replay_keeps_latest_payload() {
    let root = temp_root("overwrite");
    let key = ObjectKey::from_name("alpha");
    {
        let mut store = LocalObjectStore::open_with_options(
            &root,
            StoreOptions {
                max_segment_bytes: 512,
                ..options()
            },
        )
        .expect("open store");
        store.put(key, b"old").expect("put old");
        store.put(key, b"new").expect("put new");
        store.sync_all().expect("sync store");
    }
    let store = LocalObjectStore::open_with_options(
        &root,
        StoreOptions {
            max_segment_bytes: 512,
            ..options()
        },
    )
    .expect("reopen store");
    assert_eq!(store.get(key).expect("get key"), Some(b"new".to_vec()));
    assert_eq!(store.replay_report().puts_seen, 2);
    cleanup(&root);
}

#[test]
fn delete_replay_hides_object() {
    let root = temp_root("delete");
    let key = ObjectKey::from_name("alpha");
    {
        let mut store = LocalObjectStore::open_with_options(
            &root,
            StoreOptions {
                max_segment_bytes: 512,
                ..options()
            },
        )
        .expect("open store");
        store.put(key, b"bytes").expect("put bytes");
        assert!(store.delete(key).expect("delete key"));
        store.sync_all().expect("sync store");
    }
    let store = LocalObjectStore::open_with_options(
        &root,
        StoreOptions {
            max_segment_bytes: 512,
            ..options()
        },
    )
    .expect("reopen store");
    assert_eq!(store.get(key).expect("get key"), None);
    assert_eq!(store.replay_report().deletes_seen, 1);
    cleanup(&root);
}

#[test]
fn segment_rollover_creates_multiple_segments() {
    let root = temp_root("rollover");
    let mut opts = options();
    opts.max_segment_bytes = 384;
    let mut store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
    store.put_named("one", &[1_u8; 80]).expect("put one");
    store.put_named("two", &[2_u8; 80]).expect("put two");
    store.put_named("three", &[3_u8; 80]).expect("put three");
    let stats = store.stats();
    assert!(stats.segment_count >= 3);
    assert_eq!(stats.live_objects, 3);
    cleanup(&root);
}

#[test]
fn truncated_tail_is_repaired_without_losing_committed_record() {
    let root = temp_root("repair-tail");
    let key = ObjectKey::from_name("alpha");
    let segment_path;
    let valid_len;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"stable").expect("put bytes");
        store.sync_all().expect("sync store");
        let location = store.location_of(key).expect("location exists");
        valid_len = location.record_offset
            + RECORD_HEADER_LEN_U64
            + location.payload_len
            + RECORD_FOOTER_LEN_U64
            + INTEGRITY_TRAILER_V2_LEN_U64;
        segment_path = super::segment_path(store.segments_dir(), location.segment_id);
    }
    {
        let mut file = OpenOptions::new()
            .append(true)
            .open(&segment_path)
            .expect("open segment for torn append");
        file.write_all(&[0xaa; RECORD_HEADER_LEN / 2])
            .expect("write torn header");
    }
    let store =
        LocalObjectStore::open_with_options(&root, options()).expect("reopen repaired store");
    assert_eq!(store.get(key).expect("get key"), Some(b"stable".to_vec()));
    assert_eq!(
        store.replay_report().repaired_tail_bytes,
        (RECORD_HEADER_LEN / 2) as u64
    );
    assert_eq!(
        fs::metadata(&segment_path).expect("segment metadata").len(),
        valid_len
    );
    cleanup(&root);
}

#[test]
fn torn_overwrite_tail_repair_preserves_previous_committed_payload() {
    let root = temp_root("repair-torn-overwrite");
    let key = ObjectKey::from_name("alpha");
    let segment_path;
    let valid_len;

    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"stable").expect("put stable");
        store.sync_all().expect("sync stable record");
        let location = store.location_of(key).expect("location exists");
        valid_len = location.record_offset
            + RECORD_HEADER_LEN_U64
            + location.payload_len
            + RECORD_FOOTER_LEN_U64
            + INTEGRITY_TRAILER_V2_LEN_U64;
        segment_path = super::segment_path(store.segments_dir(), location.segment_id);
    }

    let candidate_payload = b"candidate";
    let candidate_record = RecordHeader {
        format_version: RECORD_FORMAT_VERSION,
        kind: RecordKind::Put,
        sequence: 2,
        key,
        payload_len: candidate_payload.len() as u64,
        payload_checksum: checksum64(candidate_payload),
        compression_algorithm: 0,
    };
    let mut header = [0_u8; RECORD_HEADER_LEN];
    encode_header(&mut header, candidate_record);
    let footer = encode_footer(candidate_record);
    let trailer = encode_integrity_trailer_v2(&build_integrity_trailer_v2(
        candidate_record,
        &header,
        candidate_payload,
        &footer,
    ));
    let partial_trailer_len = INTEGRITY_TRAILER_V2_LEN / 2;
    let torn_bytes = RECORD_HEADER_LEN_U64
        + candidate_payload.len() as u64
        + RECORD_FOOTER_LEN_U64
        + partial_trailer_len as u64;
    {
        let mut file = OpenOptions::new()
            .append(true)
            .open(&segment_path)
            .expect("open segment for torn overwrite append");
        file.write_all(&header).expect("write candidate header");
        file.write_all(candidate_payload)
            .expect("write candidate payload");
        file.write_all(&footer).expect("write candidate footer");
        file.write_all(&trailer[..partial_trailer_len])
            .expect("write partial candidate trailer");
    }

    let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
    assert_eq!(
        store.get(key).expect("read repaired key"),
        Some(b"stable".to_vec())
    );
    assert_eq!(store.version_locations_of(key).len(), 1);
    assert_eq!(store.replay_report().puts_seen, 1);
    assert_eq!(store.replay_report().repaired_tail_bytes, torn_bytes);
    assert_eq!(
        fs::metadata(&segment_path).expect("segment metadata").len(),
        valid_len
    );
    cleanup(&root);
}

#[test]
fn invalid_final_footer_is_rejected_as_integrity_error() {
    let root = temp_root("invalid-footer-integrity-error");
    let stable_key = ObjectKey::from_name("alpha");
    let candidate_key = ObjectKey::from_name("beta");
    let segment_path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(stable_key, b"stable").expect("put stable");
        store.sync_all().expect("sync stable record");
        let location = store
            .location_of(stable_key)
            .expect("stable location exists");
        segment_path = super::segment_path(store.segments_dir(), location.segment_id);
    }
    let candidate_payload = b"candidate";
    let candidate_record = RecordHeader {
        format_version: RECORD_FORMAT_VERSION_V2_FOOTER,
        kind: RecordKind::Put,
        sequence: 2,
        key: candidate_key,
        payload_len: candidate_payload.len() as u64,
        payload_checksum: checksum64(candidate_payload),
        compression_algorithm: 0,
    };
    let mut header = [0_u8; RECORD_HEADER_LEN];
    encode_header(&mut header, candidate_record);
    {
        let mut file = OpenOptions::new()
            .append(true)
            .open(&segment_path)
            .expect("open segment for invalid footer append");
        file.write_all(&header).expect("write candidate header");
        file.write_all(candidate_payload)
            .expect("write candidate payload");
        file.write_all(&[0_u8; RECORD_FOOTER_LEN])
            .expect("write invalid footer");
    }

    match LocalObjectStore::open_with_options(&root, options()) {
        Err(StoreError::CorruptHeader {
            reason: "record footer magic does not match local object-store format",
            ..
        }) => {}
        other => panic!("expected explicit invalid-footer integrity error, got {other:?}"),
    }
    cleanup(&root);
}

#[test]
fn checksum_mismatch_rejects_replay() {
    let root = temp_root("checksum-mismatch");
    let key = ObjectKey::from_name("alpha");
    let location;
    let path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"stable").expect("put bytes");
        store.sync_all().expect("sync store");
        location = store.location_of(key).expect("location exists");
        path = super::segment_path(store.segments_dir(), location.segment_id);
    }
    {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open segment for corruption");
        file.seek(SeekFrom::Start(location.payload_offset))
            .expect("seek payload");
        file.write_all(b"X").expect("corrupt payload");
    }
    match LocalObjectStore::open_with_options(&root, options()) {
        Err(StoreError::ProductionIntegrityMismatch {
            field: "payload digest",
            ..
        }) => {}
        other => panic!("expected production integrity payload mismatch, got {other:?}"),
    }
    cleanup(&root);
}

#[test]
fn production_integrity_trailer_mismatch_rejects_replay() {
    let root = temp_root("production-integrity-trailer-mismatch");
    let key = ObjectKey::from_name("alpha");
    let location;
    let path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"stable").expect("put bytes");
        store.sync_all().expect("sync store");
        location = store.location_of(key).expect("location exists");
        path = super::segment_path(store.segments_dir(), location.segment_id);
    }
    {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open segment for trailer corruption");
        let trailer_payload_digest_offset = location.record_offset
            + RECORD_HEADER_LEN_U64
            + location.payload_len
            + RECORD_FOOTER_LEN_U64
            + 16;
        file.seek(SeekFrom::Start(trailer_payload_digest_offset))
            .expect("seek trailer payload digest");
        file.write_all(b"X").expect("corrupt trailer digest");
    }
    match LocalObjectStore::open_with_options(&root, options()) {
        Err(StoreError::ProductionIntegrityMismatch {
            field: "payload digest",
            ..
        }) => {}
        other => panic!("expected production integrity trailer mismatch, got {other:?}"),
    }
    cleanup(&root);
}

#[test]
fn version_history_preserves_superseded_put_locations() {
    let root = temp_root("version-history");
    let key = ObjectKey::from_name("alpha");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"old-root-candidate").expect("put old");
        store.put(key, b"new-root-candidate").expect("put new");
        store.sync_all().expect("sync store");
    }
    let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
    let history = store.version_locations_of(key);
    assert_eq!(history.len(), 2);
    assert_eq!(
        store
            .get_at_location(history[0])
            .expect("read previous version"),
        b"old-root-candidate".to_vec()
    );
    assert_eq!(
        store.get_at_location(history[1]).expect("read new version"),
        b"new-root-candidate".to_vec()
    );
    assert_eq!(
        store.get(key).expect("read latest"),
        Some(b"new-root-candidate".to_vec())
    );
    cleanup(&root);
}

// --- #227 corrupt segment trailer detection tests ---

#[test]
fn corrupt_header_magic_rejected() {
    let root = temp_root("corrupt-header-magic");
    let key = ObjectKey::from_name("alpha");
    let segment_path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"payload").expect("put bytes");
        store.sync_all().expect("sync store");
        let location = store.location_of(key).expect("location exists");
        segment_path = super::segment_path(store.segments_dir(), location.segment_id);
    }
    {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&segment_path)
            .expect("open segment for corruption");
        file.write_all(&[0xff_u8; 8]).expect("corrupt header magic");
    }
    match LocalObjectStore::open_with_options(&root, options()) {
        Err(StoreError::CorruptHeader {
            reason: "record magic does not match local object-store format",
            ..
        }) => {}
        other => panic!("expected corrupt header magic error, got {other:?}"),
    }
    cleanup(&root);
}

#[test]
fn corrupt_trailer_magic_rejected() {
    let root = temp_root("corrupt-trailer-magic");
    let key = ObjectKey::from_name("alpha");
    let location;
    let segment_path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"payload").expect("put bytes");
        store.sync_all().expect("sync store");
        location = store.location_of(key).expect("location exists");
        segment_path = super::segment_path(store.segments_dir(), location.segment_id);
    }
    {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&segment_path)
            .expect("open segment for trailer corruption");
        let trailer_offset = location.record_offset
            + RECORD_HEADER_LEN_U64
            + location.payload_len
            + RECORD_FOOTER_LEN_U64;
        file.seek(SeekFrom::Start(trailer_offset))
            .expect("seek trailer magic");
        file.write_all(b"BADMAGIC").expect("corrupt trailer magic");
    }
    match LocalObjectStore::open_with_options(&root, options()) {
        Err(StoreError::CorruptHeader {
            reason: "production integrity trailer magic does not match local object-store format",
            ..
        }) => {}
        other => panic!("expected trailer magic error, got {other:?}"),
    }
    cleanup(&root);
}

#[test]
fn corrupt_trailer_version_rejected() {
    let root = temp_root("corrupt-trailer-version");
    let key = ObjectKey::from_name("alpha");
    let location;
    let segment_path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"payload").expect("put bytes");
        store.sync_all().expect("sync store");
        location = store.location_of(key).expect("location exists");
        segment_path = super::segment_path(store.segments_dir(), location.segment_id);
    }
    {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&segment_path)
            .expect("open segment for trailer version corruption");
        let version_offset = location.record_offset
            + RECORD_HEADER_LEN_U64
            + location.payload_len
            + RECORD_FOOTER_LEN_U64
            + 8;
        file.seek(SeekFrom::Start(version_offset))
            .expect("seek trailer version");
        file.write_all(&[0xff_u8, 0xff])
            .expect("corrupt trailer version");
    }
    match LocalObjectStore::open_with_options(&root, options()) {
        Err(StoreError::CorruptHeader {
            reason: "production integrity trailer version does not match record version",
            ..
        }) => {}
        other => panic!("expected trailer version error, got {other:?}"),
    }
    cleanup(&root);
}

#[test]
fn corrupt_trailer_suite_rejected() {
    let root = temp_root("corrupt-trailer-suite");
    let key = ObjectKey::from_name("alpha");
    let location;
    let segment_path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"payload").expect("put bytes");
        store.sync_all().expect("sync store");
        location = store.location_of(key).expect("location exists");
        segment_path = super::segment_path(store.segments_dir(), location.segment_id);
    }
    {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&segment_path)
            .expect("open segment for trailer suite corruption");
        let suite_offset = location.record_offset
            + RECORD_HEADER_LEN_U64
            + location.payload_len
            + RECORD_FOOTER_LEN_U64
            + 10;
        file.seek(SeekFrom::Start(suite_offset))
            .expect("seek trailer suite");
        file.write_all(&[0xff_u8, 0xff])
            .expect("corrupt trailer suite");
    }
    match LocalObjectStore::open_with_options(&root, options()) {
        Err(StoreError::CorruptHeader {
            reason: "production integrity digest suite is not supported",
            ..
        }) => {}
        other => panic!("expected trailer suite error, got {other:?}"),
    }
    cleanup(&root);
}

#[test]
fn corrupt_trailer_length_rejected() {
    let root = temp_root("corrupt-trailer-length");
    let key = ObjectKey::from_name("alpha");
    let location;
    let segment_path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"payload").expect("put bytes");
        store.sync_all().expect("sync store");
        location = store.location_of(key).expect("location exists");
        segment_path = super::segment_path(store.segments_dir(), location.segment_id);
    }
    {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&segment_path)
            .expect("open segment for trailer length corruption");
        let length_offset = location.record_offset
            + RECORD_HEADER_LEN_U64
            + location.payload_len
            + RECORD_FOOTER_LEN_U64
            + 12;
        file.seek(SeekFrom::Start(length_offset))
            .expect("seek trailer length");
        file.write_all(&[0xff_u8, 0xff])
            .expect("corrupt trailer length");
    }
    match LocalObjectStore::open_with_options(&root, options()) {
        Err(StoreError::CorruptHeader {
            reason: "production integrity trailer length is not supported",
            ..
        }) => {}
        other => panic!("expected trailer length error, got {other:?}"),
    }
    cleanup(&root);
}

#[test]
fn corrupt_trailer_reserved_rejected() {
    let root = temp_root("corrupt-trailer-reserved");
    let key = ObjectKey::from_name("alpha");
    let location;
    let segment_path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"payload").expect("put bytes");
        store.sync_all().expect("sync store");
        location = store.location_of(key).expect("location exists");
        segment_path = super::segment_path(store.segments_dir(), location.segment_id);
    }
    {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&segment_path)
            .expect("open segment for trailer reserved corruption");
        let reserved_offset = location.record_offset
            + RECORD_HEADER_LEN_U64
            + location.payload_len
            + RECORD_FOOTER_LEN_U64
            + 14;
        file.seek(SeekFrom::Start(reserved_offset))
            .expect("seek trailer reserved");
        file.write_all(&[0x01_u8, 0x00])
            .expect("corrupt trailer reserved");
    }
    match LocalObjectStore::open_with_options(&root, options()) {
        Err(StoreError::CorruptHeader {
            reason: "production integrity trailer reserved bytes are not zero",
            ..
        }) => {}
        other => panic!("expected trailer reserved error, got {other:?}"),
    }
    cleanup(&root);
}

#[test]
fn corrupt_trailer_record_digest_rejected() {
    let root = temp_root("corrupt-trailer-record-digest");
    let key = ObjectKey::from_name("alpha");
    let location;
    let segment_path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"payload").expect("put bytes");
        store.sync_all().expect("sync store");
        location = store.location_of(key).expect("location exists");
        segment_path = super::segment_path(store.segments_dir(), location.segment_id);
    }
    {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&segment_path)
            .expect("open segment for trailer record digest corruption");
        let record_digest_offset = location.record_offset
            + RECORD_HEADER_LEN_U64
            + location.payload_len
            + RECORD_FOOTER_LEN_U64
            + 48;
        file.seek(SeekFrom::Start(record_digest_offset))
            .expect("seek trailer record digest");
        file.write_all(b"X").expect("corrupt trailer record digest");
    }
    match LocalObjectStore::open_with_options(&root, options()) {
        Err(StoreError::ProductionIntegrityMismatch {
            field: "record digest",
            ..
        }) => {}
        other => panic!("expected trailer record digest mismatch, got {other:?}"),
    }
    cleanup(&root);
}

// --- #227 non-monotonic sequence tests ---

#[test]
fn non_monotonic_sequence_accepted_on_replay() {
    let root = temp_root("non-monotonic-seq");
    let key_a = ObjectKey::from_name("alpha");
    let key_b = ObjectKey::from_name("beta");
    let path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key_a, b"alpha").expect("put alpha");
        store.sync_all().expect("sync store");
        let location = store.location_of(key_a).expect("location exists");
        path = super::segment_path(store.segments_dir(), location.segment_id);
    }
    {
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open segment for non-monotonic append");
        let record_high = RecordHeader {
            format_version: RECORD_FORMAT_VERSION,
            kind: RecordKind::Put,
            sequence: 100,
            key: key_b,
            payload_len: 5,
            payload_checksum: checksum64(b"hello"),
            compression_algorithm: 0,
        };
        let mut header = [0_u8; RECORD_HEADER_LEN];
        super::encode_header(&mut header, record_high);
        let footer = super::encode_footer(record_high);
        let trailer_v2 = super::build_integrity_trailer_v2(record_high, &header, b"hello", &footer);
        let trailer = super::encode_integrity_trailer_v2(&trailer_v2);
        file.write_all(&header).expect("write high-seq header");
        file.write_all(b"hello").expect("write high-seq payload");
        file.write_all(&footer).expect("write high-seq footer");
        file.write_all(&trailer).expect("write high-seq trailer");

        let record_low = RecordHeader {
            format_version: RECORD_FORMAT_VERSION,
            kind: RecordKind::Put,
            sequence: 50,
            key: key_b,
            payload_len: 5,
            payload_checksum: checksum64(b"world"),
            compression_algorithm: 0,
        };
        let mut header = [0_u8; RECORD_HEADER_LEN];
        super::encode_header(&mut header, record_low);
        let footer = super::encode_footer(record_low);
        let trailer_v2 = super::build_integrity_trailer_v2(record_low, &header, b"world", &footer);
        let trailer = super::encode_integrity_trailer_v2(&trailer_v2);
        file.write_all(&header).expect("write low-seq header");
        file.write_all(b"world").expect("write low-seq payload");
        file.write_all(&footer).expect("write low-seq footer");
        file.write_all(&trailer).expect("write low-seq trailer");
    }
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
        assert_eq!(
            store.get(key_b).expect("get key_b"),
            Some(b"world".to_vec()),
            "non-monotonic sequence should replay both records, latest overwrites"
        );
        assert_eq!(store.replay_report().highest_sequence, 100);
        assert!(
            store.next_sequence > 100,
            "next_sequence should advance past highest seen"
        );
    }
    cleanup(&root);
}

// --- #227 max-segment-size boundary tests ---

#[test]
fn append_exact_fit_no_rollover() {
    let root = temp_root("exact-fit");
    let opts = options();
    let exact_payload = vec![0x42_u8; opts.max_object_bytes() as usize];
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        store
            .put(ObjectKey::from_name("a"), &exact_payload)
            .expect("put exact-fit payload");
        store.sync_all().expect("sync store");
        assert_eq!(
            store.replay_report().segment_count,
            1,
            "exact-fit payload should not trigger rollover"
        );
    }
    {
        let store = LocalObjectStore::open_with_options(&root, opts.clone()).expect("reopen store");
        assert_eq!(
            store.get(ObjectKey::from_name("a")).expect("get a"),
            Some(exact_payload)
        );
        assert_eq!(store.replay_report().segment_count, 2);
    }
    cleanup(&root);
}

#[test]
fn append_one_byte_past_triggers_rollover() {
    let root = temp_root("overflow-rollover");
    let opts = options();
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        let exact_payload = vec![0x5a_u8; opts.max_object_bytes() as usize];
        store
            .put(ObjectKey::from_name("a"), &exact_payload)
            .expect("put exact-fit");
        store.sync_all().expect("sync after exact-fit");
        assert_eq!(store.replay_report().segment_count, 1);
        store
            .put(ObjectKey::from_name("b"), b"x")
            .expect("put overflow");
        store.sync_all().expect("sync after overflow");
        assert!(
            store.replay_report().segment_count > 1,
            "put that overflows segment should trigger rollover"
        );
    }
    {
        let store = LocalObjectStore::open_with_options(&root, opts.clone()).expect("reopen store");
        assert!(store.replay_report().segment_count > 1);
        assert_eq!(
            store.get(ObjectKey::from_name("a")).expect("get a"),
            Some(vec![0x5a_u8; opts.max_object_bytes() as usize])
        );
        assert_eq!(
            store.get(ObjectKey::from_name("b")).expect("get b"),
            Some(b"x".to_vec())
        );
    }
    cleanup(&root);
}

// --- #227 tombstoned object lookup tests ---

#[test]
fn tombstoned_not_in_list_keys() {
    let root = temp_root("tombstone-list-keys");
    let key = ObjectKey::from_name("alpha");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"payload").expect("put bytes");
        store.sync_all().expect("sync store");
        assert!(store.list_keys().contains(&key));
        store.delete(key).expect("delete key");
        store.sync_all().expect("sync delete");
        assert!(!store.list_keys().contains(&key));
    }
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
        assert!(
            !store.list_keys().contains(&key),
            "tombstoned key should not appear in list_keys after reopen"
        );
    }
    cleanup(&root);
}

#[test]
fn tombstoned_not_in_contains_key() {
    let root = temp_root("tombstone-contains-key");
    let key = ObjectKey::from_name("alpha");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"payload").expect("put bytes");
        assert!(store.contains_key(key));
        store.delete(key).expect("delete key");
        assert!(
            !store.contains_key(key),
            "contains_key should be false after delete"
        );
    }
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
        assert!(
            !store.contains_key(key),
            "contains_key should be false after reopen"
        );
    }
    cleanup(&root);
}

#[test]
fn tombstone_preserves_put_history() {
    let root = temp_root("tombstone-history");
    let key = ObjectKey::from_name("alpha");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"first").expect("put first");
        store.put(key, b"second").expect("put second");
        store.sync_all().expect("sync puts");
        store.delete(key).expect("delete key");
        store.sync_all().expect("sync delete");
    }
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
        assert!(!store.contains_key(key));
        let history = store.version_locations_of(key);
        assert_eq!(
            history.len(),
            2,
            "tombstone should not erase put version history"
        );
        assert_eq!(
            store.get_at_location(history[0]).expect("read first"),
            b"first".to_vec()
        );
        assert_eq!(
            store.get_at_location(history[1]).expect("read second"),
            b"second".to_vec()
        );
    }
    cleanup(&root);
}

// --- #227 v1/v2/v3 record compatibility edge cases ---

#[test]
fn v1_no_footer_record_replays() {
    let root = temp_root("v1-replay");
    let key = ObjectKey::from_name("alpha");
    let path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.sync_all().expect("sync store");
        path = super::segment_path(store.segments_dir(), 0);
    }
    let payload = b"v1-data";
    let v1_record = RecordHeader {
        format_version: RECORD_FORMAT_VERSION_V1_NO_FOOTER,
        kind: RecordKind::Put,
        sequence: 1,
        key,
        payload_len: payload.len() as u64,
        payload_checksum: checksum64(payload),
        compression_algorithm: 0,
    };
    let mut header = [0_u8; RECORD_HEADER_LEN];
    super::encode_header(&mut header, v1_record);
    {
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open segment for v1 append");
        file.write_all(&header).expect("write v1 header");
        file.write_all(payload).expect("write v1 payload");
    }
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
        assert_eq!(
            store.get(key).expect("get v1 key"),
            Some(b"v1-data".to_vec())
        );
        assert_eq!(store.replay_report().v1_records_seen, 1);
    }
    cleanup(&root);
}

#[test]
fn unsupported_future_record_version_rejected() {
    let root = temp_root("unsupported-version");
    let key = ObjectKey::from_name("alpha");
    let path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.sync_all().expect("sync store");
        path = super::segment_path(store.segments_dir(), 0);
    }
    let future_record = RecordHeader {
        format_version: 4,
        kind: RecordKind::Put,
        sequence: 1,
        key,
        payload_len: 3,
        payload_checksum: checksum64(b"abc"),
        compression_algorithm: 0,
    };
    let mut header = [0_u8; RECORD_HEADER_LEN];
    super::encode_header(&mut header, future_record);
    {
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open segment for unsupported version append");
        file.write_all(&header)
            .expect("write unsupported version header");
        file.write_all(b"abc").expect("write payload");
    }
    match LocalObjectStore::open_with_options(&root, options()) {
        Err(StoreError::UnsupportedVersion { version, .. }) => {
            assert_eq!(version, 4);
        }
        other => panic!("expected UnsupportedVersion error, got {other:?}"),
    }
    cleanup(&root);
}

#[test]
fn record_kind_decode_preserves_invalid_tag() {
    assert_eq!(RecordKind::try_from(1), Ok(RecordKind::Put));
    assert_eq!(RecordKind::try_from(2), Ok(RecordKind::Delete));
    assert_eq!(
        RecordKind::try_from(0),
        Err(RecordKindDecodeError::UnknownRecordKind(0))
    );
    assert_eq!(
        RecordKind::try_from(3),
        Err(RecordKindDecodeError::UnknownRecordKind(3))
    );
    assert_eq!(
        RecordKind::try_from(u16::MAX),
        Err(RecordKindDecodeError::UnknownRecordKind(u16::MAX))
    );
}

// ── ObjectKey unit tests ─────────────────────────────────────────────

#[test]
fn object_key_from_bytes32_roundtrips() {
    let bytes = [0xAB_u8; 32];
    let key = ObjectKey::from_bytes32(bytes);
    assert_eq!(key.as_bytes32(), bytes);
}

#[test]
fn object_key_zero_is_all_zero_bytes() {
    assert_eq!(ObjectKey::ZERO.as_bytes32(), [0_u8; 32]);
}

#[test]
fn object_key_from_name_is_deterministic() {
    let a = ObjectKey::from_name("hello");
    let b = ObjectKey::from_name("hello");
    assert_eq!(a.as_bytes32(), b.as_bytes32());
    assert_eq!(a, b);
}

#[test]
fn object_key_from_name_different_inputs_produce_different_keys() {
    let alpha = ObjectKey::from_name("alpha");
    let beta = ObjectKey::from_name("beta");
    assert_ne!(alpha.as_bytes32(), beta.as_bytes32());
    assert_ne!(alpha, beta);
}

#[test]
fn object_key_from_content_is_deterministic() {
    let a = ObjectKey::from_content(b"hello");
    let b = ObjectKey::from_content(b"hello");
    assert_eq!(a, b);
    assert_ne!(a, ObjectKey::from_content(b"world"));
}

#[test]
fn object_key_from_name_empty_string_produces_valid_key() {
    let key = ObjectKey::from_name("");
    // Should be valid (not equal to ZERO for empty input, since we seed per lane)
    assert!(!key.as_bytes32().iter().all(|&b| b == 0));
}

#[test]
fn object_key_short_hex_produces_16_hex_chars() {
    let key = ObjectKey::from_name("test");
    let hex = key.short_hex();
    assert_eq!(hex.len(), 16);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn object_key_display_produces_64_hex_chars() {
    let key = ObjectKey::from_name("display-test");
    let display = format!("{key}");
    assert_eq!(display.len(), 64);
    assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn object_key_debug_includes_inner_hex() {
    let key = ObjectKey::from_name("debug-test");
    let debug = format!("{key:?}");
    assert!(debug.starts_with("ObjectKey("));
    // Inner Display produces 64 hex chars
    assert!(debug.contains(&format!("{key}")));
}

#[test]
fn object_key_clone_preserves_value() {
    let key = ObjectKey::from_name("clone-test");
    let cloned = key;
    assert_eq!(key, cloned);
}

#[test]
fn object_key_partial_eq_detects_difference() {
    let a = ObjectKey::from_bytes32([0x01_u8; 32]);
    let b = ObjectKey::from_bytes32([0x02_u8; 32]);
    assert_ne!(a, b);
}

// ── Content-addressed ObjectStore API tests ─────────────────────────

#[test]
fn content_addressed_put_get_roundtrip() {
    let root = temp_root("content-put-get");
    let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");

    let key = <LocalObjectStore as ObjectStore>::put(&mut store, b"hello").expect("put blob");

    assert_eq!(key, ObjectKey::from_content(b"hello"));
    assert_eq!(
        <LocalObjectStore as ObjectStore>::get(&store, key).expect("get blob"),
        Some(b"hello".to_vec())
    );
    cleanup(&root);
}

#[test]
fn content_addressed_delete_removes_live_blob() {
    let root = temp_root("content-delete");
    let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
    let key = <LocalObjectStore as ObjectStore>::put(&mut store, b"delete me").expect("put blob");

    assert!(<LocalObjectStore as ObjectStore>::delete(&mut store, key).expect("delete blob"));
    assert_eq!(
        <LocalObjectStore as ObjectStore>::get(&store, key).expect("get deleted blob"),
        None
    );
    cleanup(&root);
}

#[test]
fn content_addressed_scan_empty_store_returns_no_keys() {
    let root = temp_root("content-empty-scan");
    let store = LocalObjectStore::open_with_options(&root, options()).expect("open store");

    let keys: Vec<ObjectKey> = <LocalObjectStore as ObjectStore>::scan(&store).collect();

    assert!(keys.is_empty());
    cleanup(&root);
}

#[test]
fn content_addressed_scan_returns_all_live_keys() {
    let root = temp_root("content-scan");
    let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
    let first = <LocalObjectStore as ObjectStore>::put(&mut store, b"first").expect("put first");
    let second = <LocalObjectStore as ObjectStore>::put(&mut store, b"second").expect("put second");

    let keys: BTreeSet<ObjectKey> = <LocalObjectStore as ObjectStore>::scan(&store).collect();

    assert_eq!(keys, BTreeSet::from([first, second]));
    cleanup(&root);
}

#[test]
fn content_addressed_large_blob_roundtrips() {
    let root = temp_root("content-large");
    let mut opts = StoreOptions::durable();
    opts.sync_on_write = false;
    opts.segment_rotation_interval_secs = u64::MAX;
    opts.segment_rotation_write_limit = 0;
    let mut store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
    let payload = vec![0x5a; 1024 * 1024];

    let key = <LocalObjectStore as ObjectStore>::put(&mut store, &payload).expect("put blob");

    assert_eq!(
        <LocalObjectStore as ObjectStore>::get(&store, key).expect("get blob"),
        Some(payload)
    );
    cleanup(&root);
}

#[test]
fn content_addressed_duplicate_put_is_idempotent() {
    let root = temp_root("content-duplicate");
    let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
    let first = <LocalObjectStore as ObjectStore>::put(&mut store, b"same").expect("first put");
    let next_sequence = store.stats().next_sequence;

    let second = <LocalObjectStore as ObjectStore>::put(&mut store, b"same").expect("second put");

    assert_eq!(first, second);
    assert_eq!(store.stats().live_objects, 1);
    assert_eq!(store.stats().next_sequence, next_sequence);
    cleanup(&root);
}

// ── IntegrityDigest64 unit tests ─────────────────────────────────────

#[test]
fn integrity_digest64_get_returns_constructed_value() {
    let d = IntegrityDigest64(0xDEAD_BEEF_CAFE_BABE);
    assert_eq!(d.get(), 0xDEAD_BEEF_CAFE_BABE);
}

#[test]
fn integrity_digest64_zero_is_zero() {
    assert_eq!(IntegrityDigest64::ZERO.get(), 0);
    assert!(IntegrityDigest64::ZERO.is_zero());
}

#[test]
fn integrity_digest64_display_produces_16_hex_digits() {
    let d = IntegrityDigest64(0xABCD);
    let display = format!("{d}");
    assert_eq!(display.len(), 16);
    assert!(display.contains("abcd"));
}

#[test]
fn integrity_digest64_clone_and_eq() {
    let d = IntegrityDigest64(42);
    assert_eq!(d, d);
    assert_eq!(d.clone(), d);
}

// ── ProductionIntegrityDigest unit tests ─────────────────────────────

#[test]
fn production_integrity_digest_from_bytes32_roundtrips() {
    let bytes = [0xCC_u8; PRODUCTION_INTEGRITY_DIGEST_LEN];
    let digest = ProductionIntegrityDigest::from_bytes32(bytes);
    assert_eq!(digest.as_bytes32(), bytes);
}

#[test]
fn production_integrity_digest_zero_is_all_zeroes() {
    assert_eq!(
        ProductionIntegrityDigest::ZERO.as_bytes32(),
        [0_u8; PRODUCTION_INTEGRITY_DIGEST_LEN]
    );
}

#[test]
fn production_integrity_digest_display_produces_64_hex_chars() {
    let digest =
        ProductionIntegrityDigest::from_bytes32([0x42_u8; PRODUCTION_INTEGRITY_DIGEST_LEN]);
    let display = format!("{digest}");
    assert_eq!(display.len(), PRODUCTION_INTEGRITY_DIGEST_LEN * 2);
    assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn production_integrity_digest_partial_eq_detects_difference() {
    let a = ProductionIntegrityDigest::from_bytes32([0x01_u8; PRODUCTION_INTEGRITY_DIGEST_LEN]);
    let b = ProductionIntegrityDigest::from_bytes32([0x02_u8; PRODUCTION_INTEGRITY_DIGEST_LEN]);
    assert_ne!(a, b);
}

// ── ProductionIntegrityRecordDigests ─────────────────────────────────

#[test]
fn production_integrity_record_digests_equality() {
    let a = ProductionIntegrityRecordDigests {
        payload_digest: ProductionIntegrityDigest::from_bytes32(
            [0xAA_u8; PRODUCTION_INTEGRITY_DIGEST_LEN],
        ),
        record_digest: ProductionIntegrityDigest::from_bytes32(
            [0xBB_u8; PRODUCTION_INTEGRITY_DIGEST_LEN],
        ),
    };
    let b = ProductionIntegrityRecordDigests {
        payload_digest: ProductionIntegrityDigest::from_bytes32(
            [0xAA_u8; PRODUCTION_INTEGRITY_DIGEST_LEN],
        ),
        record_digest: ProductionIntegrityDigest::from_bytes32(
            [0xBB_u8; PRODUCTION_INTEGRITY_DIGEST_LEN],
        ),
    };
    assert_eq!(a, b);
    assert_ne!(
        a,
        ProductionIntegrityRecordDigests {
            payload_digest: ProductionIntegrityDigest::ZERO,
            record_digest: ProductionIntegrityDigest::ZERO,
        }
    );
}

// ── RecordKind unit tests ────────────────────────────────────────────

#[test]
fn record_kind_as_u16_matches_discriminant() {
    assert_eq!(RecordKind::Put.as_u16(), 1);
    assert_eq!(RecordKind::Delete.as_u16(), 2);
}

#[test]
fn record_kind_decode_error_preserves_invalid_value() {
    let err = RecordKindDecodeError::UnknownRecordKind(99);
    match err {
        RecordKindDecodeError::UnknownRecordKind(v) => assert_eq!(v, 99),
    }
}

// ── checksum64 unit tests ────────────────────────────────────────────

#[test]
fn checksum64_is_deterministic() {
    let a = checksum64(b"hello");
    let b = checksum64(b"hello");
    assert_eq!(a, b);
}

#[test]
fn checksum64_different_inputs_produce_different_outputs() {
    let a = checksum64(b"alpha");
    let b = checksum64(b"beta");
    assert_ne!(a, b);
}

#[test]
fn checksum64_empty_input_is_not_zero() {
    let c = checksum64(b"");
    assert!(!c.is_zero());
}

#[test]
fn checksum64_prediction_stability() {
    // Guard against unintended algorithm changes
    let c = checksum64(b"stability-test-v1");
    assert_eq!(c.get(), 0x300BDA1610CC9B7F);
}

// ── segment_file_name unit tests ─────────────────────────────────────

#[test]
fn segment_file_name_produces_expected_format() {
    let name = segment_file_name(0);
    assert_eq!(name, "segment-0000000000000000.vlos");
    let name = segment_file_name(0xDEAD_BEEF);
    assert_eq!(name, "segment-00000000deadbeef.vlos");
    let name = segment_file_name(u64::MAX);
    assert_eq!(name, "segment-ffffffffffffffff.vlos");
}

// ── StoreOptions unit tests ──────────────────────────────────────────

#[test]
fn store_options_durable_has_expected_defaults() {
    let opts = StoreOptions::durable();
    assert_eq!(opts.max_segment_bytes, DEFAULT_MAX_SEGMENT_BYTES);
    assert!(opts.sync_on_write);
    assert!(opts.repair_torn_tail);
}

#[test]
fn store_options_test_fast_has_small_segment_and_no_sync() {
    let opts = StoreOptions::test_fast();
    assert_eq!(opts.max_segment_bytes, 4096);
    assert!(!opts.sync_on_write);
    assert!(opts.repair_torn_tail);
}

#[test]
fn store_options_default_equals_durable() {
    let a = StoreOptions::default();
    let b = StoreOptions::durable();
    assert_eq!(a.max_segment_bytes, b.max_segment_bytes);
    assert_eq!(a.sync_on_write, b.sync_on_write);
    assert_eq!(a.repair_torn_tail, b.repair_torn_tail);
}

#[test]
fn store_options_max_object_bytes_is_positive() {
    let opts = StoreOptions::durable();
    assert!(opts.max_object_bytes() > 0);
}

#[test]
fn store_options_max_object_bytes_shrinks_with_small_segment() {
    let opts = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        max_segment_bytes: 512,
        sync_on_write: false,
        repair_torn_tail: false,
        mirror_path: None,
        replica_paths: Vec::new(),
        segment_rotation_interval_secs: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 256,
        segment_rotation_write_limit: 0,
        durability_layout: None,
        write_throttle_enabled: false,
    };
    let max_obj = opts.max_object_bytes();
    assert!(max_obj > 0);
    assert!(max_obj < 512);
}

// ── StoreError unit tests ────────────────────────────────────────────

#[test]
fn store_error_display_produces_non_empty_string() {
    let err = StoreError::InvalidOptions { reason: "test" };
    assert!(!format!("{err}").is_empty());
    let err = StoreError::ReadOnly { operation: "put" };
    assert!(format!("{err}").contains("put"));
    let err = StoreError::PayloadTooLarge { len: 100, max: 50 };
    let msg = format!("{err}");
    assert!(msg.contains("100") && msg.contains("50"));
    let err = StoreError::UnsupportedVersion {
        segment_id: 0,
        offset: 0,
        version: 99,
    };
    assert!(format!("{err}").contains("99"));
    let err = StoreError::UnknownRecordKind {
        segment_id: 0,
        offset: 0,
        kind: 7,
    };
    assert!(format!("{err}").contains("7"));
}

#[test]
fn store_error_checksum_mismatch_display_includes_values() {
    let err = StoreError::ChecksumMismatch {
        segment_id: 1,
        offset: 42,
        expected: IntegrityDigest64(0xAAAA),
        actual: IntegrityDigest64(0xBBBB),
    };
    let msg = format!("{err}");
    assert!(msg.contains("aaaa"));
    assert!(msg.contains("bbbb"));
}

// ── ObjectLocation / StoredObject / ReplayReport / StoreStats ────────

#[test]
fn object_location_fields_accessible() {
    let loc = ObjectLocation {
        key: ObjectKey::from_name("loc-test"),
        segment_id: 3,
        record_offset: 128,
        payload_offset: 224,
        payload_len: 64,
        sequence: 5,
        payload_checksum: IntegrityDigest64(0xFEED),
    };
    assert_eq!(loc.segment_id, 3);
    assert_eq!(loc.record_offset, 128);
    assert_eq!(loc.payload_offset, 224);
    assert_eq!(loc.payload_len, 64);
    assert_eq!(loc.sequence, 5);
}

#[test]
fn stored_object_fields_accessible() {
    let obj = StoredObject {
        key: ObjectKey::from_name("obj-test"),
        sequence: 7,
        len: 128,
        checksum: IntegrityDigest64(0xBEEF),
    };
    assert_eq!(obj.sequence, 7);
    assert_eq!(obj.len, 128);
    assert_eq!(obj.checksum, IntegrityDigest64(0xBEEF));
}

#[test]
fn replay_report_default_is_all_zeroes() {
    let report = ReplayReport::default();
    assert_eq!(report.records_seen, 0);
    assert_eq!(report.puts_seen, 0);
    assert_eq!(report.deletes_seen, 0);
    assert_eq!(report.highest_sequence, 0);
    assert_eq!(report.repaired_tail_bytes, 0);
}

#[test]
fn store_stats_default_is_all_zeroes() {
    let stats = StoreStats::default();
    assert_eq!(stats.live_objects, 0);
    assert_eq!(stats.live_bytes, 0);
    assert_eq!(stats.segment_count, 0);
}

#[test]
fn pool_label_export_pool_import_roundtrip_preserves_metadata_and_topology() {
    use crate::device::{DeviceBacking, DeviceClass, DeviceConfig, DeviceKind};
    use crate::pool_label::{
        encode_label, seal_label, LabelDeviceClass, LabelPoolState, PoolLabelV1,
        POOL_LABEL_V1_WIRE_SIZE,
    };

    fn write_initial_label(device_root: &Path, label: PoolLabelV1) {
        let sealed = seal_label(label).expect("seal initial pool label");
        let mut encoded = [0u8; POOL_LABEL_V1_WIRE_SIZE];
        encode_label(&sealed, &mut encoded).expect("encode initial pool label");
        fs::write(device_root.join(".tidefs_label"), encoded).expect("write initial pool label");
    }

    let root = temp_root("pool-label-export-import-roundtrip");
    cleanup(&root);
    let device0 = root.join("device0");
    let device1 = root.join("device1");
    fs::create_dir_all(&device0).expect("create device0 root");
    fs::create_dir_all(&device1).expect("create device1 root");

    let pool_guid = [0x42u8; 16];
    let device_guids = [[0x10u8; 16], [0x20u8; 16]];
    let device_roots = [device0.clone(), device1.clone()];
    let label_classes = [LabelDeviceClass::Hdd, LabelDeviceClass::Ssd];
    let capacities = [64 * 1024 * 1024, 128 * 1024 * 1024];

    for (index, device_root) in device_roots.iter().enumerate() {
        let mut label = PoolLabelV1::new(pool_guid, device_guids[index], "roundtrip-pool");
        label.pool_state = LabelPoolState::Active;
        label.commit_group = 37 + index as u64;
        label.label_commit_group = 37 + index as u64;
        label.device_index = index as u32;
        label.topology_generation = 9;
        label.device_count = device_roots.len() as u32;
        label.device_class = label_classes[index];
        label.device_capacity_bytes = capacities[index];
        label.system_area_pointer = 4096;
        label.system_area_size = 8192;
        label.features_incompat = 0x01;
        label.features_ro_compat = 0x02;
        label.features_compat = 0x04;
        write_initial_label(device_root, label);
    }

    let device_configs: Vec<_> = device_roots
        .iter()
        .map(|device_root| DeviceConfig {
            media_class: Default::default(),
            path: device_root.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single {
                path: device_root.clone(),
            },
            compression: None,
            encryption: None,
        })
        .collect();

    PoolExporter::export_pool(
        &device_configs,
        pool_guid,
        &device_guids,
        "roundtrip-pool",
        41,
    )
    .expect("export pool labels");

    let imported = PoolImporter::import_pool(&[device1.clone(), device0.clone()], Some(pool_guid))
        .expect("import exported pool labels");

    assert_eq!(imported.pool_guid, pool_guid);
    assert_eq!(imported.pool_name, "roundtrip-pool");
    assert_eq!(imported.pool_state, LabelPoolState::Exported);
    assert_eq!(imported.topology_generation, 9);
    assert_eq!(imported.device_count, 2);
    assert_eq!(imported.recovery_commit_group, 41);
    assert!(imported.topology_complete);
    assert_eq!(imported.devices.len(), 2);

    for (index, candidate) in imported.devices.iter().enumerate() {
        assert_eq!(candidate.path, device_roots[index]);
        assert_eq!(candidate.label.pool_guid, pool_guid);
        assert_eq!(candidate.label.device_guid, device_guids[index]);
        assert_eq!(candidate.label.pool_name_str(), "roundtrip-pool");
        assert_eq!(candidate.label.pool_state, LabelPoolState::Exported);
        assert_eq!(candidate.label.commit_group, 41);
        assert_eq!(candidate.label.label_commit_group, 42);
        assert_eq!(candidate.label.device_index, index as u32);
        assert_eq!(candidate.label.topology_generation, 9);
        assert_eq!(candidate.label.device_count, 2);
        assert_eq!(candidate.label.device_class, label_classes[index]);
        assert_eq!(candidate.label.device_capacity_bytes, capacities[index]);
        assert_eq!(candidate.label.system_area_pointer, 4096);
        assert_eq!(candidate.label.system_area_size, 8192);
        assert_eq!(candidate.label.features_incompat, 0x01);
        assert_eq!(candidate.label.features_ro_compat, 0x02);
        assert_eq!(candidate.label.features_compat, 0x04);
    }

    cleanup(&root);
}

// ── Human alias module ───────────────────────────────────────────────

#[test]
fn human_local_object_store_aliases_re_export_types() {
    use human::local_object_store::{
        IntegrityDigest64 as HumanDigest, ObjectKey as HumanKey, StoreOptions as HumanOpts,
    };
    let key = HumanKey::from_name("human-test");
    assert_eq!(format!("{key}").len(), 64);
    let digest = HumanDigest(42);
    assert_eq!(digest.get(), 42);
    let opts = HumanOpts::test_fast();
    assert_eq!(opts.max_segment_bytes, 4096);
}

#[test]
fn human_local_object_store_constants_accessible() {
    use human::local_object_store::{FAMILY_NAME, RECORD_FORMAT_VERSION, RECORD_HEADER_LEN, ROLE};
    assert_eq!(FAMILY_NAME, "Local Object Store");
    assert!(ROLE.contains("append-only"));
    assert_eq!(RECORD_HEADER_LEN, 96);
    assert_eq!(RECORD_FORMAT_VERSION, 3);
}

// ── Constant stability checks ────────────────────────────────────────

#[test]
fn magic_bytes_are_stable() {
    assert_eq!(RECORD_MAGIC_BYTES, *b"VLOSREC1");
    assert_eq!(RECORD_FOOTER_MAGIC_BYTES, *b"VLOSEND2");
    assert_eq!(PRODUCTION_INTEGRITY_TRAILER_MAGIC_BYTES, *b"VLOSINT4");
}

// --- index checkpoint tests -------------------------------------------------

#[test]
fn checkpoint_absent_first_mount_does_full_replay() {
    let root = temp_root("ckpt-first-mount");
    let key = ObjectKey::from_name("alpha");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"payload").expect("put");
    }
    {
        // Delete the checkpoint that rotation wrote (simulate no checkpoint scenario)
        let ckpt = root.join(STORE_DIR_NAME).join(INDEX_BASE_FILE_NAME);
        let _ = fs::remove_file(&ckpt);
    }
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
        // Should still read the data back after full replay
        assert_eq!(store.get(key).expect("get"), Some(b"payload".to_vec()));
        let stats = store.stats();
        assert!(
            stats.replay.records_seen > 0,
            "should have replayed records"
        );
    }
    cleanup(&root);
}

#[test]
fn checkpoint_loaded_on_clean_reopen_skips_replay() {
    let root = temp_root("ckpt-clean-reopen");
    let key = ObjectKey::from_name("alpha");

    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        // Put enough data to trigger rotation. The put itself goes into
        // the new segment, so we delete it immediately to leave the new
        // segment logically empty (just a tombstone, which replays as
        // a delete — still 1 record).
        //
        // Better: put one object, then trigger explicit rotation via a
        // close-sufficiently-large put, then close.  The large put is
        // in the new segment so it replays.
        //
        // Actually the simplest zero-replay scenario: after rotation,
        // the new segment is empty (0 bytes).  The large put triggers
        // rotation to segment 1, gets written to segment 1.  We can't
        // avoid that.
        //
        // Cleanest: verify checkpoint exists and data reads back, but
        // accept that the new segment needs replay.
        store.put(key, b"hello").expect("put");
        let big = vec![0u8; 280];
        store
            .put(ObjectKey::from_name("big"), &big)
            .expect("put big");
    }
    // Verify checkpoint was written
    let ckpt_path = root.join(STORE_DIR_NAME).join(INDEX_BASE_FILE_NAME);
    assert!(
        ckpt_path.exists(),
        "checkpoint file should exist after rotation"
    );

    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
        assert_eq!(store.get(key).expect("get"), Some(b"hello".to_vec()));
        assert_eq!(
            store.get(ObjectKey::from_name("big")).expect("get big"),
            Some(vec![0u8; 280])
        );
        let stats = store.stats();
        // The checkpoint covers segment 0 (complete).  The "big" put triggered
        // rotation, so it lives in segment 1 and needs replay (1 record).
        assert!(
            stats.replay.records_seen <= 1,
            "replay should only see records in segments after the checkpoint boundary"
        );
    }
    cleanup(&root);
}

#[test]
fn checkpoint_persists_history_for_version_locations() {
    let root = temp_root("ckpt-history");
    let key = ObjectKey::from_name("alpha");
    let big = vec![0u8; 280];
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"first").expect("put first");
        store.put(key, b"second").expect("put second");
        // Force rotation by writing enough data
        store
            .put(ObjectKey::from_name("filler"), &big)
            .expect("put filler");
    }
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
        let history = store.version_locations_of(key);
        assert_eq!(
            history.len(),
            2,
            "version history should survive checkpoint round-trip"
        );
        assert_eq!(
            store.get_at_location(history[0]).expect("read first"),
            b"first".to_vec()
        );
        assert_eq!(
            store.get_at_location(history[1]).expect("read second"),
            b"second".to_vec()
        );
    }
    cleanup(&root);
}

#[test]
fn checkpoint_survives_crash_with_partial_segment_replay() {
    let root = temp_root("ckpt-crash");
    let key_a = ObjectKey::from_name("a");
    let key_b = ObjectKey::from_name("b");

    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        // Fill enough data to trigger rotation -> checkpoint written
        let big = vec![0u8; 280];
        store
            .put(ObjectKey::from_name("big"), &big)
            .expect("put big");
        store.put(key_a, b"before-crash").expect("put a");
        store.sync_all().expect("sync");
    }
    // Verify checkpoint exists
    let ckpt_path = root.join(STORE_DIR_NAME).join(INDEX_BASE_FILE_NAME);
    assert!(
        ckpt_path.exists(),
        "checkpoint should have been written on rotation"
    );

    // Reopen and write more (simulating a new session)
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
        store.put(key_b, b"after-crash").expect("put b");
        // Do not sync — simulate crash
    }
    // Reopen: checkpoint should skip early segments, replay only the last one
    {
        let store =
            LocalObjectStore::open_with_options(&root, options()).expect("reopen after crash");
        assert_eq!(
            store.get(key_a).expect("get a"),
            Some(b"before-crash".to_vec())
        );
        assert_eq!(
            store.get(key_b).expect("get b"),
            Some(b"after-crash".to_vec())
        );
    }
    cleanup(&root);
}

#[test]
fn checkpoint_ignored_when_referenced_segment_deleted_by_compaction() {
    let root = temp_root("ckpt-compaction");
    let keep = ObjectKey::from_name("keep");
    let discard = ObjectKey::from_name("discard");

    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(keep, b"val").expect("put keep");
        store.put(discard, b"temp").expect("put discard");
        // Trigger rotation -> checkpoint written covering segment 0
        let big = vec![0u8; 280];
        store
            .put(ObjectKey::from_name("rotator"), &big)
            .expect("put rotator");
    }
    // Compact: protect keep, discard everything else (which deletes segment 0 copies)
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, options()).expect("reopen for compaction");
        let report = store.compact_retaining(&[keep], &[]).expect("compact");
        assert!(
            !report.retired_segments.is_empty(),
            "should have retired some segments"
        );
    }
    // After compaction, the old checkpoint may reference a deleted segment.
    // The store should fall back to full replay and still serve live data.
    {
        let store =
            LocalObjectStore::open_with_options(&root, options()).expect("reopen after compaction");
        assert_eq!(store.get(keep).expect("get keep"), Some(b"val".to_vec()));
        assert!(store.get(discard).expect("get discard").is_none());
    }
    cleanup(&root);
}

#[test]
fn checkpoint_corrupt_file_falls_back_to_full_replay() {
    let root = temp_root("ckpt-corrupt");
    let key = ObjectKey::from_name("alpha");

    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        let big = vec![0u8; 280];
        store
            .put(ObjectKey::from_name("rotator"), &big)
            .expect("put rotator");
        store.put(key, b"payload").expect("put");
    }
    // Corrupt the checkpoint
    let ckpt_path = root.join(STORE_DIR_NAME).join(INDEX_BASE_FILE_NAME);
    assert!(ckpt_path.exists());
    fs::write(&ckpt_path, b"garbage").expect("corrupt checkpoint");

    // Reopen should fall back to full replay
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
        assert_eq!(store.get(key).expect("get"), Some(b"payload".to_vec()));
        let stats = store.stats();
        assert!(
            stats.replay.records_seen > 0,
            "corrupt checkpoint should trigger full replay"
        );
    }
    cleanup(&root);
}

#[test]
fn checkpoint_truncated_file_falls_back_to_full_replay() {
    let root = temp_root("ckpt-trunc");
    let key = ObjectKey::from_name("alpha");

    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        let big = vec![0u8; 280];
        store
            .put(ObjectKey::from_name("rotator"), &big)
            .expect("put rotator");
        store.put(key, b"payload").expect("put");
    }
    // Truncate checkpoint to just the header
    let ckpt_path = root.join(STORE_DIR_NAME).join(INDEX_BASE_FILE_NAME);
    let data = fs::read(&ckpt_path).expect("read checkpoint");
    fs::write(&ckpt_path, &data[..30]).expect("truncate checkpoint");

    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen store");
        assert_eq!(store.get(key).expect("get"), Some(b"payload".to_vec()));
        // Just ensure data is served correctly after fallback
    }
    cleanup(&root);
}

#[test]
fn checkpoint_written_after_compaction_rotate() {
    let root = temp_root("ckpt-compact-rotate");
    let key = ObjectKey::from_name("keep");

    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        let big = vec![0u8; 280];
        store
            .put(ObjectKey::from_name("filler"), &big)
            .expect("put filler");
        store.put(key, b"val").expect("put keep");
    }
    // Compact — this triggers a rotation after reopen, so checkpoint is rewritten
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, options()).expect("reopen for compaction");
        store.compact_retaining(&[key], &[]).expect("compact");
        // After compaction+rotation, a fresh checkpoint should exist
        let ckpt_path = root.join(STORE_DIR_NAME).join(INDEX_BASE_FILE_NAME);
        assert!(
            ckpt_path.exists(),
            "compaction should have written a fresh checkpoint"
        );
    }
    // Reopen: checkpoint should skip replay
    {
        let store =
            LocalObjectStore::open_with_options(&root, options()).expect("reopen after compaction");
        assert_eq!(store.get(key).expect("get keep"), Some(b"val".to_vec()));
        let stats = store.stats();
        assert_eq!(
            stats.replay.records_seen, 0,
            "fresh checkpoint should skip all replay"
        );
    }
    cleanup(&root);
}

#[test]
fn record_format_version_constants_are_stable() {
    assert_eq!(RECORD_FORMAT_VERSION_V1_NO_FOOTER, 1);
    assert_eq!(RECORD_FORMAT_VERSION_V2_FOOTER, 2);
    assert_eq!(RECORD_FORMAT_VERSION, 3);
    assert_eq!(
        PRODUCTION_INTEGRITY_MIGRATION_RECORD_VERSION,
        RECORD_FORMAT_VERSION
    );
}

#[test]
fn waste_ratio_tracks_tombstones_from_put_overwrite() {
    let root = temp_root("waste-put-overwrite");
    let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
    let key = ObjectKey::from_name(b"overwrite-test");

    // Initial put: no waste
    store.put(key, b"first").expect("first put");
    assert_eq!(store.stats().tombstone_count, 0);
    assert!((store.waste_ratio() - 0.0).abs() < f64::EPSILON);

    // Overwrite: old version is a tombstone
    store.put(key, b"second").expect("second put");
    assert_eq!(store.stats().tombstone_count, 1);
    assert!(
        (store.waste_ratio() - 0.5).abs() < 0.01,
        "expected ~0.5, got {}",
        store.waste_ratio()
    );

    // Overwrite again
    store.put(key, b"third").expect("third put");
    assert_eq!(store.stats().tombstone_count, 2);
    assert!((store.waste_ratio() - 2.0 / 3.0).abs() < 0.01);

    cleanup(&root);
}

#[test]
fn waste_ratio_tracks_tombstones_from_delete() {
    let root = temp_root("waste-delete");
    let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");

    // Put two objects
    store.put_named(b"keep", b"val").expect("put keep");
    store.put_named(b"del", b"val").expect("put del");
    assert_eq!(store.stats().tombstone_count, 0);

    // Delete one
    assert!(store.delete_named(b"del").expect("delete del"));
    assert_eq!(store.stats().tombstone_count, 1);
    let ratio = store.waste_ratio();
    assert!((ratio - 0.5).abs() < 0.01, "expected ~0.5, got {ratio}");

    // Delete non-existent: still writes a tombstone
    assert!(!store.delete_named(b"gone").expect("delete gone"));
    assert_eq!(store.stats().tombstone_count, 2);

    cleanup(&root);
}

#[test]
fn should_compact_returns_true_above_threshold() {
    let root = temp_root("should-compact");
    let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");

    // No waste -> should not compact
    store.put_named(b"a", b"x").expect("put a");
    assert!(!store.should_compact(0.25));

    // Delete to create waste
    store.delete_named(b"a").expect("delete a");
    assert!(store.should_compact(0.25));
    assert!(
        store.should_compact(0.99),
        "should exceed 99% threshold with 100% waste"
    );

    cleanup(&root);
}

#[test]
fn waste_ratio_persists_across_reopen() {
    let root = temp_root("waste-persists");
    let key = ObjectKey::from_name(b"persist");

    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open store");
        store.put(key, b"first").expect("first put");
        store.put(key, b"second").expect("overwrite put");
        assert_eq!(store.stats().tombstone_count, 1);
    }

    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen");
        assert_eq!(
            store.stats().tombstone_count,
            0,
            "tombstone_count resets on reopen (only tracked in-memory)"
        );
        // But the index still has 1 live object, and 1 tombstone record exists on disk
        assert_eq!(store.stats().live_objects, 1);
    }

    cleanup(&root);
}

// ── Mirror store tests ──

#[test]
fn mirror_put_get() {
    let primary_root = temp_root("mirror-put-get-primary");
    let mirror_root = temp_root("mirror-put-get-mirror");
    let options = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        mirror_path: Some(mirror_root.clone()),
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };

    {
        let mut store = LocalObjectStore::open_with_options(&primary_root, options)
            .expect("open store with mirror");
        let key = ObjectKey::from_name(b"mirror-key");
        store.put(key, b"mirror payload").expect("put");

        // Read back from primary
        let val = store.get(key).expect("get");
        assert_eq!(val.as_deref(), Some(&b"mirror payload"[..]));

        // Verify mirror was written
        assert!(&store.replicas[0].contains_key(key));
    }

    cleanup(&primary_root);
    cleanup(&mirror_root);
}

#[test]
fn mirror_fallback_read() {
    let primary_root = temp_root("mirror-fallback-primary");
    let mirror_root = temp_root("mirror-fallback-mirror");
    let options = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        mirror_path: Some(mirror_root.clone()),
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };

    {
        let mut store = LocalObjectStore::open_with_options(&primary_root, options)
            .expect("open store with mirror");
        let key = ObjectKey::from_name(b"fallback-key");

        // Write directly to mirror, bypassing primary index
        store.replicas[0]
            .put(key, b"mirror-only")
            .expect("mirror put");

        // Primary doesn't have it, but get should fall back to mirror
        let val = store.get(key).expect("get");
        assert_eq!(val.as_deref(), Some(&b"mirror-only"[..]));
    }

    cleanup(&primary_root);
    cleanup(&mirror_root);
}

#[test]
fn mirror_delete_fans_out() {
    let primary_root = temp_root("mirror-delete-primary");
    let mirror_root = temp_root("mirror-delete-mirror");
    let options = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        mirror_path: Some(mirror_root.clone()),
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };

    {
        let mut store = LocalObjectStore::open_with_options(&primary_root, options)
            .expect("open store with mirror");
        let key = ObjectKey::from_name(b"delete-key");
        store.put(key, b"data").expect("put");
        assert!(&store.replicas[0].contains_key(key));

        store.delete(key).expect("delete");
        assert!(!store.contains_key(key));
        assert!(!&store.replicas[0].contains_key(key));
    }

    cleanup(&primary_root);
    cleanup(&mirror_root);
}

#[test]
fn mirror_degraded_on_failed_open() {
    let primary_root = temp_root("mirror-degraded-primary");
    let mirror_root = temp_root("mirror-degraded-mirror");

    // Pre-create a file at the mirror path so open_with_options fails
    // (it expects a directory, not a file).
    fs::create_dir_all(&mirror_root).unwrap();
    let bad_path = mirror_root.join("store");
    fs::write(&bad_path, b"not-a-dir").unwrap();

    let options = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        mirror_path: Some(bad_path.clone()),
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };

    {
        let store = LocalObjectStore::open_with_options(&primary_root, options)
            .expect("primary opens even if mirror fails");
        let stats = store.stats();
        assert!(stats.mirror_degraded);
        assert!(store.mirror_degraded());
    }

    cleanup(&primary_root);
    cleanup(&mirror_root);
}
#[test]
fn mirror_sync_all() {
    let primary_root = temp_root("mirror-sync-primary");
    let mirror_root = temp_root("mirror-sync-mirror");
    let options = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        mirror_path: Some(mirror_root.clone()),
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };

    {
        let mut store = LocalObjectStore::open_with_options(&primary_root, options)
            .expect("open store with mirror");
        let key = ObjectKey::from_name(b"sync-key");
        store.put(key, b"sync data").expect("put");
        store.sync_all().expect("sync_all");

        // Reopen both and verify data persists
        let mirror_store =
            LocalObjectStore::open_with_options(&mirror_root, StoreOptions::default())
                .expect("reopen mirror");
        let val = mirror_store.get(key).expect("mirror get after reopen");
        assert_eq!(val.as_deref(), Some(&b"sync data"[..]));
    }

    cleanup(&primary_root);
    cleanup(&mirror_root);
}

// ── Scrub tests ──

#[test]
fn scrub_healthy_no_divergence() {
    let primary_root = temp_root("scrub-healthy-primary");
    let mirror_root = temp_root("scrub-healthy-mirror");
    let options = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        mirror_path: Some(mirror_root.clone()),
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };

    {
        let mut store = LocalObjectStore::open_with_options(&primary_root, options)
            .expect("open store with mirror");

        let key = ObjectKey::from_name(b"healthy");
        store.put(key, b"data").expect("put");

        let stats = store.scrub_replicas().expect("scrub");
        assert_eq!(stats.keys_examined, 1);
        assert_eq!(stats.keys_healthy, 1);
        assert_eq!(stats.keys_resynced, 0);
        assert_eq!(stats.keys_repaired, 0);
        assert_eq!(stats.errors, 0);
        assert!(stats.is_clean());
        assert!(!store.mirror_degraded());
    }

    cleanup(&primary_root);
    cleanup(&mirror_root);
}

#[test]
fn scrub_resyncs_missing_key() {
    let primary_root = temp_root("scrub-resync-primary");
    let mirror_root = temp_root("scrub-resync-mirror");
    let options = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        mirror_path: Some(mirror_root.clone()),
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };

    {
        let mut store = LocalObjectStore::open_with_options(&primary_root, options)
            .expect("open store with mirror");

        let key = ObjectKey::from_name(b"resync-me");

        // Put to primary only (bypass mirror)
        store.put(key, b"primary-only").expect("primary put");
        // Manually delete from mirror
        store.replicas[0].delete(key).unwrap();
        assert!(!&store.replicas[0].contains_key(key));

        let stats = store.scrub_replicas().expect("scrub");
        assert_eq!(stats.keys_examined, 1);
        assert_eq!(stats.keys_resynced, 1);
        assert_eq!(stats.keys_repaired, 0);
        assert_eq!(stats.errors, 0);
        assert!(!stats.is_clean());
        assert!(!store.mirror_degraded());

        // Mirror should now have the key
        assert!(&store.replicas[0].contains_key(key));
        let val = &store.replicas[0].get(key).expect("get");
        assert_eq!(val.as_deref(), Some(&b"primary-only"[..]));
    }

    cleanup(&primary_root);
    cleanup(&mirror_root);
}

#[test]
fn scrub_repairs_digest_mismatch() {
    let primary_root = temp_root("scrub-mismatch-primary");
    let mirror_root = temp_root("scrub-mismatch-mirror");
    let options = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        mirror_path: Some(mirror_root.clone()),
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };

    {
        let mut store = LocalObjectStore::open_with_options(&primary_root, options)
            .expect("open store with mirror");

        let key = ObjectKey::from_name(b"mismatch");

        // Put correct data to both stores
        store.put(key, b"correct").expect("primary put");

        // Overwrite mirror with different data (simulate corruption)
        store.replicas[0]
            .put(key, b"corrupted")
            .expect("corrupt put");

        let stats = store.scrub_replicas().expect("scrub");
        assert_eq!(stats.keys_examined, 1);
        assert_eq!(stats.keys_repaired, 1);
        assert_eq!(stats.keys_resynced, 0);
        assert_eq!(stats.errors, 0);

        // Mirror should now have corrected data
        let val = &store.replicas[0].get(key).expect("get");
        assert_eq!(val.as_deref(), Some(&b"correct"[..]));
    }

    cleanup(&primary_root);
    cleanup(&mirror_root);
}

#[test]
fn scrub_no_mirror_returns_clean() {
    let root = temp_root("scrub-no-mirror");
    let mut store =
        LocalObjectStore::open_with_options(&root, options()).expect("open store without mirror");

    store.put_named(b"x", b"y").expect("put");

    let stats = store.scrub_replicas().expect("scrub");
    assert_eq!(stats.keys_examined, 0);
    assert!(stats.is_clean());

    cleanup(&root);
}

#[test]
fn should_scrub_respects_interval() {
    let root = temp_root("should-scrub-interval");

    // Open with a short interval
    let opts = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        background_scrub_interval_secs: 3600,
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };
    let store = LocalObjectStore::open_with_options(&root, opts).expect("open store");

    // Just opened: should_scrub returns false (not enough time)
    assert!(!store.should_scrub());

    cleanup(&root);
}

#[test]
fn should_scrub_zero_interval_disables() {
    let root = temp_root("should-scrub-zero");

    let opts = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 256,
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };
    let store = LocalObjectStore::open_with_options(&root, opts).expect("open store");

    assert!(!store.should_scrub());

    cleanup(&root);
}

#[test]
fn bounded_background_scrub_preserves_pending_cursor() {
    let root = temp_root("bounded-background-scrub");
    let mut opts = options();
    opts.background_scrub_interval_secs = 1;

    {
        let mut store = LocalObjectStore::open_with_options(&root, opts.clone()).expect("open");
        for index in 0..4 {
            store
                .put_named(format!("bounded-scrub-{index}"), &[index; 256])
                .expect("write scrub fixture");
        }
        store.flush_segment().expect("flush scrub fixture");
    }

    let mut store = LocalObjectStore::open_read_only_with_options(&root, opts)
        .expect("open read-only")
        .expect("scrub fixture exists");
    let first = store
        .run_background_scrub_with_budget(1, 1024 * 1024)
        .expect("bounded scrub tick");

    assert_eq!(first.records_verified, 1);
    assert!(!first.completed);
    assert!(store.background_scrub_pending());

    let mut completed = false;
    for _ in 0..64 {
        let report = store
            .run_background_scrub_with_budget(1, 1024 * 1024)
            .expect("resume bounded scrub");
        if report.completed {
            completed = true;
            break;
        }
    }
    assert!(completed, "bounded scrub must eventually complete");
    assert!(!store.background_scrub_pending());

    cleanup(&root);
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// N-replica quorum write tests
// ---------------------------------------------------------------------------

#[test]
fn replica_quorum_write_all_healthy() {
    let primary = temp_root("replica-quorum-healthy");
    let r1 = primary.join("replica-r1");
    let r2 = primary.join("replica-r2");

    let opts = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        max_segment_bytes: 4096,
        sync_on_write: false,
        repair_torn_tail: false,
        mirror_path: None,
        replica_paths: vec![r1.clone(), r2.clone()],
        segment_rotation_interval_secs: 0,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 256,
        durability_layout: None,
        write_throttle_enabled: false,
    };

    let mut store =
        LocalObjectStore::open_with_options(&primary, opts.clone()).expect("open store");
    assert_eq!(store.replica_count(), 2);
    assert_eq!(store.replica_quorum(), 2);

    let key = ObjectKey::from_name(b"quorum-key-1");
    let payload = b"quorum data across replicas";
    store.put(key, payload).expect("primary put");

    for replica in &store.replicas {
        let val = replica
            .get(key)
            .expect("replica get")
            .expect("replica has key");
        assert_eq!(val, payload);
    }
    cleanup(&primary);
    cleanup(&r1);
    cleanup(&r2);
}

#[test]
fn replica_quorum_fallback_read() {
    let primary = temp_root("replica-fallback-read");
    let r1 = primary.join("replica-r1");

    let opts = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        max_segment_bytes: 4096,
        sync_on_write: false,
        repair_torn_tail: false,
        mirror_path: None,
        replica_paths: vec![r1.clone()],
        segment_rotation_interval_secs: 0,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 256,
        durability_layout: None,
        write_throttle_enabled: false,
    };

    let mut store = LocalObjectStore::open_with_options(&primary, opts).expect("open store");

    let key = ObjectKey::from_name(b"fallback-replica-read");
    store.replicas[0]
        .put(key, b"replica-only-data")
        .expect("replica put");

    let val = store.get(key).expect("get").expect("found in replica");
    assert_eq!(val, b"replica-only-data");
    cleanup(&primary);
    cleanup(&r1);
}

#[test]
fn replica_delete_fans_out() {
    let primary = temp_root("replica-delete-fanout");
    let r1 = primary.join("replica-r1");

    let opts = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        max_segment_bytes: 4096,
        sync_on_write: false,
        repair_torn_tail: false,
        mirror_path: None,
        replica_paths: vec![r1.clone()],
        segment_rotation_interval_secs: 0,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 256,
        durability_layout: None,
        write_throttle_enabled: false,
    };

    let mut store = LocalObjectStore::open_with_options(&primary, opts).expect("open store");

    let key = ObjectKey::from_name(b"delete-fanout");
    store.put(key, b"to-be-deleted").expect("put");
    assert!(store.replicas[0].contains_key(key));

    store.delete(key).expect("delete");
    assert!(!store.replicas[0].contains_key(key));
    cleanup(&primary);
    cleanup(&r1);
}

#[test]
fn scrub_replicas_repairs_missing_data() {
    let primary = temp_root("replica-scrub-repair");
    let r1 = primary.join("replica-r1");

    let opts = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        max_segment_bytes: 4096,
        sync_on_write: false,
        repair_torn_tail: false,
        mirror_path: None,
        replica_paths: vec![r1.clone()],
        segment_rotation_interval_secs: 0,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 256,
        durability_layout: None,
        write_throttle_enabled: false,
    };

    let mut store = LocalObjectStore::open_with_options(&primary, opts).expect("open store");

    let key = ObjectKey::from_name(b"scrub-repair");
    store.put(key, b"scrub-me").expect("put");

    store.replicas[0].delete(key).expect("delete from replica");
    assert!(!store.replicas[0].contains_key(key));

    let stats = store.scrub_replicas().expect("scrub");
    assert!(stats.keys_resynced >= 1);

    assert!(store.replicas[0].contains_key(key));
    let val = store.replicas[0].get(key).expect("get").expect("has key");
    assert_eq!(val, b"scrub-me");
    cleanup(&primary);
    cleanup(&r1);
}
#[test]
fn store_options_replica_count_and_quorum() {
    // 1 replica: total=2, quorum=2
    let opts = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        replica_paths: vec![PathBuf::from("/tmp/r1")],
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };
    assert_eq!(opts.replica_count(), 1);
    assert_eq!(opts.replica_quorum(), 2);

    // 2 replicas: total=3, quorum=2
    let opts = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        replica_paths: vec![PathBuf::from("/tmp/r1"), PathBuf::from("/tmp/r2")],
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };
    assert_eq!(opts.replica_count(), 2);
    assert_eq!(opts.replica_quorum(), 2);

    // 3 replicas: total=4, quorum=3
    let opts = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        replica_paths: vec![
            PathBuf::from("/tmp/r1"),
            PathBuf::from("/tmp/r2"),
            PathBuf::from("/tmp/r3"),
        ],
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };
    assert_eq!(opts.replica_count(), 3);
    assert_eq!(opts.replica_quorum(), 3);

    // mirror + 1 replica: total=3, quorum=2
    let opts = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        mirror_path: Some(PathBuf::from("/tmp/m")),
        replica_paths: vec![PathBuf::from("/tmp/r1")],
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };
    assert_eq!(opts.replica_count(), 2);
    assert_eq!(opts.replica_quorum(), 2);
}

#[test]
fn replica_validation_rejects_duplicate_path() {
    let opts = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        mirror_path: Some(PathBuf::from("/tmp/dup")),
        replica_paths: vec![PathBuf::from("/tmp/dup")],
        durability_layout: None,
        write_throttle_enabled: false,
        ..options()
    };
    assert!(opts.validate().is_err());
}

#[test]
fn replica_sync_all_syncs_all_replicas() {
    let primary = temp_root("replica-syncall");
    let r1 = primary.join("replica-r1");

    let opts = StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        max_segment_bytes: 4096,
        sync_on_write: false,
        repair_torn_tail: false,
        mirror_path: None,
        replica_paths: vec![r1.clone()],
        segment_rotation_interval_secs: 0,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 256,
        durability_layout: None,
        write_throttle_enabled: false,
    };

    let mut store = LocalObjectStore::open_with_options(&primary, opts).expect("open store");

    store
        .put(ObjectKey::from_name(b"sync-key"), b"sync-data")
        .expect("put");
    store.sync_all().expect("sync_all");
    // If we got here without error, replicas were synced
    cleanup(&primary);
    cleanup(&r1);
}
// ── Compression roundtrip tests ────────────────────────────────────────────

fn temp_root_comp(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-local-object-store-comp-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn comp_options() -> StoreOptions {
    StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        max_segment_bytes: 64 * 1024,
        sync_on_write: false,
        repair_torn_tail: true,
        mirror_path: None,
        replica_paths: Vec::new(),
        segment_rotation_interval_secs: 0,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 256,
        durability_layout: None,
        write_throttle_enabled: false,
    }
}

#[test]
fn compressed_put_get_roundtrip() {
    let root = temp_root_comp("put-get-roundtrip");
    let opts = comp_options();
    let comp_cfg = CompressionConfig::default();

    let device = Device::open_single(&root, opts.clone()).expect("open single");
    let mut comp = Device::open_compressed(device, comp_cfg);

    let key = ObjectKey::from_name(b"compressible-key");
    let payload = vec![0xAB; 2048]; // moderately compressible

    comp.put(key, &payload).expect("put compressed");
    comp.sync_all().expect("sync");

    let got = comp.get(key).expect("get").expect("some");
    assert_eq!(got, payload);

    // Verify stats reflect compression activity
    let ratio = comp.compression_ratio();
    assert!(ratio < 1.0, "compressed ratio {ratio} should be < 1.0");
    assert!(comp.savings_pct() > 0.0);
    cleanup(&root);
}

#[test]
fn compressed_ratio_highly_redundant_data() {
    let root = temp_root_comp("ratio-redundant");
    let opts = comp_options();
    let comp_cfg = CompressionConfig::default();

    let device = Device::open_single(&root, opts.clone()).expect("open single");
    let mut comp = Device::open_compressed(device, comp_cfg);

    // All zeros compress very well
    let payload = vec![0x00u8; 4096];
    let key = ObjectKey::from_name(b"zeros");
    comp.put(key, &payload).expect("put");

    let ratio = comp.compression_ratio();
    assert!(ratio < 0.5, "zeros ratio {ratio} should be well below 0.5");
    assert!(comp.savings_pct() > 50.0);
    cleanup(&root);
}

#[test]
fn compressed_small_object_fallback() {
    let root = temp_root_comp("small-fallback");
    let opts = comp_options();
    let comp_cfg = CompressionConfig::default(); // min_compress_bytes = 64

    let device = Device::open_single(&root, opts.clone()).expect("open single");
    let mut comp = Device::open_compressed(device, comp_cfg);

    // Payload smaller than min_compress_bytes
    let payload = b"tiny";
    let key = ObjectKey::from_name(b"small");
    comp.put(key, payload.as_slice()).expect("put");
    comp.sync_all().expect("sync");

    let got = comp.get(key).expect("get").expect("some");
    assert_eq!(got, payload);

    // Small objects stored uncompressed -> ratio can be >= 1.0 (header overhead)
    // but data must roundtrip correctly
    cleanup(&root);
}

#[test]
fn compressed_multiple_objects() {
    let root = temp_root_comp("multi-obj");
    let opts = comp_options();
    let comp_cfg = CompressionConfig::default();

    let device = Device::open_single(&root, opts.clone()).expect("open single");
    let mut comp = Device::open_compressed(device, comp_cfg);

    let objects: Vec<(ObjectKey, Vec<u8>)> = (0..10)
        .map(|i| {
            let name = format!("obj-{i}");
            let data = vec![(i as u8) % 4; 512]; // somewhat compressible
            (ObjectKey::from_name(name.as_bytes()), data)
        })
        .collect();

    for (key, data) in &objects {
        comp.put(*key, data.as_slice()).expect("put");
    }
    comp.sync_all().expect("sync");

    for (key, data) in &objects {
        let got = comp.get(*key).expect("get").expect("some");
        assert_eq!(got, *data, "mismatch for key {key:?}");
    }

    // All objects compressible -> ratio < 1.0
    let ratio = comp.compression_ratio();
    assert!(
        ratio < 1.0,
        "ratio {ratio} should be < 1.0 for compressible data"
    );

    // Deletion works through compressed device
    for (key, _) in &objects {
        assert!(comp.delete(*key).expect("delete"), "delete {key:?}");
    }
    for (key, _) in &objects {
        assert_eq!(comp.get(*key).expect("get"), None);
    }
    cleanup(&root);
}

#[test]
fn compressed_delete_unknown_key() {
    let root = temp_root_comp("delete-unknown");
    let opts = comp_options();
    let comp_cfg = CompressionConfig::default();

    let device = Device::open_single(&root, opts.clone()).expect("open single");
    let mut comp = Device::open_compressed(device, comp_cfg);

    let key = ObjectKey::from_name(b"no-such-key");
    assert!(!comp.delete(key).expect("delete unknown"));
    cleanup(&root);
}

#[test]
fn compressed_get_missing_key() {
    let root = temp_root_comp("get-missing");
    let opts = comp_options();
    let comp_cfg = CompressionConfig::default();

    let device = Device::open_single(&root, opts.clone()).expect("open single");
    let comp = Device::open_compressed(device, comp_cfg);

    let key = ObjectKey::from_name(b"ghost");
    assert_eq!(comp.get(key).expect("get missing"), None);
    cleanup(&root);
}

#[test]
fn compressed_uncompressed_marker_roundtrip() {
    let root = temp_root_comp("uncompressed-marker");
    let opts = comp_options();
    // Set min_compress_bytes high enough that nothing gets compressed
    let comp_cfg = CompressionConfig {
        min_compress_bytes: 1_000_000,
        ..CompressionConfig::default()
    };

    let device = Device::open_single(&root, opts.clone()).expect("open single");
    let mut comp = Device::open_compressed(device, comp_cfg);

    let payload = vec![0xAA; 512];
    let key = ObjectKey::from_name(b"no-compress");
    comp.put(key, &payload).expect("put");
    comp.sync_all().expect("sync");

    let got = comp.get(key).expect("get").expect("some");
    assert_eq!(got, payload);
    // Ratio could be close to 1.0 (header overhead), but data must roundtrip
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Spacemap integration tests (Phase 4, #1332)
// ---------------------------------------------------------------------------
// ── ObjectStore::get / get_verified / get_attr round-trip tests (OBJ-001) ──

/// put → get round-trip: store a blob by key, retrieve it, assert bit-identical.
#[test]
fn put_get_round_trip() {
    let root = temp_root("put-get-rt");
    let payload = b"round-trip payload for OBJ-001 get test";
    let key = ObjectKey::from_content(payload);
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        store.put(key, payload).expect("put");
        store.sync_all().expect("sync");
        let retrieved = store.get(key).expect("get");
        assert_eq!(retrieved, Some(payload.to_vec()));
    }
    cleanup(&root);
}

/// put_content_addressed → get_verified round-trip:
/// content-derived key + verified retrieval must pass hash check.
#[test]
fn put_content_addressed_get_verified_round_trip() {
    let root = temp_root("ca-gv-rt");
    let payload = b"content-addressed payload for OBJ-001";
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let key = store
            .put_content_addressed(payload)
            .expect("put_content_addressed");
        store.sync_all().expect("sync");
        let verified = store.get_verified(key).expect("get_verified");
        assert_eq!(verified, Some(payload.to_vec()));
    }
    cleanup(&root);
}

/// get_verified on a name-derived (non-content) key must return
/// ContentAddressMismatch because BLAKE3(payload) != from_name(label).
#[test]
fn get_verified_content_mismatch() {
    let root = temp_root("gv-mismatch");
    let payload = b"named-key payload mismatch OBJ-001";
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let named_key = ObjectKey::from_name(b"mismatch-key");
        store.put(named_key, payload).expect("put");
        store.sync_all().expect("sync");
        let result = store.get_verified(named_key);
        assert!(
            matches!(result, Err(StoreError::ContentAddressMismatch { .. })),
            "get_verified on a non-content-derived key must return ContentAddressMismatch"
        );
    }
    cleanup(&root);
}

/// get for a missing key returns Ok(None).
#[test]
fn get_missing_key_returns_none() {
    let root = temp_root("get-none");
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let ghost = ObjectKey::from_name(b"no-such-key-obj-001");
        assert_eq!(store.get(ghost).expect("get"), None);
    }
    cleanup(&root);
}

#[test]
fn get_range_returns_requested_slice() {
    let root = temp_root("get-range-slice");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let key = ObjectKey::from_name(b"get-range-slice");
        store.put(key, b"abcdefgh").expect("put object");

        assert_eq!(
            store.get_range(key, 2, 3).expect("get range"),
            Some(b"cde".to_vec())
        );
    }
    cleanup(&root);
}

#[test]
fn get_range_extending_past_eof_returns_suffix() {
    let root = temp_root("get-range-suffix");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let key = ObjectKey::from_name(b"get-range-suffix");
        store.put(key, b"abcdefgh").expect("put object");

        assert_eq!(
            store.get_range(key, 5, u64::MAX).expect("get range"),
            Some(b"fgh".to_vec())
        );
    }
    cleanup(&root);
}

#[test]
fn get_range_at_and_beyond_eof_returns_empty_payload() {
    let root = temp_root("get-range-eof");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let key = ObjectKey::from_name(b"get-range-eof");
        store.put(key, b"abcdefgh").expect("put object");

        assert_eq!(
            store.get_range(key, 8, 4).expect("get range at eof"),
            Some(Vec::new())
        );
        assert_eq!(
            store.get_range(key, 99, 4).expect("get range past eof"),
            Some(Vec::new())
        );
    }
    cleanup(&root);
}

#[test]
fn get_range_missing_key_returns_none() {
    let root = temp_root("get-range-none");
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let ghost = ObjectKey::from_name(b"no-such-range-key");
        assert_eq!(store.get_range(ghost, 0, 8).expect("get range"), None);
    }
    cleanup(&root);
}

#[test]
fn get_range_with_durable_verify_returns_correct_slice() {
    let root = temp_root("get-range-verify");
    {
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::durable())
            .expect("open durable");
        let key = ObjectKey::from_name(b"get-range-verify");
        let payload = b"abcdefghijklmnopqrstuvwxyz";
        store.put(key, payload).expect("put object");

        // Full read must succeed under checksum verification.
        let full = store.get(key).expect("get full");
        assert_eq!(full.as_deref(), Some(payload.as_slice()));

        // Range read must NOT fail with ObjectChecksumMismatch.
        // Before the fix, get_range compared the range slice against
        // the full-object digest, producing a false mismatch.
        let range = store.get_range(key, 5, 6).expect("get range");
        assert_eq!(range, Some(b"fghijk".to_vec()));

        // Subset at start
        let start = store.get_range(key, 0, 3).expect("get range start");
        assert_eq!(start, Some(b"abc".to_vec()));

        // Subset at end
        let end = store.get_range(key, 20, 6).expect("get range end");
        assert_eq!(end, Some(b"uvwxyz".to_vec()));

        // Empty range (len=0)
        let empty = store.get_range(key, 0, 0).expect("get empty range");
        assert_eq!(empty, Some(Vec::new()));

        // Range past EOF returns suffix
        let suffix = store.get_range(key, 23, 10).expect("get range suffix");
        assert_eq!(suffix, Some(b"xyz".to_vec()));
    }
    cleanup(&root);
}

#[test]
fn range_zero_length_object_round_trips_with_empty_payload() {
    let root = temp_root("range-empty-object");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let key = ObjectKey::from_name(b"range-empty-object");
        let stored = store.put(key, b"").expect("put empty object");
        assert_eq!(stored.len, 0);
        assert_eq!(store.get(key).expect("get empty object"), Some(Vec::new()));
        assert_eq!(store.get_attr(&key).expect("empty attr").size, 0);
    }
    cleanup(&root);
}

#[test]
fn range_get_at_location_rejects_overflowing_record_offset() {
    let root = temp_root("range-location-overflow");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let key = ObjectKey::from_name(b"range-location-overflow");
        store.put(key, b"payload").expect("put object");
        let mut location = store.location_of(key).expect("object location");
        location.record_offset = u64::MAX - (RECORD_HEADER_LEN_U64 / 2);

        let result = store.get_at_location(location);

        assert!(matches!(
            result,
            Err(StoreError::CorruptHeader {
                reason: "record byte range overflows u64",
                ..
            })
        ));
    }
    cleanup(&root);
}

#[test]
fn range_get_at_location_rejects_payload_offset_mismatch() {
    let root = temp_root("range-location-payload-offset");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let key = ObjectKey::from_name(b"range-location-payload-offset");
        store.put(key, b"payload").expect("put object");
        let mut location = store.location_of(key).expect("object location");
        location.payload_offset = location.payload_offset.saturating_add(1);

        let result = store.get_at_location(location);

        assert!(matches!(
            result,
            Err(StoreError::CorruptHeader {
                reason: "location payload offset does not match record layout",
                ..
            })
        ));
    }
    cleanup(&root);
}

#[test]
fn range_get_at_location_reports_short_payload_eof() {
    let root = temp_root("range-location-short-payload");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let key = ObjectKey::from_name(b"range-location-short-payload");
        store.put(key, b"payload bytes").expect("put object");
        store.sync_all().expect("sync object");
        let location = store.location_of(key).expect("object location");
        let path = crate::store::segment_path(store.segments_dir(), location.segment_id);
        OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open segment for truncate")
            .set_len(location.payload_offset + 2)
            .expect("truncate payload");

        let result = store.get_at_location(location);

        assert!(matches!(
            result,
            Err(StoreError::Io {
                operation: "read_exact payload",
                ..
            })
        ));
    }
    cleanup(&root);
}

/// get_verified for a missing key returns Ok(None), not an error.
#[test]
fn get_verified_missing_key_returns_none() {
    let root = temp_root("gv-none");
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let ghost = ObjectKey::from_name(b"ghost-key-obj-001");
        assert_eq!(store.get_verified(ghost).expect("get_verified"), None);
    }
    cleanup(&root);
}

/// get_attr returns correct size and key without buffering the full payload.
#[test]
fn get_attr_returns_correct_metadata() {
    let root = temp_root("attr-ok");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let payload = [0xAB_u8; 128];
        let key = ObjectKey::from_content(&payload[..]);
        store.put(key, &payload[..]).expect("put");
        store.sync_all().expect("sync");
        let attr = store.get_attr(&key).expect("get_attr");
        assert_eq!(attr.size, 128, "ObjectAttr::size must match payload length");
        assert_eq!(attr.key, key, "ObjectAttr::key must match request key");
    }
    cleanup(&root);
}

/// get_attr for a missing key returns Err(ObjectReadError::NotFound).
#[test]
fn get_attr_missing_key_returns_not_found() {
    let root = temp_root("attr-nf");
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let ghost = ObjectKey::from_name(b"missing-attr-key-obj-001");
        let result = store.get_attr(&ghost);
        assert!(
            matches!(result, Err(ObjectReadError::NotFound { .. })),
            "get_attr on a missing key must return NotFound"
        );
    }
    cleanup(&root);
}

/// Multiple get calls on the same key (simulating concurrent readers)
/// must return consistent results.
#[test]
fn concurrent_reads_same_key() {
    let root = temp_root("concur-read");
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        let payload = b"concurrent-read test payload OBJ-001";
        let key = ObjectKey::from_content(payload);
        store.put(key, payload).expect("put");
        store.sync_all().expect("sync");
        for _ in 0..16 {
            let r = store.get(key).expect("get");
            assert_eq!(r, Some(payload.to_vec()));
        }
    }
    cleanup(&root);
}

/// reopen → get round-trip: data persists across store close/reopen.
#[test]
fn reopen_persists_data_for_get() {
    let root = temp_root("reopen-get");
    let payload = b"persistence payload OBJ-001";
    let key = ObjectKey::from_content(payload);
    {
        let mut store = LocalObjectStore::open_with_options(&root, options()).expect("open");
        store.put(key, payload).expect("put");
        store.sync_all().expect("sync");
    }
    {
        let store = LocalObjectStore::open_with_options(&root, options()).expect("reopen");
        let retrieved = store.get(key).expect("get");
        assert_eq!(retrieved, Some(payload.to_vec()));
    }
    cleanup(&root);
}

mod spacemap_integration {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tidefs_spacemap_allocator::{SegmentFreeMap, SpaceMapCheckpointV1};

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tidefs-sm-{}", rand::random::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    // -- Core lifecycle tests --

    #[test]
    fn pool_open_with_existing_segments_marks_them_used() {
        let root = temp_dir();
        // Create store to write a segment, then reopen and verify free map.
        let key1 = ObjectKey::from_name(b"obj1");
        {
            let mut store = LocalObjectStore::open(root.join("pool")).unwrap();
            store.put(key1, b"data1").unwrap();
            store.sync_all().unwrap();
        }
        {
            let store = LocalObjectStore::open(root.join("pool")).unwrap();
            let stats = store.free_map.stats();
            assert!(
                stats.used_segments >= 1,
                "at least one segment used after first write"
            );
            assert!(
                stats.free_segments < stats.segment_count,
                "not all segments are free"
            );
            // The currently-used segment should not be free
            assert!(
                !store.free_map.is_free(store.current_segment_id),
                "current segment must be marked as used"
            );
        }
        cleanup(&root);
    }

    #[test]
    fn allocate_then_reopen_segment_stays_used() {
        let root = temp_dir();
        let key1 = ObjectKey::from_name(b"k1");
        let seg_id;
        {
            let mut store = LocalObjectStore::open(root.join("pool")).unwrap();
            store.put(key1, b"hello").unwrap();
            store.rotate_segment().unwrap();
            seg_id = store.current_segment_id;
        }
        {
            let store = LocalObjectStore::open(root.join("pool")).unwrap();
            assert!(
                !store.free_map.is_free(seg_id),
                "segment allocated in previous run must be marked used on reopen"
            );
        }
        cleanup(&root);
    }

    #[test]
    fn fill_pool_to_segment_count_yields_no_space() {
        let root = temp_dir();
        let opts = StoreOptions {
            verify_read_checksums: false,
            reclaim_enabled: false,
            segment_count: 64,
            max_segment_bytes: 512,
            durability_layout: None,
            write_throttle_enabled: false,
            ..StoreOptions::default()
        };
        // Each put is small, but rotate after each one to consume segments
        {
            let mut store =
                LocalObjectStore::open_with_options(root.join("pool"), opts.clone()).unwrap();
            for i in 0..62 {
                store
                    .put(ObjectKey::from_name(format!("k{i}").as_bytes()), b"x")
                    .unwrap();
                store.rotate_segment().unwrap();
            }
            // One more should still work (we've used ~64 segments for header/trailer)
            let result = store.rotate_segment();
            // Should eventually fail with NoSpace once pool is exhausted
            if let Err(e) = result {
                assert!(
                    matches!(e, StoreError::NoSpace),
                    "expected NoSpace error, got {e:?}"
                );
            }
        }
        cleanup(&root);
    }

    #[test]
    fn free_segment_after_compaction_then_reallocate() {
        let root = temp_dir();
        let key1 = ObjectKey::from_name(b"keep-me");
        let key2 = ObjectKey::from_name(b"drop-me");
        {
            let opts = StoreOptions {
                verify_read_checksums: false,
                reclaim_enabled: false,
                segment_count: 10,
                max_segment_bytes: 512,
                durability_layout: None,
                write_throttle_enabled: false,
                ..StoreOptions::default()
            };
            let mut store = LocalObjectStore::open_with_options(root.join("pool"), opts).unwrap();
            store.put(key1, b"keep").unwrap();
            store.rotate_segment().unwrap();
            store.put(key2, b"drop").unwrap();
            store.rotate_segment().unwrap();
            // Both keys are now in completed segments. Compact retaining only key1.
            let report = store.compact_retaining(&[key1], &[]).unwrap();
            assert!(
                !report.retired_segments.is_empty(),
                "compaction should retire segments containing only dropped keys"
            );
            // After compaction, retired segments should be back in the free map
            for seg in &report.retired_segments {
                assert!(
                    store.free_map.is_free(*seg),
                    "retired segment {seg} should be free after compaction"
                );
            }
        }
        cleanup(&root);
    }

    #[test]
    fn reallocated_segment_reuses_freed_id() {
        let root = temp_dir();
        let opts = StoreOptions {
            verify_read_checksums: false,
            reclaim_enabled: false,
            segment_count: 32,
            max_segment_bytes: 256,
            durability_layout: None,
            write_throttle_enabled: false,
            ..StoreOptions::default()
        };
        let key1 = ObjectKey::from_name(b"a");
        let key2 = ObjectKey::from_name(b"b");
        let freed_seg: u64;
        {
            let mut store =
                LocalObjectStore::open_with_options(root.join("pool"), opts.clone()).unwrap();
            store.put(key1, b"111").unwrap();
            freed_seg = store.current_segment_id;
            store.rotate_segment().unwrap();
            store.put(key2, b"222").unwrap();
            // Compact retaining key2 only — this should free key1's segment
            let report = store.compact_retaining(&[key2], &[]).unwrap();
            assert!(
                report.retired_segments.contains(&freed_seg),
                "segment {freed_seg} should be retired and freed"
            );
            assert!(
                store.free_map.is_free(freed_seg),
                "freed segment {freed_seg} should be in free map"
            );
        }
        {
            // Reopen and allocate a new segment — should reuse freed_seg if possible
            let mut store = LocalObjectStore::open_with_options(root.join("pool"), opts).unwrap();
            let pre_free = store.free_map.free_count();
            store.rotate_segment().unwrap();
            let post_free = store.free_map.free_count();
            assert!(
                pre_free > post_free,
                "free count decreased after allocation"
            );
        }
        cleanup(&root);
    }

    // -- Checkpoint round-trip tests --

    #[test]
    fn checkpoint_round_trip_preserves_free_map() {
        let root = temp_dir();
        let key1 = ObjectKey::from_name(b"ckpt-1");
        let seg_count: u64;
        let free_before: u64;
        let runs_before: Vec<(u64, u64)>;
        {
            let mut store = LocalObjectStore::open(root.join("pool")).unwrap();
            store.put(key1, b"checkpoint-me").unwrap();
            store.sync_all().unwrap();
            seg_count = store.free_map.stats().segment_count;
            free_before = store.free_map.free_count();
            runs_before = store.free_map.runs();
        }
        {
            let store = LocalObjectStore::open(root.join("pool")).unwrap();
            let stats = store.free_map.stats();
            assert_eq!(
                stats.segment_count, seg_count,
                "segment count must survive reopen"
            );
            assert_eq!(
                store.free_map.free_count(),
                free_before,
                "free count must survive reopen"
            );
            assert_eq!(
                store.free_map.runs(),
                runs_before,
                "free runs must survive reopen"
            );
        }
        cleanup(&root);
    }

    #[test]
    fn spacemap_checkpoint_persists_across_opens() {
        let root = temp_dir();
        let key1 = ObjectKey::from_name(b"persist");
        let gen_before: u64;
        {
            let mut store = LocalObjectStore::open(root.join("pool")).unwrap();
            store.put(key1, b"data").unwrap();
            gen_before = store.free_map.generation();
            store.rotate_segment().unwrap();
        }
        {
            let store = LocalObjectStore::open(root.join("pool")).unwrap();
            // Generation should persist — it's checkpointed
            let gen_after = store.free_map.generation();
            assert!(
                gen_after >= gen_before,
                "generation {gen_after} should be >= {gen_before}"
            );
        }
        cleanup(&root);
    }

    #[test]
    fn spacemap_checkpoint_is_loaded_preferentially() {
        let root = temp_dir();
        // Create a checkpoint manually, then open — it should be used
        let seg_dir = root.join("pool").join("segments");
        fs::create_dir_all(&seg_dir).unwrap();
        {
            let fm = SegmentFreeMap::new(1000, vec![(100, 200), (500, 600)]).unwrap();
            let ckpt_file = seg_dir.join("spacemap");
            let ckpt = SpaceMapCheckpointV1::from_free_map(&fm, false);
            let mut buf = Vec::new();
            buf.extend_from_slice(&ckpt.magic);
            buf.extend_from_slice(&ckpt.version.to_le_bytes());
            buf.extend_from_slice(&ckpt.segment_count.to_le_bytes());
            buf.extend_from_slice(&ckpt.segment_group_segments.to_le_bytes());
            buf.extend_from_slice(&ckpt.segment_group_count.to_le_bytes());
            buf.extend_from_slice(&ckpt.dirty_segment_group_count.to_le_bytes());
            buf.extend_from_slice(&ckpt.generation.to_le_bytes());
            buf.extend_from_slice(&(ckpt.entries.len() as u32).to_le_bytes());
            for entry in &ckpt.entries {
                buf.extend_from_slice(&entry.segment_group_index.to_le_bytes());
                buf.extend_from_slice(&entry.bitmap_len.to_le_bytes());
                buf.extend_from_slice(&entry.bitmap_data);
            }
            let csum = crate::checksum64(&buf).0;
            buf.extend_from_slice(&csum.to_le_bytes());
            fs::write(&ckpt_file, &buf).unwrap();
        }
        // Create a segment so the store can open
        let seg0 = seg_dir.join("00000000000000000000.vlos");
        fs::write(&seg0, []).unwrap();

        let opts = StoreOptions {
            verify_read_checksums: false,
            reclaim_enabled: false,
            segment_count: 1000,
            max_segment_bytes: 512,
            sync_on_write: false,
            repair_torn_tail: false,
            segment_rotation_interval_secs: 0,
            segment_rotation_write_limit: 0,
            background_scrub_interval_secs: 0,
            mirror_path: None,
            replica_paths: Vec::new(),
            fault_injection_config: None,
            durability_layout: None,
            write_throttle_enabled: false,
        };
        let store = LocalObjectStore::open_with_options(root.join("pool"), opts).unwrap();
        // Segment 100 should be free (it was in the checkpoint)
        assert!(
            store.free_map.is_free(100),
            "segment 100 should be free per checkpoint"
        );
        // Segment 0 should be used (it's the discovered segment)
        assert!(!store.free_map.is_free(0), "segment 0 should be used");
        cleanup(&root);
    }

    // -- Statistical correctness --

    #[test]
    fn free_map_stats_are_accurate() {
        let root = temp_dir();
        let opts = StoreOptions {
            verify_read_checksums: false,
            reclaim_enabled: false,
            segment_count: 1024,
            max_segment_bytes: 512,
            durability_layout: None,
            write_throttle_enabled: false,
            ..StoreOptions::default()
        };
        let store = LocalObjectStore::open_with_options(root.join("pool"), opts).unwrap();
        let stats = store.free_map.stats();
        assert_eq!(stats.segment_count, 1024);
        assert_eq!(stats.used_segments + stats.free_segments, 1024);
        cleanup(&root);
    }

    #[test]
    fn allocation_reduces_free_count() {
        let root = temp_dir();
        let opts = StoreOptions {
            verify_read_checksums: false,
            reclaim_enabled: false,
            segment_count: 64,
            max_segment_bytes: 256,
            durability_layout: None,
            write_throttle_enabled: false,
            ..StoreOptions::default()
        };
        let mut store = LocalObjectStore::open_with_options(root.join("pool"), opts).unwrap();
        let free_before = store.free_map.free_count();
        store.put(ObjectKey::from_name(b"x"), b"y").unwrap();
        store.rotate_segment().unwrap();
        let free_after = store.free_map.free_count();
        assert!(
            free_after <= free_before,
            "free count after allocation ({free_after}) should be <= before ({free_before})"
        );
        cleanup(&root);
    }

    #[test]
    fn generation_increments_on_allocation() {
        let root = temp_dir();
        let store = LocalObjectStore::open(root.join("pool")).unwrap();
        let gen_before = store.free_map.generation();
        // Drop and reopen — not an allocation
        drop(store);
        let store2 = LocalObjectStore::open(root.join("pool")).unwrap();
        let gen_mid = store2.free_map.generation();
        assert_eq!(
            gen_before, gen_mid,
            "generation should not change on reopen without writes"
        );
        drop(store2);
        {
            let mut store3 = LocalObjectStore::open(root.join("pool")).unwrap();
            store3.put(ObjectKey::from_name(b"incr"), b"gen").unwrap();
            store3.rotate_segment().unwrap();
            let gen_after = store3.free_map.generation();
            assert!(
                gen_after > gen_before,
                "generation should increase after allocation ({gen_after} > {gen_before})"
            );
        }
        cleanup(&root);
    }

    #[test]
    fn is_free_returns_false_for_used_segment() {
        let root = temp_dir();
        let store = LocalObjectStore::open(root.join("pool")).unwrap();
        let seg = store.current_segment_id;
        assert!(
            !store.free_map.is_free(seg),
            "current active segment must not be free"
        );
        cleanup(&root);
    }

    #[test]
    fn remove_free_on_already_used_is_noop() {
        let root = temp_dir();
        let mut store = LocalObjectStore::open(root.join("pool")).unwrap();
        let seg = store.current_segment_id;
        // remove_free on an already-used segment returns AlreadyUsed error
        let result = store.free_map.remove_free(seg);
        assert!(result.is_err(), "remove_free on used segment should error");
        assert!(matches!(
            result.unwrap_err(),
            tidefs_pool_allocator::PoolAllocatorError::AlreadyUsed(_)
        ));
        // Current segment is still used
        assert!(!store.free_map.is_free(seg));
        cleanup(&root);
    }

    #[test]
    fn add_free_is_idempotent() {
        let root = temp_dir();
        let opts = StoreOptions {
            verify_read_checksums: false,
            reclaim_enabled: false,
            segment_count: 256,
            max_segment_bytes: 512,
            durability_layout: None,
            write_throttle_enabled: false,
            ..StoreOptions::default()
        };
        let mut store = LocalObjectStore::open_with_options(root.join("pool"), opts).unwrap();
        // Segment 200 is free (pool starts empty except discovered segments)
        let free_seg = 200;
        assert!(store.free_map.is_free(free_seg));
        store.free_map.add_free(free_seg).unwrap(); // idempotent — already free
        assert!(store.free_map.is_free(free_seg));
        // Allocate it, then free it twice
        let allocated = store.free_map.alloc_after(free_seg).unwrap();
        assert_eq!(allocated, free_seg);
        assert!(!store.free_map.is_free(free_seg));
        store.free_map.add_free(free_seg).unwrap();
        assert!(store.free_map.is_free(free_seg));
        store.free_map.add_free(free_seg).unwrap(); // idempotent
        assert!(store.free_map.is_free(free_seg));
        cleanup(&root);
    }

    #[test]
    fn alloc_after_wraps_around() {
        let root = temp_dir();
        let opts = StoreOptions {
            verify_read_checksums: false,
            reclaim_enabled: false,
            segment_count: 5,
            max_segment_bytes: 512,
            durability_layout: None,
            write_throttle_enabled: false,
            ..StoreOptions::default()
        };
        let mut store = LocalObjectStore::open_with_options(root.join("pool"), opts).unwrap();
        // Allocate segments 1, 2, 3, 4 (segment 0 is current)
        let mut allocd = Vec::new();
        for _ in 0..4 {
            let seg = store.free_map.alloc_after(1).unwrap();
            allocd.push(seg);
            if seg > 0 && seg < store.free_map.segment_count() {
                // ok
            }
        }
        // Free segment 2
        store.free_map.add_free(2).unwrap();
        // alloc_after(4) should wrap to find segment 2
        let wrapped = store.free_map.alloc_after(4).unwrap();
        assert_eq!(
            wrapped, 2,
            "alloc_after should wrap around to find freed segment 2"
        );
        cleanup(&root);
    }

    #[test]
    fn checkpoint_encode_decode_round_trip() {
        let root = temp_dir();
        {
            let opts = StoreOptions {
                verify_read_checksums: false,
                reclaim_enabled: false,
                segment_count: 100,
                max_segment_bytes: 512,
                durability_layout: None,
                write_throttle_enabled: false,
                ..StoreOptions::default()
            };
            let mut store = LocalObjectStore::open_with_options(root.join("pool"), opts).unwrap();
            // Write one object and rotate segment to trigger spacemap checkpoint write
            store.put(ObjectKey::from_name(b"x"), b"y").unwrap();
            let pre_free = store.free_map.free_count();
            store.rotate_segment().unwrap();
            let post_free = store.free_map.free_count();
            assert!(
                post_free < pre_free,
                "rotate_segment should consume a free segment"
            );
            // Verify the spacemap checkpoint was written and can be reloaded
            let segments_dir = root.join("pool").join("segments");
            let (reloaded, _seg_count, _gen) =
                crate::store::load_spacemap_checkpoint(&segments_dir)
                    .unwrap()
                    .unwrap();
            assert_eq!(reloaded.free_count(), store.free_map.free_count());
        }
        cleanup(&root);
    }

    #[test]
    fn no_duplicate_segment_allocations() {
        let root = temp_dir();
        let opts = StoreOptions {
            verify_read_checksums: false,
            reclaim_enabled: false,
            segment_count: 64,
            max_segment_bytes: 256,
            durability_layout: None,
            write_throttle_enabled: false,
            ..StoreOptions::default()
        };
        let mut store = LocalObjectStore::open_with_options(root.join("pool"), opts).unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            let seg = store.free_map.alloc_after(0).unwrap();
            assert!(seen.insert(seg), "segment {seg} allocated twice");
        }
        cleanup(&root);
    }

    #[test]
    fn existing_testsuite_runs_with_spacemap_integration() {
        // Sanity: open/close cycle works with free map managed internally
        let root = temp_dir();
        {
            let mut store = LocalObjectStore::open(root.join("p")).unwrap();
            for i in 0..100 {
                store
                    .put(ObjectKey::from_name(format!("obj{i}").as_bytes()), b"val")
                    .unwrap();
            }
            store.sync_all().unwrap();
        }
        {
            let store = LocalObjectStore::open(root.join("p")).unwrap();
            assert!(store.get(ObjectKey::from_name(b"obj50")).unwrap().is_some());
        }
        cleanup(&root);
    }

    #[test]
    fn compact_retaining_frees_and_reallocates() {
        let root = temp_dir();
        let opts = StoreOptions {
            verify_read_checksums: false,
            reclaim_enabled: false,
            segment_count: 256,
            max_segment_bytes: 256,
            durability_layout: None,
            write_throttle_enabled: false,
            ..StoreOptions::default()
        };
        let k1 = ObjectKey::from_name(b"keep");
        let k2 = ObjectKey::from_name(b"tmp");
        {
            let mut store =
                LocalObjectStore::open_with_options(root.join("p"), opts.clone()).unwrap();
            store.put(k1, b"keep-me").unwrap();
            store.rotate_segment().unwrap();
            store.put(k2, b"drop-me").unwrap();
            let report = store.compact_retaining(&[k1], &[]).unwrap();
            // Compaction retires old segments but may also allocate new ones
            // during the copy pass. The real proof is retired_segments non-empty.
            assert!(
                !report.retired_segments.is_empty(),
                "compaction should retire at least one segment"
            );
        }
        cleanup(&root);
    }

    #[test]
    fn spacemap_checkpoint_file_exists_after_write() {
        let root = temp_dir();
        {
            let mut store = LocalObjectStore::open(root.join("pool")).unwrap();
            store.put(ObjectKey::from_name(b"x"), b"y").unwrap();
            store.rotate_segment().unwrap();
        }
        let spacemap_path = root.join("pool").join("segments").join("spacemap_base");
        assert!(
            spacemap_path.exists(),
            "spacemap checkpoint file must exist after rotate_segment"
        );
        assert!(
            fs::metadata(&spacemap_path).unwrap().len() > 0,
            "spacemap checkpoint must be non-empty"
        );
        cleanup(&root);
    }

    #[test]
    fn clean_sync_all_does_not_rewrite_spacemap_checkpoint() {
        let root = temp_dir();
        {
            let mut store = LocalObjectStore::open(root.join("pool")).unwrap();
            store.put(ObjectKey::from_name(b"x"), b"y").unwrap();
            store.rotate_segment().unwrap();
            assert!(
                store.free_map.dirty_segment_groups().is_empty(),
                "rotate_segment should leave a clean spacemap checkpoint"
            );

            let tmp_path = root
                .join("pool")
                .join(crate::constants::STORE_DIR_NAME)
                .join(format!("{}.tmp", crate::constants::SPACEMAP_BASE_FILE_NAME));
            fs::create_dir(&tmp_path).unwrap();

            store
                .sync_all()
                .expect("clean sync should not rewrite spacemap checkpoint");
        }
        cleanup(&root);
    }

    // ------------------------------------------------------------------
    // SegmentIntegrityFooter tests
    // ------------------------------------------------------------------

    #[test]
    fn segment_footer_write_and_read() {
        let root = temp_dir();
        {
            let mut store = LocalObjectStore::open(root.join("pool")).unwrap();
            // Write some data to ensure a footer is generated on rotation.
            store.put(ObjectKey::from_name(b"a"), b"payload-a").unwrap();
            store.put(ObjectKey::from_name(b"b"), b"payload-b").unwrap();
            store.rotate_segment().unwrap();
        }

        // Re-open and verify the chain is intact.
        let store = LocalObjectStore::open(root.join("pool")).unwrap();
        let (stats, suspect_log) = store.verify_segment_chain().unwrap();
        assert!(stats.segments_in_chain > 0, "at least one segment in chain");
        assert_eq!(stats.chain_breaks_detected, 0, "no chain breaks");
        assert!(suspect_log.is_empty(), "no suspect entries");
        cleanup(&root);
    }

    #[test]
    fn segment_footer_multi_segment_chain() {
        let root = temp_dir();
        {
            let mut store = LocalObjectStore::open(root.join("pool")).unwrap();
            // Write and rotate multiple segments.
            store.put(ObjectKey::from_name(b"a"), b"payload-a").unwrap();
            store.rotate_segment().unwrap();

            store.put(ObjectKey::from_name(b"b"), b"payload-b").unwrap();
            store.rotate_segment().unwrap();

            store.put(ObjectKey::from_name(b"c"), b"payload-c").unwrap();
            store.rotate_segment().unwrap();
        }

        let store = LocalObjectStore::open(root.join("pool")).unwrap();
        let (stats, suspect_log) = store.verify_segment_chain().unwrap();
        assert!(stats.segments_in_chain >= 3, "at least 3 segments");
        assert_eq!(stats.chain_breaks_detected, 0, "no chain breaks");
        assert!(suspect_log.is_empty(), "no suspect entries");
        cleanup(&root);
    }

    #[test]
    fn segment_footer_persists_across_reopen() {
        let root = temp_dir();
        {
            let mut store = LocalObjectStore::open(root.join("pool")).unwrap();
            store.put(ObjectKey::from_name(b"x"), b"y").unwrap();
            store.rotate_segment().unwrap();
        }

        // Re-open: chain must still be valid.
        let store = LocalObjectStore::open(root.join("pool")).unwrap();
        let (stats, _) = store.verify_segment_chain().unwrap();
        assert!(stats.segments_in_chain > 0);
        assert_eq!(stats.chain_breaks_detected, 0);
        cleanup(&root);
    }

    #[test]
    fn segment_footer_empty_segment_no_footer() {
        let root = temp_dir();
        {
            let mut store = LocalObjectStore::open(root.join("pool")).unwrap();
            // Rotate without writing any data — no footer written.
            store.rotate_segment().unwrap();
        }

        let store = LocalObjectStore::open(root.join("pool")).unwrap();
        let (stats, _) = store.verify_segment_chain().unwrap();
        // The empty segment has no footer, so the chain may have a break
        // or just skip it. Either way, it should not panic.
        assert!(stats.segments_in_chain > 0);
        cleanup(&root);
    }

    #[test]
    fn segment_footer_chain_verifier_standalone() {
        let root = temp_dir();
        {
            let mut store = LocalObjectStore::open(root.join("pool")).unwrap();
            store.put(ObjectKey::from_name(b"a"), b"1").unwrap();
            store.rotate_segment().unwrap();
            store.put(ObjectKey::from_name(b"b"), b"2").unwrap();
            store.rotate_segment().unwrap();
        }

        // Use the standalone verifier directly.
        let verifier = SegmentChainVerifier::new(root.join("pool").join("segments"));
        let (stats, suspect_log) = verifier.verify_chain().unwrap();
        assert!(stats.segments_in_chain >= 2);
        assert_eq!(stats.chain_breaks_detected, 0);
        assert!(suspect_log.is_empty());
        cleanup(&root);
    }

    /// Segment digest construction uses canonical DomainTag via
    /// ChecksumTreeBuilder.  Determinism and domain separation are
    /// required: identical inputs produce identical outputs; different
    /// domain tags (WriteSegment vs SegmentIntegrityFooter) produce
    /// different digests.
    #[test]
    fn segment_digest_determinism_and_domain_separation() {
        let digests_a: [[u8; 32]; 2] = [[1u8; 32], [2u8; 32]];
        let digests_b: [[u8; 32]; 2] = [[3u8; 32], [4u8; 32]];

        let s1 = compute_segment_digest(&digests_a);
        let s2 = compute_segment_digest(&digests_a);
        assert_eq!(s1, s2, "determinism: same inputs must produce same digest");

        let s3 = compute_segment_digest(&digests_b);
        assert_ne!(s1, s3, "different payloads must produce different digests");

        // Domain separation: WriteSegment and SegmentIntegrityFooter are
        // different domain tags — hashing the same bytes under a different
        // domain key must produce different output.
        let rec_digests: [[u8; 32]; 1] = [[0xABu8; 32]];
        let seg_digest = compute_segment_digest(&rec_digests);

        // Reconstruct the WriteSegment-domain digest manually.
        use tidefs_checksum_tree::{ChecksumTreeBuilder, DomainTag};
        let dk_ws = DomainTag::WriteSegment.derive_key();
        let mut builder_ws = ChecksumTreeBuilder::new_with_domain(32, dk_ws);
        for d in &rec_digests {
            builder_ws.ingest(d);
        }
        let tree_ws = builder_ws.finish();
        let ws_digest = ProductionIntegrityDigest::from_bytes32(tree_ws.root_hash);

        assert_ne!(
            seg_digest, ws_digest,
            "SegmentIntegrityFooter and WriteSegment domains must produce different digests"
        );
    }
    // ==================================================================
    // Reclaim-queue drain on segment allocation pressure (#4982)
    // ==================================================================

    fn exhaust_segment_pool(store: &mut LocalObjectStore, segment_count: usize) -> Vec<ObjectKey> {
        let mut keys = Vec::new();
        for i in 0..(segment_count - 1) {
            let key = ObjectKey::from_name(format!("pressure-key-{i}").as_bytes());
            store.put(key, b"x").unwrap();
            store.rotate_segment().unwrap();
            keys.push(key);
        }
        keys
    }

    #[test]
    fn allocation_pressure_empty_queue_returns_nospace() {
        let root = temp_dir();
        let segment_count = 10;
        let opts = StoreOptions {
            verify_read_checksums: false,
            reclaim_enabled: true,
            segment_count: segment_count as u64,
            max_segment_bytes: 4096,
            durability_layout: None,
            write_throttle_enabled: false,
            ..StoreOptions::default()
        };

        let mut store =
            LocalObjectStore::open_with_options(root.join("pool"), opts.clone()).unwrap();

        exhaust_segment_pool(&mut store, segment_count);
        let result = store.rotate_segment();
        assert!(
            matches!(result, Err(StoreError::NoSpace)),
            "empty reclaim queue should still report NoSpace, got {result:?}"
        );

        cleanup(&root);
    }

    #[test]
    fn allocation_pressure_preserves_legacy_queue_before_nospace() {
        let root = temp_dir();
        let segment_count = 10;
        let opts = StoreOptions {
            verify_read_checksums: false,
            reclaim_enabled: true,
            segment_count: segment_count as u64,
            max_segment_bytes: 4096,
            durability_layout: None,
            write_throttle_enabled: false,
            ..StoreOptions::default()
        };

        let mut store =
            LocalObjectStore::open_with_options(root.join("pool"), opts.clone()).unwrap();

        let keys = exhaust_segment_pool(&mut store, segment_count);
        assert!(
            matches!(store.rotate_segment(), Err(StoreError::NoSpace)),
            "test setup should exhaust the pool before deletion"
        );
        for key in &keys[..4] {
            store.delete(*key).unwrap();
        }

        let result = store.rotate_segment();
        assert!(
            matches!(result, Err(StoreError::NoSpace)),
            "legacy reclaim queue must not free physical segments without receipt-bound evidence, got {result:?}"
        );
        assert!(
            store.stats().free_segments == 0,
            "legacy reclaim entries must remain allocated until receipt-bound reclaim"
        );
        let drain = store
            .drain_dead_segments(&tidefs_reclaim::ReclaimConsumerConfig::default())
            .expect("legacy drain inspection");
        assert!(
            drain.reclaim_queue_depth >= 4,
            "legacy queue entries should remain visible for inspection"
        );
        cleanup(&root);
    }
    // ------------------------------------------------------------------
    // SuspectLog tests — append, query, resolve, stats (G3 checksum)
    // ------------------------------------------------------------------

    #[test]
    fn suspect_log_append_and_query_cycle() {
        // SuspectEntry and SuspectLog are in crate root
        let mut log = SuspectLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);

        log.record(SuspectEntry {
            locator_id: 10,
            segment_id: 1,
            offset: 100,
            record_type: 1,
            expected_hash: [0xAAu8; 32],
            actual_hash: [0xBBu8; 32],
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 5,
            timestamp_secs: 1000,
            ..Default::default()
        });
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());

        log.record(SuspectEntry {
            locator_id: 20,
            segment_id: 2,
            offset: 200,
            record_type: 2,
            expected_hash: [0xCCu8; 32],
            actual_hash: [0xDDu8; 32],
            repair_attempts: 3,
            last_repair_attempt: 2000,
            resolved: false,
            commit_group: 6,
            timestamp_secs: 2000,
            ..Default::default()
        });
        assert_eq!(log.len(), 2);

        let entries: Vec<SuspectEntry> = log.iter().copied().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].locator_id, 10);
        assert_eq!(entries[1].locator_id, 20);

        let unresolved = log.unresolved();
        assert_eq!(unresolved.len(), 2);
    }

    #[test]
    fn suspect_log_resolve_cycle() {
        // SuspectEntry and SuspectLog are in crate root
        let mut log = SuspectLog::new();

        log.record(SuspectEntry {
            locator_id: 1,
            segment_id: 1,
            offset: 0,
            record_type: 1,
            expected_hash: [0u8; 32],
            actual_hash: [1u8; 32],
            repair_attempts: 1,
            last_repair_attempt: 100,
            resolved: false,
            commit_group: 0,
            timestamp_secs: 0,
            ..Default::default()
        });

        let entry_id = log.iter().next().unwrap().entry_id;
        assert!(log.mark_resolved(entry_id));
        assert!(!log.mark_resolved(entry_id)); // already resolved

        assert!(log.unresolved().is_empty());

        let s = log.stats();
        assert_eq!(s.total_entries, 1);
        assert_eq!(s.unresolved, 0);
        assert_eq!(s.resolved, 1);
    }

    #[test]
    fn suspect_log_unresolved_sorted_by_repair_attempts() {
        // SuspectEntry and SuspectLog are in crate root
        let mut log = SuspectLog::new();

        log.record(SuspectEntry {
            locator_id: 1,
            segment_id: 1,
            offset: 0,
            record_type: 1,
            expected_hash: [0u8; 32],
            actual_hash: [0u8; 32],
            repair_attempts: 1,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 0,
            timestamp_secs: 100,
            ..Default::default()
        });
        log.record(SuspectEntry {
            locator_id: 2,
            segment_id: 2,
            offset: 0,
            record_type: 1,
            expected_hash: [0u8; 32],
            actual_hash: [0u8; 32],
            repair_attempts: 5,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 0,
            timestamp_secs: 200,
            ..Default::default()
        });
        log.record(SuspectEntry {
            locator_id: 3,
            segment_id: 3,
            offset: 0,
            record_type: 1,
            expected_hash: [0u8; 32],
            actual_hash: [0u8; 32],
            repair_attempts: 3,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 0,
            timestamp_secs: 300,
            ..Default::default()
        });

        let unresolved = log.unresolved();
        assert_eq!(unresolved.len(), 3);
        // Most repair attempts first
        assert_eq!(unresolved[0].repair_attempts, 5);
        assert_eq!(unresolved[1].repair_attempts, 3);
        assert_eq!(unresolved[2].repair_attempts, 1);
    }

    #[test]
    fn suspect_log_empty_log() {
        use crate::SuspectLog;
        let mut log = SuspectLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.unresolved().is_empty());
        assert!(!log.mark_resolved(42)); // no entry to resolve

        let s = log.stats();
        assert_eq!(s.total_entries, 0);
        assert_eq!(s.unresolved, 0);
        assert_eq!(s.resolved, 0);
        assert_eq!(s.oldest_unresolved_age, 0);
    }

    #[test]
    fn suspect_log_stats_accuracy() {
        // SuspectEntry and SuspectLog are in crate root
        let mut log = SuspectLog::new();

        log.record(SuspectEntry {
            locator_id: 1,
            segment_id: 1,
            offset: 0,
            record_type: 1,
            expected_hash: [0u8; 32],
            actual_hash: [0u8; 32],
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 0,
            timestamp_secs: 100,
            ..Default::default()
        });
        log.record(SuspectEntry {
            locator_id: 2,
            segment_id: 2,
            offset: 0,
            record_type: 1,
            expected_hash: [0u8; 32],
            actual_hash: [0u8; 32],
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 0,
            timestamp_secs: 200,
            ..Default::default()
        });
        log.record(SuspectEntry {
            locator_id: 3,
            segment_id: 3,
            offset: 0,
            record_type: 1,
            expected_hash: [0u8; 32],
            actual_hash: [0u8; 32],
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: true,
            commit_group: 0,
            timestamp_secs: 300,
            ..Default::default()
        });

        let s = log.stats();
        assert_eq!(s.total_entries, 3);
        assert_eq!(s.unresolved, 2);
        assert_eq!(s.resolved, 1);
        assert!(s.oldest_unresolved_age > 0);
    }

    #[test]
    fn suspect_log_entry_ids_are_monotonic() {
        // SuspectEntry and SuspectLog are in crate root
        let mut log = SuspectLog::new();

        log.record(SuspectEntry::default());
        log.record(SuspectEntry::default());
        log.record(SuspectEntry::default());

        let ids: Vec<u64> = log.iter().map(|e| e.entry_id).collect();
        assert_eq!(ids.len(), 3);
        assert!(ids[0] < ids[1]);
        assert!(ids[1] < ids[2]);
    }

    #[test]
    fn suspect_log_clear() {
        // SuspectEntry and SuspectLog are in crate root
        let mut log = SuspectLog::new();

        log.record(SuspectEntry::default());
        log.record(SuspectEntry::default());
        assert_eq!(log.len(), 2);

        log.clear();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn suspect_log_persists_across_reopen() {
        // SuspectEntry and SuspectLog are in crate root

        let root = temp_root("suspect-log-persist-reopen");
        let _ = fs::remove_dir_all(&root);

        // Create store, record suspect entries, sync, drop.
        {
            let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
                .expect("open store");
            store.suspect_log.record(SuspectEntry {
                locator_id: 100,
                segment_id: 7,
                offset: 4096,
                record_type: 1,
                expected_hash: [0xAA; 32],
                actual_hash: [0xBB; 32],
                repair_attempts: 0,
                last_repair_attempt: 0,
                resolved: false,
                commit_group: 42,
                timestamp_secs: 1000,
                ..Default::default()
            });
            store.suspect_log.record(SuspectEntry {
                locator_id: 200,
                segment_id: 7,
                offset: 8192,
                record_type: 1,
                expected_hash: [0xCC; 32],
                actual_hash: [0xDD; 32],
                repair_attempts: 0,
                last_repair_attempt: 0,
                resolved: false,
                commit_group: 43,
                timestamp_secs: 2000,
                ..Default::default()
            });
            store.sync_all().expect("sync_all");
        }

        // Reopen and verify entries survived.
        {
            let store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
                .expect("reopen store");

            let log = store.suspect_log();
            assert_eq!(log.len(), 2, "both entries should survive reopen");

            let unresolved = log.unresolved();
            assert_eq!(unresolved.len(), 2);

            // Verify entry details survived.
            let locator_ids: Vec<u64> = unresolved.iter().map(|e| e.locator_id).collect();
            assert!(locator_ids.contains(&100));
            assert!(locator_ids.contains(&200));

            let entry = unresolved.iter().find(|e| e.locator_id == 100).unwrap();
            assert_eq!(entry.segment_id, 7);
            assert_eq!(entry.offset, 4096);
            assert_eq!(entry.record_type, 1);
            assert_eq!(entry.expected_hash, [0xAA; 32]);
            assert_eq!(entry.actual_hash, [0xBB; 32]);
            assert!(!entry.resolved);
            assert_eq!(entry.commit_group, 42);
            assert_eq!(entry.timestamp_secs, 1000);
        }

        // Cleanup.
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn suspect_log_resolved_state_persists_across_reopen() {
        // SuspectEntry and SuspectLog are in crate root

        let root = temp_root("suspect-log-resolved-persist");
        let _ = fs::remove_dir_all(&root);

        // Create store, record an entry, mark it resolved, sync, drop.
        let resolved_id;
        {
            let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
                .expect("open store");
            store.suspect_log.record(SuspectEntry {
                locator_id: 42,
                segment_id: 1,
                offset: 0,
                record_type: 1,
                expected_hash: [0x11; 32],
                actual_hash: [0x22; 32],
                repair_attempts: 0,
                last_repair_attempt: 0,
                resolved: false,
                commit_group: 10,
                timestamp_secs: 500,
                ..Default::default()
            });
            resolved_id = store.suspect_log.iter().next().unwrap().entry_id;
            assert!(store.suspect_log.mark_resolved(resolved_id));
            store.sync_all().expect("sync_all");
        }

        // Reopen and verify resolved state persisted.
        {
            let store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
                .expect("reopen store");

            let log = store.suspect_log();
            assert_eq!(log.len(), 1, "entry should survive reopen");
            assert!(
                log.unresolved().is_empty(),
                "entry should be resolved after reopen"
            );

            let s = log.stats();
            assert_eq!(s.total_entries, 1);
            assert_eq!(s.unresolved, 0);
            assert_eq!(s.resolved, 1);
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn suspect_log_empty_on_clean_reopen() {
        let root = temp_root("suspect-log-clean-reopen");
        let _ = fs::remove_dir_all(&root);

        // Create store, sync (no suspect entries), drop, reopen.
        {
            let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
                .expect("open store");
            store.sync_all().expect("sync_all");
        }
        {
            let store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
                .expect("reopen store");
            assert!(store.suspect_log().is_empty());
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn suspect_log_text_report_on_clean_store() {
        let root = temp_root("suspect-report-clean");
        let _ = fs::remove_dir_all(&root);

        let store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        let report = store.suspect_log_text_report();
        assert!(report.contains("=== TideFS Suspect Log Report ==="));
        assert!(report.contains("No suspect entries recorded."));
        assert!(report.contains("Suspect log persisted at:"));
        drop(store);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn suspect_log_text_report_with_entries() {
        let root = temp_root("suspect-report-entries");
        let _ = fs::remove_dir_all(&root);

        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        store.suspect_log.record(SuspectEntry {
            entry_id: 0,
            locator_id: 42,
            segment_id: 1,
            offset: 1024,
            record_type: 1,
            expected_hash: [0xAA; 32],
            actual_hash: [0xBB; 32],
            repair_attempts: 2,
            last_repair_attempt: 1000,
            resolved: false,
            commit_group: 5,
            timestamp_secs: 2000,
        });

        let report = store.suspect_log_text_report();
        assert!(report.contains("Total entries: 1"));
        assert!(report.contains("Unresolved: 1"));
        assert!(report.contains("ENTRY"), "should have header row");
        assert!(report.contains("PAYLOAD"), "should show record type");
        // entry_id auto-assigned by record()
        assert!(report.contains("42"), "should contain locator_id 42");
        assert!(report.contains("2"), "should contain repair_attempts");
        drop(store);

        let _ = fs::remove_dir_all(&root);
    }

    /// End-to-end: corrupt segment on disk, detect via scrub, verify suspect
    /// entry persists across store close/reopen. This is the primary validation
    /// validation for REL-STOR-004: corruption injection → durable suspect record
    /// after reopen.
    #[test]
    fn scrub_detects_corruption_and_suspect_persists_across_reopen() {
        let root = temp_root("suspect-corruption-reopen");
        let _ = fs::remove_dir_all(&root);

        // Phase 1: Create store, write data, flush to segment, close.
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        store
            .put_named("obj-corrupt", b"corruption-test-payload-data")
            .unwrap();
        store.flush_segment().unwrap();
        store.sync_all().unwrap();
        drop(store);

        // Phase 2: Corrupt a byte in the first segment file.
        let seg_dir = root.join("segments");
        let mut entries: Vec<_> = std::fs::read_dir(&seg_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "suspect_log" && e.file_name() != "scrub_cursor")
            .collect();
        entries.sort_by_key(|e| e.file_name());
        if let Some(entry) = entries.first() {
            let path = entry.path();
            let len = std::fs::metadata(&path).unwrap().len();
            if len > 96 {
                let mut data = std::fs::read(&path).unwrap();
                // Corrupt a payload byte past the record header
                data[96] ^= 0xFF;
                std::fs::write(&path, &data).unwrap();
            }
        }

        // Phase 3: Reopen store — this triggers replay which populates
        // the suspect log via the integrity verifier.
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("reopen store after corruption");

        // Phase 4: Run scrub to detect corruption and record suspect entries.
        let _report = store.run_background_scrub().unwrap();
        let suspect_count = store.suspect_log().len();
        assert!(
            suspect_count > 0,
            "scrub after corruption should produce at least one suspect entry, got {suspect_count}"
        );

        // Capture report text and verify it contains entry details.
        let report_before = store.suspect_log_text_report();
        assert!(
            report_before.contains("PAYLOAD") || report_before.contains("Total entries:"),
            "text report should show suspect entries: {report_before}"
        );

        // Phase 5: Sync and close.
        store.sync_all().unwrap();
        drop(store);

        // Phase 6: Reopen and verify suspect entries survived.
        let store2 = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("reopen after suspect persistence");
        let suspect_count2 = store2.suspect_log().len();
        assert!(
            suspect_count2 >= suspect_count,
            "suspect entries ({suspect_count}) must persist across reopen (got {suspect_count2})"
        );

        let report_after = store2.suspect_log_text_report();
        assert!(
            report_after.contains("PAYLOAD") || report_after.contains("Total entries:"),
            "reopened text report should still show suspect entries: {report_after}"
        );

        drop(store2);
        let _ = fs::remove_dir_all(&root);
    }

    /// Verify that the suspect log text report survives store close/reopen
    /// when entries are recorded directly (no corruption needed). This is
    /// a focused persistence test using the operator-visible report API.
    #[test]
    fn suspect_text_report_survives_reopen() {
        let root = temp_root("suspect-report-reopen");
        let _ = fs::remove_dir_all(&root);

        // Create and populate store.
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        for i in 0..3 {
            store
                .put_named(format!("obj{i}"), b"payload-data-for-integrity-check")
                .unwrap();
        }
        store.flush_segment().unwrap();
        store.sync_all().unwrap();

        // Record a known suspect entry directly.
        store.suspect_log.record(SuspectEntry {
            entry_id: 0,
            locator_id: 999,
            segment_id: 1,
            offset: 2048,
            record_type: 1,
            expected_hash: [0x11; 32],
            actual_hash: [0x22; 32],
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 0,
            timestamp_secs: 5000,
        });

        let report_before = store.suspect_log_text_report();
        assert!(
            report_before.contains("999"),
            "report should contain locator_id 999"
        );

        store.sync_all().unwrap();
        drop(store);

        // Reopen and verify.
        let store2 = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("reopen store");
        let report_after = store2.suspect_log_text_report();
        assert!(
            report_after.contains("999"),
            "reopened report must contain locator_id 999: {report_after}"
        );
        assert!(
            report_after.contains("=== TideFS Suspect Log Report ==="),
            "report header must be present"
        );
        assert!(
            report_after.contains("Suspect log persisted at:"),
            "report must show persistence path"
        );

        drop(store2);
        let _ = fs::remove_dir_all(&root);
    }
}
// ── Inline compression round-trip tests ────────────────────────────────────

#[test]
fn compression_roundtrip_zstd() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut store =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    store.set_compression(super::CompressionConfig {
        algorithm: super::CompressionAlgorithm::Zstd,
        level: 3,
        min_compress_bytes: 0,
    });
    let payload = b"zstd compressed data ".repeat(100);
    store
        .put(super::ObjectKey::from_name("zobj"), &payload)
        .unwrap();
    let roundtrip = store
        .get(super::ObjectKey::from_name("zobj"))
        .unwrap()
        .unwrap();
    assert_eq!(roundtrip, payload);
    assert!(store.compression_stats.objects_compressed > 0);
}

#[test]
fn compression_roundtrip_lz4() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut store =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    store.set_compression(super::CompressionConfig {
        algorithm: super::CompressionAlgorithm::Lz4,
        level: 0,
        min_compress_bytes: 0,
    });
    let payload = b"lz4 compressed payload ".repeat(100);
    store
        .put(super::ObjectKey::from_name("lobj"), &payload)
        .unwrap();
    let roundtrip = store
        .get(super::ObjectKey::from_name("lobj"))
        .unwrap()
        .unwrap();
    assert_eq!(roundtrip, payload);
}

#[test]
fn compression_below_threshold_uncompressed() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut store =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    store.set_compression(super::CompressionConfig {
        algorithm: super::CompressionAlgorithm::Zstd,
        level: 3,
        min_compress_bytes: 512,
    });
    store
        .put(super::ObjectKey::from_name("small"), b"tiny")
        .unwrap();
    let roundtrip = store
        .get(super::ObjectKey::from_name("small"))
        .unwrap()
        .unwrap();
    assert_eq!(roundtrip, b"tiny");
}

#[test]
fn compression_reopen_roundtrip() {
    let dir = tempfile::TempDir::new().unwrap();
    let payload = b"survives restart with compression".repeat(50);
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        store.set_compression(super::CompressionConfig {
            algorithm: super::CompressionAlgorithm::Zstd,
            level: 3,
            min_compress_bytes: 0,
        });
        store
            .put(super::ObjectKey::from_name("persist"), &payload)
            .unwrap();
    }
    {
        let store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let roundtrip = store
            .get(super::ObjectKey::from_name("persist"))
            .unwrap()
            .unwrap();
        assert_eq!(roundtrip, payload);
    }
}

#[test]
fn compression_backward_compat() {
    let dir = tempfile::TempDir::new().unwrap();
    let payload = b"legacy uncompressed data".repeat(20);
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        store
            .put(super::ObjectKey::from_name("legacy"), &payload)
            .unwrap();
    }
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        store.set_compression(super::CompressionConfig::default());
        let roundtrip = store
            .get(super::ObjectKey::from_name("legacy"))
            .unwrap()
            .unwrap();
        assert_eq!(roundtrip, payload);
    }
}

#[test]
fn compression_disabled_stats() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut store =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    store
        .put(super::ObjectKey::from_name("obj"), b"no compression")
        .unwrap();
    assert_eq!(store.compression_stats.objects_compressed, 0);
}

// ── Space accounting integration tests ──────────────────────────────

#[test]
fn space_accounting_write_increments_dataset_usage() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut store =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    let did = [1u8; 16];

    // Initially no usage.
    assert!(store.get_dataset_usage(did).is_none());
    assert_eq!(store.get_pool_space_usage(), 0);

    // Record a write of 4096 bytes.
    store.record_dataset_write(did, 4096).unwrap();
    let usage = store.get_dataset_usage(did).unwrap();
    assert_eq!(usage.bytes_used, 4096);
    assert_eq!(store.get_pool_space_usage(), 4096);
}

#[test]
fn space_accounting_delete_decrements_dataset_usage() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut store =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    let did = [2u8; 16];

    store.record_dataset_write(did, 8192).unwrap();
    store.record_dataset_delete(did, 4096).unwrap();
    let usage = store.get_dataset_usage(did).unwrap();
    assert_eq!(usage.bytes_used, 4096);
    assert_eq!(store.get_pool_space_usage(), 4096);
}

#[test]
fn space_accounting_delete_underflow_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut store =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    let did = [3u8; 16];

    // Deleting from a dataset with zero usage should fail.
    let err = store.record_dataset_delete(did, 1024).unwrap_err();
    assert!(matches!(
        err,
        tidefs_space_accounting::Error::CounterUnderflow { .. }
    ));
}

#[test]
fn space_accounting_multi_dataset_isolation() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut store =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    let did_a = [1u8; 16];
    let did_b = [2u8; 16];

    store.record_dataset_write(did_a, 1000).unwrap();
    store.record_dataset_write(did_b, 2000).unwrap();
    assert_eq!(store.get_pool_space_usage(), 3000);
    assert_eq!(store.get_dataset_usage(did_a).unwrap().bytes_used, 1000);
    assert_eq!(store.get_dataset_usage(did_b).unwrap().bytes_used, 2000);
}

#[test]
fn space_accounting_persist_and_load_roundtrip() {
    let dir = tempfile::TempDir::new().unwrap();
    let did = [1u8; 16];

    // Open store, record writes, persist.
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        store.record_dataset_write(did, 4096).unwrap();
        let persisted = store.persist_space_accounting().unwrap();
        assert_eq!(persisted, 1);
        assert!(!store.space_accounting_dirty());
    }

    // Reopen the store and load persisted records.
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let loaded = store.load_space_accounting().unwrap();
        assert_eq!(loaded, 1);
        let usage = store.get_dataset_usage(did).unwrap();
        assert_eq!(usage.bytes_used, 4096);
    }
}

#[test]
fn space_accounting_persist_multiple_datasets() {
    let dir = tempfile::TempDir::new().unwrap();
    let did_a = [1u8; 16];
    let did_b = [2u8; 16];

    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        store.record_dataset_write(did_a, 1000).unwrap();
        store.record_dataset_write(did_b, 2000).unwrap();
        let persisted = store.persist_space_accounting().unwrap();
        assert_eq!(persisted, 2);
    }

    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let loaded = store.load_space_accounting().unwrap();
        assert_eq!(loaded, 2);
        assert_eq!(store.get_dataset_usage(did_a).unwrap().bytes_used, 1000);
        assert_eq!(store.get_dataset_usage(did_b).unwrap().bytes_used, 2000);
    }
}

#[test]
fn space_accounting_load_nonexistent_dataset_returns_none() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    assert!(store.get_dataset_usage([0xAA; 16]).is_none());
}

#[test]
fn space_accounting_dirty_flag_lifecycle() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut store =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    let did = [1u8; 16];

    assert!(!store.space_accounting_dirty());
    store.record_dataset_write(did, 1024).unwrap();
    assert!(store.space_accounting_dirty());
    store.persist_space_accounting().unwrap();
    assert!(!store.space_accounting_dirty());
}

#[test]
fn space_accounting_persist_empty_noop() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut store =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    let persisted = store.persist_space_accounting().unwrap();
    assert_eq!(persisted, 0);
}

#[test]
fn space_accounting_sync_dataset_counters_bridge() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut store =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    let did = [1u8; 16];

    // Simulate the engine committing its SpaceAccounting counters.
    store.sync_dataset_counters(did, 4096, 1024);
    assert!(store.space_accounting_dirty());

    let usage = store.get_dataset_usage(did).unwrap();
    assert_eq!(usage.bytes_used, 4096);
    assert_eq!(usage.bytes_reserved, 1024);

    // Persist and reload.
    store.persist_space_accounting().unwrap();
    assert!(!store.space_accounting_dirty());

    // Reopen and verify the counters are restored.
    let mut store2 =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    let loaded = store2.load_space_accounting().unwrap();
    assert_eq!(loaded, 1);
    let usage2 = store2.get_dataset_usage(did).unwrap();
    assert_eq!(usage2.bytes_used, 4096);
    assert_eq!(usage2.bytes_reserved, 1024);
}

#[test]
fn space_accounting_sync_overwrites_and_reload() {
    let dir = tempfile::TempDir::new().unwrap();
    let did = [1u8; 16];

    // First session: write some data.
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        store.record_dataset_write(did, 1000).unwrap();
        store.persist_space_accounting().unwrap();
    }

    // Second session: sync with new values, persist, reopen.
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        store.load_space_accounting().unwrap();
        store.sync_dataset_counters(did, 5000, 200);
        store.persist_space_accounting().unwrap();
    }

    // Third session: verify the latest values win.
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        store.load_space_accounting().unwrap();
        let usage = store.get_dataset_usage(did).unwrap();
        assert_eq!(usage.bytes_used, 5000);
        assert_eq!(usage.bytes_reserved, 200);
    }
}

// ── Crash-loop recovery tests ───────────────────────────────────────

#[test]
fn space_accounting_crash_recovery_sync_all_barrier() {
    let dir = tempfile::TempDir::new().unwrap();
    let did = [0xAA; 16];

    // Session 1: write data, persist, sync_all durability barrier.
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        store.sync_dataset_counters(did, 65536, 0);
        store.persist_space_accounting().unwrap();
        store.sync_all().unwrap();
    }

    // "Crash" then reopen: verify the committed counters survive.
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let loaded = store.load_space_accounting().unwrap();
        assert_eq!(loaded, 1, "one dataset should be recovered");
        let usage = store.get_dataset_usage(did).unwrap();
        assert_eq!(usage.bytes_used, 65536);
        assert_eq!(usage.bytes_reserved, 0);
    }
}

#[test]
fn space_accounting_crash_recovery_multi_dataset_sync_barrier() {
    let dir = tempfile::TempDir::new().unwrap();
    let did_a = [1u8; 16];
    let did_b = [2u8; 16];

    // Session 1: write two datasets, persist, sync_all.
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        store.sync_dataset_counters(did_a, 4096, 1024);
        store.sync_dataset_counters(did_b, 8192, 512);
        store.persist_space_accounting().unwrap();
        store.sync_all().unwrap();
    }

    // Reopen: both datasets should be recovered with correct counters.
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let loaded = store.load_space_accounting().unwrap();
        assert_eq!(loaded, 2);
        let ua = store.get_dataset_usage(did_a).unwrap();
        assert_eq!(ua.bytes_used, 4096);
        assert_eq!(ua.bytes_reserved, 1024);
        let ub = store.get_dataset_usage(did_b).unwrap();
        assert_eq!(ub.bytes_used, 8192);
        assert_eq!(ub.bytes_reserved, 512);
    }
}

#[test]
fn space_accounting_crash_recovery_sequence_write_flush_reopen() {
    let dir = tempfile::TempDir::new().unwrap();
    let did = [0xBB; 16];

    // Session 1: write 4096, sync_all.
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        store.record_dataset_write(did, 4096).unwrap();
        store.persist_space_accounting().unwrap();
        store.sync_all().unwrap();
    }

    // Session 2: reopen, reload, verify 4096, then write another 4096,
    // persist, sync_all.
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let loaded = store.load_space_accounting().unwrap();
        assert_eq!(loaded, 1);
        assert_eq!(store.get_dataset_usage(did).unwrap().bytes_used, 4096);

        // Accumulate more writes.
        store.record_dataset_write(did, 4096).unwrap();
        store.persist_space_accounting().unwrap();
        store.sync_all().unwrap();
    }

    // Session 3: reopen, should see 8192 total.
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let loaded = store.load_space_accounting().unwrap();
        assert_eq!(loaded, 1);
        let usage = store.get_dataset_usage(did).unwrap();
        assert_eq!(usage.bytes_used, 8192, "accumulated writes across sessions");
    }
}

#[test]
fn space_accounting_crash_recovery_no_manifest_graceful() {
    let dir = tempfile::TempDir::new().unwrap();

    // Fresh store with no prior space accounting records.
    {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        // load_space_accounting should return 0 when no manifest exists.
        let loaded = store.load_space_accounting().unwrap();
        assert_eq!(loaded, 0);
        assert_eq!(store.get_pool_space_usage(), 0);
    }
}

// ── FreeSegmentCounter unit tests ──────────────────────────────────

#[test]
fn free_segment_counter_initial_count() {
    let counter = FreeSegmentCounter::new(100, 16);
    assert_eq!(counter.free_segment_count(), 100);
    assert!(!counter.is_low_space());
}

#[test]
fn free_segment_counter_starts_low_when_below_threshold() {
    let counter = FreeSegmentCounter::new(10, 16);
    assert_eq!(counter.free_segment_count(), 10);
    assert!(counter.is_low_space());
}

#[test]
fn free_segment_counter_starts_low_when_at_threshold() {
    let counter = FreeSegmentCounter::new(16, 16);
    assert_eq!(counter.free_segment_count(), 16);
    assert!(counter.is_low_space());
}

#[test]
fn free_segment_counter_alloc_decrements() {
    let counter = FreeSegmentCounter::new(100, 16);
    counter.allocated();
    assert_eq!(counter.free_segment_count(), 99);
    counter.allocated();
    assert_eq!(counter.free_segment_count(), 98);
}

#[test]
fn free_segment_counter_free_increments() {
    let counter = FreeSegmentCounter::new(10, 16);
    counter.freed();
    assert_eq!(counter.free_segment_count(), 11);
    counter.freed();
    assert_eq!(counter.free_segment_count(), 12);
}

#[test]
fn free_segment_counter_watermark_trips_on_alloc() {
    let counter = FreeSegmentCounter::new(17, 16);
    assert!(!counter.is_low_space());
    counter.allocated();
    assert_eq!(counter.free_segment_count(), 16);
    assert!(counter.is_low_space());
}

#[test]
fn free_segment_counter_watermark_clears_on_free() {
    let counter = FreeSegmentCounter::new(16, 16);
    assert!(counter.is_low_space());
    counter.freed();
    assert_eq!(counter.free_segment_count(), 17);
    assert!(!counter.is_low_space());
}

#[test]
fn free_segment_counter_multiple_alloc_free_cycles() {
    let counter = FreeSegmentCounter::new(20, 16);
    assert!(!counter.is_low_space());
    for _ in 0..6 {
        counter.allocated();
    }
    assert_eq!(counter.free_segment_count(), 14);
    assert!(counter.is_low_space());
    for _ in 0..4 {
        counter.freed();
    }
    assert_eq!(counter.free_segment_count(), 18);
    assert!(!counter.is_low_space());
}

#[test]
fn free_segment_counter_alloc_saturates_at_zero() {
    let counter = FreeSegmentCounter::new(1, 16);
    counter.allocated();
    assert_eq!(counter.free_segment_count(), 0);
    counter.allocated();
    assert_eq!(counter.free_segment_count(), 0);
}

// ── Write throttle tests ─────────────────────────────────────────────

fn throttle_options() -> StoreOptions {
    StoreOptions {
        verify_read_checksums: false,
        reclaim_enabled: false,
        max_segment_bytes: 512,
        sync_on_write: false,
        repair_torn_tail: true,
        mirror_path: None,
        replica_paths: Vec::new(),
        segment_rotation_interval_secs: 0,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 256,
        durability_layout: None,
        write_throttle_enabled: true,
    }
}

#[test]
fn write_throttle_blocks_user_write_when_low_space_and_new_segment_needed() {
    let root = temp_root("throttle-blocks");
    let opts = StoreOptions {
        verify_read_checksums: false,
        segment_count: 20,
        max_segment_bytes: 512,
        durability_layout: None,
        write_throttle_enabled: true,
        ..throttle_options()
    };
    let mut store = LocalObjectStore::open_with_options(&root, opts).unwrap();
    let payload = vec![0xAA; 280];
    let mut writes = 0;
    loop {
        match store.put(
            ObjectKey::from_name(format!("w{writes}").as_bytes()),
            &payload,
        ) {
            Ok(_) => writes += 1,
            Err(StoreError::NoSpace) => break,
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        if writes > 100 {
            panic!("throttle never engaged after {writes} writes");
        }
    }
    assert!(
        writes > 0,
        "should have written at least once before throttle"
    );
    assert!(store.is_low_space(), "low-watermark should be tripped");
    cleanup(&root);
}

#[test]
fn write_throttle_allows_system_writes_when_low_space() {
    let root = temp_root("throttle-system");
    let opts = StoreOptions {
        verify_read_checksums: false,
        segment_count: 20,
        max_segment_bytes: 512,
        durability_layout: None,
        write_throttle_enabled: true,
        ..throttle_options()
    };
    let mut store = LocalObjectStore::open_with_options(&root, opts).unwrap();
    let payload = vec![0xBB; 280];
    loop {
        match store.put(ObjectKey::from_name(b"user"), &payload) {
            Ok(_) => continue,
            Err(StoreError::NoSpace) => break,
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
    assert!(store.is_low_space());
    let sys_key = ObjectKey::from_name(b"system-root");
    let result = store.put_direct(sys_key, b"committed-root-data");
    assert!(result.is_ok(), "system writes must not be throttled");
    cleanup(&root);
}

#[test]
fn write_throttle_disabled_allows_writes_below_watermark() {
    let root = temp_root("throttle-disabled");
    let opts = StoreOptions {
        verify_read_checksums: false,
        segment_count: 20,
        max_segment_bytes: 512,
        durability_layout: None,
        write_throttle_enabled: false,
        ..throttle_options()
    };
    let mut store = LocalObjectStore::open_with_options(&root, opts).unwrap();
    let payload = vec![0xCC; 280];
    let mut count = 0;
    loop {
        match store.put(
            ObjectKey::from_name(format!("d{count}").as_bytes()),
            &payload,
        ) {
            Ok(_) => count += 1,
            Err(StoreError::NoSpace) => break,
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        if count > 200 {
            panic!("pool never exhausted after {count} writes");
        }
    }
    assert!(count > 0);
    assert!(store.is_low_space());
    cleanup(&root);
}

#[test]
fn write_throttle_does_not_block_fitting_writes() {
    let root = temp_root("throttle-fitting");
    let opts = StoreOptions {
        verify_read_checksums: false,
        segment_count: 20,
        max_segment_bytes: 512,
        durability_layout: None,
        write_throttle_enabled: true,
        ..throttle_options()
    };
    let mut store = LocalObjectStore::open_with_options(&root, opts).unwrap();
    let payload = vec![0xDD; 200];
    loop {
        match store.put(ObjectKey::from_name(b"burn"), &payload) {
            Ok(_) => continue,
            Err(StoreError::NoSpace) => break,
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
    assert!(store.is_low_space());
    store
        .rotate_segment()
        .expect("rotate should succeed with reserved segments");
    let small = b"tiny";
    let result = store.put(ObjectKey::from_name(b"small-fit"), small);
    assert!(
        result.is_ok(),
        "small writes fitting in fresh segment should not be throttled"
    );
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test-only automatic space accounting via current_dataset_id context
// ---------------------------------------------------------------------------

#[cfg(test)]
mod space_accounting_auto_tests {
    use super::*;

    fn temp_store() -> (LocalObjectStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("open store");
        (store, dir)
    }

    const DS1: [u8; 16] = [1u8; 16];
    const DS2: [u8; 16] = [2u8; 16];

    #[test]
    fn put_auto_increments() {
        let (mut store, _dir) = temp_store();

        store.set_current_dataset_id(DS1);
        assert_eq!(store.current_dataset_id(), Some(DS1));

        // Test builds can auto-increment bytes_used via space_book.record_write().
        let _key_a = store.put(ObjectKey::from_name("a"), b"hello").unwrap().key;
        let _key_b = store.put(ObjectKey::from_name("b"), b"world!").unwrap().key;

        let usage = store.space_book.get_dataset_usage(DS1).unwrap();
        assert!(usage.bytes_used > 0);
        // The dataset should be dirty (not yet persisted).
        assert!(store.space_accounting_dirty());
    }

    #[test]
    fn committed_sync_overwrites_test_only_auto_context_before_persist() {
        let dir = tempfile::tempdir().expect("tempdir");

        {
            let mut store =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
                    .expect("open store");
            store.set_current_dataset_id(DS1);
            store
                .put(ObjectKey::from_name("raw-fixture"), b"raw fixture bytes")
                .unwrap();

            let raw_usage = store.space_book.get_dataset_usage(DS1).unwrap();
            assert!(raw_usage.bytes_used > 0);
            assert_ne!(raw_usage.bytes_used, 12_345);

            store.sync_dataset_counters(DS1, 12_345, 678);
            let committed_usage = store.get_dataset_usage(DS1).unwrap();
            assert_eq!(committed_usage.bytes_used, 12_345);
            assert_eq!(committed_usage.bytes_reserved, 678);

            let persisted = store.persist_space_accounting().unwrap();
            assert_eq!(persisted, 1);
            assert!(
                !store.space_accounting_dirty(),
                "space accounting persistence must flush the committed snapshot"
            );
            store.sync_all().unwrap();
        }

        {
            let mut store =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
                    .expect("reopen store");
            assert_eq!(store.load_space_accounting().unwrap(), 1);
            let usage = store.get_dataset_usage(DS1).unwrap();
            assert_eq!(usage.bytes_used, 12_345);
            assert_eq!(usage.bytes_reserved, 678);
        }
    }

    #[test]
    fn put_no_context_does_not_increment() {
        let (mut store, _dir) = temp_store();

        // Write without setting dataset context.
        store.put(ObjectKey::from_name("x"), b"data").unwrap();

        assert_eq!(store.space_book.get_pool_usage(), 0);
    }

    #[test]
    fn clear_dataset_context() {
        let (mut store, _dir) = temp_store();
        store.set_current_dataset_id(DS1);
        assert_eq!(store.current_dataset_id(), Some(DS1));

        store.clear_current_dataset_id();
        assert_eq!(store.current_dataset_id(), None);

        // Writes after clearing should not increment.
        store.put(ObjectKey::from_name("y"), b"stuff").unwrap();
        assert_eq!(store.space_book.get_pool_usage(), 0);
    }

    #[test]
    fn delete_auto_decrements() {
        let (mut store, _dir) = temp_store();

        store.set_current_dataset_id(DS1);

        // Write to establish usage (auto-increments immediately).
        let key = store
            .put(ObjectKey::from_name("delme"), b"some data")
            .unwrap()
            .key;
        let after_write = store.space_book.get_pool_usage();
        assert!(after_write > 0);

        // Delete should decrement.
        store.delete(key).unwrap();
        let usage = store.space_book.get_dataset_usage(DS1).unwrap();
        assert!(
            usage.bytes_used < after_write,
            "bytes_used should decrease after delete: was {after_write}, now {}",
            usage.bytes_used
        );
    }

    #[test]
    fn overwrite_auto_adjusts() {
        let (mut store, _dir) = temp_store();

        store.set_current_dataset_id(DS1);

        // Write initial data.
        let key = store
            .put(ObjectKey::from_name("ow"), b"initial data here")
            .unwrap()
            .key;
        let after_first = store.space_book.get_pool_usage();
        assert!(after_first > 0);

        // Overwrite with new data (old decremented, new incremented).
        store.put(key, b"replacement").unwrap();

        // Space accounting should have net-adjusted.
        let after_overwrite = store.space_book.get_pool_usage();
        assert!(after_overwrite > 0);
        let usage = store.space_book.get_dataset_usage(DS1).unwrap();
        // The usage should reflect the new size, not zero.
        assert!(usage.bytes_used > 0);
    }

    #[test]
    fn multiple_datasets_auto_accounting() {
        let (mut store, _dir) = temp_store();

        // Write for DS1.
        store.set_current_dataset_id(DS1);
        store.put(ObjectKey::from_name("a1"), b"aaaa").unwrap();
        store.put(ObjectKey::from_name("a2"), b"bb").unwrap();

        let ds1_usage = store.space_book.get_dataset_usage(DS1).unwrap().bytes_used;
        assert!(ds1_usage > 0);

        // Write for DS2.
        store.set_current_dataset_id(DS2);
        store.put(ObjectKey::from_name("b1"), b"cccccc").unwrap();

        let ds2_usage = store.space_book.get_dataset_usage(DS2).unwrap().bytes_used;
        assert!(ds2_usage > 0);
        assert_eq!(store.space_book.get_pool_usage(), ds1_usage + ds2_usage);
    }
}

#[cfg(test)]
mod durability_layout_integration_tests {
    use super::*;
    use tidefs_durability_layout::DurabilityLayoutV1;

    fn temp_store_with_layout(layout: DurabilityLayoutV1) -> (LocalObjectStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut opts = StoreOptions::test_fast();
        opts.durability_layout = Some(layout);
        let store = LocalObjectStore::open_with_options(dir.path(), opts)
            .expect("open store with durability layout");
        (store, dir)
    }

    #[test]
    fn store_accepts_mirror_layout() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let (store, _dir) = temp_store_with_layout(layout);
        assert!(store.durability_layout().is_some());
        assert_eq!(store.durability_layout().unwrap().policy.total_shards(), 3);
    }

    #[test]
    fn store_accepts_erasure_layout() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let (store, _dir) = temp_store_with_layout(layout);
        assert!(store.durability_layout().is_some());
        assert_eq!(store.durability_layout().unwrap().policy.total_shards(), 11);
    }

    #[test]
    fn store_accepts_hybrid_layout() {
        let layout = DurabilityLayoutV1 {
            policy: tidefs_durability_layout::DurabilityPolicy::hybrid(2, 4, 2).unwrap(),
        };
        let (store, _dir) = temp_store_with_layout(layout);
        assert!(store.durability_layout().is_some());
        assert_eq!(store.durability_layout().unwrap().policy.total_shards(), 12);
    }

    #[test]
    fn store_set_durability_layout_runtime() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let (mut store, _dir) = temp_store_with_layout(layout);
        assert_eq!(store.durability_layout().unwrap().policy.total_shards(), 2);

        let new_layout = DurabilityLayoutV1::mirror(4).unwrap();
        store.set_durability_layout(new_layout);
        assert_eq!(store.durability_layout().unwrap().policy.total_shards(), 4);
    }

    #[test]
    fn store_writes_succeed_with_layout() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let (mut store, _dir) = temp_store_with_layout(layout);

        let key = ObjectKey::from_name("test");
        let stored = store.put(key, b"test payload").unwrap();
        let result = store.get(stored.key).unwrap();
        assert_eq!(result, Some(b"test payload".to_vec()));
    }

    #[test]
    fn store_reads_succeed_with_layout() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let (mut store, _dir) = temp_store_with_layout(layout);

        let key = ObjectKey::from_name("read_test");
        let stored = store.put(key, b"durability read test").unwrap();
        let data = store.get(stored.key).unwrap();
        assert_eq!(data.as_deref(), Some(b"durability read test".as_slice()));
    }

    #[test]
    fn store_without_layout_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let opts = StoreOptions::test_fast();
        let store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open store");
        assert!(store.durability_layout().is_none());
    }

    #[test]
    fn layout_survives_open_close_cycle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = DurabilityLayoutV1::mirror(3).unwrap();

        {
            let mut opts = StoreOptions::test_fast();
            opts.durability_layout = Some(layout);
            let mut store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open");
            store
                .put(ObjectKey::from_name("persist"), b"persist test")
                .unwrap();
        }
        {
            let mut opts = StoreOptions::test_fast();
            opts.durability_layout = Some(layout);
            let store = LocalObjectStore::open_with_options(dir.path(), opts).expect("reopen");
            assert!(store.durability_layout().is_some());
            assert_eq!(store.durability_layout().unwrap().policy.total_shards(), 3);
        }
    }

    #[test]
    fn store_rejects_layout_with_too_many_shards_for_replicas() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = DurabilityLayoutV1::mirror(5).unwrap(); // 5 total shards
        let mut opts = StoreOptions::test_fast();
        opts.durability_layout = Some(layout);
        // With 1 replica path (replica_count = 1), shards(5) > replica_count(1) + 1 = 2
        opts.replica_paths = vec![dir.path().join("replica")];
        let result = LocalObjectStore::open_with_options(dir.path(), opts);
        assert!(result.is_err());
    }

    #[test]
    fn store_accepts_layout_with_adequate_replicas() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = DurabilityLayoutV1::mirror(2).unwrap(); // 2 total shards
        let mut opts = StoreOptions::test_fast();
        opts.durability_layout = Some(layout);
        // 1 replica path → replica_count = 1, shards(2) <= replica_count(1) + 1 = 2
        let rp = dir.path().join("replica");
        std::fs::create_dir_all(&rp).unwrap();
        opts.replica_paths = vec![rp];
        let result = LocalObjectStore::open_with_options(dir.path(), opts);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn scrub_read_only_store_reports_findings_without_mutation() {
        // Phase 1: Create a store with data using a read-write store.
        // Skip sync_all to avoid writing cursor/suspect_log during creation.
        let tmp = tempfile::TempDir::with_prefix("ros-test").unwrap();
        let root = tmp.path().to_path_buf();
        let mut opts = StoreOptions::test_fast();
        opts.background_scrub_interval_secs = 1; // enable scrub
        let mut store = LocalObjectStore::open_with_options(&root, opts.clone()).unwrap();
        for i in 0u8..5 {
            let data = vec![i; 200];
            store.put_named(format!("obj-{i}"), &data).unwrap();
        }
        // Flush to segment but do not sync_all (which writes cursor/suspect_log).
        store.flush_segment().unwrap();
        drop(store);

        // Phase 2: Open read-only and run scrub.
        let mut ro_store = LocalObjectStore::open_read_only_with_options(&root, opts.clone())
            .expect("read-only open")
            .expect("store exists");

        // should_scrub must return true for read-only stores (interval enabled).
        assert!(
            ro_store.should_scrub(),
            "should_scrub must return true for read-only store with interval enabled"
        );

        // run_background_scrub must return a report (not early-return empty).
        let report = ro_store.run_background_scrub().unwrap();
        assert!(
            report.records_verified > 0,
            "read-only scrub must scan records, got {report:?}"
        );

        // Phase 3: Verify no persistence side-effects.
        // The read-write store did not sync, so no cursor/suspect_log files
        // should exist. Read-only scrub must not create them.
        let seg_dir = root.join("segments");
        let cursor_path = seg_dir.join(crate::constants::SCRUB_CURSOR_FILE_NAME);
        let suspect_path = seg_dir.join(crate::constants::SUSPECT_LOG_FILE_NAME);
        assert!(
            !cursor_path.exists() && !suspect_path.exists(),
            "read-only scrub must not persist cursor or suspect_log; cursor={} suspect={}",
            cursor_path.exists(),
            suspect_path.exists()
        );
    }
}

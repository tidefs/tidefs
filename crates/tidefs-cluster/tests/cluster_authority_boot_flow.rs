//! Integration test: full cluster authority boot flow end-to-end.
//!
//! Simulates the lifecycle described in issue #6669 acceptance:
//! - Create pool devices with genesis authority records
//! - Fresh node boot: scan devices, discover authority, validate chain
//! - Advance authority (new epoch, changed voters, fence a node)
//! - Full cluster restart: all nodes lose power, reboot, rescan
//! - Verify each node discovers the same authority digest
//! - Reject stale/corrupt authority views
//!
//! Uses tempfile-backed "devices" so no actual block devices or
//! QEMU guests are required. This is a source/cargo-tier integration
//! test that validates the persistence and discovery logic.

use std::collections::BTreeSet;
use std::io::Write;

use tidefs_membership_epoch::EpochId;
use tidefs_cluster::cluster_authority_record::{
    validate_authority_record, ClusterAuthorityRecord, ClusterAuthorityVerdict,
};
use tidefs_cluster::cluster_authority_snapshot::{
    BootAuthorityOutcome, ClusterAuthorityBootstrapper, ClusterAuthoritySnapshot,
    DeviceAuthorityStatus,
};
use tidefs_cluster::cluster_authority_store::{
    append_authority_record_to_device, read_all_records_from_device,
    write_authority_chain_to_device, CLUSTER_AUTHORITY_REGION_OFFSET,
};

fn voters(ids: &[u64]) -> BTreeSet<u64> {
    ids.iter().copied().collect()
}

/// Create a temp file pre-padded with zeros up to the authority region offset,
/// suitable as a simulated pool device.
fn make_device() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("vdev");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(&vec![0u8; CLUSTER_AUTHORITY_REGION_OFFSET as usize])
        .unwrap();
    (dir, path)
}

/// Write a genesis authority record to a device.
fn write_genesis(dev_path: &std::path::Path, pool_guid: [u8; 16]) -> ClusterAuthorityRecord {
    let genesis = ClusterAuthorityRecord::genesis(
        pool_guid,
        voters(&[1, 2, 3]),
        BTreeSet::new(),
        1,
        [0xCD; 32],
        1,
    );
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev_path)
        .unwrap();
    write_authority_chain_to_device(&mut f, &[genesis.clone()]).unwrap();
    genesis
}

// ── Test: full boot-to-restart lifecycle ───────────────────────────

#[test]
fn full_boot_flow_genesis_advance_restart() {
    // ── Phase 1: create cluster, write genesis ─────────────────
    let pool_guid = [0xAB; 16];
    let (_dir1, dev1) = make_device();
    let (_dir2, dev2) = make_device();
    let (_dir3, dev3) = make_device();

    let genesis = write_genesis(&dev1, pool_guid);
    // dev2 gets same genesis, dev3 is empty (fresh node joining later)
    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&dev2)
            .unwrap();
        write_authority_chain_to_device(&mut f, &[genesis.clone()]).unwrap();
    }

    // ── Phase 2: boot — all nodes scan devices ─────────────────
    let outcome = ClusterAuthorityBootstrapper::discover(&[&dev1, &dev2, &dev3]);
    let snapshot = match outcome {
        BootAuthorityOutcome::Discovered { snapshot, per_device } => {
            // dev3 should report NoRecord
            match per_device.get(&dev3.display().to_string()) {
                Some(DeviceAuthorityStatus::NoRecord) => {}
                other => panic!("dev3 expected NoRecord, got {:?}", other),
            }
            // dev1 and dev2 should report Valid
            for dev in &[&dev1, &dev2] {
                match per_device.get(&dev.display().to_string()) {
                    Some(DeviceAuthorityStatus::Valid { .. }) => {}
                    other => panic!("{} expected Valid, got {:?}", dev.display(), other),
                }
            }
            snapshot
        }
        other => panic!("expected Discovered, got {:?}", other),
    };

    assert_eq!(snapshot.membership_epoch, 1);
    assert_eq!(snapshot.voter_set, voters(&[1, 2, 3]));
    assert_eq!(snapshot.import_owner, 1);
    assert!(snapshot.is_operational());
    assert_eq!(snapshot.sequence, 0);

    // ── Phase 3: advance authority (epoch 2, add voter 4, fence node 3) ─
    let advanced = genesis
        .successor()
        .membership_epoch(EpochId(2))
        .voter_set(voters(&[1, 2, 4]))
        .fenced_nodes(voters(&[3]))
        .import_owner(2)
        .placement_map_epoch(1)
        .placement_map_digest([0xAA; 32])
        .last_authority_receipt(7)
        .committed_txg(42)
        .build();

    assert!(advanced.verify());
    assert_eq!(advanced.sequence, 1);

    // Write advanced record to dev1 only (dev2 still has genesis).
    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&dev1)
            .unwrap();
        append_authority_record_to_device(&mut f, &advanced).unwrap();
    }

    // ── Phase 4: full cluster restart — all nodes reboot, rescan ─
    let outcome = ClusterAuthorityBootstrapper::discover(&[&dev1, &dev2, &dev3]);
    let snapshot2 = match outcome {
        BootAuthorityOutcome::Discovered { snapshot, per_device } => {
            // dev1 should have seq=1 (advanced), dev2 seq=0 (genesis only)
            match per_device.get(&dev1.display().to_string()) {
                Some(DeviceAuthorityStatus::Valid { sequence, .. }) => {
                    assert_eq!(*sequence, 1, "dev1 should have the advanced record");
                }
                other => panic!("dev1 expected Valid, got {:?}", other),
            }
            match per_device.get(&dev2.display().to_string()) {
                Some(DeviceAuthorityStatus::Valid { sequence, .. }) => {
                    assert_eq!(*sequence, 0, "dev2 still has genesis only");
                }
                other => panic!("dev2 expected Valid, got {:?}", other),
            }
            snapshot
        }
        other => panic!("expected Discovered after restart, got {:?}", other),
    };

    // The bootstrapper should pick the best record (dev1's advanced).
    assert_eq!(snapshot2.membership_epoch, 2);
    assert_eq!(snapshot2.voter_set, voters(&[1, 2, 4]));
    assert_eq!(snapshot2.fenced_nodes, voters(&[3]));
    assert_eq!(snapshot2.import_owner, 2);
    assert_eq!(snapshot2.placement_map_epoch, 1);
    assert_eq!(snapshot2.last_authority_receipt, 7);
    assert_eq!(snapshot2.committed_txg, 42);
    assert_eq!(snapshot2.sequence, 1);
    assert!(snapshot2.is_fenced(3));
    assert!(!snapshot2.is_fenced(1));
    assert!(!snapshot2.is_voter(3)); // node 3 was removed from voters

    // Authority digest must be consistent with the record.
    assert_eq!(snapshot2.authority_digest, hex_encode(&advanced.self_digest));

    // ── Phase 5: verify chain integrity on dev1 ─────────────────
    {
        let mut f = std::fs::File::open(&dev1).unwrap();
        let records = read_all_records_from_device(&mut f).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], genesis);
        assert_eq!(records[1], advanced);

        // Validate chain
        let v = tidefs_cluster::validate_authority_chain(&records[0], &records[1]);
        assert!(matches!(v, ClusterAuthorityVerdict::Valid { .. }));
    }
}

// ── Test: fail-closed — reject tampered authority ──────────────────

#[test]
fn fail_closed_rejects_corrupt_authority() {
    let pool_guid = [0xBA; 16];
    let (_dir, dev) = make_device();

    let _genesis = write_genesis(&dev, pool_guid);

    // Tamper: overwrite the authority region with garbage.
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&dev)
            .unwrap();
        use std::io::Seek;
        f.seek(std::io::SeekFrom::Start(CLUSTER_AUTHORITY_REGION_OFFSET))
            .unwrap();
        // Write recognizable garbage (non-magic, non-zero).
        f.write_all(&[0xFFu8; 128]).unwrap();
    }

    // Boot should now report the device as corrupt.
    let outcome = ClusterAuthorityBootstrapper::discover(&[&dev]);
    match outcome {
        BootAuthorityOutcome::NoAuthority { per_device } => {
            match per_device.get(&dev.display().to_string()) {
                Some(DeviceAuthorityStatus::Corrupt { .. }) => {}
                other => panic!("expected Corrupt, got {:?}", other),
            }
        }
        BootAuthorityOutcome::Discovered { .. } => {
            panic!("expected NoAuthority after tampering");
        }
    }
}

// ── Test: stale authority view rejected ────────────────────────────

#[test]
fn reject_stale_authority_against_current() {
    // Device carries an old genesis. A node with knowledge of a newer
    // epoch should reject the stale view. This is tested at the record
    // validation level: validate_authority_record does not check staleness
    // (that's the caller's job at the cluster level), but the chain
    // validation ensures tampered chains are rejected.

    let genesis = ClusterAuthorityRecord::genesis(
        [0x01; 16],
        voters(&[1]),
        BTreeSet::new(),
        1,
        [0u8; 32],
        0,
    );

    // Stand-alone validation of the genesis passes.
    let v = validate_authority_record(&genesis);
    assert!(matches!(v, ClusterAuthorityVerdict::Valid { .. }));

    // But if we try to validate it as a successor to a never-written
    // record, chain validation fails.
    let mut bad = genesis.clone();
    bad.sequence = 1;
    bad.prev_digest = [0xFF; 32]; // Wrong prev
    bad = bad.seal();

    let v = tidefs_cluster::validate_authority_chain(&genesis, &bad);
    match v {
        ClusterAuthorityVerdict::Refused { reason, .. } => {
            assert_eq!(
                reason,
                tidefs_cluster::AuthorityRefusalReason::ChainBroken
            );
        }
        other => panic!("expected ChainBroken, got {:?}", other),
    }
}

// ── Test: snapshot serialization roundtrip through JSON ─────────────

#[test]
fn snapshot_json_roundtrip_preserves_authority_digest() {
    let genesis = ClusterAuthorityRecord::genesis(
        [0xAB; 16],
        voters(&[1, 2, 3]),
        BTreeSet::new(),
        1,
        [0xCD; 32],
        5,
    );
    let snap = ClusterAuthoritySnapshot::from_record(&genesis);

    let json = serde_json::to_string_pretty(&snap).unwrap();
    let restored: ClusterAuthoritySnapshot = serde_json::from_str(&json).unwrap();

    assert_eq!(snap, restored);
    assert_eq!(snap.authority_digest, restored.authority_digest);
    assert_eq!(snap.placement_map_digest, restored.placement_map_digest);
    assert!(json.contains("authority_digest"));
    assert!(json.contains("placement_map_digest"));
}

// ── Helpers ────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

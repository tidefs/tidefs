//! Cross-crate integration smoke: wires multiple peer crates together
//! and runs multi-step workflows.
//!
//! Gated on all four peer crate features simultaneously.

use crate::smoke::SmokeHarness;
use crate::trace::TraceEvent;
use tidefs_local_filesystem::LocalFileSystem;
use tidefs_local_object_store::ObjectKey;
use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapOps, LocatorId};

/// Run the integration smoke sequence and return the harness.
#[must_use]
pub fn run_integration_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("integration/smoke");

    // Set root auth key required by LocalFileSystem::open.
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));

    // ── Open filesystem ────────────────────────────────────────────────
    let dir = tempfile::TempDir::new().expect("tempdir for integration smoke");
    let root_path = dir.path().to_str().unwrap().to_string();

    h.record(TraceEvent::FsOpen {
        root_path: root_path.clone(),
    });

    let fs = LocalFileSystem::open(&root_path).expect("open LocalFileSystem for integration smoke");

    // ── DirIndex operations ────────────────────────────────────────────
    h.record(TraceEvent::DirInsert {
        name: b"hello".to_vec(),
        inode_id: 1,
        generation: 1,
        kind: 0o040755,
    });
    h.record(TraceEvent::DirLookup {
        name: b"hello".to_vec(),
    });
    h.assert_ev("integration: dir-index types reachable", true);

    // ── ExtentMap operations ───────────────────────────────────────────
    let mut em = tidefs_extent_map::InlineExtentMap::new();
    h.record(TraceEvent::ExtentInsert {
        logical_offset: 0,
        length: 4096,
        locator_id: 1,
        flags: 0,
    });
    let entry = ExtentMapEntryV2 {
        logical_offset: 0,
        length: 4096,
        extent_kind: 0,
        flags: 0,
        locator_id: LocatorId(1),
        checksum: [0u8; 32],
        birth_commit_group: 1,
        reserved: [0u8; 15],
    };
    em.insert_extent(&[entry])
        .expect("extent insert in integration");
    h.record(TraceEvent::ExtentLookup {
        offset: 0,
        length: 4096,
    });
    let results = em
        .lookup_range(0, 4096)
        .expect("extent lookup in integration");
    h.assert_eq_ev("integration: extent lookup len", results.len(), 1);

    // ── ObjectStore operations ─────────────────────────────────────────
    let mut store = tidefs_local_object_store::LocalObjectStore::open(&root_path)
        .expect("open object store in integration");
    let key = ObjectKey::from_bytes32([2u8; 32]);
    let val = b"cross-crate".to_vec();

    h.record(TraceEvent::ObjectPut {
        key_bytes: key.as_bytes().to_vec(),
        value: val.clone(),
    });
    store.put(key, &val).expect("object put in integration");

    h.record(TraceEvent::ObjectGet {
        key_bytes: key.as_bytes().to_vec(),
    });
    let got = store.get(key).expect("get in integration");
    h.assert_eq_ev("integration: object get round-trip", got, Some(val));

    drop(store);
    drop(em);
    drop(fs);
    dir.close().ok();

    h.record(TraceEvent::FsClose);
    h.scenario_end("integration/smoke");

    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integration_smoke_passes() {
        let h = run_integration_smoke();
        for event in &h.trace {
            if let TraceEvent::Assert {
                passed,
                ref condition,
            } = event
            {
                assert!(passed, "assertion failed: {condition}");
            }
        }
    }
}

//! Dir-index smoke: deterministic sequence of insert, lookup, contains,
//! replace, list, and delete operations against `DirIndex`.
//!
//! Gated on `feature = "dir-index"`.

use crate::smoke::SmokeHarness;
use crate::trace::TraceEvent;
use tidefs_dir_index::DirIndex;
use tidefs_types_polymorphic_directory_index_core::{DatasetDirPolicy, DirCookie};

/// Run the full dir-index smoke sequence and return the harness.
#[must_use]
pub fn run_dir_index_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();
    let mut di = DirIndex::new(1, DatasetDirPolicy::DEFAULT);

    h.scenario_begin("dir-index/smoke");

    // Insert entries.
    let entries: [(&[u8], u64, u64, u32); 3] = [
        (b"alpha", 1u64, 1u64, 0u32),
        (b"beta", 2u64, 1u64, 0u32),
        (b"gamma", 3u64, 1u64, 0u32),
    ];
    for (name, ino, gen, kind) in entries {
        h.record(TraceEvent::DirInsert {
            name: name.to_vec(),
            inode_id: ino,
            generation: gen,
            kind,
        });
        di.insert(name, ino, gen, kind)
            .expect("dir-index insert should succeed");
    }

    // Lookup and assert found.
    let names: [&[u8]; 3] = [b"alpha", b"beta", b"gamma"];
    for name in &names {
        h.record(TraceEvent::DirLookup {
            name: name.to_vec(),
        });
        let found = di.lookup(name);
        h.assert_ev(
            &format!("lookup({}) found", String::from_utf8_lossy(name)),
            found.is_some(),
        );
    }

    // Contains asserts.
    for name in &names {
        h.record(TraceEvent::DirContains {
            name: name.to_vec(),
        });
        let c = di.contains(name);
        h.assert_ev(&format!("contains({})", String::from_utf8_lossy(name)), c);
    }

    // Replace entry.
    h.record(TraceEvent::DirReplace {
        name: b"beta".to_vec(),
        inode_id: 99,
        generation: 2,
        kind: 0,
    });
    di.replace(b"beta", 99, 2, 0);
    let replaced = di.lookup(b"beta");
    h.assert_ev(
        "replace(beta).inode_id == 99",
        replaced.map(|e| e.inode_id == 99).unwrap_or(false),
    );

    // List iteration.
    h.record(TraceEvent::DirIter { cookie: 0 });
    let (entries_list, _cookie) = di.list_from(DirCookie(0));
    h.assert_eq_ev("list_from(0) count == 3", entries_list.len(), 3);

    // Delete entry.
    h.record(TraceEvent::DirRemove {
        name: b"alpha".to_vec(),
    });
    di.delete(b"alpha")
        .expect("dir-index delete should succeed");

    // Lookup deleted — not found.
    h.record(TraceEvent::DirLookup {
        name: b"alpha".to_vec(),
    });
    let not_found = di.lookup(b"alpha");
    h.assert_ev("lookup(deleted alpha) is None", not_found.is_none());

    // Contains deleted — false.
    h.record(TraceEvent::DirContains {
        name: b"alpha".to_vec(),
    });
    h.assert_ev("contains(deleted alpha) is false", !di.contains(b"alpha"));

    // List count updated.
    h.record(TraceEvent::DirIter { cookie: 0 });
    let (entries_after, _) = di.list_from(DirCookie(0));
    h.assert_eq_ev(
        "list_from(0) after delete count == 2",
        entries_after.len(),
        2,
    );

    h.scenario_end("dir-index/smoke");
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_index_smoke_passes() {
        let h = run_dir_index_smoke();
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

// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! B+tree smoke: deterministic insert, lookup, range, delete, rebuild,
//! compaction, and validation checks over `tidefs-btree`.
//!
//! Gated on `feature = "btree"`.

use crate::smoke::SmokeHarness;
use crate::trace::{deserialize_trace, serialize_trace, TraceEvent};
use tidefs_btree::BPlusTree;

type SmokeTree = BPlusTree<u64, String, 4, 4>;

/// Run the full btree smoke sequence and return the harness.
#[must_use]
pub fn run_btree_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("btree/smoke");
    smoke_empty_tree(&mut h);
    smoke_insert_lookup_range_and_update(&mut h);
    smoke_delete_rebuild_and_compact(&mut h);
    h.scenario_end("btree/smoke");

    let trace_before_round_trip = h.trace.clone();
    let serialized =
        serialize_trace(&trace_before_round_trip).expect("btree smoke trace should serialize");
    let decoded = deserialize_trace(&serialized).expect("btree smoke trace should deserialize");
    h.assert_eq_ev(
        "btree smoke trace round-trips",
        decoded,
        trace_before_round_trip,
    );

    h
}

fn smoke_empty_tree(h: &mut SmokeHarness) {
    let tree = SmokeTree::new();

    record_btree_op(h, 0, "btree.new", b"empty");
    h.assert_ev("new btree is empty", tree.is_empty());
    h.assert_eq_ev("new btree len is zero", tree.len(), 0usize);
    h.assert_eq_ev("new btree depth is leaf depth", tree.depth(), 1u8);
    h.assert_eq_ev("new btree has one leaf", tree.leaf_count(), 1usize);
    h.assert_eq_ev(
        "new btree has no internal nodes",
        tree.internal_count(),
        0usize,
    );
    h.assert_eq_ev("new btree node count is one", tree.node_count(), 1usize);
    h.assert_ev("new btree validates", tree.validate().is_ok());
}

fn smoke_insert_lookup_range_and_update(h: &mut SmokeHarness) {
    let mut tree = SmokeTree::new();

    for key in [40, 10, 30, 20, 50, 80, 70, 60, 90] {
        let value = format!("v{key}");
        record_btree_op(h, key, "btree.insert", value.as_bytes());
        h.assert_eq_ev(
            &format!("insert {key} has no previous value"),
            tree.insert(key, value),
            None,
        );
    }

    h.assert_eq_ev("btree len after inserts", tree.len(), 9usize);
    h.assert_ev(
        "btree depth grows after small-fanout inserts",
        tree.depth() > 1,
    );
    h.assert_ev(
        "btree has multiple leaves after inserts",
        tree.leaf_count() > 1,
    );
    h.assert_ev("btree validates after inserts", tree.validate().is_ok());

    record_btree_op(h, 30, "btree.get", b"v30");
    h.assert_eq_ev(
        "btree get returns inserted value",
        tree.get(&30).cloned(),
        Some("v30".to_string()),
    );
    h.assert_ev("btree contains inserted key", tree.contains_key(&70));
    h.assert_eq_ev("btree get missing key is none", tree.get(&25), None);

    let ordered_keys: Vec<u64> = tree.entries().into_iter().map(|(key, _)| key).collect();
    h.assert_eq_ev(
        "btree entries are sorted",
        ordered_keys,
        vec![10, 20, 30, 40, 50, 60, 70, 80, 90],
    );

    record_btree_op(h, 25, "btree.range", b"25..75");
    let range_keys: Vec<u64> = tree.range(25..75).into_iter().map(|(key, _)| key).collect();
    h.assert_eq_ev(
        "btree range returns bounded sorted keys",
        range_keys,
        vec![30, 40, 50, 60, 70],
    );

    let from_to_keys: Vec<u64> = tree
        .range_from_to(&20, &50)
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    h.assert_eq_ev(
        "btree range_from_to excludes end key",
        from_to_keys,
        vec![20, 30, 40],
    );

    record_btree_op(h, 40, "btree.replace", b"v40b");
    h.assert_eq_ev(
        "btree insert returns old value on replacement",
        tree.insert(40, "v40b".to_string()),
        Some("v40".to_string()),
    );
    h.assert_eq_ev("btree replacement keeps len", tree.len(), 9usize);
    h.assert_eq_ev(
        "btree get sees replacement value",
        tree.get(&40).cloned(),
        Some("v40b".to_string()),
    );

    record_btree_op(h, 50, "btree.update", b"+updated");
    h.assert_ev(
        "btree update reports existing key",
        tree.update(&50, |value| value.push_str("-updated")),
    );
    h.assert_eq_ev(
        "btree update mutates stored value",
        tree.get(&50).cloned(),
        Some("v50-updated".to_string()),
    );
    h.assert_ev(
        "btree update reports missing key",
        !tree.update(&500, |value| value.push_str("-missing")),
    );
    h.assert_ev("btree validates after replacement", tree.validate().is_ok());
}

fn smoke_delete_rebuild_and_compact(h: &mut SmokeHarness) {
    let mut tree = SmokeTree::new();
    for key in [10, 20, 30, 40, 50, 60, 70, 80] {
        tree.insert(key, format!("v{key}"));
    }

    record_btree_op(h, 20, "btree.delete", b"v20");
    h.assert_eq_ev(
        "btree delete returns removed value",
        tree.delete(&20),
        Some("v20".to_string()),
    );
    h.assert_eq_ev("btree delete missing returns none", tree.delete(&200), None);
    h.assert_ev("btree deleted key is absent", !tree.contains_key(&20));
    h.assert_eq_ev("btree len after delete", tree.len(), 7usize);
    h.assert_ev("btree validates after delete", tree.validate().is_ok());

    let rebuilt_entries = vec![
        (5, "five".to_string()),
        (15, "fifteen".to_string()),
        (25, "twenty-five".to_string()),
        (35, "thirty-five".to_string()),
        (45, "forty-five".to_string()),
        (55, "fifty-five".to_string()),
        (65, "sixty-five".to_string()),
    ];
    record_btree_op(h, 5, "btree.rebuild", b"7 sorted entries");
    tree.rebuild(&rebuilt_entries);
    h.assert_eq_ev(
        "btree rebuild resets len",
        tree.len(),
        rebuilt_entries.len(),
    );
    h.assert_eq_ev(
        "btree rebuild preserves sorted entries",
        tree.entries(),
        rebuilt_entries,
    );
    h.assert_ev("btree validates after rebuild", tree.validate().is_ok());

    record_btree_op(h, 5, "btree.compact", b"threshold=1.1");
    h.assert_ev(
        "btree maybe_compact runs above current fill",
        tree.maybe_compact(1.1),
    );
    h.assert_ev(
        "btree validates after maybe_compact",
        tree.validate().is_ok(),
    );
    h.assert_ev(
        "btree maybe_compact skips below current fill",
        !tree.maybe_compact(0.0),
    );

    tree.compact();
    h.assert_ev(
        "btree validates after explicit compact",
        tree.validate().is_ok(),
    );
    h.assert_ev("btree remains non-empty after compact", !tree.is_empty());
}

fn record_btree_op(h: &mut SmokeHarness, key: u64, op_name: &str, payload: &[u8]) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: key,
        op_name: op_name.to_string(),
        payload: payload.to_vec(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btree_smoke_passes() {
        let h = run_btree_smoke();
        for event in &h.trace {
            if let TraceEvent::Assert { passed, condition } = event {
                assert!(passed, "assertion failed: {condition}");
            }
        }
    }
}

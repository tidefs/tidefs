// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Smoke framework: deterministic harness that exercises peer crates.
//!
//! `SmokeHarness` instantiates one of each peer crate's core type (behind
//! feature gates), runs small deterministic operation sequences, records
//! every call into the trace oracle, and asserts post-condition invariants
//! (e.g., after insert + lookup the entry is found; after remove + lookup
//! the entry is absent).

use crate::trace::{Trace, TraceEvent};

// ── SmokeHarness ───────────────────────────────────────────────────────────

/// Central smoke harness.
///
/// Holds a trace buffer and provides helper methods for each peer crate's
/// smoke scenario.  Each method gates on its corresponding feature flag.
pub struct SmokeHarness {
    /// Accumulated event trace.
    pub trace: Trace,
    /// Whether assertions are strict (fail immediately) or lenient (record only).
    pub strict: bool,
}

impl SmokeHarness {
    /// Create a new smoke harness with an empty trace.
    #[must_use]
    pub fn new() -> Self {
        Self {
            trace: Vec::new(),
            strict: true,
        }
    }

    /// Create a new harness that records but never panics on assertion failure.
    #[must_use]
    pub fn lenient() -> Self {
        Self {
            trace: Vec::new(),
            strict: false,
        }
    }

    /// Record a single event.
    pub fn record(&mut self, event: TraceEvent) {
        self.trace.push(event);
    }

    /// Record an assertion outcome.
    pub fn assert_eq_ev<T: std::fmt::Debug + PartialEq>(
        &mut self,
        condition: &str,
        left: T,
        right: T,
    ) {
        let passed = left == right;
        self.trace.push(TraceEvent::Assert {
            condition: condition.to_string(),
            passed,
        });
        if self.strict && !passed {
            panic!("smoke assertion failed: {condition}  left={left:?}  right={right:?}");
        }
    }

    /// Record a simple boolean assertion.
    pub fn assert_ev(&mut self, condition: &str, value: bool) {
        self.trace.push(TraceEvent::Assert {
            condition: condition.to_string(),
            passed: value,
        });
        if self.strict && !value {
            panic!("smoke assertion failed: {condition}");
        }
    }

    /// Begin a named scenario.
    pub fn scenario_begin(&mut self, name: &str) {
        self.trace.push(TraceEvent::ScenarioBegin {
            name: name.to_string(),
        });
    }

    /// End a named scenario.
    pub fn scenario_end(&mut self, name: &str) {
        self.trace.push(TraceEvent::ScenarioEnd {
            name: name.to_string(),
        });
    }
}

impl Default for SmokeHarness {
    fn default() -> Self {
        Self::new()
    }
}

// ── btree smoke ───────────────────────────────────────────────────────────

#[cfg(feature = "storage-core")]
pub mod btree;

// ── block-allocator smoke ─────────────────────────────────────────────────

#[cfg(feature = "storage-core")]
pub mod block_allocator;

// ── ublk smoke ───────────────────────────────────────
#[cfg(feature = "ublk")]
pub mod block_volume_adapter_core;

// ── dir-index smoke ────────────────────────────────────────────────────────

#[cfg(feature = "storage-core")]
pub mod dir_index;

// ── inode-table smoke ──────────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod inode_table;

// ── inode-attributes smoke ─────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod inode_attributes;

// ── extent-map smoke ───────────────────────────────────────────────────────
#[cfg(feature = "storage-core")]
pub mod extent_map;

// ── object-store smoke ─────────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod object_store;

// ── encryption smoke ───────────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod encryption;

// ── object-io smoke ────────────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod object_io;

// ── xattr-storage smoke ────────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod xattr_storage;

// ── reclaim smoke ─────────────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod reclaim;

// ── namespace smoke ───────────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod namespace;

// ── permission smoke ───────────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod permission;

// ── fuse integration smoke ──────────────────────
#[cfg(feature = "fuse")]
pub mod fuse_basic_ops;
#[cfg(feature = "fuse")]
pub mod fuse_xattr_acl_locks;

// ── workers-locks smoke ────────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod workers_locks;

// ── P5-02 ingress smoke ───────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod ingress;

// ── P5-02 capacity smoke ──────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod capacity;

// ── P5-02 fusewire smoke ──────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod fusewire;

// ── P5-02 reply smoke ─────────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod reply;

// ── workers-io smoke ───────────────────────────────────────────────────────
#[cfg(all(feature = "fuse", test))]
pub mod workers_io;

// ── local-filesystem smoke ─────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod local_fs;

// ── VFS engine smoke ──────────────────────────────────────────────────────

// ── VFS engine contract tests ───────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod vfs_engine;
#[cfg(feature = "fuse")]
pub mod vfs_engine_contract;

// ── POSIX semantics smoke ─────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod posix_semantics;

// ── commit_group smoke ─────────────────────────────────────────────────────────────
#[cfg(feature = "fuse")]
pub mod commit_group;

// ── integration smoke (multiple crates wired together) ─────────────────────
#[cfg(feature = "fuse")]
pub mod integration;

// ── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_new_has_empty_trace() {
        let h = SmokeHarness::new();
        assert!(h.trace.is_empty());
        assert!(h.strict);
    }

    #[test]
    fn harness_records_scenario_events() {
        let mut h = SmokeHarness::new();
        h.scenario_begin("example");
        h.record(TraceEvent::DirInsert {
            name: b"test".to_vec(),
            inode_id: 1,
            generation: 1,
            kind: 0,
        });
        h.scenario_end("example");
        assert_eq!(h.trace.len(), 3);
        assert_eq!(h.trace[0].label(), "ScenarioBegin");
        assert_eq!(h.trace[1].label(), "DirInsert");
        assert_eq!(h.trace[2].label(), "ScenarioEnd");
    }

    #[test]
    fn harness_assert_passes() {
        let mut h = SmokeHarness::new();
        h.assert_eq_ev("smoke sanity", 1, 1);
        assert_eq!(h.trace.last().unwrap().label(), "Assert");
    }

    #[test]
    fn harness_assertion_trace_is_round_trippable() {
        let mut h = SmokeHarness::new();
        h.scenario_begin("rt");
        h.assert_eq_ev("2 == 2", 2, 2);
        h.scenario_end("rt");

        let data = crate::trace::serialize_trace(&h.trace).unwrap();
        let back = crate::trace::deserialize_trace(&data).unwrap();
        assert_eq!(h.trace, back);
    }
}

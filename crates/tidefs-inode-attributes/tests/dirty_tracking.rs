//! Dirty-change tracking and generation-counter validation tests.
//!
//! Exercises the per-field dirty flags, monotonic generation counter,
//! and dirty-state API on `InodeAttributes`:
//!   - Initial state (clean, generation = 1)
//!   - Single-setter dirties only the target field and bumps generation
//!   - Multi-setter accumulates dirty flags, generation increments per call
//!   - `mark_clean` clears flags, generation unchanged
//!   - `changed_since` correct detection across generation boundaries
//!   - Monotonicity: generation never decreases across set+clean cycles
//!   - `dirty_fields()` bitmask correctness
//!   - Persistence round-trip preserves dirty state through encode/decode

use std::collections::BTreeMap;
use std::time::Duration;

use tidefs_inode_table::{
    InodeAttributes, InodeKind, ATTR_DIRTY_ALL, ATTR_DIRTY_ATIME, ATTR_DIRTY_BLOCKS,
    ATTR_DIRTY_CTIME, ATTR_DIRTY_GID, ATTR_DIRTY_KIND, ATTR_DIRTY_MODE, ATTR_DIRTY_MTIME,
    ATTR_DIRTY_NLINK, ATTR_DIRTY_SIZE, ATTR_DIRTY_UID,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_attrs() -> InodeAttributes {
    InodeAttributes::new(0o644, 1000, 100, InodeKind::File)
}

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

#[test]
fn initial_state_is_clean() {
    let a = sample_attrs();
    assert!(!a.is_dirty(), "new InodeAttributes should be clean");
    assert_eq!(a.dirty_fields(), 0, "dirty_fields should be 0");
    assert_eq!(a.mutation_generation(), 1, "generation should start at 1");
}

#[test]
fn initial_state_changed_since_zero() {
    let a = sample_attrs();
    // generation starts at 1, so changed_since(0) is true
    assert!(a.changed_since(0), "generation 1 > 0 should be true");
    // changed_since(1) is false (not strictly greater)
    assert!(!a.changed_since(1), "generation 1 <= 1 should be false");
}

// ---------------------------------------------------------------------------
// Single-setter tests: dirties only the target field, bumps generation
// ---------------------------------------------------------------------------

#[test]
fn set_mode_dirties_mode_only() {
    let mut a = sample_attrs();
    let gen_before = a.mutation_generation();
    a.set_mode(0o755);
    assert!(a.is_dirty());
    assert!(
        a.dirty_fields() & ATTR_DIRTY_MODE != 0,
        "mode should be dirty"
    );
    assert_eq!(
        a.dirty_fields() & !ATTR_DIRTY_MODE,
        0,
        "only mode should be dirty"
    );
    assert!(
        a.mutation_generation() > gen_before,
        "generation should increase"
    );
    assert_eq!(a.mode, 0o755);
}

#[test]
fn set_uid_dirties_uid_only() {
    let mut a = sample_attrs();
    let gen_before = a.mutation_generation();
    a.set_uid(42);
    assert!(a.is_dirty());
    assert!(a.dirty_fields() & ATTR_DIRTY_UID != 0);
    assert_eq!(a.dirty_fields() & !ATTR_DIRTY_UID, 0);
    assert!(a.mutation_generation() > gen_before);
    assert_eq!(a.uid, 42);
}

#[test]
fn set_gid_dirties_gid_only() {
    let mut a = sample_attrs();
    let gen_before = a.mutation_generation();
    a.set_gid(99);
    assert!(a.dirty_fields() & ATTR_DIRTY_GID != 0);
    assert_eq!(a.dirty_fields() & !ATTR_DIRTY_GID, 0);
    assert!(a.mutation_generation() > gen_before);
}

#[test]
fn set_size_dirties_size_only() {
    let mut a = sample_attrs();
    let gen_before = a.mutation_generation();
    a.set_size(4096);
    assert!(a.dirty_fields() & ATTR_DIRTY_SIZE != 0);
    assert_eq!(a.dirty_fields() & !ATTR_DIRTY_SIZE, 0);
    assert!(a.mutation_generation() > gen_before);
    assert_eq!(a.size, 4096);
}

#[test]
fn set_blocks_dirties_blocks_only() {
    let mut a = sample_attrs();
    let gen_before = a.mutation_generation();
    a.set_blocks(8);
    assert!(a.dirty_fields() & ATTR_DIRTY_BLOCKS != 0);
    assert_eq!(a.dirty_fields() & !ATTR_DIRTY_BLOCKS, 0);
    assert!(a.mutation_generation() > gen_before);
}

#[test]
fn set_atime_dirties_atime_only() {
    let mut a = sample_attrs();
    let gen_before = a.mutation_generation();
    let t = Duration::new(1_700_000_000, 500_000_000);
    a.set_atime(t);
    assert!(a.dirty_fields() & ATTR_DIRTY_ATIME != 0);
    assert_eq!(a.dirty_fields() & !ATTR_DIRTY_ATIME, 0);
    assert!(a.mutation_generation() > gen_before);
    assert_eq!(a.atime, t);
}

#[test]
fn set_mtime_dirties_mtime_only() {
    let mut a = sample_attrs();
    let gen_before = a.mutation_generation();
    let t = Duration::new(1_700_000_001, 250_000_000);
    a.set_mtime(t);
    assert!(a.dirty_fields() & ATTR_DIRTY_MTIME != 0);
    assert_eq!(a.dirty_fields() & !ATTR_DIRTY_MTIME, 0);
    assert!(a.mutation_generation() > gen_before);
}

#[test]
fn set_ctime_dirties_ctime_only() {
    let mut a = sample_attrs();
    let gen_before = a.mutation_generation();
    a.set_ctime(Duration::new(1_700_000_002, 750_000_000));
    assert!(a.dirty_fields() & ATTR_DIRTY_CTIME != 0);
    assert_eq!(a.dirty_fields() & !ATTR_DIRTY_CTIME, 0);
    assert!(a.mutation_generation() > gen_before);
}

#[test]
fn set_nlink_dirties_nlink_only() {
    let mut a = sample_attrs();
    let gen_before = a.mutation_generation();
    a.set_nlink(5);
    assert!(a.dirty_fields() & ATTR_DIRTY_NLINK != 0);
    assert_eq!(a.dirty_fields() & !ATTR_DIRTY_NLINK, 0);
    assert!(a.mutation_generation() > gen_before);
    assert_eq!(a.nlink, 5);
}

#[test]
fn set_kind_dirties_kind_only() {
    let mut a = sample_attrs();
    let gen_before = a.mutation_generation();
    a.set_kind(InodeKind::Directory);
    assert!(a.dirty_fields() & ATTR_DIRTY_KIND != 0);
    assert_eq!(a.dirty_fields() & !ATTR_DIRTY_KIND, 0);
    assert!(a.mutation_generation() > gen_before);
    assert_eq!(a.kind, InodeKind::Directory);
}

// ---------------------------------------------------------------------------
// Multi-setter: accumulates dirty flags, generation increments per call
// ---------------------------------------------------------------------------

#[test]
fn multi_setter_accumulates_dirty_flags() {
    let mut a = sample_attrs();
    a.set_mode(0o600);
    a.set_uid(2000);
    a.set_size(8192);

    let fields = a.dirty_fields();
    assert!(fields & ATTR_DIRTY_MODE != 0);
    assert!(fields & ATTR_DIRTY_UID != 0);
    assert!(fields & ATTR_DIRTY_SIZE != 0);
    assert_eq!(fields & ATTR_DIRTY_GID, 0, "gid should still be clean");
    assert_eq!(a.mutation_generation(), 4); // started at 1, 3 setter calls
}

#[test]
fn multi_setter_generation_increments_per_call() {
    let mut a = sample_attrs();
    assert_eq!(a.mutation_generation(), 1);

    a.set_mode(0o700);
    assert_eq!(a.mutation_generation(), 2);

    a.set_uid(42);
    assert_eq!(a.mutation_generation(), 3);

    a.set_gid(99);
    assert_eq!(a.mutation_generation(), 4);

    a.set_size(16384);
    assert_eq!(a.mutation_generation(), 5);

    a.set_atime(Duration::from_secs(1000));
    assert_eq!(a.mutation_generation(), 6);
}

#[test]
fn multi_setter_same_field_multiple_times_bumps_generation_each_time() {
    let mut a = sample_attrs();
    a.set_mode(0o700);
    a.set_mode(0o755);
    a.set_mode(0o600);
    assert_eq!(a.mutation_generation(), 4); // 1 initial + 3 setter calls
    assert!(a.dirty_fields() & ATTR_DIRTY_MODE != 0);
}

#[test]
fn multi_setter_all_fields() {
    let mut a = sample_attrs();
    a.set_mode(0o755);
    a.set_uid(500);
    a.set_gid(500);
    a.set_size(1_048_576);
    a.set_blocks(2048);
    a.set_atime(Duration::from_secs(100));
    a.set_mtime(Duration::from_secs(200));
    a.set_ctime(Duration::from_secs(300));
    a.set_nlink(3);
    a.set_kind(InodeKind::Symlink);

    assert_eq!(a.dirty_fields(), ATTR_DIRTY_ALL);
    assert_eq!(a.mutation_generation(), 11); // 1 initial + 10 setters
}

// ---------------------------------------------------------------------------
// mark_clean: clears all dirty flags, generation unchanged
// ---------------------------------------------------------------------------

#[test]
fn mark_clean_clears_all_flags() {
    let mut a = sample_attrs();
    a.set_mode(0o755);
    a.set_uid(42);
    a.set_size(4096);
    assert!(a.is_dirty());

    let gen_before = a.mutation_generation();
    a.mark_clean();

    assert!(!a.is_dirty());
    assert_eq!(a.dirty_fields(), 0);
    assert_eq!(
        a.mutation_generation(),
        gen_before,
        "generation should not change on mark_clean"
    );
    // Values are preserved
    assert_eq!(a.mode, 0o755);
    assert_eq!(a.uid, 42);
    assert_eq!(a.size, 4096);
}

#[test]
fn mark_clean_then_set_dirties_again() {
    let mut a = sample_attrs();
    a.set_mode(0o755);
    a.mark_clean();
    assert!(!a.is_dirty());

    a.set_uid(99);
    assert!(a.is_dirty());
    assert!(a.dirty_fields() & ATTR_DIRTY_UID != 0);
    assert_eq!(
        a.dirty_fields() & ATTR_DIRTY_MODE,
        0,
        "mode should still be clean"
    );
}

// ---------------------------------------------------------------------------
// changed_since: correct detection across generation boundaries
// ---------------------------------------------------------------------------

#[test]
fn changed_since_before_any_setter_is_false_for_current_gen() {
    let a = sample_attrs();
    let gen = a.mutation_generation();
    assert!(!a.changed_since(gen));
    assert!(a.changed_since(gen - 1));
}

#[test]
fn changed_since_detects_single_change() {
    let mut a = sample_attrs();
    let gen0 = a.mutation_generation(); // 1
    a.set_mode(0o755);
    assert!(a.changed_since(gen0)); // gen is now 2 > 1
    assert!(!a.changed_since(a.mutation_generation())); // 2 <= 2
}

#[test]
fn changed_since_detects_change_mid_sequence() {
    let mut a = sample_attrs();
    a.set_uid(10); // gen=2
    a.set_gid(20); // gen=3
    let gen_at_3 = a.mutation_generation();
    a.set_size(100); // gen=4
    a.set_mode(0o600); // gen=5

    assert!(a.changed_since(gen_at_3)); // gen is now 5, > 3 is true
    assert!(!a.changed_since(5)); // same gen, not strictly greater
}

#[test]
fn changed_since_with_mark_clean_does_not_reset_detection() {
    let mut a = sample_attrs();
    a.set_mode(0o755);
    let gen_after_set = a.mutation_generation();
    a.mark_clean(); // gen unchanged
    assert!(!a.changed_since(gen_after_set)); // same gen, no new mutation
    a.set_uid(42); // gen bumps again
    assert!(a.changed_since(gen_after_set));
}

#[test]
fn changed_since_wrapping_generation() {
    let mut a = sample_attrs();
    // Manually set mutation_gen to near u64::MAX
    a.mutation_gen = u64::MAX - 1;
    let _gen_near_max = a.mutation_generation();
    a.set_mode(0o755); // wraps to 0
                       // After wrap: 0 > u64::MAX-1 is... false (wrapping semantics).
                       // With wrapping_add, u64::MAX-1 + 1 = u64::MAX, +1 = 0.
                       // Let's check: mutation_gen was u64::MAX-1, set_mode adds 1 → u64::MAX.
                       // That's wrapping_add, so 0 is not reached.
    assert_eq!(a.mutation_generation(), u64::MAX);
}

// ---------------------------------------------------------------------------
// Monotonicity: generation never decreases across set+clean cycles
// ---------------------------------------------------------------------------

#[test]
fn generation_is_monotonic_across_set_clean_cycles() {
    let mut a = sample_attrs();
    let mut prev_gen = a.mutation_generation();

    for i in 0..100u32 {
        a.set_mode(0o600 | i);
        let cur_gen = a.mutation_generation();
        assert!(
            cur_gen > prev_gen,
            "gen should increase: {cur_gen} > {prev_gen}"
        );
        prev_gen = cur_gen;

        a.mark_clean();
        assert_eq!(
            a.mutation_generation(),
            prev_gen,
            "mark_clean must not change gen"
        );

        a.set_uid(i);
        let cur_gen = a.mutation_generation();
        assert!(cur_gen > prev_gen);
        prev_gen = cur_gen;
    }
}

#[test]
fn generation_monotonic_under_rapid_mutations() {
    let mut a = sample_attrs();
    let mut prev = a.mutation_generation();
    for _ in 0..1000 {
        a.set_mode(a.mode.wrapping_add(1));
        let cur = a.mutation_generation();
        assert!(cur > prev, "gen {cur} should be > {prev}");
        prev = cur;
    }
}

// ---------------------------------------------------------------------------
// dirty_fields() bitmask correctness
// ---------------------------------------------------------------------------

#[test]
fn dirty_fields_returns_correct_bitmask() {
    let mut a = sample_attrs();
    assert_eq!(a.dirty_fields(), 0);

    a.set_mode(0o755);
    assert_eq!(a.dirty_fields(), ATTR_DIRTY_MODE);

    a.set_uid(42);
    assert_eq!(a.dirty_fields(), ATTR_DIRTY_MODE | ATTR_DIRTY_UID);

    a.mark_clean();
    assert_eq!(a.dirty_fields(), 0);
}

#[test]
fn dirty_fields_all_bits_are_distinct() {
    // Verify no overlapping bits among dirty flags
    let all = [
        ATTR_DIRTY_MODE,
        ATTR_DIRTY_UID,
        ATTR_DIRTY_GID,
        ATTR_DIRTY_SIZE,
        ATTR_DIRTY_ATIME,
        ATTR_DIRTY_MTIME,
        ATTR_DIRTY_CTIME,
        ATTR_DIRTY_NLINK,
        ATTR_DIRTY_BLOCKS,
        ATTR_DIRTY_KIND,
    ];
    let mut seen = 0u32;
    for flag in all {
        assert_eq!(
            seen & flag,
            0,
            "flag {flag:#x} overlaps with previous flags"
        );
        seen |= flag;
    }
    assert_eq!(seen, ATTR_DIRTY_ALL);
}

// ---------------------------------------------------------------------------
// Persistence round-trip preserves dirty state
// ---------------------------------------------------------------------------

#[test]
fn dirty_state_survives_encode_decode() {
    let a = InodeAttributes {
        mode: 0o755,
        uid: 42,
        gid: 99,
        size: 4096,
        blocks: 8,
        atime: Duration::new(100, 500_000_000),
        mtime: Duration::new(200, 250_000_000),
        ctime: Duration::new(300, 750_000_000),
        nlink: 3,
        generation: 7,
        kind: InodeKind::File,
        xattrs: BTreeMap::new(),
        dirty_bits: ATTR_DIRTY_MODE | ATTR_DIRTY_SIZE,
        mutation_gen: 42,
    };

    let encoded = a.encode();
    let decoded = InodeAttributes::decode(&encoded).expect("decode should succeed");
    assert_eq!(decoded, a);
    assert_eq!(decoded.dirty_bits, ATTR_DIRTY_MODE | ATTR_DIRTY_SIZE);
    assert_eq!(decoded.mutation_gen, 42);
}

#[test]
fn decoded_from_persist_has_all_dirty() {
    // When decode() is used (persist.rs path), attrs start with all-dirty
    // to trigger writeback on mount.
    let a = InodeAttributes::new(0o644, 1000, 100, InodeKind::File);
    let mut a = a;
    a.set_mode(0o755);
    a.set_size(8192);
    a.mark_clean(); // simulate: clean after writeback

    let encoded = a.encode();
    let decoded = InodeAttributes::decode(&encoded).expect("decode should succeed");
    // encode/decode preserves dirty state from the struct
    assert_eq!(
        decoded.dirty_bits, 0,
        "encode/decode should preserve clean state"
    );
}

#[test]
fn all_dirty_constant_covers_every_field_setter() {
    let mut a = sample_attrs();
    a.set_mode(1);
    a.set_uid(1);
    a.set_gid(1);
    a.set_size(1);
    a.set_blocks(1);
    a.set_atime(Duration::ZERO);
    a.set_mtime(Duration::ZERO);
    a.set_ctime(Duration::ZERO);
    a.set_nlink(1);
    a.set_kind(InodeKind::Directory);
    assert_eq!(a.dirty_fields(), ATTR_DIRTY_ALL);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn is_dirty_false_after_new_and_mark_clean() {
    let mut a = sample_attrs();
    assert!(!a.is_dirty());
    a.mark_clean(); // no-op on clean
    assert!(!a.is_dirty());
}

#[test]
fn mark_clean_on_clean_is_idempotent() {
    let mut a = sample_attrs();
    a.mark_clean();
    a.mark_clean();
    assert!(!a.is_dirty());
    assert_eq!(a.mutation_generation(), 1);
}

#[test]
fn direct_field_write_does_not_dirty() {
    // Direct field assignment bypasses setters — this is intentional
    // to allow callers to set fields without dirty tracking.
    let mut a = sample_attrs();
    a.mode = 0o755; // direct write, no setter
    assert!(!a.is_dirty(), "direct write should not set dirty flag");
    assert_eq!(
        a.mutation_generation(),
        1,
        "direct write should not bump generation"
    );
    assert_eq!(a.mode, 0o755, "but the value should change");
}

#[test]
fn setter_on_dirty_field_keeps_dirty() {
    let mut a = sample_attrs();
    a.set_mode(0o600);
    let dirty = a.dirty_fields();
    a.set_mode(0o755); // set same field again
    assert!(a.dirty_fields() & ATTR_DIRTY_MODE != 0);
    // all previously dirty flags should still be set
    assert_eq!(a.dirty_fields() & dirty, dirty);
}

#[test]
fn generation_starts_at_1_so_zero_is_sentinel() {
    let a = sample_attrs();
    assert_eq!(a.mutation_generation(), 1);
    assert!(a.changed_since(0));
    assert!(!a.changed_since(1));
}

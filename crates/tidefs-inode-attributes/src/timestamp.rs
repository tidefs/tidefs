//! POSIX timestamp maintenance: automatic atime/mtime/ctime update rules.
//!
//! Implements the POSIX timestamp transition rules for read (atime),
//! write (mtime+ctime), truncate (mtime+ctime), and metadata-change
//! (ctime) operations, with configurable `relatime`, `noatime`, and
//! `strictatime` mount-option semantics.
//!
//! The core entry point is [`apply_timestamp_rules`] which mutates a
//! [`PosixAttrs`] in-place according to the chosen [`TimestampPolicy`]
//! and the current wall-clock time.

use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_types_vfs_core::PosixAttrs;

// ── Timestamp policy ─────────────────────────────────────────────────────

/// Mount-level policy controlling automatic atime updates.
///
/// POSIX requires atime to be updated on read(2) unless the filesystem
/// is mounted with a policy that suppresses it. `Relatime` (the default)
/// balances correctness and write amplification by only updating atime
/// when the previous atime is not newer than mtime or ctime, or more than
/// 24 hours have elapsed since the last atime update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampPolicy {
    /// `relatime`: update atime only when previous atime <= mtime,
    /// previous atime <= ctime, or >24h since last atime update.
    Relatime,
    /// `noatime`: suppress atime updates except when the operation also
    /// changes mtime or ctime.
    Noatime,
    /// `strictatime`: always update atime on read.
    Strictatime,
}

impl Default for TimestampPolicy {
    fn default() -> Self {
        Self::Relatime
    }
}

// ── Update kind ───────────────────────────────────────────────────────────

/// The kind of operation that triggers timestamp maintenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampUpdate {
    /// A read operation: may update atime (subject to policy).
    Read,
    /// A write operation: updates mtime and ctime.
    Write,
    /// A truncate operation: updates mtime and ctime.
    Truncate,
    /// A metadata mutation (chmod, chown, utimens, link, unlink, rename):
    /// updates ctime.
    MetadataChange,
}

// ── Wall-clock helper ─────────────────────────────────────────────────────

fn current_time_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(i64::MAX)
}

/// Number of nanoseconds in 24 hours (used by relatime staleness check).
const RELATIME_24H_NS: i64 = 86_400_000_000_000;

// ── Core rule engine ──────────────────────────────────────────────────────

/// Apply POSIX timestamp transition rules to `attrs` in-place.
///
/// * `update` — what kind of operation triggered the update.
/// * `attrs` — mutable reference to the inode attributes; timestamps are
///   modified in-place.
/// * `policy` — the mount-level atime policy (`Relatime`, `Noatime`, or
///   `Strictatime`).
///
/// Returns `true` when at least one timestamp field was modified.
pub fn apply_timestamp_rules(
    update: TimestampUpdate,
    attrs: &mut PosixAttrs,
    policy: TimestampPolicy,
) -> bool {
    let now = current_time_ns();
    apply_timestamp_rules_at(update, attrs, policy, now)
}

/// Apply timestamp rules with an explicit wall-clock value (for testability).
///
/// All semantics match [`apply_timestamp_rules`].
pub fn apply_timestamp_rules_at(
    update: TimestampUpdate,
    attrs: &mut PosixAttrs,
    policy: TimestampPolicy,
    now_ns: i64,
) -> bool {
    match update {
        TimestampUpdate::Read => apply_atime_rules(attrs, policy, now_ns),
        TimestampUpdate::Write => apply_mtime_ctime_rules(attrs, now_ns),
        TimestampUpdate::Truncate => apply_mtime_ctime_rules(attrs, now_ns),
        TimestampUpdate::MetadataChange => apply_ctime_only_rules(attrs, now_ns),
    }
}

// ── Per-operation rules ───────────────────────────────────────────────────

/// Apply mtime+ctime update (used by write and truncate).
fn apply_mtime_ctime_rules(attrs: &mut PosixAttrs, now_ns: i64) -> bool {
    attrs.mtime_ns = now_ns;
    attrs.ctime_ns = now_ns;
    true
}

/// Apply ctime-only update (used by metadata mutations).
fn apply_ctime_only_rules(attrs: &mut PosixAttrs, now_ns: i64) -> bool {
    attrs.ctime_ns = now_ns;
    true
}

/// Apply atime update subject to the configured policy.
///
/// `strictatime` always updates. `noatime` suppresses updates.
/// `relatime` updates only when:
/// - the previous atime is not newer than mtime, or
/// - the previous atime is not newer than ctime, or
/// - more than 24 hours have elapsed since the last atime update.
fn apply_atime_rules(attrs: &mut PosixAttrs, policy: TimestampPolicy, now_ns: i64) -> bool {
    match policy {
        TimestampPolicy::Strictatime => {
            attrs.atime_ns = now_ns;
            true
        }
        TimestampPolicy::Noatime => false,
        TimestampPolicy::Relatime => {
            if should_update_atime_relatime(attrs, now_ns) {
                attrs.atime_ns = now_ns;
                true
            } else {
                false
            }
        }
    }
}

/// Relatime decision: should atime be updated?
fn should_update_atime_relatime(attrs: &PosixAttrs, now_ns: i64) -> bool {
    if attrs.atime_ns <= attrs.mtime_ns {
        return true;
    }
    if attrs.atime_ns <= attrs.ctime_ns {
        return true;
    }
    if now_ns.saturating_sub(attrs.atime_ns) >= RELATIME_24H_NS {
        return true;
    }
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn base_attrs() -> PosixAttrs {
        PosixAttrs {
            mode: 0o644,
            uid: 1000,
            gid: 100,
            nlink: 1,
            rdev: 0,
            atime_ns: 1_000_000_000,
            mtime_ns: 2_000_000_000,
            ctime_ns: 3_000_000_000,
            btime_ns: 0,
            size: 4096,
            blocks_512: 8,
            blksize: 4096,
        }
    }

    // ── Read updates atime ────────────────────────────────────────────────

    #[test]
    fn read_updates_atime_strictatime() {
        let mut attrs = base_attrs();
        let now = 9_000_000_000;
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Strictatime,
            now,
        );
        assert!(changed);
        assert_eq!(attrs.atime_ns, now);
        assert_eq!(attrs.mtime_ns, 2_000_000_000);
        assert_eq!(attrs.ctime_ns, 3_000_000_000);
    }

    #[test]
    fn read_updates_atime_relatime_when_atime_older_than_mtime() {
        let mut attrs = base_attrs();
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Relatime,
            9_000_000_000,
        );
        assert!(changed);
        assert_eq!(attrs.atime_ns, 9_000_000_000);
    }

    #[test]
    fn read_updates_atime_relatime_when_atime_older_than_ctime() {
        let mut attrs = base_attrs();
        attrs.mtime_ns = 500_000_000;
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Relatime,
            9_000_000_000,
        );
        assert!(changed);
        assert_eq!(attrs.atime_ns, 9_000_000_000);
    }

    #[test]
    fn read_suppresses_atime_relatime_when_atime_recent() {
        let mut attrs = base_attrs();
        attrs.atime_ns = 8_000_000_000;
        attrs.mtime_ns = 5_000_000_000;
        attrs.ctime_ns = 6_000_000_000;
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Relatime,
            9_000_000_000,
        );
        assert!(!changed);
        assert_eq!(attrs.atime_ns, 8_000_000_000);
    }

    #[test]
    fn read_updates_atime_relatime_after_24_hours() {
        let mut attrs = base_attrs();
        attrs.atime_ns = 1_000_000_000;
        attrs.mtime_ns = 500_000_000;
        attrs.ctime_ns = 600_000_000;
        let now = 1_000_000_000 + RELATIME_24H_NS + 1;
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Relatime,
            now,
        );
        assert!(changed);
        assert_eq!(attrs.atime_ns, now);
    }

    #[test]
    fn read_suppresses_atime_noatime() {
        let mut attrs = base_attrs();
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Noatime,
            9_000_000_000,
        );
        assert!(!changed);
        assert_eq!(attrs.atime_ns, 1_000_000_000);
    }

    // ── Write updates mtime and ctime ─────────────────────────────────────

    #[test]
    fn write_updates_mtime_and_ctime() {
        let mut attrs = base_attrs();
        let now = 9_000_000_000;
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Write,
            &mut attrs,
            TimestampPolicy::Relatime,
            now,
        );
        assert!(changed);
        assert_eq!(attrs.mtime_ns, now);
        assert_eq!(attrs.ctime_ns, now);
        assert_eq!(attrs.atime_ns, 1_000_000_000);
    }

    #[test]
    fn write_policy_does_not_affect_mtime_ctime() {
        for policy in &[
            TimestampPolicy::Relatime,
            TimestampPolicy::Noatime,
            TimestampPolicy::Strictatime,
        ] {
            let mut attrs = base_attrs();
            let now = 9_000_000_000;
            apply_timestamp_rules_at(TimestampUpdate::Write, &mut attrs, *policy, now);
            assert_eq!(attrs.mtime_ns, now, "mtime for {policy:?}");
            assert_eq!(attrs.ctime_ns, now, "ctime for {policy:?}");
        }
    }

    // ── Truncate updates mtime and ctime ──────────────────────────────────

    #[test]
    fn truncate_updates_mtime_and_ctime() {
        let mut attrs = base_attrs();
        let now = 9_000_000_000;
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Truncate,
            &mut attrs,
            TimestampPolicy::Relatime,
            now,
        );
        assert!(changed);
        assert_eq!(attrs.mtime_ns, now);
        assert_eq!(attrs.ctime_ns, now);
        assert_eq!(attrs.atime_ns, 1_000_000_000);
    }

    // ── Metadata change updates ctime only ────────────────────────────────

    #[test]
    fn metadata_change_updates_ctime_only() {
        let mut attrs = base_attrs();
        let now = 9_000_000_000;
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::MetadataChange,
            &mut attrs,
            TimestampPolicy::Relatime,
            now,
        );
        assert!(changed);
        assert_eq!(attrs.ctime_ns, now);
        assert_eq!(attrs.mtime_ns, 2_000_000_000);
        assert_eq!(attrs.atime_ns, 1_000_000_000);
    }

    // ── Nanosecond preservation ───────────────────────────────────────────

    #[test]
    fn nanosecond_preservation_read() {
        let mut attrs = base_attrs();
        let now = 1_500_000_001;
        apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Strictatime,
            now,
        );
        assert_eq!(attrs.atime_ns, now);
    }

    #[test]
    fn nanosecond_preservation_write() {
        let mut attrs = base_attrs();
        let now = 2_500_000_001;
        apply_timestamp_rules_at(
            TimestampUpdate::Write,
            &mut attrs,
            TimestampPolicy::Relatime,
            now,
        );
        assert_eq!(attrs.mtime_ns, now);
        assert_eq!(attrs.ctime_ns, now);
    }

    // ── Edge cases ────────────────────────────────────────────────────────

    #[test]
    fn zero_timestamp_bootstrap() {
        let mut attrs = PosixAttrs {
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 0,
            rdev: 0,
            atime_ns: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            btime_ns: 0,
            size: 0,
            blocks_512: 0,
            blksize: 0,
        };
        let now = 10_000_000_000;
        apply_timestamp_rules_at(
            TimestampUpdate::Write,
            &mut attrs,
            TimestampPolicy::Relatime,
            now,
        );
        assert_eq!(attrs.mtime_ns, now);
        assert_eq!(attrs.ctime_ns, now);
    }

    #[test]
    fn relatime_boundary_mtime_newer_triggers_update() {
        let mut attrs = base_attrs();
        assert!(attrs.atime_ns < attrs.mtime_ns);
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Relatime,
            9_000_000_000,
        );
        assert!(changed);
    }

    #[test]
    fn relatime_boundary_ctime_newer_triggers_update() {
        let mut attrs = base_attrs();
        attrs.mtime_ns = 500_000_000;
        assert!(attrs.atime_ns < attrs.ctime_ns);
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Relatime,
            9_000_000_000,
        );
        assert!(changed);
    }

    #[test]
    fn relatime_boundary_equal_mtime_triggers_update() {
        let mut attrs = base_attrs();
        attrs.atime_ns = 5_000_000_000;
        attrs.mtime_ns = 5_000_000_000;
        attrs.ctime_ns = 4_000_000_000;
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Relatime,
            9_000_000_000,
        );
        assert!(changed);
        assert_eq!(attrs.atime_ns, 9_000_000_000);
    }

    #[test]
    fn relatime_boundary_equal_ctime_triggers_update() {
        let mut attrs = base_attrs();
        attrs.atime_ns = 5_000_000_000;
        attrs.mtime_ns = 4_000_000_000;
        attrs.ctime_ns = 5_000_000_000;
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Relatime,
            9_000_000_000,
        );
        assert!(changed);
        assert_eq!(attrs.atime_ns, 9_000_000_000);
    }

    #[test]
    fn noatime_with_explicit_utimes() {
        let mut attrs = base_attrs();
        apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Noatime,
            9_000_000_000,
        );
        assert_eq!(attrs.atime_ns, 1_000_000_000);
    }

    #[test]
    fn directory_readdir_atime() {
        let mut attrs = base_attrs();
        let now = 9_000_000_000;
        apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Strictatime,
            now,
        );
        assert_eq!(attrs.atime_ns, now);
    }

    #[test]
    fn metadata_only_does_not_touch_mtime() {
        let mut attrs = base_attrs();
        let old_mtime = attrs.mtime_ns;
        apply_timestamp_rules_at(
            TimestampUpdate::MetadataChange,
            &mut attrs,
            TimestampPolicy::Relatime,
            9_000_000_000,
        );
        assert_eq!(attrs.mtime_ns, old_mtime);
    }

    #[test]
    fn concurrent_updates_idempotent_atime() {
        let mut attrs = base_attrs();
        let t1 = 10_000_000_000;
        apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Relatime,
            t1,
        );
        assert_eq!(attrs.atime_ns, t1);
        let t2 = t1 + 1;
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Relatime,
            t2,
        );
        assert!(!changed);
        assert_eq!(attrs.atime_ns, t1);
    }

    #[test]
    fn relatime_24h_boundary_exactly_24h_triggers() {
        let mut attrs = base_attrs();
        attrs.atime_ns = 1_000_000_000;
        attrs.mtime_ns = 500_000_000;
        attrs.ctime_ns = 600_000_000;
        let now = attrs.atime_ns + RELATIME_24H_NS;
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Relatime,
            now,
        );
        assert!(changed);
        assert_eq!(attrs.atime_ns, now);
    }

    #[test]
    fn relatime_24h_boundary_just_under_24h_suppressed() {
        let mut attrs = base_attrs();
        attrs.atime_ns = 1_000_000_000;
        attrs.mtime_ns = 500_000_000;
        attrs.ctime_ns = 600_000_000;
        let now = attrs.atime_ns + RELATIME_24H_NS - 1;
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Relatime,
            now,
        );
        assert!(!changed);
        assert_eq!(attrs.atime_ns, 1_000_000_000);
    }

    #[test]
    fn timestamp_update_always_returns_true_for_write() {
        let mut attrs = base_attrs();
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Write,
            &mut attrs,
            TimestampPolicy::Noatime,
            9_000_000_000,
        );
        assert!(changed);
    }

    #[test]
    fn timestamp_update_always_returns_true_for_truncate() {
        let mut attrs = base_attrs();
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Truncate,
            &mut attrs,
            TimestampPolicy::Noatime,
            9_000_000_000,
        );
        assert!(changed);
    }

    #[test]
    fn timestamp_update_always_returns_true_for_metadata_change() {
        let mut attrs = base_attrs();
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::MetadataChange,
            &mut attrs,
            TimestampPolicy::Noatime,
            9_000_000_000,
        );
        assert!(changed);
    }

    #[test]
    fn size_and_blksize_untouched_by_timestamp_update() {
        let mut attrs = base_attrs();
        let old_size = attrs.size;
        let old_blksize = attrs.blksize;
        apply_timestamp_rules_at(
            TimestampUpdate::Write,
            &mut attrs,
            TimestampPolicy::Relatime,
            9_000_000_000,
        );
        assert_eq!(attrs.size, old_size);
        assert_eq!(attrs.blksize, old_blksize);
    }

    #[test]
    fn writable_atime_update_not_suppressed_by_noatime_during_write() {
        let mut attrs = base_attrs();
        let old_atime = attrs.atime_ns;
        apply_timestamp_rules_at(
            TimestampUpdate::Write,
            &mut attrs,
            TimestampPolicy::Noatime,
            9_000_000_000,
        );
        assert_eq!(attrs.mtime_ns, 9_000_000_000);
        assert_eq!(attrs.ctime_ns, 9_000_000_000);
        assert_eq!(attrs.atime_ns, old_atime);
    }

    #[test]
    fn relatime_atime_equals_mtime_still_checks_ctime() {
        let mut attrs = base_attrs();
        attrs.atime_ns = 5_000_000_000;
        attrs.mtime_ns = 5_000_000_000;
        attrs.ctime_ns = 7_000_000_000;
        let changed = apply_timestamp_rules_at(
            TimestampUpdate::Read,
            &mut attrs,
            TimestampPolicy::Relatime,
            9_000_000_000,
        );
        assert!(changed);
        assert_eq!(attrs.atime_ns, 9_000_000_000);
    }

    #[test]
    fn relatime_default_policy_is_relatime() {
        assert_eq!(TimestampPolicy::default(), TimestampPolicy::Relatime);
    }
}

//! Deterministic crash injection hooks for commit_group-boundary testing (#1230).
//!
//! This module provides a thread_local!-based crash injection mechanism
//! that allows tests to trigger controlled crashes at precise points in
//! the commit_group lifecycle, filesystem operations, and background services.
//!
//! The mechanism is zero-cost in production: when no hooks are armed,
//! check_crash_hook() is a single Option check followed by a return.
//!
//! ## Determinism
//!
//! Same armed hook + same seed-based workload + same FixedClock =
//! same crash outcome. Hook counters advance strictly, ensuring
//! deterministic replay with the trace oracle (#1174).

use std::collections::BTreeMap;
use tidefs_local_object_store::CrashInjectionPoint;

/// Crash trigger mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashMode {
    /// Force an immediate abnormal termination via abort().
    /// The process dies without running destructors or flushing buffers.
    /// Equivalent behaviour to receiving SIGKILL.
    Sigkill,
    /// Exit with code 99, simulating power loss.
    /// Panic with a structured message for test harness catch_unwind.
    TestPanic,
    PowerLoss,
}

/// Configuration for a crash injection test.
#[derive(Clone, Debug)]
pub struct CrashTestConfig {
    /// Map of crash hook -> hit count threshold (crash on Nth hit).
    pub armed_hooks: BTreeMap<CrashInjectionPoint, u64>,
    /// Crash trigger mode.
    pub crash_mode: CrashMode,
}

// ---------------------------------------------------------------------------
// Thread-local state
// ---------------------------------------------------------------------------

struct CrashHookState {
    armed: BTreeMap<CrashInjectionPoint, u64>,
    crash_mode: CrashMode,
    fired: bool,
    hit_count: u64,
}

thread_local! {
    static CRASH_HOOK_STATE: std::cell::RefCell<Option<CrashHookState>> =
        const { std::cell::RefCell::new(None) };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Arm crash hooks for a test. Subsequent calls to check_crash_hook()
/// will decrement hit counters for armed hooks and trigger a crash when
/// a counter reaches zero.
pub fn arm_crash_hooks(config: CrashTestConfig) {
    CRASH_HOOK_STATE.with(|state| {
        *state.borrow_mut() = Some(CrashHookState {
            armed: config.armed_hooks,
            crash_mode: config.crash_mode,
            fired: false,
            hit_count: 0,
        });
    });
}

/// Disarm all crash hooks. Safe to call even if no hooks are armed.
pub fn disarm_crash_hooks() {
    CRASH_HOOK_STATE.with(|state| {
        *state.borrow_mut() = None;
    });
}

/// Check whether a crash should be triggered at the given injection point.
///
/// If the point is armed and the hit counter reaches zero, the process
/// is terminated according to the configured CrashMode.
///
/// Returns true if a crash was triggered (the caller should not continue),
/// but in practice this function never returns when a crash fires.
pub fn check_crash_hook(point: CrashInjectionPoint) -> bool {
    CRASH_HOOK_STATE.with(|state| {
        let mut state = state.borrow_mut();
        match state.as_mut() {
            None => false,
            Some(s) => {
                let trigger = match s.armed.get_mut(&point) {
                    None => return false,
                    Some(count) => {
                        if *count == 0 {
                            return false;
                        }
                        *count -= 1;
                        s.hit_count += 1;
                        *count == 0
                    }
                };

                if !trigger {
                    return false;
                }

                s.fired = true;
                match s.crash_mode {
                    CrashMode::Sigkill => {
                        // abort() sends SIGABRT and terminates immediately
                        // without running destructors, equivalent to SIGKILL
                        // for crash-recovery testing purposes.
                        std::process::abort();
                    }
                    CrashMode::PowerLoss => {
                        std::process::exit(99);
                    }
                    CrashMode::TestPanic => {
                        panic!("CRASH_HOOK_FIRED: {point:?}");
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disarmed_hook_never_crashes() {
        assert!(!check_crash_hook(
            CrashInjectionPoint::CommitGroupBeforeQuiesce
        ));
    }

    #[test]
    fn armed_hook_ignores_wrong_point() {
        let mut hooks = BTreeMap::new();
        hooks.insert(CrashInjectionPoint::CommitGroupBeforeQuiesce, 1);
        arm_crash_hooks(CrashTestConfig {
            armed_hooks: hooks,
            crash_mode: CrashMode::PowerLoss,
        });
        assert!(!check_crash_hook(
            CrashInjectionPoint::CommitGroupAfterQuiesce
        ));
        assert!(!check_crash_hook(
            CrashInjectionPoint::CommitGroupBeforeSync
        ));
        disarm_crash_hooks();
    }

    #[test]
    fn armed_hook_countdown() {
        let mut hooks = BTreeMap::new();
        hooks.insert(CrashInjectionPoint::CommitGroupBeforeQuiesce, 2);
        arm_crash_hooks(CrashTestConfig {
            armed_hooks: hooks,
            crash_mode: CrashMode::PowerLoss,
        });
        // First hit: count 2→1, no crash
        assert!(!check_crash_hook(
            CrashInjectionPoint::CommitGroupBeforeQuiesce
        ));
        disarm_crash_hooks();
    }

    #[test]
    fn disarm_clears_state() {
        let mut hooks = BTreeMap::new();
        hooks.insert(CrashInjectionPoint::CommitGroupBeforeSync, 1);
        arm_crash_hooks(CrashTestConfig {
            armed_hooks: hooks,
            crash_mode: CrashMode::PowerLoss,
        });
        disarm_crash_hooks();
        assert!(!check_crash_hook(
            CrashInjectionPoint::CommitGroupBeforeSync
        ));
    }
}

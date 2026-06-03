//! FUSE `destroy` handler — graceful session teardown.
//!
//! Provides:
//! - [`DestroyContext`]: identity context for a FUSE destroy operation.
//! - [`handle_destroy`]: entry point for `FUSE_DESTROY` (opcode 38)
//!   that orchestrates ordered teardown: drain forget batch, flush
//!   pending I/O, commit the intent log, and signal shutdown.
//!
//! # FUSE protocol semantics
//!
//! - `FUSE_DESTROY` (opcode 38): Sent by the kernel when the filesystem
//!   is unmounted.  The daemon must perform graceful teardown: drain
//!   pending operations, flush dirty data, commit a final consistent
//!   state, and release resources.  After destroy, no further FUSE
//!   requests will arrive.
//!
//! # Best-effort teardown
//!
//! Destroy must not hang — the kernel expects the daemon to exit
//! promptly after processing this message.  All teardown steps are
//! best-effort: failures are logged but do not block the shutdown
//! sequence.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::destroy;
//!
//! let ctx = destroy::DestroyContext::new();
//! destroy::handle_destroy(&ctx, || {
//!     // Step 1: drain forget batch
//!     // Step 2: drain pending writeback
//!     // Step 3: flush open file handles
//!     // Step 4: commit intent log
//!     // Step 5: write final committed root
//!     // Step 6: signal shutdown handle
//! });
//! ```

use std::fmt;

// ---------------------------------------------------------------------------
// DestroyContext
// ---------------------------------------------------------------------------

/// Identity context for a FUSE `destroy` request.
///
/// Carries metadata about the teardown operation.  Currently a
/// zero-sized marker type; future extensions may add teardown-time
/// policy (e.g. drain timeout).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DestroyContext;

impl DestroyContext {
    /// Create a new destroy context.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

// ---------------------------------------------------------------------------
// DestroyError
// ---------------------------------------------------------------------------

/// Errors that can occur during destroy teardown.
///
/// All errors are non-fatal: destroy is best-effort and must not
/// prevent the daemon from exiting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DestroyError {
    /// Drain step failed (e.g. writeback flush error).
    Drain(String),
    /// Intent-log commit failed.
    Commit(String),
    /// Final committed-root write failed.
    FinalRoot(String),
    /// Shutdown signal failed.
    Shutdown(String),
}

impl fmt::Display for DestroyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Drain(msg) => write!(f, "destroy drain: {msg}"),
            Self::Commit(msg) => write!(f, "destroy commit: {msg}"),
            Self::FinalRoot(msg) => write!(f, "destroy final root: {msg}"),
            Self::Shutdown(msg) => write!(f, "destroy shutdown: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// handle_destroy — ordered teardown entry point
// ---------------------------------------------------------------------------

/// Execute the ordered destroy teardown sequence.
///
/// Calls `teardown()` which should perform all shutdown steps.
/// Failures are collected as `DestroyError` values and returned;
/// the caller should log them but must not allow them to block
/// daemon exit.
///
/// # Teardown order
///
/// The canonical teardown sequence is:
///
/// 1. Drain the forget batch (process any remaining deferred
///    `FUSE_FORGET` entries).
/// 2. Drain pending writeback (flush dirty pages to storage).
/// 3. Flush all open file handles.
/// 4. Commit the intent log (ensure crash safety).
/// 5. Write the final committed root.
/// 6. Signal the shutdown handle (wake any waiters).
///
/// Steps are executed in order.  A failure in one step does not
/// prevent subsequent steps from running.
#[inline]
pub fn handle_destroy(
    _ctx: &DestroyContext,
    teardown: impl FnOnce() -> Vec<DestroyError>,
) -> Vec<DestroyError> {
    teardown()
}

// ---------------------------------------------------------------------------
// Canned teardown helpers
// ---------------------------------------------------------------------------

/// A teardown step that never fails.
///
/// Use this for optional steps that may not be wired (e.g. no
/// shutdown handle attached).
#[inline]
pub fn teardown_noop() -> Result<(), DestroyError> {
    Ok(())
}

/// Wrap a fallible teardown step, converting `Err(e)` into
/// `DestroyError::Drain(e.to_string())`.
#[inline]
pub fn teardown_drain_step(result: Result<(), impl ToString>) -> Result<(), DestroyError> {
    result.map_err(|e| DestroyError::Drain(e.to_string()))
}

/// Wrap a fallible commit step, converting `Err(e)` into
/// `DestroyError::Commit(e.to_string())`.
#[inline]
pub fn teardown_commit_step(result: Result<(), impl ToString>) -> Result<(), DestroyError> {
    result.map_err(|e| DestroyError::Commit(e.to_string()))
}

/// Wrap a fallible final-root step, converting `Err(e)` into
/// `DestroyError::FinalRoot(e.to_string())`.
#[inline]
pub fn teardown_final_root_step(result: Result<(), impl ToString>) -> Result<(), DestroyError> {
    result.map_err(|e| DestroyError::FinalRoot(e.to_string()))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DestroyContext ---------------------------------------------------

    #[test]
    fn destroy_context_new_is_default() {
        let ctx = DestroyContext::new();
        assert_eq!(ctx, DestroyContext);
    }

    #[test]
    fn destroy_context_copy_and_clone() {
        let ctx = DestroyContext::new();
        let copy = ctx;
        assert_eq!(ctx, copy);
        let clone = ctx;
        assert_eq!(ctx, clone);
    }

    #[test]
    fn destroy_context_debug() {
        let ctx = DestroyContext::new();
        let s = format!("{ctx:?}");
        assert!(!s.is_empty());
    }

    // -- handle_destroy --------------------------------------------------

    #[test]
    fn handle_destroy_empty_teardown() {
        let ctx = DestroyContext::new();
        let errors = handle_destroy(&ctx, std::vec::Vec::new);
        assert!(errors.is_empty());
    }

    #[test]
    fn handle_destroy_with_errors() {
        let ctx = DestroyContext::new();
        let errors = handle_destroy(&ctx, || {
            vec![
                DestroyError::Drain("writeback flush failed".into()),
                DestroyError::Commit("intent log full".into()),
            ]
        });
        assert_eq!(errors.len(), 2);
        assert!(matches!(errors[0], DestroyError::Drain(_)));
        assert!(matches!(errors[1], DestroyError::Commit(_)));
    }

    #[test]
    fn handle_destroy_all_error_variants() {
        let ctx = DestroyContext::new();
        let errors = handle_destroy(&ctx, || {
            vec![
                DestroyError::Drain("d1".into()),
                DestroyError::Commit("c1".into()),
                DestroyError::FinalRoot("f1".into()),
                DestroyError::Shutdown("s1".into()),
            ]
        });
        assert_eq!(errors.len(), 4);
    }

    // -- DestroyError::Display -------------------------------------------

    #[test]
    fn destroy_error_drain_display() {
        let e = DestroyError::Drain("test".into());
        assert_eq!(e.to_string(), "destroy drain: test");
    }

    #[test]
    fn destroy_error_commit_display() {
        let e = DestroyError::Commit("test".into());
        assert_eq!(e.to_string(), "destroy commit: test");
    }

    #[test]
    fn destroy_error_final_root_display() {
        let e = DestroyError::FinalRoot("test".into());
        assert_eq!(e.to_string(), "destroy final root: test");
    }

    #[test]
    fn destroy_error_shutdown_display() {
        let e = DestroyError::Shutdown("test".into());
        assert_eq!(e.to_string(), "destroy shutdown: test");
    }

    #[test]
    fn destroy_error_clone_and_eq() {
        let e1 = DestroyError::Drain("msg".into());
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn destroy_error_debug() {
        let e = DestroyError::Commit("dbg".into());
        let s = format!("{e:?}");
        assert!(s.contains("Commit"));
        assert!(s.contains("dbg"));
    }

    // -- Teardown helpers ------------------------------------------------

    #[test]
    fn teardown_noop_returns_ok() {
        assert_eq!(teardown_noop(), Ok(()));
    }

    #[test]
    fn teardown_drain_step_ok() {
        let r: Result<(), &str> = Ok(());
        assert_eq!(teardown_drain_step(r), Ok(()));
    }

    #[test]
    fn teardown_drain_step_err() {
        let r: Result<(), &str> = Err("fail");
        let e = teardown_drain_step(r);
        assert!(matches!(e, Err(DestroyError::Drain(_))));
    }

    #[test]
    fn teardown_commit_step_ok() {
        let r: Result<(), &str> = Ok(());
        assert_eq!(teardown_commit_step(r), Ok(()));
    }

    #[test]
    fn teardown_commit_step_err() {
        let r: Result<(), &str> = Err("fail");
        let e = teardown_commit_step(r);
        assert!(matches!(e, Err(DestroyError::Commit(_))));
    }

    #[test]
    fn teardown_final_root_step_ok() {
        let r: Result<(), &str> = Ok(());
        assert_eq!(teardown_final_root_step(r), Ok(()));
    }

    #[test]
    fn teardown_final_root_step_err() {
        let r: Result<(), &str> = Err("fail");
        let e = teardown_final_root_step(r);
        assert!(matches!(e, Err(DestroyError::FinalRoot(_))));
    }

    // -- Integration: handle_destroy with teardown steps -----------------

    #[test]
    fn handle_destroy_collects_step_errors() {
        let ctx = DestroyContext::new();
        let errors = handle_destroy(&ctx, || {
            let mut errs = Vec::new();
            // Simulate each teardown step
            if let Err(e) = teardown_drain_step(Err("drain failure")) {
                errs.push(e);
            }
            if let Err(e) = teardown_commit_step(Err("commit failure")) {
                errs.push(e);
            }
            if teardown_noop().is_err() {
                errs.push(DestroyError::Drain("unexpected".into()));
            }
            errs
        });
        assert_eq!(errors.len(), 2);
    }

    #[test]
    fn handle_destroy_all_steps_ok() {
        let ctx = DestroyContext::new();
        let errors = handle_destroy(&ctx, || {
            let mut errs = Vec::new();
            if let Err(e) = teardown_drain_step(Ok::<(), &str>(())) {
                errs.push(e);
            }
            if let Err(e) = teardown_commit_step(Ok::<(), &str>(())) {
                errs.push(e);
            }
            if let Err(e) = teardown_final_root_step(Ok::<(), &str>(())) {
                errs.push(e);
            }
            errs
        });
        assert!(errors.is_empty());
    }
}

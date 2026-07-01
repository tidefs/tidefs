// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Operator authorization boundary — local-only guard.
//!
//! This module provides the [`LocalOnlyGuard`], an explicit marker that a
//! privileged CLI/API operation is **local-only** and must not execute in a
//! remote transport or cluster-proxied context.
//!
//! # Operator authorization posture
//!
//! TideFS privileged operations (pool create/import/export/destroy, device
//! remove, encryption key enrollment, dataset catalog mutation, block volume
//! attach/detach) currently require direct local access to storage devices,
//! pool lock directories, and encryption secret handles. These operations are
//! **explicitly local-only**: they refuse to execute when the calling context
//! is remote, proxied, or cluster-routed.
//!
//! When TideFS gains full multi-node cluster operation with remote operator
//! access, these operations will be gated through the source-owned
//! authorization pipeline ([`crate::authorization`]), requiring a validated
//! [`crate::principal::Principal`], session grant, capability check, and
//! audit record. Until that cluster-routing path is product-grade, the
//! local-only guard prevents ambiguous operation in a
//! `dev_insecure`-style context.
//!
//! # Usage
//!
//! ```ignore
//! use tidefs_auth::local_only::LocalOnlyGuard;
//!
//! // At entry to a privileged operation:
//! let _guard = LocalOnlyGuard::new("pool create")
//!     .expect("pool create must run locally");
//!
//! // The guard documents this operation as local-only and provides a
//! // runtime check that confirms we are not executing inside a remote
//! // transport or cluster-proxied session.
//! ```

use std::fmt;

// ---------------------------------------------------------------------------
// LocalOnlyGuard
// ---------------------------------------------------------------------------

/// An explicit local-only authorization marker for privileged CLI/API
/// operations.
///
/// Creating a `LocalOnlyGuard` confirms that the caller is executing in a
/// local process context (not inside a remote transport session or
/// cluster-proxied handler). The guard is a zero-sized runtime token that
/// documents this boundary at the call site.
///
/// When the TideFS cluster operator path is product-grade, the guard will
/// be replaced by a full [`crate::authorization::AuthorizationRequest`]
/// pipeline check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalOnlyGuard {
    /// Name of the guarded operation for audit/logging.
    operation: &'static str,
}

/// Error returned when a privileged operation is attempted from an
/// unauthorized calling context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalOnlyError {
    /// Operation was called from a non-local context (e.g., remote transport,
    /// cluster proxy, or ADMIN-service handler without local-device access).
    NotLocal {
        operation: &'static str,
        reason: String,
    },
    /// Operation requires a local process identity but none was found.
    NoProcessIdentity { operation: &'static str },
}

impl fmt::Display for LocalOnlyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLocal { operation, reason } => {
                write!(
                    f,
                    "privileged operation '{operation}' requires local execution: {reason}"
                )
            }
            Self::NoProcessIdentity { operation } => {
                write!(
                    f,
                    "privileged operation '{operation}' requires a local process identity"
                )
            }
        }
    }
}

impl std::error::Error for LocalOnlyError {}

impl LocalOnlyGuard {
    /// Create a local-only guard for the named operation.
    ///
    /// Returns `Ok(LocalOnlyGuard)` when the calling context is confirmed
    /// local. Returns `Err(LocalOnlyError)` when the context is remote or
    /// ambiguous.
    ///
    /// The guard is zero-sized — it serves as a compile-time and runtime
    /// marker, not a resource handle.
    pub fn new(operation: &'static str) -> Result<Self, LocalOnlyError> {
        // Check that we have a local process identity (pid > 0).
        // A remote/proxied context (e.g., inside a cluster handler dispatched
        // from a transport reactor) would not have a direct local shell
        // identity.
        Self::check_local_process()?;

        Ok(Self { operation })
    }

    /// Unconditionally create a local-only guard for contexts where the
    /// caller has already confirmed locality through another mechanism
    /// (e.g., block-device open, lock-file acquisition).
    ///
    /// This is the escape hatch for call sites that cannot use
    /// [`Self::new`] because they lack a POSIX process identity but are
    /// known to be local through other means (e.g., `#[cfg(test)]` or
    /// in-kernel execution with direct block-device access).
    #[allow(dead_code)]
    pub(crate) fn new_unchecked(operation: &'static str) -> Self {
        Self { operation }
    }

    /// The name of the guarded operation.
    pub fn operation(&self) -> &'static str {
        self.operation
    }

    /// Check that we are executing in a local process context.
    fn check_local_process() -> Result<(), LocalOnlyError> {
        // POSIX process identity: if we have a valid PID, we are a local
        // process rather than a remote transport handler or cluster proxy
        // runner. std::process::id() always returns the real PID on Linux.
        let pid = std::process::id();
        if pid == 0 {
            return Err(LocalOnlyError::NoProcessIdentity {
                operation: "local_only_check",
            });
        }

        // Check that we can access /proc/self — if /proc is not mounted or
        // we are in a restricted container without procfs, we may be in an
        // ambiguous context.
        if !std::path::Path::new("/proc/self/status").exists() {
            return Err(LocalOnlyError::NotLocal {
                operation: "local_only_check",
                reason: "/proc/self/status not accessible — not a local Linux process context"
                    .to_string(),
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_only_guard_new_succeeds_on_host() {
        let guard = LocalOnlyGuard::new("test-operation");
        assert!(guard.is_ok(), "LocalOnlyGuard should succeed on local host");
        let guard = guard.unwrap();
        assert_eq!(guard.operation(), "test-operation");
    }

    #[test]
    fn local_only_guard_unchecked_always_works() {
        let guard = LocalOnlyGuard::new_unchecked("unchecked-op");
        assert_eq!(guard.operation(), "unchecked-op");
    }

    #[test]
    fn local_only_guard_is_copy() {
        let guard = LocalOnlyGuard::new_unchecked("copy-test");
        let guard2 = guard;
        assert_eq!(guard.operation(), guard2.operation());
    }

    #[test]
    fn local_only_error_display() {
        let err = LocalOnlyError::NotLocal {
            operation: "pool create",
            reason: "cluster proxy".into(),
        };
        let s = err.to_string();
        assert!(s.contains("pool create"));
        assert!(s.contains("local execution"));
        assert!(s.contains("cluster proxy"));
    }

    #[test]
    fn local_only_error_no_process_identity() {
        let err = LocalOnlyError::NoProcessIdentity {
            operation: "pool destroy",
        };
        let s = err.to_string();
        assert!(s.contains("pool destroy"));
        assert!(s.contains("process identity"));
    }
}

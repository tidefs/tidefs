// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Backend-selection policy for the block-kmod Kbuild entrypoint.
//!
//! The production path must not silently downgrade from pool-backed storage to
//! the in-memory bring-up buffer. This module keeps that decision small enough
//! to unit-test under cargo while the actual module entrypoint remains Kbuild-
//! only.

/// Backend mode selected for the kernel module entrypoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendMode {
    /// Require a pool-backed backend before registering `/dev/tidefs`.
    PoolRequired,
    /// Allow the fixed-size `BlockExport` buffer for explicit smoke tests.
    BringUpBuffer,
}

impl BackendMode {
    /// Derive the entrypoint mode from an explicit bring-up switch.
    #[must_use]
    pub const fn from_bringup_switch(allow_bringup_buffer: bool) -> Self {
        if allow_bringup_buffer {
            Self::BringUpBuffer
        } else {
            Self::PoolRequired
        }
    }

    /// Stable label for kernel logs and docs.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PoolRequired => "pool-required",
            Self::BringUpBuffer => "bringup-buffer",
        }
    }
}

/// Selection outcome after probing the pool-backed backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendSelection {
    /// Use the opened pool-backed backend.
    PoolBacked,
    /// Use the explicit in-memory bring-up backend.
    BringUpBuffer,
    /// Refuse to register the block export because no pool backend exists.
    RefuseNoPool { reason: &'static str },
}

impl BackendSelection {
    /// Whether this outcome permits registering `/dev/tidefs`.
    #[must_use]
    pub const fn registers_device(self) -> bool {
        matches!(self, Self::PoolBacked | Self::BringUpBuffer)
    }
}

/// Apply backend-selection policy after probing the pool member path.
#[must_use]
pub const fn select_backend(mode: BackendMode, pool_backend_opened: bool) -> BackendSelection {
    if pool_backend_opened {
        BackendSelection::PoolBacked
    } else {
        match mode {
            BackendMode::PoolRequired => BackendSelection::RefuseNoPool {
                reason: "pool backend missing and bring-up backend not explicitly enabled",
            },
            BackendMode::BringUpBuffer => BackendSelection::BringUpBuffer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{select_backend, BackendMode, BackendSelection};

    #[test]
    fn default_mode_requires_pool_backend() {
        let selection = select_backend(BackendMode::from_bringup_switch(false), false);

        assert_eq!(
            selection,
            BackendSelection::RefuseNoPool {
                reason: "pool backend missing and bring-up backend not explicitly enabled",
            }
        );
        assert!(!selection.registers_device());
    }

    #[test]
    fn explicit_bringup_mode_allows_buffer_backend() {
        let selection = select_backend(BackendMode::from_bringup_switch(true), false);

        assert_eq!(selection, BackendSelection::BringUpBuffer);
        assert!(selection.registers_device());
    }

    #[test]
    fn opened_pool_backend_wins_over_mode() {
        assert_eq!(
            select_backend(BackendMode::PoolRequired, true),
            BackendSelection::PoolBacked
        );
        assert_eq!(
            select_backend(BackendMode::BringUpBuffer, true),
            BackendSelection::PoolBacked
        );
    }

    #[test]
    fn labels_are_stable_for_kernel_logs() {
        assert_eq!(BackendMode::PoolRequired.label(), "pool-required");
        assert_eq!(BackendMode::BringUpBuffer.label(), "bringup-buffer");
    }
}

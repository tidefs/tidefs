//! Queue lifecycle state machine for ublk device attach, drain, and teardown.
//!
//! The [`QueueLifecycle`] type enforces drain-before-removal semantics:
//! an attached device must transition through [`QueueLifecycleState::Draining`]
//! before it can enter [`QueueLifecycleState::Removing`], ensuring in-flight
//! I/O is completed before the kernel `UBLK_CMD_DEL_DEV` is issued.
//!
//! After reaching [`QueueLifecycleState::Removed`], a device may be
//! re-attached by calling [`QueueLifecycle::attach`] again.
//!
//! # State transition diagram
//!
//! ```text
//! Unattached ──attach()──▶ Attached ──drain()──▶ Draining
//!      ▲                      │                      │
//!      │                      │                      │
//!      │                 remove_idempotent()    remove()
//!      │                      │                      │
//!      │                      ▼                      ▼
//!      └─────────────── Removed ◀──confirm_removed()── Removing
//!            re-attach via attach()
//! ```

use std::fmt;

/// The five canonical lifecycle states for a ublk device queue.
///
/// The state machine enforces drain-before-removal: a device must pass
/// through `Draining` before it can reach `Removing`, ensuring all
/// in-flight I/O is completed before kernel device teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueLifecycleState {
    /// No device is present. This is the initial state before any
    /// device is attached, and the state after a successful `remove()`
    /// followed by `confirm_removed()`.
    Unattached,
    /// Device is live and accepting block I/O through the ublk
    /// data-queue rings. This is the operational state.
    Attached,
    /// Drain has been initiated; in-flight I/O is completing.
    /// No new I/O requests are accepted while draining.
    Draining,
    /// Device removal is in progress. The kernel `UBLK_CMD_DEL_DEV`
    /// has been issued (or is about to be), and resource cleanup
    /// (fd close, buffer release, queue unregistration) is pending.
    Removing,
    /// Device has been fully removed. All kernel resources have been
    /// freed, file descriptors closed, and the device is ready for
    /// garbage collection or re-attach.
    Removed,
}

impl QueueLifecycleState {
    /// Human-readable state name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unattached => "unattached",
            Self::Attached => "attached",
            Self::Draining => "draining",
            Self::Removing => "removing",
            Self::Removed => "removed",
        }
    }

    /// Returns `true` if the device is in a state where it can accept I/O.
    #[must_use]
    pub const fn is_io_capable(self) -> bool {
        matches!(self, Self::Attached)
    }

    /// Returns `true` if the device is in a terminal-ish state from which
    /// re-attach is possible (`Unattached` or `Removed`).
    #[must_use]
    pub const fn is_re_attachable(self) -> bool {
        matches!(self, Self::Unattached | Self::Removed)
    }

    /// Returns `true` if the state is part of the teardown sequence.
    #[must_use]
    pub const fn is_tearing_down(self) -> bool {
        matches!(self, Self::Draining | Self::Removing)
    }
}

impl fmt::Display for QueueLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors returned when a lifecycle transition is rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueLifecycleError {
    /// The requested transition is not valid from the current state.
    InvalidTransition {
        /// The current state when the transition was attempted.
        current: QueueLifecycleState,
        /// The name of the transition that was attempted (e.g. "attach", "drain").
        attempted: &'static str,
    },
    /// `drain()` was called but the device is not `Attached`.
    NotAttached {
        /// The current state.
        current: QueueLifecycleState,
    },
    /// `remove()` was called but the device is not `Draining`.
    NotDraining {
        /// The current state.
        current: QueueLifecycleState,
    },
}

impl QueueLifecycleError {
    /// Human-readable error string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidTransition { .. } => "invalid_transition",
            Self::NotAttached { .. } => "not_attached",
            Self::NotDraining { .. } => "not_draining",
        }
    }

    /// Extract a device ID hint from the error, if any.
    #[must_use]
    pub const fn current_state(self) -> QueueLifecycleState {
        match self {
            Self::InvalidTransition { current, .. }
            | Self::NotAttached { current }
            | Self::NotDraining { current } => current,
        }
    }
}

impl fmt::Display for QueueLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { current, attempted } => {
                write!(
                    f,
                    "invalid queue lifecycle transition: cannot {attempted} from state {current}"
                )
            }
            Self::NotAttached { current } => {
                write!(
                    f,
                    "cannot drain queue: device is {current}, expected Attached"
                )
            }
            Self::NotDraining { current } => {
                write!(
                    f,
                    "cannot remove queue: device is {current}, expected Draining"
                )
            }
        }
    }
}

/// A state machine governing the lifecycle of a ublk device queue.
///
/// Enforces drain-before-removal sequencing:
///
/// 1. [`attach`](QueueLifecycle::attach) — `Unattached`/`Removed` → `Attached`
/// 2. [`drain`](QueueLifecycle::drain) — `Attached` → `Draining`
/// 3. [`remove`](QueueLifecycle::remove) — `Draining` → `Removing`
/// 4. [`confirm_removed`](QueueLifecycle::confirm_removed) — `Removing` → `Removed`
///
/// # Idempotent removal
///
/// [`remove_idempotent`](QueueLifecycle::remove_idempotent) transitions
/// immediately to `Removed` from any state, bypassing the drain sequence.
/// This is intended for error recovery paths where normal drain cannot
/// complete (e.g. a crashed daemon restart).
///
/// # Re-attach
///
/// After reaching `Removed`, calling `attach()` transitions back to
/// `Attached`, restarting the lifecycle. This supports the "remove then
/// re-attach" pattern needed by repeated validation runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueLifecycle {
    state: QueueLifecycleState,
}

impl QueueLifecycle {
    /// Create a new lifecycle in the `Unattached` state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: QueueLifecycleState::Unattached,
        }
    }

    /// Create a new lifecycle already in the `Attached` state.
    ///
    /// This is a convenience constructor for situations where a device
    /// is created and immediately considered live (e.g. after successful
    /// `UBLK_CMD_ADD_DEV`).
    #[must_use]
    pub const fn attached() -> Self {
        Self {
            state: QueueLifecycleState::Attached,
        }
    }

    /// Return the current state.
    #[must_use]
    pub const fn state(&self) -> QueueLifecycleState {
        self.state
    }

    /// Transition from `Unattached` or `Removed` to `Attached`.
    ///
    /// # Errors
    ///
    /// Returns [`QueueLifecycleError::InvalidTransition`] if the current
    /// state is not `Unattached` or `Removed`.
    pub fn attach(&mut self) -> Result<(), QueueLifecycleError> {
        match self.state {
            QueueLifecycleState::Unattached | QueueLifecycleState::Removed => {
                self.state = QueueLifecycleState::Attached;
                Ok(())
            }
            current => Err(QueueLifecycleError::InvalidTransition {
                current,
                attempted: "attach",
            }),
        }
    }

    /// Initiate drain, transitioning from `Attached` to `Draining`.
    ///
    /// After this transition no new I/O is accepted for this queue.
    /// The caller is responsible for waiting for in-flight I/O
    /// completion before calling [`remove`](QueueLifecycle::remove).
    ///
    /// # Errors
    ///
    /// Returns [`QueueLifecycleError::NotAttached`] if the device is
    /// not in `Attached` state.
    pub fn drain(&mut self) -> Result<(), QueueLifecycleError> {
        match self.state {
            QueueLifecycleState::Attached => {
                self.state = QueueLifecycleState::Draining;
                Ok(())
            }
            current => Err(QueueLifecycleError::NotAttached { current }),
        }
    }

    /// Complete the drain and begin removal, transitioning from
    /// `Draining` to `Removing`.
    ///
    /// The caller should have already ensured in-flight I/O is
    /// drained before calling this method. After this transition,
    /// the kernel `UBLK_CMD_DEL_DEV` can be safely issued.
    ///
    /// # Errors
    ///
    /// Returns [`QueueLifecycleError::NotDraining`] if the device is
    /// not in `Draining` state.
    pub fn remove(&mut self) -> Result<(), QueueLifecycleError> {
        match self.state {
            QueueLifecycleState::Draining => {
                self.state = QueueLifecycleState::Removing;
                Ok(())
            }
            current => Err(QueueLifecycleError::NotDraining { current }),
        }
    }

    /// Confirm that removal cleanup is complete, transitioning to `Removed`.
    ///
    /// Call this after all kernel resources (fds, buffers, queue
    /// registrations) have been freed.
    ///
    /// # Errors
    ///
    /// Returns [`QueueLifecycleError::InvalidTransition`] if the
    /// lifecycle is not in `Removing` state.
    pub fn confirm_removed(&mut self) -> Result<(), QueueLifecycleError> {
        match self.state {
            QueueLifecycleState::Removing => {
                self.state = QueueLifecycleState::Removed;
                Ok(())
            }
            current => Err(QueueLifecycleError::InvalidTransition {
                current,
                attempted: "confirm_removed",
            }),
        }
    }

    /// Force removal from any state, bypassing drain sequencing.
    ///
    /// Transitions immediately to `Removed`. This is idempotent:
    /// calling it on an already-`Removed` lifecycle is a no-op
    /// (stays `Removed`).
    ///
    /// Use this for error recovery paths where the normal drain
    /// sequence cannot complete (e.g. device is in an unknown
    /// kernel state after daemon restart).
    pub fn remove_idempotent(&mut self) {
        self.state = QueueLifecycleState::Removed;
    }

    /// Returns `true` if the device can accept I/O.
    #[must_use]
    pub const fn is_io_capable(&self) -> bool {
        self.state.is_io_capable()
    }

    /// Returns `true` if the device can be re-attached.
    #[must_use]
    pub const fn is_re_attachable(&self) -> bool {
        self.state.is_re_attachable()
    }
}

impl Default for QueueLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for QueueLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.state)
    }
}

/// A handle providing the public lifecycle API for daemon-side code.
///
/// Wraps a [`QueueLifecycle`] state machine and a device ID, exposing
/// the core operations: `attach()`, `drain()`, `remove()`, and
/// `remove_idempotent()`.
///
/// The handle is a thin wrapper; actual resource management (fd close,
/// buffer release) is performed by the caller after observing state
/// transitions through this handle.
///
/// # Example
///
/// ```ignore
/// let mut handle = QueueLifecycleHandle::new();
/// handle.attach(42)?;           // Unattached → Attached
/// // ... process I/O ...
/// handle.drain()?;              // Attached → Draining
/// // ... wait for in-flight I/O ...
/// handle.remove()?;             // Draining → Removing
/// // ... issue DEL_DEV, close fds ...
/// handle.confirm_removed()?;    // Removing → Removed
/// // Re-attach is now possible:
/// handle.attach(42)?;           // Removed → Attached
/// ```
#[derive(Debug)]
pub struct QueueLifecycleHandle {
    lifecycle: QueueLifecycle,
    dev_id: Option<u32>,
}

impl QueueLifecycleHandle {
    /// Create a new handle in the `Unattached` state with no device ID.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lifecycle: QueueLifecycle::new(),
            dev_id: None,
        }
    }

    /// Return the current lifecycle state.
    #[must_use]
    pub fn state(&self) -> QueueLifecycleState {
        self.lifecycle.state()
    }

    /// Return the device ID, if one has been attached.
    #[must_use]
    pub const fn dev_id(&self) -> Option<u32> {
        self.dev_id
    }

    /// Attach a device with the given `dev_id`.
    ///
    /// Transitions from `Unattached` or `Removed` to `Attached`.
    ///
    /// # Errors
    ///
    /// Returns [`QueueLifecycleError`] if the transition is invalid
    /// (e.g. the handle is in `Attached` or `Draining` state).
    pub fn attach(&mut self, dev_id: u32) -> Result<(), QueueLifecycleError> {
        self.lifecycle.attach()?;
        self.dev_id = Some(dev_id);
        Ok(())
    }

    /// Initiate drain, transitioning from `Attached` to `Draining`.
    ///
    /// After this call, no new I/O should be accepted for this device.
    ///
    /// # Errors
    ///
    /// Returns [`QueueLifecycleError::NotAttached`] if the device is
    /// not `Attached`.
    pub fn drain(&mut self) -> Result<(), QueueLifecycleError> {
        self.lifecycle.drain()
    }

    /// Complete the drain and begin removal.
    ///
    /// Transitions from `Draining` to `Removing`.
    ///
    /// # Errors
    ///
    /// Returns [`QueueLifecycleError::NotDraining`] if the device is
    /// not `Draining`.
    pub fn remove(&mut self) -> Result<(), QueueLifecycleError> {
        self.lifecycle.remove()
    }

    /// Confirm cleanup is complete, transitioning to `Removed`.
    ///
    /// Clears the stored device ID.
    ///
    /// # Errors
    ///
    /// Returns [`QueueLifecycleError::InvalidTransition`] if not in
    /// `Removing` state.
    pub fn confirm_removed(&mut self) -> Result<(), QueueLifecycleError> {
        self.lifecycle.confirm_removed()?;
        self.dev_id = None;
        Ok(())
    }

    /// Force removal from any state, clearing the device ID.
    ///
    /// Transitions to `Removed` regardless of current state.
    /// Idempotent: calling on an already-`Removed` handle is a no-op
    /// for the state (the handle stays `Removed`).
    pub fn remove_idempotent(&mut self) {
        self.lifecycle.remove_idempotent();
        self.dev_id = None;
    }

    /// Returns `true` if the device can accept I/O.
    #[must_use]
    pub fn is_io_capable(&self) -> bool {
        self.lifecycle.is_io_capable()
    }

    /// Returns `true` if the device can be re-attached.
    #[must_use]
    pub fn is_re_attachable(&self) -> bool {
        self.lifecycle.is_re_attachable()
    }
}

impl Default for QueueLifecycleHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for QueueLifecycleHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.dev_id {
            Some(id) => write!(f, "QueueLifecycleHandle(dev_id={id}, {})", self.lifecycle),
            None => write!(f, "QueueLifecycleHandle({})", self.lifecycle),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── QueueLifecycleState ────────────────────────────────────────────

    #[test]
    fn state_as_str() {
        assert_eq!(QueueLifecycleState::Unattached.as_str(), "unattached");
        assert_eq!(QueueLifecycleState::Attached.as_str(), "attached");
        assert_eq!(QueueLifecycleState::Draining.as_str(), "draining");
        assert_eq!(QueueLifecycleState::Removing.as_str(), "removing");
        assert_eq!(QueueLifecycleState::Removed.as_str(), "removed");
    }

    #[test]
    fn state_display() {
        assert_eq!(QueueLifecycleState::Unattached.to_string(), "unattached");
        assert_eq!(QueueLifecycleState::Attached.to_string(), "attached");
    }

    #[test]
    fn state_is_io_capable() {
        assert!(!QueueLifecycleState::Unattached.is_io_capable());
        assert!(QueueLifecycleState::Attached.is_io_capable());
        assert!(!QueueLifecycleState::Draining.is_io_capable());
        assert!(!QueueLifecycleState::Removing.is_io_capable());
        assert!(!QueueLifecycleState::Removed.is_io_capable());
    }

    #[test]
    fn state_is_re_attachable() {
        assert!(QueueLifecycleState::Unattached.is_re_attachable());
        assert!(!QueueLifecycleState::Attached.is_re_attachable());
        assert!(!QueueLifecycleState::Draining.is_re_attachable());
        assert!(!QueueLifecycleState::Removing.is_re_attachable());
        assert!(QueueLifecycleState::Removed.is_re_attachable());
    }

    #[test]
    fn state_is_tearing_down() {
        assert!(!QueueLifecycleState::Unattached.is_tearing_down());
        assert!(!QueueLifecycleState::Attached.is_tearing_down());
        assert!(QueueLifecycleState::Draining.is_tearing_down());
        assert!(QueueLifecycleState::Removing.is_tearing_down());
        assert!(!QueueLifecycleState::Removed.is_tearing_down());
    }

    // ── QueueLifecycle ─────────────────────────────────────────────────

    #[test]
    fn new_starts_unattached() {
        let lc = QueueLifecycle::new();
        assert_eq!(lc.state(), QueueLifecycleState::Unattached);
        assert!(!lc.is_io_capable());
        assert!(lc.is_re_attachable());
    }

    #[test]
    fn attached_constructor_starts_in_attached() {
        let lc = QueueLifecycle::attached();
        assert_eq!(lc.state(), QueueLifecycleState::Attached);
        assert!(lc.is_io_capable());
        assert!(!lc.is_re_attachable());
    }

    #[test]
    fn default_is_unattached() {
        let lc = QueueLifecycle::default();
        assert_eq!(lc.state(), QueueLifecycleState::Unattached);
    }

    #[test]
    fn full_happy_path_lifecycle() {
        let mut lc = QueueLifecycle::new();

        // Unattached → Attached
        lc.attach().unwrap();
        assert_eq!(lc.state(), QueueLifecycleState::Attached);

        // Attached → Draining
        lc.drain().unwrap();
        assert_eq!(lc.state(), QueueLifecycleState::Draining);

        // Draining → Removing
        lc.remove().unwrap();
        assert_eq!(lc.state(), QueueLifecycleState::Removing);

        // Removing → Removed
        lc.confirm_removed().unwrap();
        assert_eq!(lc.state(), QueueLifecycleState::Removed);

        // Removed → Attached (re-attach)
        lc.attach().unwrap();
        assert_eq!(lc.state(), QueueLifecycleState::Attached);
    }

    #[test]
    fn attach_from_unattached() {
        let mut lc = QueueLifecycle::new();
        assert!(lc.attach().is_ok());
        assert_eq!(lc.state(), QueueLifecycleState::Attached);
    }

    #[test]
    fn attach_from_removed_re_attaches() {
        let mut lc = QueueLifecycle::new();
        lc.attach().unwrap();
        lc.remove_idempotent();
        assert_eq!(lc.state(), QueueLifecycleState::Removed);
        assert!(lc.attach().is_ok());
        assert_eq!(lc.state(), QueueLifecycleState::Attached);
    }

    #[test]
    fn attach_from_attached_fails() {
        let mut lc = QueueLifecycle::attached();
        let err = lc.attach().unwrap_err();
        assert_eq!(err.current_state(), QueueLifecycleState::Attached);
    }

    #[test]
    fn attach_from_draining_fails() {
        let mut lc = QueueLifecycle::attached();
        lc.drain().unwrap();
        let err = lc.attach().unwrap_err();
        assert_eq!(err.current_state(), QueueLifecycleState::Draining);
    }

    #[test]
    fn drain_from_attached_succeeds() {
        let mut lc = QueueLifecycle::attached();
        assert!(lc.drain().is_ok());
        assert_eq!(lc.state(), QueueLifecycleState::Draining);
    }

    #[test]
    fn drain_from_unattached_fails() {
        let mut lc = QueueLifecycle::new();
        let err = lc.drain().unwrap_err();
        assert!(matches!(err, QueueLifecycleError::NotAttached { .. }));
    }

    #[test]
    fn drain_from_draining_fails() {
        let mut lc = QueueLifecycle::attached();
        lc.drain().unwrap();
        let err = lc.drain().unwrap_err();
        assert_eq!(err.current_state(), QueueLifecycleState::Draining);
    }

    #[test]
    fn drain_from_removed_fails() {
        let mut lc = QueueLifecycle::new();
        lc.attach().unwrap();
        lc.remove_idempotent();
        let err = lc.drain().unwrap_err();
        assert_eq!(err.current_state(), QueueLifecycleState::Removed);
    }

    #[test]
    fn remove_from_draining_succeeds() {
        let mut lc = QueueLifecycle::attached();
        lc.drain().unwrap();
        assert!(lc.remove().is_ok());
        assert_eq!(lc.state(), QueueLifecycleState::Removing);
    }

    #[test]
    fn remove_from_attached_fails() {
        let mut lc = QueueLifecycle::attached();
        let err = lc.remove().unwrap_err();
        assert!(matches!(err, QueueLifecycleError::NotDraining { .. }));
    }

    #[test]
    fn remove_from_unattached_fails() {
        let mut lc = QueueLifecycle::new();
        let err = lc.remove().unwrap_err();
        assert_eq!(err.current_state(), QueueLifecycleState::Unattached);
    }

    #[test]
    fn confirm_removed_succeeds() {
        let mut lc = QueueLifecycle::attached();
        lc.drain().unwrap();
        lc.remove().unwrap();
        assert!(lc.confirm_removed().is_ok());
        assert_eq!(lc.state(), QueueLifecycleState::Removed);
    }

    #[test]
    fn confirm_removed_from_attached_fails() {
        let mut lc = QueueLifecycle::attached();
        let err = lc.confirm_removed().unwrap_err();
        assert_eq!(err.current_state(), QueueLifecycleState::Attached);
    }

    #[test]
    fn confirm_removed_from_draining_fails() {
        let mut lc = QueueLifecycle::attached();
        lc.drain().unwrap();
        let err = lc.confirm_removed().unwrap_err();
        assert_eq!(err.current_state(), QueueLifecycleState::Draining);
    }

    #[test]
    fn remove_idempotent_from_any_state() {
        for start in [
            QueueLifecycleState::Unattached,
            QueueLifecycleState::Attached,
            QueueLifecycleState::Draining,
            QueueLifecycleState::Removing,
            QueueLifecycleState::Removed,
        ] {
            let mut lc = match start {
                QueueLifecycleState::Unattached => QueueLifecycle::new(),
                QueueLifecycleState::Attached => QueueLifecycle::attached(),
                QueueLifecycleState::Draining => {
                    let mut l = QueueLifecycle::attached();
                    l.drain().unwrap();
                    l
                }
                QueueLifecycleState::Removing => {
                    let mut l = QueueLifecycle::attached();
                    l.drain().unwrap();
                    l.remove().unwrap();
                    l
                }
                QueueLifecycleState::Removed => {
                    let mut l = QueueLifecycle::attached();
                    l.remove_idempotent();
                    l
                }
            };
            lc.remove_idempotent();
            assert_eq!(
                lc.state(),
                QueueLifecycleState::Removed,
                "remove_idempotent from {start} should result in Removed"
            );
        }
    }

    #[test]
    fn remove_idempotent_is_idempotent() {
        let mut lc = QueueLifecycle::attached();
        lc.remove_idempotent();
        assert_eq!(lc.state(), QueueLifecycleState::Removed);
        lc.remove_idempotent();
        assert_eq!(lc.state(), QueueLifecycleState::Removed);
        lc.remove_idempotent();
        assert_eq!(lc.state(), QueueLifecycleState::Removed);
    }

    #[test]
    fn display_formatting() {
        let lc = QueueLifecycle::attached();
        let s = lc.to_string();
        assert_eq!(s, "attached");

        let lc2 = QueueLifecycle::new();
        assert_eq!(lc2.to_string(), "unattached");
    }

    // ── QueueLifecycleError ────────────────────────────────────────────

    #[test]
    fn error_as_str() {
        assert_eq!(
            QueueLifecycleError::InvalidTransition {
                current: QueueLifecycleState::Attached,
                attempted: "attach"
            }
            .as_str(),
            "invalid_transition"
        );
        assert_eq!(
            QueueLifecycleError::NotAttached {
                current: QueueLifecycleState::Unattached
            }
            .as_str(),
            "not_attached"
        );
        assert_eq!(
            QueueLifecycleError::NotDraining {
                current: QueueLifecycleState::Attached
            }
            .as_str(),
            "not_draining"
        );
    }

    #[test]
    fn error_display_contains_state() {
        let err = QueueLifecycleError::NotAttached {
            current: QueueLifecycleState::Draining,
        };
        let s = err.to_string();
        assert!(s.contains("draining"));
        assert!(s.contains("draining"));
        assert!(s.contains("Attached"));
    }

    #[test]
    fn error_current_state() {
        assert_eq!(
            QueueLifecycleError::InvalidTransition {
                current: QueueLifecycleState::Removing,
                attempted: "attach"
            }
            .current_state(),
            QueueLifecycleState::Removing
        );
    }

    // ── QueueLifecycleHandle ───────────────────────────────────────────

    #[test]
    fn handle_new_is_unattached_no_dev_id() {
        let h = QueueLifecycleHandle::new();
        assert_eq!(h.state(), QueueLifecycleState::Unattached);
        assert_eq!(h.dev_id(), None);
    }

    #[test]
    fn handle_default_is_new() {
        let h = QueueLifecycleHandle::default();
        assert_eq!(h.state(), QueueLifecycleState::Unattached);
    }

    #[test]
    fn handle_attach_sets_dev_id() {
        let mut h = QueueLifecycleHandle::new();
        h.attach(42).unwrap();
        assert_eq!(h.state(), QueueLifecycleState::Attached);
        assert_eq!(h.dev_id(), Some(42));
        assert!(h.is_io_capable());
    }

    #[test]
    fn handle_full_lifecycle() {
        let mut h = QueueLifecycleHandle::new();

        h.attach(7).unwrap();
        assert_eq!(h.state(), QueueLifecycleState::Attached);
        assert_eq!(h.dev_id(), Some(7));

        h.drain().unwrap();
        assert_eq!(h.state(), QueueLifecycleState::Draining);
        assert_eq!(h.dev_id(), Some(7)); // dev_id preserved during drain

        h.remove().unwrap();
        assert_eq!(h.state(), QueueLifecycleState::Removing);
        assert_eq!(h.dev_id(), Some(7)); // dev_id preserved during remove

        h.confirm_removed().unwrap();
        assert_eq!(h.state(), QueueLifecycleState::Removed);
        assert_eq!(h.dev_id(), None); // cleared on confirm_removed

        // Re-attach
        h.attach(99).unwrap();
        assert_eq!(h.state(), QueueLifecycleState::Attached);
        assert_eq!(h.dev_id(), Some(99));
    }

    #[test]
    fn handle_remove_idempotent_clears_dev_id() {
        let mut h = QueueLifecycleHandle::new();
        h.attach(55).unwrap();
        assert_eq!(h.dev_id(), Some(55));

        h.remove_idempotent();
        assert_eq!(h.state(), QueueLifecycleState::Removed);
        assert_eq!(h.dev_id(), None);
    }

    #[test]
    fn handle_drain_fails_when_not_attached() {
        let mut h = QueueLifecycleHandle::new();
        let err = h.drain().unwrap_err();
        assert_eq!(err.current_state(), QueueLifecycleState::Unattached);
    }

    #[test]
    fn handle_remove_fails_when_not_draining() {
        let mut h = QueueLifecycleHandle::new();
        h.attach(1).unwrap();
        let err = h.remove().unwrap_err();
        assert_eq!(err.current_state(), QueueLifecycleState::Attached);
    }

    #[test]
    fn handle_display() {
        let h = QueueLifecycleHandle::new();
        assert!(h.to_string().contains("unattached"));

        let mut h2 = QueueLifecycleHandle::new();
        h2.attach(42).unwrap();
        let s = h2.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("attached"));
    }

    #[test]
    fn handle_is_io_capable_and_re_attachable() {
        let mut h = QueueLifecycleHandle::new();
        assert!(!h.is_io_capable());
        assert!(h.is_re_attachable());

        h.attach(1).unwrap();
        assert!(h.is_io_capable());
        assert!(!h.is_re_attachable());

        h.drain().unwrap();
        assert!(!h.is_io_capable());
        assert!(!h.is_re_attachable());

        h.remove_idempotent();
        assert!(!h.is_io_capable());
        assert!(h.is_re_attachable());
    }
}

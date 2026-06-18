// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Epoch transition error types for membership-gated epoch advances.
//!
//! This module provides [`EpochTransitionError`] which extends the existing
//! [`EpochAdvanceError`] (in `lib.rs`) with membership-aware and I/O variants
//! needed by [`EpochService`](super::epoch_service::EpochService).

use std::fmt;

/// Errors returned when proposing or committing an epoch transition.
///
/// Distinct from [`EpochAdvanceError`](super::EpochAdvanceError) which handles
/// the lower-level monotonicity and barrier checks internal to
/// [`EpochCounter`](super::EpochCounter).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EpochTransitionError {
    /// The proposed epoch is not strictly greater than the current epoch.
    NotMonotonic { current: u64, proposed: u64 },
    /// The requesting node is not a member of the current epoch.
    NotMember { member_id: u64, current_epoch: u64 },
    /// The transition was already recorded (idempotency guard).
    AlreadyTransitioned { epoch: u64 },
    /// An I/O error occurred during persistence.
    IoError(String),
    /// A transition is already in progress (barrier held).
    TransitionInProgress,
}

impl fmt::Display for EpochTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMonotonic { current, proposed } => {
                write!(
                    f,
                    "epoch transition not monotonic: current={current}, proposed={proposed}"
                )
            }
            Self::NotMember {
                member_id,
                current_epoch,
            } => {
                write!(
                    f,
                    "node {member_id} is not a member of epoch {current_epoch}"
                )
            }
            Self::AlreadyTransitioned { epoch } => {
                write!(f, "epoch {epoch} already transitioned (idempotent)")
            }
            Self::IoError(msg) => {
                write!(f, "epoch persistence I/O error: {msg}")
            }
            Self::TransitionInProgress => {
                write!(f, "another epoch transition is already in progress")
            }
        }
    }
}

impl std::error::Error for EpochTransitionError {}

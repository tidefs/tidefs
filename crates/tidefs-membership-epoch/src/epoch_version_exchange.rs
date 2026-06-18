// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Epoch-version exchange message types for connection-time epoch
//! synchronization.
//!
//! When a transport session is established between two peers, a
//! bidirectional epoch-version exchange runs after roster verification
//! succeeds. Each side sends its current committed epoch number, and
//! the receiving side compares the remote epoch against its own.
//!
//! If the remote peer is behind, the receiver flags it for catch-up
//! via the existing [`crate::epoch_catch_up`] protocol. If the remote
//! peer is ahead, the local node initiates catch-up.
//!
//! ## Wire format
//!
//! Both messages derive `serde::Serialize` and `serde::Deserialize`
//! for bincode wire encoding. They carry no new crypto surface; they
//! rely on the existing transport/session security boundary.
//!
//! ## Exchange flow
//!
//! ```text
//! Initiator (connect side)          Responder (accept side)
//!      │                                    │
//!      │──── EpochVersion(epoch=5) ───────▶ │
//!      │                                    │ compare: remote=5, local=7
//!      │                                    │ → remote is behind
//!      │ ◀── EpochVersion(epoch=7) ─────── │
//!      │ compare: remote=7, local=5         │
//!      │ → local is behind                  │
//!      ▼                                    ▼
//!   initiate catch-up                   flag remote for catch-up
//! ```

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// EpochVersionMessage
// ---------------------------------------------------------------------------

/// A single epoch-version announcement exchanged at connection time.
///
/// Carries the sender's current committed epoch number. After both
/// sides exchange versions, each side compares the remote epoch
/// against its own local epoch and decides whether catch-up is needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochVersionMessage {
    /// The sender's current committed epoch number.
    pub epoch_number: u64,
}

impl EpochVersionMessage {
    /// Create a new epoch-version message.
    #[must_use]
    pub const fn new(epoch_number: u64) -> Self {
        Self { epoch_number }
    }
}

// ---------------------------------------------------------------------------
// EpochVersionExchangeOutcome
// ---------------------------------------------------------------------------

/// The result of comparing a remote peer's epoch version against the
/// local node's current epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochVersionExchangeOutcome {
    /// Both peers are at the same epoch. No catch-up needed.
    InSync,
    /// The remote peer is behind. It should be flagged for catch-up
    /// delivery.
    RemoteBehind {
        /// Remote peer's epoch number.
        remote_epoch: u64,
        /// Local node's current epoch number.
        local_epoch: u64,
    },
    /// The local node is behind the remote peer. Local catch-up should
    /// be initiated.
    LocalBehind {
        /// Remote peer's epoch number.
        remote_epoch: u64,
        /// Local node's current epoch number.
        local_epoch: u64,
    },
}

impl EpochVersionExchangeOutcome {
    /// Evaluate the exchange outcome given the remote and local epochs.
    #[must_use]
    pub fn evaluate(remote_epoch: u64, local_epoch: u64) -> Self {
        match remote_epoch.cmp(&local_epoch) {
            std::cmp::Ordering::Equal => Self::InSync,
            std::cmp::Ordering::Less => Self::RemoteBehind {
                remote_epoch,
                local_epoch,
            },
            std::cmp::Ordering::Greater => Self::LocalBehind {
                remote_epoch,
                local_epoch,
            },
        }
    }

    /// Returns `true` if the outcome is [`InSync`](Self::InSync).
    #[must_use]
    pub fn is_in_sync(&self) -> bool {
        matches!(self, Self::InSync)
    }

    /// Returns `true` if the local node needs to initiate catch-up.
    #[must_use]
    pub fn local_needs_catchup(&self) -> bool {
        matches!(self, Self::LocalBehind { .. })
    }

    /// Returns `true` if the remote peer needs catch-up.
    #[must_use]
    pub fn remote_needs_catchup(&self) -> bool {
        matches!(self, Self::RemoteBehind { .. })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- EpochVersionMessage ----

    #[test]
    fn epoch_version_message_construction() {
        let msg = EpochVersionMessage::new(42);
        assert_eq!(msg.epoch_number, 42);
    }

    #[test]
    fn epoch_version_message_roundtrip_bincode() {
        let msg = EpochVersionMessage::new(7);
        let encoded = bincode::serialize(&msg).expect("serialize");
        let decoded: EpochVersionMessage = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn epoch_version_message_zero_epoch() {
        let msg = EpochVersionMessage::new(0);
        let encoded = bincode::serialize(&msg).expect("serialize");
        let decoded: EpochVersionMessage = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded, msg);
    }

    // ---- EpochVersionExchangeOutcome ----

    #[test]
    fn outcome_in_sync() {
        let outcome = EpochVersionExchangeOutcome::evaluate(5, 5);
        assert!(matches!(outcome, EpochVersionExchangeOutcome::InSync));
        assert!(outcome.is_in_sync());
        assert!(!outcome.local_needs_catchup());
        assert!(!outcome.remote_needs_catchup());
    }

    #[test]
    fn outcome_remote_behind() {
        let outcome = EpochVersionExchangeOutcome::evaluate(3, 7);
        assert!(matches!(
            outcome,
            EpochVersionExchangeOutcome::RemoteBehind {
                remote_epoch: 3,
                local_epoch: 7,
            }
        ));
        assert!(!outcome.is_in_sync());
        assert!(!outcome.local_needs_catchup());
        assert!(outcome.remote_needs_catchup());
    }

    #[test]
    fn outcome_local_behind() {
        let outcome = EpochVersionExchangeOutcome::evaluate(10, 5);
        assert!(matches!(
            outcome,
            EpochVersionExchangeOutcome::LocalBehind {
                remote_epoch: 10,
                local_epoch: 5,
            }
        ));
        assert!(!outcome.is_in_sync());
        assert!(outcome.local_needs_catchup());
        assert!(!outcome.remote_needs_catchup());
    }

    #[test]
    fn outcome_local_behind_by_one() {
        let outcome = EpochVersionExchangeOutcome::evaluate(2, 1);
        assert!(outcome.local_needs_catchup());
    }

    #[test]
    fn outcome_remote_behind_by_one() {
        let outcome = EpochVersionExchangeOutcome::evaluate(1, 2);
        assert!(outcome.remote_needs_catchup());
    }

    #[test]
    fn outcome_zero_epochs() {
        let outcome = EpochVersionExchangeOutcome::evaluate(0, 0);
        assert!(outcome.is_in_sync());
    }
}

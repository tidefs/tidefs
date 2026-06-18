// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Reconnect-state push message for delivering committed epoch state to a
//! reconnecting known peer during transport session establishment.
//!
//! When a peer that is already a member of the current committed roster
//! reconnects (after disconnect or crash), the acceptor side sends a
//! [`ReconnectStatePushMessage`] carrying the full committed epoch view
//! so the peer can synchronize without re-running the full node-join
//! handshake. This fills the gap between initial node-join (#5317) and
//! post-commit roster push (#5977).
//!
//! ## Wire format
//!
//! ```text
//! [0..8)   push_seq         u64 LE -- monotonic push sequence number
//! [8..16)  epoch            u64 LE -- epoch number
//! [16..48) roster_hash      32 bytes -- BLAKE3-256 roster hash
//! [48..52) member_count     u32 LE -- number of member IDs
//! [52..M)  member_ids       member_count x u64 LE -- sorted member node IDs
//! [M..M+8) target_peer_id   u64 LE -- the peer this reconnect push is for
//! [M+8..]  peer_roster_epoch u64 LE -- epoch when this peer was first rostered
//! ```

use tidefs_membership_epoch::epoch_commit_subscriber::CommittedRoster;
use tidefs_membership_epoch::EpochId;

/// A transport-level reconnect-state push message delivering the committed
/// roster plus target-peer metadata to a reconnecting peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconnectStatePushMessage {
    pub push_seq: u64,
    pub roster: CommittedRoster,
    pub target_peer_id: u64,
    pub peer_roster_epoch: u64,
}

impl ReconnectStatePushMessage {
    #[must_use]
    pub fn new(
        push_seq: u64,
        roster: CommittedRoster,
        target_peer_id: u64,
        peer_roster_epoch: u64,
    ) -> Self {
        Self {
            push_seq,
            roster,
            target_peer_id,
            peer_roster_epoch,
        }
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mc = self.roster.member_ids.len() as u32;
        let mut buf = Vec::with_capacity(68 + mc as usize * 8);
        buf.extend_from_slice(&self.push_seq.to_le_bytes());
        buf.extend_from_slice(&self.roster.epoch.0.to_le_bytes());
        buf.extend_from_slice(&self.roster.roster_hash);
        buf.extend_from_slice(&mc.to_le_bytes());
        for id in &self.roster.member_ids {
            buf.extend_from_slice(&id.to_le_bytes());
        }
        buf.extend_from_slice(&self.target_peer_id.to_le_bytes());
        buf.extend_from_slice(&self.peer_roster_epoch.to_le_bytes());
        buf
    }

    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 68 {
            return None;
        }
        let push_seq = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let epoch = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let mut roster_hash = [0u8; 32];
        roster_hash.copy_from_slice(&data[16..48]);
        let mc = u32::from_le_bytes(data[48..52].try_into().unwrap()) as usize;
        let members_end = 52 + mc * 8;
        if data.len() < members_end + 16 {
            return None;
        }
        let mut member_ids = Vec::with_capacity(mc);
        for i in 0..mc {
            let off = 52 + i * 8;
            member_ids.push(u64::from_le_bytes(data[off..off + 8].try_into().unwrap()));
        }
        let target_peer_id =
            u64::from_le_bytes(data[members_end..members_end + 8].try_into().unwrap());
        let peer_roster_epoch =
            u64::from_le_bytes(data[members_end + 8..members_end + 16].try_into().unwrap());
        Some(Self {
            push_seq,
            roster: CommittedRoster {
                epoch: EpochId(epoch),
                member_ids,
                roster_hash,
            },
            target_peer_id,
            peer_roster_epoch,
        })
    }

    #[must_use]
    pub fn target_in_roster(&self) -> bool {
        self.roster.contains(self.target_peer_id)
    }
}

// ---------------------------------------------------------------------------
// Handler & Dispatcher
// ---------------------------------------------------------------------------
use std::sync::Arc;

pub trait ReconnectStatePushHandler: Send + Sync {
    fn on_reconnect_state_push(&self, push_seq: u64, msg: &ReconnectStatePushMessage);
}

pub struct ReconnectStatePushDispatcher {
    handler: Arc<dyn ReconnectStatePushHandler>,
}

impl ReconnectStatePushDispatcher {
    #[must_use]
    pub fn new(handler: Arc<dyn ReconnectStatePushHandler>) -> Self {
        Self { handler }
    }

    pub fn handle_raw(&self, payload: &[u8]) -> Result<(), String> {
        let msg = ReconnectStatePushMessage::decode(payload)
            .ok_or_else(|| "reconnect-state push: decode failed".to_string())?;
        self.handler.on_reconnect_state_push(msg.push_seq, &msg);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ReconnectStatePushOutcome — validation result for incoming state push
// ---------------------------------------------------------------------------

/// Outcome of validating an incoming [`ReconnectStatePushMessage`] against
/// the current membership state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconnectStatePushOutcome {
    /// The state push is valid: the target peer is in the roster and
    /// the epoch is current.
    Accepted,
    /// The target peer is not present in the push's own roster.
    TargetNotInRoster {
        target_peer_id: u64,
    },
    /// The state push's epoch is behind the current known epoch.
    StaleEpoch {
        push_epoch: u64,
        current_epoch: u64,
    },
    /// The state push's target peer is not in the current roster
    /// (peer has departed since the push was generated).
    PeerDeparted {
        target_peer_id: u64,
    },
}

impl ReconnectStatePushOutcome {
    /// Whether the state push was accepted.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }

    /// Human-readable outcome label.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::TargetNotInRoster { .. } => "target_not_in_roster",
            Self::StaleEpoch { .. } => "stale_epoch",
            Self::PeerDeparted { .. } => "peer_departed",
        }
    }
}

impl ReconnectStatePushMessage {
    /// Validate this state push against a current roster and epoch.
    ///
    /// Checks that:
    /// 1. The target peer is in the push's own roster (internal consistency).
    /// 2. The push's epoch is not behind the current epoch.
    /// 3. The target peer is still in the current roster.
    #[must_use]
    pub fn validate(
        &self,
        current_roster: &[u64],
        current_epoch: u64,
    ) -> ReconnectStatePushOutcome {
        // Internal consistency: target must be in the push's own roster
        if !self.target_in_roster() {
            return ReconnectStatePushOutcome::TargetNotInRoster {
                target_peer_id: self.target_peer_id,
            };
        }
        // Epoch check: push must not be behind
        let push_epoch = self.roster.epoch.0;
        if push_epoch < current_epoch {
            return ReconnectStatePushOutcome::StaleEpoch {
                push_epoch,
                current_epoch,
            };
        }
        // Membership check: target must still be in the current roster
        if !current_roster.contains(&self.target_peer_id) {
            return ReconnectStatePushOutcome::PeerDeparted {
                target_peer_id: self.target_peer_id,
            };
        }
        ReconnectStatePushOutcome::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tidefs_membership_epoch::EpochId;

    fn mk(epoch: u64, ids: Vec<u64>) -> CommittedRoster {
        CommittedRoster::new(EpochId(epoch), ids)
    }

    #[test]
    fn roundtrip_empty() {
        let m = ReconnectStatePushMessage::new(0, mk(1, vec![]), 42, 1);
        let d = ReconnectStatePushMessage::decode(&m.encode()).unwrap();
        assert_eq!(d.push_seq, 0);
        assert!(d.roster.member_ids.is_empty());
        assert_eq!(d.target_peer_id, 42);
    }

    #[test]
    fn roundtrip_one() {
        let r = mk(5, vec![42]);
        let m = ReconnectStatePushMessage::new(1, r.clone(), 42, 5);
        let d = ReconnectStatePushMessage::decode(&m.encode()).unwrap();
        assert_eq!(d.roster.epoch, EpochId(5));
        assert_eq!(d.roster.roster_hash, r.roster_hash);
    }

    #[test]
    fn roundtrip_multi() {
        let ids = vec![1, 3, 5, 7, 9, 11];
        let r = mk(3, ids.clone());
        let m = ReconnectStatePushMessage::new(7, r.clone(), 3, 2);
        let d = ReconnectStatePushMessage::decode(&m.encode()).unwrap();
        assert_eq!(d.roster.member_ids, ids);
        assert_eq!(d.target_peer_id, 3);
    }

    #[test]
    fn short_buf() {
        assert!(ReconnectStatePushMessage::decode(&[]).is_none());
        assert!(ReconnectStatePushMessage::decode(&[0u8; 67]).is_none());
    }

    #[test]
    fn truncated_members() {
        let r = mk(1, vec![10, 20]);
        let mut enc = ReconnectStatePushMessage::new(0, r, 10, 1).encode();
        enc.truncate(52 + 8 + 16);
        assert!(ReconnectStatePushMessage::decode(&enc).is_none());
    }

    #[test]
    fn deterministic() {
        let r = mk(2, vec![10, 20]);
        let m = ReconnectStatePushMessage::new(0, r, 10, 2);
        assert_eq!(m.encode(), m.encode());
    }

    #[test]
    fn target_in_roster_yes() {
        let m = ReconnectStatePushMessage::new(0, mk(1, vec![10, 20, 30]), 20, 1);
        assert!(m.target_in_roster());
    }

    #[test]
    fn target_in_roster_no() {
        let m = ReconnectStatePushMessage::new(0, mk(1, vec![10, 20, 30]), 99, 1);
        assert!(!m.target_in_roster());
    }

    struct TH {
        calls: Mutex<Vec<(u64, ReconnectStatePushMessage)>>,
    }
    impl TH {
        fn new() -> Self {
            Self {
                calls: Mutex::new(vec![]),
            }
        }
    }
    impl ReconnectStatePushHandler for TH {
        fn on_reconnect_state_push(&self, s: u64, m: &ReconnectStatePushMessage) {
            self.calls.lock().unwrap().push((s, m.clone()));
        }
    }

    #[test]
    fn dispatcher_works() {
        let h = Arc::new(TH::new());
        let d = ReconnectStatePushDispatcher::new(h.clone());
        let m = ReconnectStatePushMessage::new(3, mk(5, vec![1, 2, 3]), 2, 5);
        assert!(d.handle_raw(&m.encode()).is_ok());
        assert_eq!(h.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn dispatcher_bad() {
        let h = Arc::new(TH::new());
        let d = ReconnectStatePushDispatcher::new(h.clone());
        assert!(d.handle_raw(&[0u8; 10]).is_err());
    }

    #[test]
    fn dispatcher_multi() {
        let h = Arc::new(TH::new());
        let d = ReconnectStatePushDispatcher::new(h.clone());
        for i in 0..5 {
            d.handle_raw(&ReconnectStatePushMessage::new(i, mk(i, vec![i]), i, i).encode())
                .unwrap();
        }
        assert_eq!(h.calls.lock().unwrap().len(), 5);
    }

    // ------------------------------------------------------------------
    // ReconnectStatePushOutcome validation tests
    // ------------------------------------------------------------------

    #[test]
    fn validate_accepts_current_peer() {
        let r = mk(5, vec![1, 2, 3]);
        let m = ReconnectStatePushMessage::new(0, r, 2, 5);
        let outcome = m.validate(&[1, 2, 3], 5);
        assert_eq!(outcome, ReconnectStatePushOutcome::Accepted);
        assert!(outcome.is_accepted());
    }

    #[test]
    fn validate_rejects_target_not_in_push_roster() {
        let r = mk(3, vec![1, 2]);
        let m = ReconnectStatePushMessage::new(0, r, 99, 3);
        let outcome = m.validate(&[1, 2], 3);
        assert_eq!(
            outcome,
            ReconnectStatePushOutcome::TargetNotInRoster { target_peer_id: 99 }
        );
        assert!(!outcome.is_accepted());
    }

    #[test]
    fn validate_rejects_stale_epoch() {
        let r = mk(2, vec![1, 2, 3]);
        let m = ReconnectStatePushMessage::new(0, r, 2, 2);
        let outcome = m.validate(&[1, 2, 3], 5);
        assert_eq!(
            outcome,
            ReconnectStatePushOutcome::StaleEpoch {
                push_epoch: 2,
                current_epoch: 5,
            }
        );
        assert!(!outcome.is_accepted());
    }

    #[test]
    fn validate_rejects_departed_peer() {
        let r = mk(4, vec![1, 2, 3]);
        let m = ReconnectStatePushMessage::new(0, r, 3, 4);
        // Peer 3 is in the push's roster but NOT in the current roster
        let outcome = m.validate(&[1, 2], 4);
        assert_eq!(
            outcome,
            ReconnectStatePushOutcome::PeerDeparted { target_peer_id: 3 }
        );
        assert!(!outcome.is_accepted());
    }

    #[test]
    fn validate_target_not_in_roster_takes_precedence() {
        // Target not in push's own roster should be caught first
        let r = mk(1, vec![1, 2]);
        let m = ReconnectStatePushMessage::new(0, r, 99, 1);
        let outcome = m.validate(&[1, 2], 5);
        assert_eq!(
            outcome,
            ReconnectStatePushOutcome::TargetNotInRoster { target_peer_id: 99 }
        );
    }

    #[test]
    fn validate_outcome_as_str() {
        assert_eq!(ReconnectStatePushOutcome::Accepted.as_str(), "accepted");
        assert_eq!(
            ReconnectStatePushOutcome::TargetNotInRoster { target_peer_id: 1 }.as_str(),
            "target_not_in_roster"
        );
        assert_eq!(
            ReconnectStatePushOutcome::StaleEpoch { push_epoch: 1, current_epoch: 2 }.as_str(),
            "stale_epoch"
        );
        assert_eq!(
            ReconnectStatePushOutcome::PeerDeparted { target_peer_id: 1 }.as_str(),
            "peer_departed"
        );
    }
}

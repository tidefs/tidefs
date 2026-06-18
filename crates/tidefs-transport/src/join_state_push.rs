// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Join-state push message for delivering committed epoch state to a
//! first-time joining peer during the transport join handshake.
//!
//! When a brand-new peer connects and is not yet in the committed roster,
//! the acceptor side sends a [`JoinStatePushMessage`] carrying the current
//! committed epoch view so the peer can participate in epoch-gate enforcement
//! immediately. This closes the first-time peer-join gap after initial
//! transport connection acceptance.
//!
//! ## Wire format
//!
//! ```text
//! [0..8)   push_seq         u64 LE -- monotonic push sequence number
//! [8..16)  epoch            u64 LE -- epoch number
//! [16..48) roster_hash      32 bytes -- BLAKE3-256 roster hash
//! [48..52) member_count     u32 LE -- number of member IDs
//! [52..M)  member_ids       member_count x u64 LE -- sorted member node IDs
//! [M..M+8) joining_peer_id  u64 LE -- the peer this join push is for
//! ```

use tidefs_membership_epoch::epoch_commit_subscriber::CommittedRoster;
use tidefs_membership_epoch::EpochId;

/// A transport-level join-state push message delivering the committed roster
/// to a first-time joining peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinStatePushMessage {
    /// Monotonic push sequence number (per-sender).
    pub push_seq: u64,
    /// The committed roster at the time of join.
    pub roster: CommittedRoster,
    /// The peer this join-state push is addressed to.
    pub joining_peer_id: u64,
}

impl JoinStatePushMessage {
    /// Create a new join-state push message.
    #[must_use]
    pub fn new(push_seq: u64, roster: CommittedRoster, joining_peer_id: u64) -> Self {
        Self {
            push_seq,
            roster,
            joining_peer_id,
        }
    }

    /// Encode to binary wire format.
    ///
    /// Format: push_seq(u64 LE) + epoch(u64 LE) + roster_hash(32 bytes)
    /// + member_count(u32 LE) + member_ids(u64 LE each) + joining_peer_id(u64 LE).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mc = self.roster.member_ids.len() as u32;
        let mut buf = Vec::with_capacity(60 + mc as usize * 8);
        buf.extend_from_slice(&self.push_seq.to_le_bytes());
        buf.extend_from_slice(&self.roster.epoch.0.to_le_bytes());
        buf.extend_from_slice(&self.roster.roster_hash);
        buf.extend_from_slice(&mc.to_le_bytes());
        for id in &self.roster.member_ids {
            buf.extend_from_slice(&id.to_le_bytes());
        }
        buf.extend_from_slice(&self.joining_peer_id.to_le_bytes());
        buf
    }

    /// Decode from binary wire format.
    ///
    /// Returns `None` if the buffer is too short or member_count exceeds
    /// the available data.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Self> {
        // Minimum: push_seq(8) + epoch(8) + roster_hash(32) + member_count(4) + joining_peer_id(8) = 60
        if data.len() < 60 {
            return None;
        }
        let push_seq = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let epoch = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let mut roster_hash = [0u8; 32];
        roster_hash.copy_from_slice(&data[16..48]);
        let mc = u32::from_le_bytes(data[48..52].try_into().unwrap()) as usize;
        let members_end = 52 + mc * 8;
        if data.len() < members_end + 8 {
            return None;
        }
        let mut member_ids = Vec::with_capacity(mc);
        for i in 0..mc {
            let off = 52 + i * 8;
            member_ids.push(u64::from_le_bytes(data[off..off + 8].try_into().unwrap()));
        }
        let joining_peer_id =
            u64::from_le_bytes(data[members_end..members_end + 8].try_into().unwrap());
        Some(Self {
            push_seq,
            roster: CommittedRoster {
                epoch: EpochId(epoch),
                member_ids,
                roster_hash,
            },
            joining_peer_id,
        })
    }

    /// Whether the joining peer is already in the roster (should not happen
    /// on a correct join path; used for integrity checking).
    #[must_use]
    pub fn joining_peer_in_roster(&self) -> bool {
        self.roster.contains(self.joining_peer_id)
    }
}

// ---------------------------------------------------------------------------
// Handler & Dispatcher
// ---------------------------------------------------------------------------
use std::sync::Arc;

/// Trait for handling incoming join-state push messages.
pub trait JoinStatePushHandler: Send + Sync {
    fn on_join_state_push(&self, push_seq: u64, msg: &JoinStatePushMessage);
}

/// Bridges transport message dispatch to a registered [`JoinStatePushHandler`].
///
/// Decodes incoming join-state push transport messages and forwards the
/// parsed message to the handler.
pub struct JoinStatePushDispatcher {
    handler: Arc<dyn JoinStatePushHandler>,
}

impl JoinStatePushDispatcher {
    #[must_use]
    pub fn new(handler: Arc<dyn JoinStatePushHandler>) -> Self {
        Self { handler }
    }

    pub fn handle_raw(&self, payload: &[u8]) -> Result<(), String> {
        let msg = JoinStatePushMessage::decode(payload)
            .ok_or_else(|| "join-state push: decode failed".to_string())?;
        self.handler.on_join_state_push(msg.push_seq, &msg);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tidefs_membership_epoch::EpochId;

    fn mk(epoch: u64, ids: Vec<u64>) -> CommittedRoster {
        CommittedRoster::new(EpochId(epoch), ids)
    }

    #[test]
    fn roundtrip_empty_roster() {
        let m = JoinStatePushMessage::new(0, mk(1, vec![]), 42);
        let d = JoinStatePushMessage::decode(&m.encode()).unwrap();
        assert_eq!(d.push_seq, 0);
        assert!(d.roster.member_ids.is_empty());
        assert_eq!(d.joining_peer_id, 42);
    }

    #[test]
    fn roundtrip_one_member() {
        let r = mk(5, vec![10]);
        let m = JoinStatePushMessage::new(1, r.clone(), 99);
        let d = JoinStatePushMessage::decode(&m.encode()).unwrap();
        assert_eq!(d.roster.epoch, EpochId(5));
        assert_eq!(d.roster.roster_hash, r.roster_hash);
        assert_eq!(d.roster.member_ids, vec![10]);
        assert_eq!(d.joining_peer_id, 99);
    }

    #[test]
    fn roundtrip_multi_member() {
        let ids = vec![1, 3, 5, 7, 9, 11];
        let r = mk(3, ids.clone());
        let m = JoinStatePushMessage::new(7, r, 5);
        let d = JoinStatePushMessage::decode(&m.encode()).unwrap();
        assert_eq!(d.roster.member_ids, ids);
        assert_eq!(d.joining_peer_id, 5);
    }

    #[test]
    fn short_buf_returns_none() {
        assert!(JoinStatePushMessage::decode(&[]).is_none());
        assert!(JoinStatePushMessage::decode(&[0u8; 59]).is_none());
    }

    #[test]
    fn truncated_members_returns_none() {
        let r = mk(1, vec![10, 20]);
        let mut enc = JoinStatePushMessage::new(0, r, 10).encode();
        // Trim off joining_peer_id so member_count says 2 but data is too short
        enc.truncate(52 + 8 + 8); // only one member when count says 2
        assert!(JoinStatePushMessage::decode(&enc).is_none());
    }

    #[test]
    fn deterministic_encoding() {
        let r = mk(2, vec![10, 20]);
        let m = JoinStatePushMessage::new(0, r, 30);
        assert_eq!(m.encode(), m.encode());
    }

    #[test]
    fn joining_peer_in_roster_false_for_new_peer() {
        let m = JoinStatePushMessage::new(0, mk(1, vec![10, 20, 30]), 99);
        assert!(!m.joining_peer_in_roster());
    }

    #[test]
    fn joining_peer_in_roster_true_when_present() {
        let m = JoinStatePushMessage::new(0, mk(1, vec![10, 20, 30]), 20);
        assert!(m.joining_peer_in_roster());
    }

    struct TH {
        calls: Mutex<Vec<(u64, JoinStatePushMessage)>>,
    }
    impl TH {
        fn new() -> Self {
            Self {
                calls: Mutex::new(vec![]),
            }
        }
    }
    impl JoinStatePushHandler for TH {
        fn on_join_state_push(&self, s: u64, m: &JoinStatePushMessage) {
            self.calls.lock().unwrap().push((s, m.clone()));
        }
    }

    #[test]
    fn dispatcher_forwards_to_handler() {
        let h = Arc::new(TH::new());
        let d = JoinStatePushDispatcher::new(h.clone());
        let m = JoinStatePushMessage::new(3, mk(5, vec![1, 2, 3]), 2);
        assert!(d.handle_raw(&m.encode()).is_ok());
        assert_eq!(h.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn dispatcher_bad_payload_returns_err() {
        let h = Arc::new(TH::new());
        let d = JoinStatePushDispatcher::new(h.clone());
        assert!(d.handle_raw(&[0u8; 10]).is_err());
        assert_eq!(h.calls.lock().unwrap().len(), 0);
    }

    #[test]
    fn dispatcher_multiple_messages() {
        let h = Arc::new(TH::new());
        let d = JoinStatePushDispatcher::new(h.clone());
        for i in 0..5 {
            d.handle_raw(&JoinStatePushMessage::new(i, mk(i, vec![i]), i).encode())
                .unwrap();
        }
        assert_eq!(h.calls.lock().unwrap().len(), 5);
    }

    #[test]
    fn roundtrip_large_roster() {
        let ids: Vec<u64> = (0..100).collect();
        let r = mk(10, ids.clone());
        let m = JoinStatePushMessage::new(42, r.clone(), 77);
        let d = JoinStatePushMessage::decode(&m.encode()).unwrap();
        assert_eq!(d.roster.member_ids, ids);
        assert_eq!(d.roster.epoch, EpochId(10));
        assert_eq!(d.roster.roster_hash, r.roster_hash);
        assert_eq!(d.push_seq, 42);
        assert_eq!(d.joining_peer_id, 77);
    }
}

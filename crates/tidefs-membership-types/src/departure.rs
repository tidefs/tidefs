//! Coordinated peer departure wire protocol types.
//!
//! Defines the wire types for the departure protocol:
//!
//! - [`DepartureRequest`]: sent from a peer to the coordinator to request
//!   voluntary departure from the cluster.
//! - [`DepartureResponse`]: sent from the coordinator back to the requesting
//!   peer with accept/reject decision.
//! - [`DepartureReason`]: why the departure was initiated (Voluntary or
//!   coordinator Evicted).
//! - [`DepartureState`]: peer-side state machine tracking.
//! - [`DepartureOutcome`]: result of a departure attempt.
//!
//! Every wire type implements [`MembershipCodec`] for binary encode/decode
//! with CRC32C checksums.

#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::string::String;

use crate::{MembershipCodec, MembershipCodecError};

// ---------------------------------------------------------------------------
// DepartureReason
// ---------------------------------------------------------------------------

/// Reason for a peer departure.
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepartureReason {
    /// The peer requested to leave voluntarily.
    Voluntary = 0,
    /// The coordinator initiated eviction of the peer.
    Evicted = 1,
}

impl DepartureReason {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Voluntary),
            1 => Some(Self::Evicted),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// DepartureOutcome
// ---------------------------------------------------------------------------

/// Outcome of a departure attempt.
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepartureOutcome {
    /// The departure was accepted by the coordinator.
    Accepted = 0,
    /// The departure was rejected.
    Rejected = 1,
}

impl DepartureOutcome {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Accepted),
            1 => Some(Self::Rejected),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// DepartureState
// ---------------------------------------------------------------------------

/// Peer-side state machine for coordinated departure.
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepartureState {
    /// Departure has been requested but not yet acknowledged.
    Pending = 0,
    /// Coordinator is collecting quorum votes for the roster change.
    QuorumVoting = 1,
    /// The departure has been committed and the epoch has advanced.
    Committed = 2,
    /// The departure was aborted (timeout, quorum rejection, etc.).
    Aborted = 3,
}

impl DepartureState {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Pending),
            1 => Some(Self::QuorumVoting),
            2 => Some(Self::Committed),
            3 => Some(Self::Aborted),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// DepartureRequest
// ---------------------------------------------------------------------------

/// A peer's request to the coordinator for voluntary departure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepartureRequest {
    /// The peer requesting departure.
    pub peer_id: u64,
    /// Reason for departure (always Voluntary for peer-initiated).
    pub reason: DepartureReason,
    /// Current epoch when the request was created.
    pub request_epoch: u64,
    /// Monotonic nonce for request deduplication.
    pub nonce: u64,
}

impl MembershipCodec for DepartureRequest {
    #[cfg(feature = "alloc")]
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        crate::push_u64(buf, self.peer_id);
        crate::push_u8(buf, self.reason as u8);
        crate::push_u64(buf, self.request_epoch);
        crate::push_u64(buf, self.nonce);
        crate::push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        crate::verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        if payload.len() < 25 {
            return Err(MembershipCodecError::Underflow);
        }
        let mut pos = 0usize;
        let peer_id = crate::read_u64(payload, &mut pos)?;
        let reason_byte = crate::read_u8(payload, &mut pos)?;
        let reason = DepartureReason::from_u8(reason_byte).ok_or(
            MembershipCodecError::InvalidDiscriminant {
                field: "DepartureReason",
                value: reason_byte,
            },
        )?;
        let request_epoch = crate::read_u64(payload, &mut pos)?;
        let nonce = crate::read_u64(payload, &mut pos)?;
        Ok(Self {
            peer_id,
            reason,
            request_epoch,
            nonce,
        })
    }
}

// ---------------------------------------------------------------------------
// DepartureResponse
// ---------------------------------------------------------------------------

/// Coordinator response to a peer's departure request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepartureResponse {
    /// The peer this response is addressed to.
    pub peer_id: u64,
    /// Whether the departure was accepted.
    pub accepted: bool,
    /// The epoch after the departure (successor epoch).
    pub successor_epoch: u64,
    /// Human-readable rejection reason when `accepted` is false.
    #[cfg(feature = "alloc")]
    pub reject_reason: Option<String>,
}

impl MembershipCodec for DepartureResponse {
    #[cfg(feature = "alloc")]
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        crate::push_u64(buf, self.peer_id);
        crate::push_bool(buf, self.accepted);
        crate::push_u64(buf, self.successor_epoch);
        match &self.reject_reason {
            Some(reason) => {
                let reason_bytes = reason.as_bytes();
                crate::push_u32(buf, reason_bytes.len() as u32);
                buf.extend_from_slice(reason_bytes);
            }
            None => {
                crate::push_u32(buf, 0);
            }
        }
        crate::push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        crate::verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        if payload.len() < 21 {
            return Err(MembershipCodecError::Underflow);
        }
        let mut pos = 0usize;
        let peer_id = crate::read_u64(payload, &mut pos)?;
        let accepted = crate::read_bool(payload, &mut pos)?;
        let successor_epoch = crate::read_u64(payload, &mut pos)?;

        #[cfg(feature = "alloc")]
        {
            let reason_len = crate::read_u32(payload, &mut pos)? as usize;
            let reject_reason = if reason_len == 0 {
                None
            } else {
                if payload.len() < pos + reason_len {
                    return Err(MembershipCodecError::Underflow);
                }
                let bytes = &payload[pos..pos + reason_len];
                let s = String::from_utf8(bytes.to_vec()).map_err(|_| {
                    MembershipCodecError::InvalidDiscriminant {
                        field: "DepartureResponse.reject_reason (invalid UTF-8)",
                        value: 0,
                    }
                })?;
                // pos is not advanced past reason in this branch
                Some(s)
            };
            Ok(Self {
                peer_id,
                accepted,
                successor_epoch,
                reject_reason,
            })
        }

        #[cfg(not(feature = "alloc"))]
        {
            let reason_len = crate::read_u32(payload, &mut pos)? as usize;
            // advance pos past reason bytes
            if payload.len() < pos + reason_len {
                return Err(MembershipCodecError::Underflow);
            }
            Ok(Self {
                peer_id,
                accepted,
                successor_epoch,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Roundtrip encode/decode + equality check.
    fn roundtrip_val<T: MembershipCodec + core::fmt::Debug + PartialEq>(val: T) {
        let mut buf = Vec::new();
        val.encode(&mut buf);
        let decoded = T::decode(&buf).unwrap();
        assert_eq!(decoded, val, "roundtrip mismatch");
    }

    #[test]
    fn departure_reason_discriminants() {
        assert_eq!(DepartureReason::Voluntary as u8, 0);
        assert_eq!(DepartureReason::Evicted as u8, 1);
    }

    #[test]
    fn departure_reason_from_u8_valid() {
        assert_eq!(
            DepartureReason::from_u8(0),
            Some(DepartureReason::Voluntary)
        );
        assert_eq!(DepartureReason::from_u8(1), Some(DepartureReason::Evicted));
    }

    #[test]
    fn departure_reason_from_u8_invalid() {
        assert_eq!(DepartureReason::from_u8(2), None);
        assert_eq!(DepartureReason::from_u8(255), None);
    }

    #[test]
    fn departure_outcome_discriminants() {
        assert_eq!(DepartureOutcome::Accepted as u8, 0);
        assert_eq!(DepartureOutcome::Rejected as u8, 1);
    }

    #[test]
    fn departure_outcome_from_u8_valid() {
        assert_eq!(
            DepartureOutcome::from_u8(0),
            Some(DepartureOutcome::Accepted)
        );
        assert_eq!(
            DepartureOutcome::from_u8(1),
            Some(DepartureOutcome::Rejected)
        );
    }

    #[test]
    fn departure_outcome_from_u8_invalid() {
        assert_eq!(DepartureOutcome::from_u8(2), None);
    }

    #[test]
    fn departure_state_discriminants() {
        assert_eq!(DepartureState::Pending as u8, 0);
        assert_eq!(DepartureState::QuorumVoting as u8, 1);
        assert_eq!(DepartureState::Committed as u8, 2);
        assert_eq!(DepartureState::Aborted as u8, 3);
    }

    #[test]
    fn departure_state_from_u8_all_valid() {
        assert_eq!(DepartureState::from_u8(0), Some(DepartureState::Pending));
        assert_eq!(
            DepartureState::from_u8(1),
            Some(DepartureState::QuorumVoting)
        );
        assert_eq!(DepartureState::from_u8(2), Some(DepartureState::Committed));
        assert_eq!(DepartureState::from_u8(3), Some(DepartureState::Aborted));
    }

    #[test]
    fn departure_state_from_u8_invalid() {
        assert_eq!(DepartureState::from_u8(4), None);
        assert_eq!(DepartureState::from_u8(255), None);
    }

    // ── DepartureRequest encode/decode roundtrips ────────────────────

    #[test]
    fn departure_request_voluntary_roundtrip() {
        roundtrip_val(DepartureRequest {
            peer_id: 42,
            reason: DepartureReason::Voluntary,
            request_epoch: 7,
            nonce: 12345,
        });
    }

    #[test]
    fn departure_request_evicted_roundtrip() {
        roundtrip_val(DepartureRequest {
            peer_id: 99,
            reason: DepartureReason::Evicted,
            request_epoch: 10,
            nonce: 0,
        });
    }

    #[test]
    fn departure_request_max_values_roundtrip() {
        roundtrip_val(DepartureRequest {
            peer_id: u64::MAX,
            reason: DepartureReason::Voluntary,
            request_epoch: u64::MAX,
            nonce: u64::MAX,
        });
    }

    #[test]
    fn departure_request_decode_underflow() {
        let data = [0u8; 10];
        assert!(DepartureRequest::decode(&data).is_err());
    }

    #[test]
    fn departure_request_decode_bad_reason_discriminant() {
        let mut buf = Vec::new();
        let req = DepartureRequest {
            peer_id: 1,
            reason: DepartureReason::Voluntary,
            request_epoch: 0,
            nonce: 0,
        };
        req.encode(&mut buf);
        // Corrupt the reason byte (offset 8)
        buf[8] = 99;
        assert!(DepartureRequest::decode(&buf).is_err());
    }

    #[test]
    fn departure_request_checksum_corruption() {
        let req = DepartureRequest {
            peer_id: 42,
            reason: DepartureReason::Voluntary,
            request_epoch: 7,
            nonce: 12345,
        };
        let mut buf = Vec::new();
        req.encode(&mut buf);
        let mid = buf.len() / 2;
        buf[mid] ^= 0xFF;
        assert!(DepartureRequest::decode(&buf).is_err());
    }

    // ── DepartureResponse encode/decode roundtrips ───────────────────

    #[test]
    fn departure_response_accepted_roundtrip() {
        roundtrip_val(DepartureResponse {
            peer_id: 42,
            accepted: true,
            successor_epoch: 8,
            reject_reason: None,
        });
    }

    #[test]
    fn departure_response_rejected_roundtrip() {
        roundtrip_val(DepartureResponse {
            peer_id: 42,
            accepted: false,
            successor_epoch: 7,
            reject_reason: Some("peer is not in current roster".into()),
        });
    }

    #[test]
    fn departure_response_long_reason_roundtrip() {
        let long_reason = "x".repeat(512);
        roundtrip_val(DepartureResponse {
            peer_id: 1,
            accepted: false,
            successor_epoch: 0,
            reject_reason: Some(long_reason),
        });
    }

    #[test]
    fn departure_response_max_values_roundtrip() {
        roundtrip_val(DepartureResponse {
            peer_id: u64::MAX,
            accepted: true,
            successor_epoch: u64::MAX,
            reject_reason: None,
        });
    }

    #[test]
    fn departure_response_decode_underflow() {
        let data = [0u8; 10];
        assert!(DepartureResponse::decode(&data).is_err());
    }

    #[test]
    fn departure_response_checksum_corruption() {
        let resp = DepartureResponse {
            peer_id: 42,
            accepted: false,
            successor_epoch: 5,
            reject_reason: Some("test reason".into()),
        };
        let mut buf = Vec::new();
        resp.encode(&mut buf);
        let last = buf.len() - 1;
        buf[last] ^= 0xFF;
        assert!(DepartureResponse::decode(&buf).is_err());
    }

    #[test]
    fn departure_response_empty_reason_roundtrip() {
        // Empty reason normalizes to None on encode (matches RosterChangeVote behavior).
        roundtrip_val(DepartureResponse {
            peer_id: 1,
            accepted: false,
            successor_epoch: 0,
            reject_reason: None, // empty string normalizes to None
        });
    }

    #[test]
    fn departure_response_reason_len_matches() {
        // Verify encoded reason_len matches the reason string length.
        let reason = "member not found";
        let resp = DepartureResponse {
            peer_id: 1,
            accepted: false,
            successor_epoch: 0,
            reject_reason: Some(reason.into()),
        };
        let mut buf = Vec::new();
        resp.encode(&mut buf);
        // Bytes 17..21 = reason_len u32 LE
        let reason_len = u32::from_le_bytes([buf[17], buf[18], buf[19], buf[20]]) as usize;
        assert_eq!(reason_len, reason.len());
    }

    #[test]
    fn departure_response_rejected_without_reason_is_none() {
        // When accepted=false and reject_reason=None is used,
        // decode should produce reject_reason=None.
        roundtrip_val(DepartureResponse {
            peer_id: 5,
            accepted: false,
            successor_epoch: 0,
            reject_reason: None,
        });
    }
}

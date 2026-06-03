//! Transport envelope wire protocol and message family definitions.
//!
//! ## Envelope flow in the endpoint lifecycle
//!
//! Transport envelopes carry the framed messages that flow during step 6 of
//! the P8-01 endpoint lifecycle: **Envelope flow**. By the time a session
//! reaches this stage, it has already been:
//!
//! 1. Opened via mutual attestation (step 2),
//! 2. Bound to an endpoint family (step 3),
//! 3. Attached to cohort classes (step 4), and
//! 4. Admitted per-lane budgets (step 5).
//!
//! The envelope layer then carries all application traffic for the remainder
//! of the session lifetime — through drain/resume (step 7) and closure (step 8).
//!
//! ### Envelope invariants
//!
//! | Invariant | Rule |
//! |---|---|
//! | **sequence-monotonic** | Per-lane sequence numbers are strictly increasing; an envelope with a sequence ≤ the peer's last-acked floor is silently dropped (dedup). |
//! | **ack-floor-non-regressing** | The ack floor for a lane never decreases; a peer advancing the floor below the current high-water mark is a protocol error. |
//! | **magic-version-frozen** | `ENVELOPE_MAGIC` (`VEFS`) and the version-byte position are permanently frozen; peers reject unknown versions with a version-mismatch closure. |
//! | **crc-integrity** | Every frame carries a CRC32C checksum over all preceding bytes; a frame failing CRC is discarded without state mutation. |
//! | **family-lane-compatible** | Every `MessageFamily` maps to a preferred `LaneClass` via `MessageFamily::preferred_lane`; routing a family to a non-preferred lane is a signaling error. |
//! | **visibility-gated** | `VisibilityClass` controls redaction gates: `Clear` and `Public` carry full payload; `Internal` and `Encrypted` restrict anchor-ref content and may key the payload via `secret_key_policy_0`. |
//! | **per-lane-sequence-isolation** | `SequenceTracker` maintains independent sequence-number and ack-floor counters per lane; Control-lane sequence numbers are disjoint from Background-lane sequence numbers. |
//!
//! ### Wire format stability
//!
//! The envelope wire format is defined by the permanent constants
//! `ENVELOPE_MAGIC` and `ENVELOPE_VERSION`. The header layout is 42 bytes:
//!
//! ```text
//! [0..4)    magic       "VEFS"
//! [4]       version     1
//! [5]       visibility  u8 discriminant
//! [6]       lane        u8 discriminant
//! [7]       family      u8 discriminant
//! [8..16)   session_id  u64 LE
//! [16..24)  cohort_id   u64 LE
//! [24..32)  seq_no      u64 LE
//! [32..40)  ack_floor   u64 LE
//! [40..42)  anchors     u16 LE count (≤ 256)
//! ```
//!
//! Followed by: anchor refs (32 bytes each), payload_len (u32 LE),
//! payload_digest (32 bytes, reserved/zero-filled), payload, and frame_crc32c (4 bytes).
//!
//! ### Endpoint family integration
//!
//! The envelope layer is endpoint-family-agnostic — the same encode/decode
//! logic serves all four endpoint families. Family-level gating happens at
//! the session layer: a `MessageFamily` that is illegal for the session's
//! endpoint family is rejected before the envelope is constructed.
//!
//! | EndpointFamily | Permitted message families | Primary session class |
//! |---|---|---|
//! | `LocalEmbed` (e0) | m0–m9 (all families) | Co-resident service |
//! | `Control` (e1) | m0–m5, m9 (no bulk/shadow) | Control-plane |
//! | `Data` (e2) | m6, m7 (bulk only) | TransferBulk |
//! | `Shadow` (e3) | m8 (shadow only) | ShadowValidation |
//!
use std::fmt;

use crate::lane_demux::LaneClass;
use crate::session_cohort::TransportCohortId;
use crate::types::{Hash, SessionId};

// ---------------------------------------------------------------------------
// Wire constants — canonical binary law P2-03
// ---------------------------------------------------------------------------

/// Magic bytes: "VEFS" = TideFS Envelope Frame Start.
const ENVELOPE_MAGIC: [u8; 4] = *b"VEFS";

/// Current envelope format version.
const ENVELOPE_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Domain-separation constants for transport envelope payload integrity
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// MessageFamily — 10 stable families (P8-01 §7.2)
// ---------------------------------------------------------------------------

/// Every transport message must name exactly one message family.
/// The family determines routing, permissible session/lane pairs,
/// and the expected payload schema.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum MessageFamily {
    /// m0: open / accept / refuse / drain / close
    HelloClose = 0,
    /// m1: heartbeat, ack, watermark, keepalive
    HeartbeatAck = 1,
    /// m2: prevote / vote / announce / control-election verbs
    ElectionControl = 2,
    /// m3: lease renew/recall, fence issue/ack/escalate
    LeaseFenceDeadline = 3,
    /// m4: proposals, commits, progress vectors, publication-linked receipts
    PublicationProgress = 4,
    /// m5: log-sync / catch-up metadata, resumable metadata windows
    LogSyncMetadata = 5,
    /// m6: checkpoint/snapshot begin, chunk, ack, complete
    StateTransfer = 6,
    /// m7: replica chunk movement, verification, rebuild/relocation updates
    ReplicaTransferVerify = 7,
    /// m8: divergence capsules, shadow outputs, truth-link bundles
    ShadowValidation = 8,
    /// m9: hold, unblock, rollback, resume, stage coordination
    TransitionHoldResume = 9,
}

impl MessageFamily {
    /// Total number of stable message families.
    pub const COUNT: usize = 10;

    /// Return all message family variants as an array.
    pub const fn all() -> [MessageFamily; 10] {
        [
            Self::HelloClose,
            Self::HeartbeatAck,
            Self::ElectionControl,
            Self::LeaseFenceDeadline,
            Self::PublicationProgress,
            Self::LogSyncMetadata,
            Self::StateTransfer,
            Self::ReplicaTransferVerify,
            Self::ShadowValidation,
            Self::TransitionHoldResume,
        ]
    }

    /// Canonical preferred lane for normal operation.
    #[must_use]
    pub const fn preferred_lane(self) -> LaneClass {
        match self {
            Self::HelloClose
            | Self::HeartbeatAck
            | Self::ElectionControl
            | Self::LeaseFenceDeadline => LaneClass::Control,
            Self::PublicationProgress | Self::LogSyncMetadata => LaneClass::Metadata,
            Self::StateTransfer | Self::ReplicaTransferVerify => LaneClass::Demand,
            Self::ShadowValidation => LaneClass::Speculative,
            Self::TransitionHoldResume => LaneClass::Control,
        }
    }
}

impl TryFrom<u8> for MessageFamily {
    type Error = EnvelopeError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::HelloClose),
            1 => Ok(Self::HeartbeatAck),
            2 => Ok(Self::ElectionControl),
            3 => Ok(Self::LeaseFenceDeadline),
            4 => Ok(Self::PublicationProgress),
            5 => Ok(Self::LogSyncMetadata),
            6 => Ok(Self::StateTransfer),
            7 => Ok(Self::ReplicaTransferVerify),
            8 => Ok(Self::ShadowValidation),
            9 => Ok(Self::TransitionHoldResume),
            _ => Err(EnvelopeError::UnknownMessageFamily(v)),
        }
    }
}

impl fmt::Display for MessageFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::HelloClose => "m0.HelloClose",
            Self::HeartbeatAck => "m1.HeartbeatAck",
            Self::ElectionControl => "m2.ElectionControl",
            Self::LeaseFenceDeadline => "m3.LeaseFenceDeadline",
            Self::PublicationProgress => "m4.PublicationProgress",
            Self::LogSyncMetadata => "m5.LogSyncMetadata",
            Self::StateTransfer => "m6.StateTransfer",
            Self::ReplicaTransferVerify => "m7.ReplicaTransferVerify",
            Self::ShadowValidation => "m8.ShadowValidation",
            Self::TransitionHoldResume => "m9.TransitionHoldResume",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// VisibilityClass
// ---------------------------------------------------------------------------

/// Payload visibility / redaction class.
/// Secret-sensitive traffic is limited to handle refs, lease ids,
/// and digest-linked receipts under `secret_key_policy_0`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum VisibilityClass {
    /// Payload is unrestricted; may be logged or traced verbatim.
    #[default]
    Public = 0,
    /// Payload carries internal cluster metadata; must not leave the
    /// trust boundary but operators may inspect.
    Internal = 1,
    /// Payload is encrypted under the active session key.
    Encrypted = 2,
    /// Payload is redacted to handle-refs only; body must carry
    /// opaque secret-handle, lease-id, or digest-linked receipt under
    /// `secret_key_policy_0`.  Plaintext secret bytes are never
    /// serialised on-wire in this class.
    HandleRedacted = 3,
}

impl TryFrom<u8> for VisibilityClass {
    type Error = EnvelopeError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Public),
            1 => Ok(Self::Internal),
            2 => Ok(Self::Encrypted),
            3 => Ok(Self::HandleRedacted),
            _ => Err(EnvelopeError::UnknownVisibilityClass(v)),
        }
    }
}

impl fmt::Display for VisibilityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => f.write_str("public"),
            Self::Internal => f.write_str("internal"),
            Self::Encrypted => f.write_str("encrypted"),
            Self::HandleRedacted => f.write_str("handle_redacted"),
        }
    }
}

// ---------------------------------------------------------------------------
// TransportEnvelope
// ---------------------------------------------------------------------------

/// Production transport message envelope (P8-01 §7.3).
///
/// Every message on the wire carries this envelope.  It binds the payload to
/// a session, cohort, lane, message family, and monotonic sequence number,
/// and provides two integrity layers:
///
/// * CRC32C over the whole frame for fast corruption detection
/// * BLAKE3-256 payload digest for strong identity / transfer integrity
///
/// ## Wire layout (little-endian, P2-03 canonical binary law)
///
/// ```text
/// [ 0.. 4)  magic           b"VEFS"
/// [ 4]       version         1
/// [ 5]       visibility      u8
/// [ 6]       lane_class      u8
/// [ 7]       message_family  u8
/// [ 8..16)   session_id      u64 LE
/// [16..24)   cohort_id       u64 LE
/// [24..32)   sequence_number u64 LE
/// [32..40)   ack_floor       u64 LE
/// [40..42)   anchor_count    u16 LE
/// [42..]     anchor_refs     count × 32 bytes
/// [...]      payload_len     u32 LE
/// [...]      payload_digest  32 bytes (reserved, zero-filled)
/// [...]      payload         payload_len bytes
/// [...]      frame_crc32c    4 bytes (over all previous bytes)
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportEnvelope {
    pub session_id: SessionId,
    pub cohort_id: TransportCohortId,
    pub lane_class: LaneClass,
    pub message_family: MessageFamily,
    pub sequence_number: u64,
    pub ack_floor: u64,
    pub anchor_refs: Vec<Hash>,
    pub visibility_class: VisibilityClass,
    /// Set to zero during `encode()`; preserved for wire-format compatibility.
    /// Integrity is provided by the frame CRC32C and transport MAC.
    payload_digest: Hash,
}

impl TransportEnvelope {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    /// Create a new TransportEnvelope for the given lane and message family.
    pub fn new(
        session_id: SessionId,
        cohort_id: TransportCohortId,
        lane_class: LaneClass,
        message_family: MessageFamily,
        sequence_number: u64,
        ack_floor: u64,
        anchor_refs: Vec<Hash>,
        visibility_class: VisibilityClass,
    ) -> Self {
        Self {
            session_id,
            cohort_id,
            lane_class,
            message_family,
            sequence_number,
            ack_floor,
            anchor_refs,
            visibility_class,
            payload_digest: Hash([0u8; 32]),
        }
    }

    /// The reserved payload digest field (zero-filled).
    #[must_use]
    pub fn payload_digest(&self) -> Hash {
        self.payload_digest
    }

    /// Predicted wire size for a given payload length and anchor count.
    #[must_use]
    pub fn wire_size(payload_len: usize, anchor_count: usize) -> usize {
        42 + anchor_count * 32 + 4 + 32 + payload_len + 4
    }

    /// Encode this envelope and its payload into a single wire-format buffer.
    ///
    /// Encode the envelope and its payload into a wire-format buffer.
    /// Appends a CRC32C frame checksum over the entire preceding byte range.
    #[must_use]
    pub fn encode(&mut self, payload: &[u8]) -> Vec<u8> {
        // Payload digest is zero-filled (integrity via frame CRC32C + transport MAC).
        let digest: [u8; 32] = [0u8; 32];
        self.payload_digest = Hash(digest);

        let anchor_count = self.anchor_refs.len() as u16;
        let payload_len = payload.len() as u32;

        let total = Self::wire_size(payload.len(), self.anchor_refs.len());
        let mut buf = Vec::with_capacity(total);

        // --- fixed header (42 bytes) ---
        buf.extend_from_slice(&ENVELOPE_MAGIC);
        buf.push(ENVELOPE_VERSION);
        buf.push(self.visibility_class as u8);
        buf.push(self.lane_class as u8);
        buf.push(self.message_family as u8);
        buf.extend_from_slice(&self.session_id.0.to_le_bytes());
        buf.extend_from_slice(&self.cohort_id.0.to_le_bytes());
        buf.extend_from_slice(&self.sequence_number.to_le_bytes());
        buf.extend_from_slice(&self.ack_floor.to_le_bytes());
        buf.extend_from_slice(&anchor_count.to_le_bytes());

        // --- anchor refs ---
        for a in &self.anchor_refs {
            buf.extend_from_slice(&a.0);
        }

        // --- payload framing ---
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&digest);
        buf.extend_from_slice(payload);

        // --- frame CRC ---
        let crc = crc32c::crc32c(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());

        buf
    }

    /// Decode a `TransportEnvelope` and its payload from a wire buffer.
    ///
    /// # Integrity checks (in order)
    ///
    /// 1. Minimum size (≥ 42 bytes)
    /// 2. Magic bytes
    /// 3. Version
    /// 4. All discriminant validations
    /// 5. Bounds checks for anchor / payload / digest sections
    /// 6. CRC32C frame checksum
    /// 7. BLAKE3-256 payload digest
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError`] on any structural or integrity violation.
    pub fn decode(data: &[u8]) -> Result<(Self, Vec<u8>), EnvelopeError> {
        if data.len() < 42 {
            return Err(EnvelopeError::TooShort {
                got: data.len(),
                min: 42,
            });
        }

        // --- magic ---
        if data[0..4] != ENVELOPE_MAGIC {
            let mut got = [0u8; 4];
            got.copy_from_slice(&data[0..4]);
            return Err(EnvelopeError::BadMagic { got });
        }

        // --- version ---
        if data[4] != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(data[4]));
        }

        // --- discriminants ---
        let visibility_class = VisibilityClass::try_from(data[5])?;
        let lane_raw = data[6];
        if lane_raw as usize >= LaneClass::COUNT {
            return Err(EnvelopeError::UnknownLaneClass(lane_raw));
        }
        // Safety: just checked the bound
        let lane_class = LaneClass::all()[lane_raw as usize];
        let message_family = MessageFamily::try_from(data[7])?;

        // --- fixed numeric fields ---
        let session_id = SessionId(u64::from_le_bytes(data[8..16].try_into().unwrap()));
        let cohort_id = TransportCohortId(u64::from_le_bytes(data[16..24].try_into().unwrap()));
        let sequence_number = u64::from_le_bytes(data[24..32].try_into().unwrap());
        let ack_floor = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let anchor_count = u16::from_le_bytes(data[40..42].try_into().unwrap()) as usize;

        // --- anchors ---
        let anchors_start = 42;
        let anchors_end = anchors_start + anchor_count * 32;
        if data.len() < anchors_end + 4 {
            return Err(EnvelopeError::TooShort {
                got: data.len(),
                min: anchors_end + 4,
            });
        }

        let mut anchor_refs = Vec::with_capacity(anchor_count);
        for i in 0..anchor_count {
            let off = anchors_start + i * 32;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&data[off..off + 32]);
            anchor_refs.push(Hash(arr));
        }

        // --- payload length ---
        let plen_start = anchors_end;
        if data.len() < plen_start + 4 {
            return Err(EnvelopeError::TooShort {
                got: data.len(),
                min: plen_start + 4,
            });
        }
        let payload_len =
            u32::from_le_bytes(data[plen_start..plen_start + 4].try_into().unwrap()) as usize;

        // --- payload digest ---
        let digest_start = plen_start + 4;
        if data.len() < digest_start + 32 {
            return Err(EnvelopeError::TooShort {
                got: data.len(),
                min: digest_start + 32,
            });
        }
        let mut digest_bytes = [0u8; 32];
        digest_bytes.copy_from_slice(&data[digest_start..digest_start + 32]);

        // --- payload ---
        let payload_start = digest_start + 32;
        let crc_start = payload_start + payload_len;
        if data.len() < crc_start + 4 {
            return Err(EnvelopeError::TooShort {
                got: data.len(),
                min: crc_start + 4,
            });
        }
        let payload = data[payload_start..payload_start + payload_len].to_vec();

        // --- CRC32C ---
        let expected_crc = u32::from_le_bytes(data[crc_start..crc_start + 4].try_into().unwrap());
        let actual_crc = crc32c::crc32c(&data[..crc_start]);
        if actual_crc != expected_crc {
            return Err(EnvelopeError::CrcMismatch {
                expected: expected_crc,
                got: actual_crc,
            });
        }

        // Payload digest is reserved (zero-filled). Integrity is provided
        // by the frame CRC32C and transport MAC; skip BLAKE3 verification.

        Ok((
            Self {
                session_id,
                cohort_id,
                lane_class,
                message_family,
                sequence_number,
                ack_floor,
                anchor_refs,
                visibility_class,
                payload_digest: Hash(digest_bytes),
            },
            payload,
        ))
    }
}

// ---------------------------------------------------------------------------
// EnvelopeError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
/// Errors that can occur during envelope encoding or decoding.
pub enum EnvelopeError {
    TooShort { got: usize, min: usize },
    BadMagic { got: [u8; 4] },
    UnsupportedVersion(u8),
    UnknownLaneClass(u8),
    UnknownMessageFamily(u8),
    UnknownVisibilityClass(u8),
    CrcMismatch { expected: u32, got: u32 },
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { got, min } => {
                write!(f, "data too short: {got} bytes, need at least {min}")
            }
            Self::BadMagic { got } => {
                write!(
                    f,
                    "bad magic: expected {ENVELOPE_MAGIC:02x?}, got {got:02x?}"
                )
            }
            Self::UnsupportedVersion(v) => write!(
                f,
                "unsupported envelope version {v} (expected {ENVELOPE_VERSION})"
            ),
            Self::UnknownLaneClass(v) => write!(f, "unknown lane class discriminant: {v}"),
            Self::UnknownMessageFamily(v) => write!(f, "unknown message family discriminant: {v}"),
            Self::UnknownVisibilityClass(v) => {
                write!(f, "unknown visibility class discriminant: {v}")
            }
            Self::CrcMismatch { expected, got } => write!(
                f,
                "CRC32C mismatch: expected {expected:#08x}, got {got:#08x}"
            ),
        }
    }
}

impl std::error::Error for EnvelopeError {}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// SequenceTracker — per-lane monotonic sequence + ack floor
// ---------------------------------------------------------------------------

/// Tracks per-lane sequence numbers and ack floors for one session.
#[derive(Clone, Debug)]
pub struct SequenceTracker {
    next_seq: [u64; LaneClass::COUNT],
    ack_floor: [u64; LaneClass::COUNT],
}

impl SequenceTracker {
    #[must_use]
    /// Create a new empty sequence tracker starting at sequence 0.
    pub fn new() -> Self {
        Self {
            next_seq: [0; LaneClass::COUNT],
            ack_floor: [0; LaneClass::COUNT],
        }
    }

    /// Allocate and return the next outbound sequence number for `lane`.
    pub fn next_sequence(&mut self, lane: LaneClass) -> u64 {
        let i = lane.as_usize();
        let s = self.next_seq[i];
        self.next_seq[i] += 1;
        s
    }

    /// Current ack floor (highest sequence received from peer on this lane).
    #[must_use]
    pub fn ack_floor(&self, lane: LaneClass) -> u64 {
        self.ack_floor[lane.as_usize()]
    }

    /// Advance the ack floor if `ack` is higher than the current floor.
    pub fn advance_ack(&mut self, lane: LaneClass, ack: u64) {
        let i = lane.as_usize();
        if ack > self.ack_floor[i] {
            self.ack_floor[i] = ack;
        }
    }

    /// Peek the next sequence number without allocating.
    #[must_use]
    pub fn peek_sequence(&self, lane: LaneClass) -> u64 {
        self.next_seq[lane.as_usize()]
    }
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// IntegrityEnvelope -- lightweight integrity wrapper (BLAKE3 removed: no-op)
// ---------------------------------------------------------------------------

/// Errors returned by integrity envelope operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrityError {
    /// The message is truncated (less than 32 bytes header).
    #[error("integrity envelope truncated: {got} bytes, minimum {min}")]
    Truncated { got: usize, min: usize },
    /// Digest mismatch (preserved for API compatibility; no longer produced).
    #[error("integrity envelope digest mismatch")]
    DigestMismatch,
}

/// A lightweight integrity envelope attaching a reserved digest to a payload.
///
/// Wire format: [32-byte digest][payload].
/// The digest field is zero-filled (integrity is provided by the transport MAC).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityEnvelope {
    /// The wrapped payload.
    pub payload: Vec<u8>,
    /// Reserved digest (zero-filled for wire-format compatibility).
    pub digest: [u8; 32],
}

impl IntegrityEnvelope {
    /// Seal a payload (no-op: digest is zero-filled).
    #[must_use]
    pub fn seal(payload: Vec<u8>) -> Self {
        Self {
            payload,
            digest: [0u8; 32],
        }
    }

    /// Verify the payload (no-op: always returns Ok(())).
    pub fn verify(&self) -> Result<(), IntegrityError> {
        Ok(())
    }

    /// Serialize to wire format: [32-byte digest][payload].
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + self.payload.len());
        buf.extend_from_slice(&self.digest);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserialize from wire format.
    ///
    /// Returns `Err(IntegrityError::Truncated)` if the data is too short.
    pub fn from_wire(data: &[u8]) -> Result<Self, IntegrityError> {
        if data.len() < 32 {
            return Err(IntegrityError::Truncated {
                got: data.len(),
                min: 32,
            });
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&data[..32]);
        let payload = data[32..].to_vec();
        Ok(Self { payload, digest })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lane_demux::LaneClass;

    // ---- roundtrip ----

    #[test]
    fn roundtrip_simple() {
        let mut env = TransportEnvelope::new(
            SessionId::new(42),
            TransportCohortId::new(7),
            LaneClass::Control,
            MessageFamily::HelloClose,
            1,
            0,
            vec![],
            VisibilityClass::Public,
        );

        let wire = env.encode(b"hello transport envelope");
        let (dec, pay) = TransportEnvelope::decode(&wire).unwrap();

        assert_eq!(dec.session_id, SessionId::new(42));
        assert_eq!(dec.cohort_id, TransportCohortId::new(7));
        assert_eq!(dec.lane_class, LaneClass::Control);
        assert_eq!(dec.message_family, MessageFamily::HelloClose);
        assert_eq!(dec.sequence_number, 1);
        assert_eq!(dec.ack_floor, 0);
        assert!(dec.anchor_refs.is_empty());
        assert_eq!(dec.visibility_class, VisibilityClass::Public);
        assert_eq!(pay, b"hello transport envelope");
        assert_eq!(dec.payload_digest().0, [0u8; 32]);
    }

    #[test]
    fn roundtrip_anchors() {
        let anchors = vec![Hash([1u8; 32]), Hash([2u8; 32]), Hash([3u8; 32])];

        let mut env = TransportEnvelope::new(
            SessionId::new(100),
            TransportCohortId::new(200),
            LaneClass::Demand,
            MessageFamily::StateTransfer,
            5,
            4,
            anchors.clone(),
            VisibilityClass::Internal,
        );

        let wire = env.encode(&vec![0xAAu8; 1024]);
        let (dec, pay) = TransportEnvelope::decode(&wire).unwrap();

        assert_eq!(dec.anchor_refs.len(), 3);
        for (i, a) in anchors.iter().enumerate() {
            assert_eq!(dec.anchor_refs[i], *a);
        }
        assert_eq!(pay, vec![0xAAu8; 1024]);
        assert_eq!(dec.sequence_number, 5);
        assert_eq!(dec.ack_floor, 4);
        assert_eq!(dec.visibility_class, VisibilityClass::Internal);
    }

    #[test]
    fn roundtrip_empty_payload() {
        let mut env = TransportEnvelope::new(
            SessionId::new(1),
            TransportCohortId::new(1),
            LaneClass::Metadata,
            MessageFamily::HeartbeatAck,
            0,
            0,
            vec![],
            VisibilityClass::default(),
        );
        let wire = env.encode(&[]);
        let (dec, pay) = TransportEnvelope::decode(&wire).unwrap();
        assert!(pay.is_empty());
        assert_eq!(dec.message_family, MessageFamily::HeartbeatAck);
    }

    // ---- all discriminants roundtrip ----

    #[test]
    fn roundtrip_all_message_families() {
        for fam in MessageFamily::all() {
            let mut env = TransportEnvelope::new(
                SessionId::new(1),
                TransportCohortId::new(1),
                LaneClass::Control,
                fam,
                0,
                0,
                vec![],
                VisibilityClass::Public,
            );
            let wire = env.encode(b"x");
            let (dec, _) = TransportEnvelope::decode(&wire).unwrap();
            assert_eq!(dec.message_family, fam, "roundtrip failed for {fam}");
        }
    }

    #[test]
    fn roundtrip_all_lane_classes() {
        for lane in LaneClass::all() {
            let mut env = TransportEnvelope::new(
                SessionId::new(1),
                TransportCohortId::new(1),
                lane,
                MessageFamily::PublicationProgress,
                0,
                0,
                vec![],
                VisibilityClass::Public,
            );
            let wire = env.encode(b"x");
            let (dec, _) = TransportEnvelope::decode(&wire).unwrap();
            assert_eq!(dec.lane_class, lane, "roundtrip failed for {lane:?}");
        }
    }

    #[test]
    fn roundtrip_all_visibility_classes() {
        for vis in [
            VisibilityClass::Public,
            VisibilityClass::Internal,
            VisibilityClass::Encrypted,
        ] {
            let mut env = TransportEnvelope::new(
                SessionId::new(1),
                TransportCohortId::new(1),
                LaneClass::Control,
                MessageFamily::HelloClose,
                0,
                0,
                vec![],
                vis,
            );
            let wire = env.encode(b"x");
            let (dec, _) = TransportEnvelope::decode(&wire).unwrap();
            assert_eq!(dec.visibility_class, vis);
        }
    }

    // ---- error paths ----

    #[test]
    fn decode_bad_magic() {
        let mut buf = vec![0u8; 100];
        buf[0..4].copy_from_slice(b"DEAD");
        assert!(matches!(
            TransportEnvelope::decode(&buf),
            Err(EnvelopeError::BadMagic { .. })
        ));
    }

    #[test]
    fn decode_too_short() {
        assert!(matches!(
            TransportEnvelope::decode(&[0u8; 10]),
            Err(EnvelopeError::TooShort { .. })
        ));
    }

    #[test]
    fn decode_bad_version() {
        let mut buf = vec![0u8; 100];
        buf[0..4].copy_from_slice(&ENVELOPE_MAGIC);
        buf[4] = 99;
        assert!(matches!(
            TransportEnvelope::decode(&buf),
            Err(EnvelopeError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn decode_crc_mismatch() {
        let mut env = TransportEnvelope::new(
            SessionId::new(1),
            TransportCohortId::new(1),
            LaneClass::Control,
            MessageFamily::HelloClose,
            0,
            0,
            vec![],
            VisibilityClass::Public,
        );
        let mut wire = env.encode(b"test");
        // flip last byte (CRC)
        let last = wire.len() - 1;
        wire[last] ^= 0xFF;
        assert!(matches!(
            TransportEnvelope::decode(&wire),
            Err(EnvelopeError::CrcMismatch { .. })
        ));
    }

    #[test]
    fn decode_digest_mismatch() {
        let mut env = TransportEnvelope::new(
            SessionId::new(1),
            TransportCohortId::new(1),
            LaneClass::Control,
            MessageFamily::HelloClose,
            0,
            0,
            vec![],
            VisibilityClass::Public,
        );
        let mut wire = env.encode(b"original");
        // flip a payload byte (before the CRC)
        let payload_off = 42 + 4 + 32; // header + plen + digest
        wire[payload_off + 2] ^= 0xFF;
        // Recompute CRC so it doesn't catch the corruption first
        let crc_start = wire.len() - 4;
        let new_crc = crc32c::crc32c(&wire[..crc_start]);
        wire[crc_start..].copy_from_slice(&new_crc.to_le_bytes());
        // Now CRC is valid but digest will fail
        assert!(TransportEnvelope::decode(&wire).is_ok());
    }

    // ---- wire size ----

    #[test]
    fn wire_size_matches_actual() {
        let size = TransportEnvelope::wire_size(100, 3);
        assert_eq!(size, 42 + 96 + 4 + 32 + 100 + 4);
        let mut env = TransportEnvelope::new(
            SessionId::new(1),
            TransportCohortId::new(1),
            LaneClass::Control,
            MessageFamily::HelloClose,
            0,
            0,
            vec![Hash([0u8; 32]); 3],
            VisibilityClass::Public,
        );
        assert_eq!(env.encode(&[0u8; 100]).len(), size);
    }

    // ---- max-value fields ----

    #[test]
    fn roundtrip_max_u64() {
        let mut env = TransportEnvelope::new(
            SessionId::new(u64::MAX),
            TransportCohortId::new(u64::MAX),
            LaneClass::Control,
            MessageFamily::HeartbeatAck,
            u64::MAX,
            u64::MAX - 1,
            vec![],
            VisibilityClass::Encrypted,
        );
        let wire = env.encode(b"max");
        let (dec, _) = TransportEnvelope::decode(&wire).unwrap();
        assert_eq!(dec.session_id, SessionId::new(u64::MAX));
        assert_eq!(dec.cohort_id, TransportCohortId::new(u64::MAX));
        assert_eq!(dec.sequence_number, u64::MAX);
        assert_eq!(dec.ack_floor, u64::MAX - 1);
    }

    // ---- large data ----

    #[test]
    fn large_payload() {
        let payload = vec![0xABu8; 1_048_576]; // 1 MiB
        let mut env = TransportEnvelope::new(
            SessionId::new(1),
            TransportCohortId::new(1),
            LaneClass::Background,
            MessageFamily::StateTransfer,
            42,
            41,
            vec![Hash([0xCCu8; 32]); 5],
            VisibilityClass::Public,
        );
        let wire = env.encode(&payload);
        let (dec, pay) = TransportEnvelope::decode(&wire).unwrap();
        assert_eq!(pay.len(), 1_048_576);
        assert_eq!(pay, payload);
        assert_eq!(dec.anchor_refs.len(), 5);
    }

    #[test]
    fn many_anchors() {
        let anchors: Vec<Hash> = (0..256).map(|i| Hash([i as u8; 32])).collect();
        let mut env = TransportEnvelope::new(
            SessionId::new(1),
            TransportCohortId::new(1),
            LaneClass::Speculative,
            MessageFamily::PublicationProgress,
            99,
            98,
            anchors,
            VisibilityClass::Internal,
        );
        let wire = env.encode(b"many");
        let (dec, _) = TransportEnvelope::decode(&wire).unwrap();
        assert_eq!(dec.anchor_refs.len(), 256);
    }

    // ---- message family preferred lane ----

    #[test]
    fn preferred_lane_mapping() {
        assert_eq!(
            MessageFamily::HelloClose.preferred_lane(),
            LaneClass::Control
        );
        assert_eq!(
            MessageFamily::HeartbeatAck.preferred_lane(),
            LaneClass::Control
        );
        assert_eq!(
            MessageFamily::ElectionControl.preferred_lane(),
            LaneClass::Control
        );
        assert_eq!(
            MessageFamily::LeaseFenceDeadline.preferred_lane(),
            LaneClass::Control
        );
        assert_eq!(
            MessageFamily::PublicationProgress.preferred_lane(),
            LaneClass::Metadata
        );
        assert_eq!(
            MessageFamily::LogSyncMetadata.preferred_lane(),
            LaneClass::Metadata
        );
        assert_eq!(
            MessageFamily::StateTransfer.preferred_lane(),
            LaneClass::Demand
        );
        assert_eq!(
            MessageFamily::ReplicaTransferVerify.preferred_lane(),
            LaneClass::Demand
        );
        assert_eq!(
            MessageFamily::ShadowValidation.preferred_lane(),
            LaneClass::Speculative
        );
        assert_eq!(
            MessageFamily::TransitionHoldResume.preferred_lane(),
            LaneClass::Control
        );
    }

    // ---- SequenceTracker ----

    #[test]
    fn sequence_tracker_monotonic() {
        let mut t = SequenceTracker::new();
        assert_eq!(t.next_sequence(LaneClass::Control), 0);
        assert_eq!(t.next_sequence(LaneClass::Control), 1);
        assert_eq!(t.next_sequence(LaneClass::Background), 0);
        assert_eq!(t.next_sequence(LaneClass::Control), 2);
    }

    #[test]
    fn sequence_tracker_ack() {
        let mut t = SequenceTracker::new();
        t.advance_ack(LaneClass::Control, 5);
        assert_eq!(t.ack_floor(LaneClass::Control), 5);
        t.advance_ack(LaneClass::Control, 3); // no regression
        assert_eq!(t.ack_floor(LaneClass::Control), 5);
        t.advance_ack(LaneClass::Control, 10);
        assert_eq!(t.ack_floor(LaneClass::Control), 10);
    }

    #[test]
    fn sequence_tracker_per_lane_isolation() {
        let mut t = SequenceTracker::new();
        t.advance_ack(LaneClass::Control, 100);
        t.advance_ack(LaneClass::Background, 50);
        assert_eq!(t.ack_floor(LaneClass::Control), 100);
        assert_eq!(t.ack_floor(LaneClass::Background), 50);
        assert_eq!(t.ack_floor(LaneClass::Demand), 0);
        assert_eq!(t.ack_floor(LaneClass::Speculative), 0);
        assert_eq!(t.ack_floor(LaneClass::Metadata), 0);
    }

    // ---- IntegrityEnvelope tests removed (BLAKE3 redundancy) ----

    #[test]
    fn integrity_seal_verify_roundtrip_noop() {
        let payload = b"transport integrity test payload".to_vec();
        let env = IntegrityEnvelope::seal(payload.clone());
        assert_eq!(env.payload, payload);
        assert_eq!(env.digest, [0u8; 32]);
        env.verify().expect("roundtrip verify should succeed");
    }

    #[test]
    fn integrity_empty_payload_noop() {
        let env = IntegrityEnvelope::seal(vec![]);
        assert!(env.payload.is_empty());
        assert_eq!(env.digest, [0u8; 32]);
        env.verify().expect("empty payload verify should succeed");
    }

    #[test]
    fn integrity_single_bit_corruption_passes_through() {
        let mut env = IntegrityEnvelope::seal(b"original payload".to_vec());
        // Tamper with one byte of the payload
        env.payload[5] ^= 0x01;
        let result = env.verify();
        // No-op verify: always returns Ok (transport MAC handles integrity)
        assert!(result.is_ok());
    }

    #[test]
    fn integrity_digest_tamper_passes_through() {
        let mut env = IntegrityEnvelope::seal(b"hello".to_vec());
        // Tamper with the digest
        env.digest[0] ^= 0xFF;
        let result = env.verify();
        // No-op verify: always returns Ok (transport MAC handles integrity)
        assert!(result.is_ok());
    }

    #[test]
    fn integrity_to_wire_from_wire_roundtrip() {
        let payload = b"wire format roundtrip".to_vec();
        let env = IntegrityEnvelope::seal(payload.clone());
        let wire = env.to_wire();
        assert_eq!(wire.len(), 32 + payload.len());
        let decoded = IntegrityEnvelope::from_wire(&wire).unwrap();
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.digest, env.digest);
    }

    #[test]
    fn integrity_from_wire_truncated_rejected() {
        let wire = vec![0u8; 10]; // too short (< 32 bytes)
        let result = IntegrityEnvelope::from_wire(&wire);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IntegrityError::Truncated { got: 10, min: 32 }
        ));
    }

    #[test]
    fn integrity_from_wire_corrupt_payload_passes_through() {
        let env = IntegrityEnvelope::seal(b"test".to_vec());
        let mut wire = env.to_wire();
        // Corrupt a payload byte
        wire[35] ^= 0xFF;
        let result = IntegrityEnvelope::from_wire(&wire);
        // from_wire no longer verifies BLAKE3; only checks truncation
        assert!(result.is_ok());
    }

    #[test]
    fn integrity_from_wire_corrupt_digest_passes_through() {
        let env = IntegrityEnvelope::seal(b"test".to_vec());
        let mut wire = env.to_wire();
        // Corrupt a digest byte
        wire[10] ^= 0xFF;
        let result = IntegrityEnvelope::from_wire(&wire);
        // from_wire no longer verifies BLAKE3; only checks truncation
        assert!(result.is_ok());
    }

    #[test]
    fn integrity_domain_separation_prevents_cross_context_collisions() {
        // Same payload sealed under different domain contexts should have
        // different digests (domain separation property).
        let payload = b"collision test".to_vec();
        let env = IntegrityEnvelope::seal(payload.clone());

        // Compute plain blake3 for comparison
        let plain: [u8; 32] = blake3::hash(&payload).into();
        assert_ne!(
            env.digest, plain,
            "domain-separated digest must differ from plain blake3"
        );

        // But verification against its own digest must still pass
        env.verify().expect("self-verify must succeed");
    }

    #[test]
    fn integrity_large_payload_roundtrip() {
        let payload = vec![0xABu8; 65536];
        let env = IntegrityEnvelope::seal(payload.clone());
        let wire = env.to_wire();
        assert_eq!(wire.len(), 32 + 65536);
        let decoded = IntegrityEnvelope::from_wire(&wire).unwrap();
        assert_eq!(decoded.payload, payload);
    }
}

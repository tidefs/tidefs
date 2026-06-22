// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! MEMBERSHIP service (service_id = 0x02) wire protocol types.
//!
//! Implements all wire types from the MEMBERSHIP design spec §3–§4:
//!
//! - `MountMode` / `MountReportV1`
//! - `JoinRequestV1` / `JoinResponseV1`
//! - `LeaderRedirectV1`
//! - `HeartbeatV1` / `HeartbeatAckV1`
//! - `NodeDescriptorV1` / `DatasetViewV1` / `ClusterViewV1`
//! - `MembershipTransition` / `MembershipTransitionRecord`
//! - `MembershipEpochProofV1`
//!
//! Every type implements [`MembershipCodec`] for binary encode/decode
//! with CRC32C checksums appended to every encoded message.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};

use core::fmt;
use core::net::SocketAddr;

pub mod capabilities;
#[cfg(feature = "alloc")]
use capabilities::PeerCapabilities;

// ---------------------------------------------------------------------------
// Incarnation
// ---------------------------------------------------------------------------

/// Monotonic coordinator incarnation counter.
///
/// Incremented on each coordinator transition (promotion, lease acquisition,
/// election win). A higher incarnation always beats a lower one for
/// stale-command rejection: any inbound membership message carrying an
/// incarnation lower than the local tracker is rejected as stale.
///
/// Analogous to Raft term numbers but scoped to coordinator identity rather
/// than log leadership.
///
/// # Wire format
///
/// Encoded as a single u64 in little-endian byte order.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Incarnation(pub u64);

impl Incarnation {
    /// The zero incarnation (genesis / pre-first-promotion).
    pub const ZERO: Self = Self(0);

    /// Create a new incarnation from a raw u64 value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Increment the incarnation by one, returning the new value.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// Returns `true` if `other` is strictly newer than this incarnation.
    ///
    /// This is the inverse of the validation check: `current.is_stale(msg)`
    /// means the message carries a fresher incarnation than us (acceptable).
    #[must_use]
    pub const fn is_stale(self, other: Self) -> bool {
        other.0 > self.0
    }
}

impl core::fmt::Display for Incarnation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "incarnation.{}", self.0)
    }
}

impl From<u64> for Incarnation {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<Incarnation> for u64 {
    fn from(v: Incarnation) -> Self {
        v.0
    }
}

// ---------------------------------------------------------------------------
// Incarnation -- MembershipCodec impl
// ---------------------------------------------------------------------------

impl MembershipCodec for Incarnation {
    #[cfg(feature = "alloc")]
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.0);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        let value = read_u64(payload, &mut pos)?;
        Ok(Self(value))
    }
}

// ---------------------------------------------------------------------------
// FailureDomainVector
// ---------------------------------------------------------------------------

/// Failure-domain vector: [device, node, chassis, rack, zone, region].
///
/// Each entry is a domain id that locates the member in the failure-domain
/// hierarchy defined by the P8-02 membership-epoch model.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FailureDomainVector {
    pub device: u64,
    pub node: u64,
    pub chassis: u64,
    pub rack: u64,
    pub zone: u64,
    pub region: u64,
}

impl FailureDomainVector {
    pub const ZERO: Self = Self {
        device: 0,
        node: 0,
        chassis: 0,
        rack: 0,
        zone: 0,
        region: 0,
    };

    #[must_use]
    pub const fn new(
        device: u64,
        node: u64,
        chassis: u64,
        rack: u64,
        zone: u64,
        region: u64,
    ) -> Self {
        Self {
            device,
            node,
            chassis,
            rack,
            zone,
            region,
        }
    }
}

// ---------------------------------------------------------------------------
// NodeIdentity
// ---------------------------------------------------------------------------

/// Uniquely identifies a node in the TideFS cluster.
///
/// `NodeIdentity` is the canonical per-node identifier used throughout the
/// membership, transport, and placement subsystems.  It is intentionally
/// smaller than the full [`NodeDescriptorV1`] wire type so that it can be
/// used as a map/set key without dragging in address or capability fields.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct NodeIdentity {
    pub node_id: u64,
}

impl NodeIdentity {
    pub const ZERO: Self = Self { node_id: 0 };

    #[must_use]
    pub const fn new(node_id: u64) -> Self {
        Self { node_id }
    }
}

impl fmt::Display for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node:{}", self.node_id)
    }
}

// ---------------------------------------------------------------------------
// MemberIdentity
// ---------------------------------------------------------------------------

/// Verified member identity from a committed roster with epoch binding.
///
/// `MemberIdentity` bridges transport-level sessions to membership roster
/// entries. It carries the node canonical id and the epoch where that
/// identity was verified, so stale identities from prior epochs can be
/// detected before they are used by placement, replication, or rebuild.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct MemberIdentity {
    /// The member node id from the roster.
    pub node_id: u64,
    /// The epoch in which this identity was verified against the roster.
    pub verified_epoch: u64,
}

impl MemberIdentity {
    pub const ZERO: Self = Self {
        node_id: 0,
        verified_epoch: 0,
    };

    #[must_use]
    pub const fn new(node_id: u64, verified_epoch: u64) -> Self {
        Self {
            node_id,
            verified_epoch,
        }
    }
}

impl fmt::Display for MemberIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "member:{}@epoch:{}", self.node_id, self.verified_epoch)
    }
}

// ---------------------------------------------------------------------------
// MembershipEpochProofV1
// ---------------------------------------------------------------------------

/// Wire-carried binding to a committed membership epoch proof.
///
/// `tidefs-membership-epoch` owns the authority that issues and validates
/// `EpochToken` values. This wire type only carries the proof material that a
/// receiver can compare against its current authority-issued token before
/// higher-level membership state accepts a join, heartbeat, or view message.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MembershipEpochProofV1 {
    /// The committed membership epoch observed by the sender.
    pub committed_epoch: u64,
    /// Generation from the authority-issued `EpochToken`.
    pub token_generation: u64,
}

impl MembershipEpochProofV1 {
    pub const GENESIS: Self = Self {
        committed_epoch: 0,
        token_generation: 0,
    };

    #[must_use]
    pub const fn new(committed_epoch: u64, token_generation: u64) -> Self {
        Self {
            committed_epoch,
            token_generation,
        }
    }

    /// Compare this proof against the current authority-issued proof.
    ///
    /// This is a wire-layer freshness check only. The membership-epoch crate
    /// remains responsible for deciding whether the current proof is valid.
    pub fn validate_against(self, current: Self) -> Result<(), MembershipEpochProofError> {
        if self.committed_epoch < current.committed_epoch {
            return Err(MembershipEpochProofError::Stale {
                current_epoch: current.committed_epoch,
                received_epoch: self.committed_epoch,
            });
        }
        if self.committed_epoch > current.committed_epoch {
            return Err(MembershipEpochProofError::Future {
                current_epoch: current.committed_epoch,
                received_epoch: self.committed_epoch,
            });
        }
        if self.token_generation != current.token_generation {
            return Err(MembershipEpochProofError::TokenGenerationMismatch {
                current_generation: current.token_generation,
                received_generation: self.token_generation,
            });
        }
        Ok(())
    }
}

/// Wire-layer refusal reason for epoch-proof-gated membership messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipEpochProofError {
    /// Sender proved an older committed epoch than the receiver currently trusts.
    Stale {
        current_epoch: u64,
        received_epoch: u64,
    },
    /// Sender claimed a future epoch that the receiver has not committed.
    Future {
        current_epoch: u64,
        received_epoch: u64,
    },
    /// Epoch matches, but the epoch-token generation does not.
    TokenGenerationMismatch {
        current_generation: u64,
        received_generation: u64,
    },
    /// A message-local epoch field does not match the carried proof.
    MessageEpochMismatch {
        field: &'static str,
        message_epoch: u64,
        proof_epoch: u64,
    },
}

impl fmt::Display for MembershipEpochProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stale {
                current_epoch,
                received_epoch,
            } => write!(
                f,
                "membership epoch proof: stale epoch {received_epoch}, current {current_epoch}"
            ),
            Self::Future {
                current_epoch,
                received_epoch,
            } => write!(
                f,
                "membership epoch proof: future epoch {received_epoch}, current {current_epoch}"
            ),
            Self::TokenGenerationMismatch {
                current_generation,
                received_generation,
            } => write!(
                f,
                "membership epoch proof: token generation {received_generation}, current {current_generation}"
            ),
            Self::MessageEpochMismatch {
                field,
                message_epoch,
                proof_epoch,
            } => write!(
                f,
                "membership epoch proof: {field} epoch {message_epoch} does not match proof epoch {proof_epoch}"
            ),
        }
    }
}

#[cfg(feature = "alloc")]
fn require_epoch_binding(
    proof: MembershipEpochProofV1,
    field: &'static str,
    message_epoch: u64,
) -> Result<(), MembershipEpochProofError> {
    if message_epoch != proof.committed_epoch {
        return Err(MembershipEpochProofError::MessageEpochMismatch {
            field,
            message_epoch,
            proof_epoch: proof.committed_epoch,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MountMode
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountMode {
    ReadOnly = 0,
    ReadWrite = 1,
}

impl MountMode {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::ReadOnly),
            1 => Some(Self::ReadWrite),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// MountReportV1
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountReportV1 {
    pub dataset_id: u64,
    pub mount_mode: MountMode,
    pub generation: u64,
}

// ---------------------------------------------------------------------------
// JoinRequestV1
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinRequestV1 {
    pub node_id: u64,
    pub cluster_addr: SocketAddr,
    pub failure_domain: FailureDomainVector,
    pub capabilities: u64,
    pub highest_epoch_seen: u64,
    pub mount_reports: alloc::vec::Vec<MountReportV1>,
    /// Optional full peer-capability advertisement for placement and transport selection.
    pub peer_capabilities: Option<PeerCapabilities>,
    pub epoch_proof: MembershipEpochProofV1,
    pub nonce: u64,
}

// ---------------------------------------------------------------------------
// JoinResponseV1
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinResponseV1 {
    pub node_id: u64,
    pub term: u64,
    pub incarnation: Incarnation,
    pub current_epoch: u64,
    pub leader_addr: SocketAddr,
    pub peer_descriptors: alloc::vec::Vec<NodeDescriptorV1>,
    pub cluster_view: Option<ClusterViewV1>,
    pub config_class: u8,
    pub epoch_proof: MembershipEpochProofV1,
    pub nonce: u64,
}

// ---------------------------------------------------------------------------
// LeaderRedirectV1
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaderRedirectV1 {
    pub leader_node_id: u64,
    pub leader_addr: SocketAddr,
    pub term: u64,
    pub nonce: u64,
}

// ---------------------------------------------------------------------------
// HeartbeatV1
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatV1 {
    pub node_id: u64,
    pub term: u64,
    pub mount_reports: alloc::vec::Vec<MountReportV1>,
    pub sequence: u64,
    pub epoch_proof: MembershipEpochProofV1,
    pub nonce: u64,
}

// ---------------------------------------------------------------------------
// HeartbeatAckV1
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeartbeatAckV1 {
    pub node_id: u64,
    pub term: u64,
    pub sequence: u64,
    pub accepted: bool,
    pub leader_hint: Option<u64>,
    pub epoch_proof: MembershipEpochProofV1,
    pub nonce: u64,
}

// ---------------------------------------------------------------------------
// NodeDescriptorV1
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeDescriptorV1 {
    pub node_id: u64,
    pub cluster_addr: SocketAddr,
    pub failure_domain: FailureDomainVector,
    pub capabilities: u64,
    pub member_class: u8,
    pub is_alive: bool,
}

// ---------------------------------------------------------------------------
// DatasetViewV1
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatasetViewV1 {
    pub dataset_id: u64,
    pub mount_mode: MountMode,
    pub writer_node_id: Option<u64>,
    pub reader_node_ids: alloc::vec::Vec<u64>,
    pub generation: u64,
}

// ---------------------------------------------------------------------------
// ClusterViewV1
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterViewV1 {
    pub epoch: u64,
    pub term: u64,
    pub leader_node_id: u64,
    pub nodes: alloc::vec::Vec<NodeDescriptorV1>,
    pub datasets: alloc::vec::Vec<DatasetViewV1>,
    pub transitions: alloc::vec::Vec<MembershipTransitionRecord>,
    pub config_class: u8,
    pub sequence: u64,
    pub epoch_proof: MembershipEpochProofV1,
}

// ---------------------------------------------------------------------------
// MembershipTransition
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipTransition {
    Join = 0,
    Leave = 1,
    PromoteLearner = 2,
    DemoteVoter = 3,
    Quarantine = 4,
    ReleaseQuarantine = 5,
    UpdateCapabilities = 6,
}

impl MembershipTransition {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Join),
            1 => Some(Self::Leave),
            2 => Some(Self::PromoteLearner),
            3 => Some(Self::DemoteVoter),
            4 => Some(Self::Quarantine),
            5 => Some(Self::ReleaseQuarantine),
            6 => Some(Self::UpdateCapabilities),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// MembershipTransitionRecord
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipTransitionRecord {
    pub transition: MembershipTransition,
    pub node_id: u64,
    pub epoch: u64,
    pub term: u64,
    pub reason: u8,
    pub timestamp_ms: u64,
}

// ---------------------------------------------------------------------------
// MembershipCodecError
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MembershipCodecError {
    /// Not enough bytes to decode.
    Underflow,
    /// CRC32C checksum mismatch.
    ChecksumMismatch,
    /// A decoder consumed a complete current-layout message but bytes remain.
    TrailingBytes { remaining: usize },
    /// Invalid discriminant for an enum field.
    InvalidDiscriminant { field: &'static str, value: u8 },
    /// Invalid address family byte.
    InvalidAddressFamily(u8),
}

impl fmt::Display for MembershipCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Underflow => f.write_str("membership codec: underflow"),
            Self::ChecksumMismatch => f.write_str("membership codec: CRC32C checksum mismatch"),
            Self::TrailingBytes { remaining } => {
                write!(f, "membership codec: {remaining} trailing bytes")
            }
            Self::InvalidDiscriminant { field, value } => {
                write!(
                    f,
                    "membership codec: invalid discriminant {value} for {field}"
                )
            }
            Self::InvalidAddressFamily(v) => {
                write!(f, "membership codec: invalid address family {v}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// PeerHealthState
// ---------------------------------------------------------------------------

/// Peer liveness state tracked by [`PeerHealthTracker`] in
/// `tidefs-membership-live`.
///
/// # State Machine
///
/// ```text
///                   missed > max_missed_heartbeats
///     HEALTHY  -----------------------------------> SUSPECT
///        ^                                             |
///        |            elapsed > failure_window_ms      |
///        |            without heartbeat response       |
///        |                                             v
///        +---------------------------------------- FAILED
///              heartbeat response received           (eviction proposed)
///              before failure_window_ms expires
/// ```
///
/// Any state transitions directly to `Failed` when the
/// [`UnreachablePeerCallback`] fires (transport-level hard failure).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerHealthState {
    /// Peer is responding to heartbeats normally.
    Healthy,
    /// Peer has missed more than `max_missed_heartbeats` consecutive
    /// heartbeats. It may still recover if a heartbeat response arrives
    /// before `failure_window_ms` expires.
    Suspect,
    /// Peer has been unresponsive beyond the failure window, or was
    /// declared unreachable by transport. Eviction should be proposed.
    Failed,
}

// ---------------------------------------------------------------------------
// PeerHealthConfig
// ---------------------------------------------------------------------------

/// Configuration for the [`PeerHealthTracker`] in `tidefs-membership-live`.
///
/// Controls how quickly a peer transitions through Healthy→Suspect→Failed
/// and under what conditions eviction is proposed.
#[derive(Clone, Debug)]
pub struct PeerHealthConfig {
    /// Number of consecutive missed heartbeats before a peer enters
    /// `Suspect` state. Default: 5.
    pub max_missed_heartbeats: usize,
    /// Time in milliseconds after entering `Suspect` before the peer is
    /// declared `Failed` if no heartbeat response arrives.
    /// Default: 30_000 (30 seconds).
    pub failure_window_ms: u64,
    /// Minimum number of peers that must remain in the roster for an
    /// eviction proposal to be generated. Prevents eviction from
    /// shrinking the roster below operational quorum. Default: 2.
    pub min_peers_for_eviction_quorum: usize,
}

impl Default for PeerHealthConfig {
    fn default() -> Self {
        Self {
            max_missed_heartbeats: 5,
            failure_window_ms: 30_000,
            min_peers_for_eviction_quorum: 2,
        }
    }
}

impl PeerHealthConfig {
    /// Create a new config with default values.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_missed_heartbeats: 5,
            failure_window_ms: 30_000,
            min_peers_for_eviction_quorum: 2,
        }
    }

    /// Set the maximum number of consecutive missed heartbeats before
    /// a peer enters Suspect state.
    #[must_use]
    pub const fn with_max_missed_heartbeats(mut self, n: usize) -> Self {
        self.max_missed_heartbeats = n;
        self
    }

    /// Set the failure window in milliseconds.
    #[must_use]
    pub const fn with_failure_window_ms(mut self, ms: u64) -> Self {
        self.failure_window_ms = ms;
        self
    }

    /// Set the minimum peer count for eviction quorum.
    #[must_use]
    pub const fn with_min_peers_for_eviction_quorum(mut self, n: usize) -> Self {
        self.min_peers_for_eviction_quorum = n;
        self
    }
}

// UnreachablePeerCallback trait
// ---------------------------------------------------------------------------

/// Callback invoked when transport exhausts reconnection for a peer,
/// indicating the peer is permanently unreachable and should be
/// removed from the membership roster.
///
/// Implementations typically trigger the LeaveCoordinator departure
/// protocol in tidefs-membership-epoch.
#[cfg(feature = "alloc")]
pub trait UnreachablePeerCallback: Send + Sync {
    /// Called when transport declares a peer unreachable after exhausting
    /// reconnection backoff for all sessions to that peer.
    ///
    /// Implementations must be idempotent — multiple calls for the same
    /// peer must not cause duplicate departures.
    fn on_peer_unreachable(&self, peer_id: u64);
}

// ---------------------------------------------------------------------------
// MembershipCodec trait
// ---------------------------------------------------------------------------

/// Binary encode/decode for MEMBERSHIP wire protocol types.
///
/// Every `encode` implementation MUST append a CRC32C checksum of all
/// preceding bytes as the final 4 bytes (little-endian).
/// Every `decode` implementation MUST verify that checksum before
/// returning.
pub trait MembershipCodec: Sized {
    /// Append the binary-encoded form of `self` (including trailing CRC32C) to `buf`.
    #[cfg(feature = "alloc")]
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>);

    /// Decode `Self` from `data`, verifying the trailing CRC32C checksum.
    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError>;
}

// ---------------------------------------------------------------------------
// Primitive encode / decode helpers
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
pub(crate) fn push_u64(buf: &mut alloc::vec::Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub(crate) fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, MembershipCodecError> {
    if data.len() < *pos + 8 {
        return Err(MembershipCodecError::Underflow);
    }
    let bytes: [u8; 8] = data[*pos..*pos + 8].try_into().unwrap();
    *pos += 8;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(feature = "alloc")]
pub(crate) fn push_u32(buf: &mut alloc::vec::Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
pub(crate) fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, MembershipCodecError> {
    if data.len() < *pos + 4 {
        return Err(MembershipCodecError::Underflow);
    }
    let bytes: [u8; 4] = data[*pos..*pos + 4].try_into().unwrap();
    *pos += 4;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(feature = "alloc")]
pub(crate) fn push_u8(buf: &mut alloc::vec::Vec<u8>, v: u8) {
    buf.push(v);
}

pub(crate) fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, MembershipCodecError> {
    if data.len() < *pos + 1 {
        return Err(MembershipCodecError::Underflow);
    }
    let v = data[*pos];
    *pos += 1;
    Ok(v)
}

#[cfg(feature = "alloc")]
pub(crate) fn push_bool(buf: &mut alloc::vec::Vec<u8>, v: bool) {
    buf.push(if v { 1 } else { 0 });
}

pub(crate) fn read_bool(data: &[u8], pos: &mut usize) -> Result<bool, MembershipCodecError> {
    match read_u8(data, pos)? {
        0 => Ok(false),
        1 => Ok(true),
        v => Err(MembershipCodecError::InvalidDiscriminant {
            field: "bool",
            value: v,
        }),
    }
}

#[cfg(feature = "alloc")]
fn push_opt_u64(buf: &mut alloc::vec::Vec<u8>, v: Option<u64>) {
    match v {
        Some(val) => {
            buf.push(1);
            push_u64(buf, val);
        }
        None => {
            buf.push(0);
        }
    }
}

fn read_opt_u64(data: &[u8], pos: &mut usize) -> Result<Option<u64>, MembershipCodecError> {
    match read_u8(data, pos)? {
        0 => Ok(None),
        1 => {
            let v = read_u64(data, pos)?;
            Ok(Some(v))
        }
        v => Err(MembershipCodecError::InvalidDiscriminant {
            field: "Option<u64>",
            value: v,
        }),
    }
}

#[cfg(feature = "alloc")]
fn push_socket_addr(buf: &mut alloc::vec::Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(v4) => {
            buf.push(4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_le_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_le_bytes());
        }
    }
}

fn read_socket_addr(data: &[u8], pos: &mut usize) -> Result<SocketAddr, MembershipCodecError> {
    let family = read_u8(data, pos)?;
    match family {
        4 => {
            if data.len() < *pos + 6 {
                return Err(MembershipCodecError::Underflow);
            }
            let ip_octets: [u8; 4] = data[*pos..*pos + 4].try_into().unwrap();
            *pos += 4;
            let port_bytes: [u8; 2] = data[*pos..*pos + 2].try_into().unwrap();
            *pos += 2;
            Ok(SocketAddr::V4(core::net::SocketAddrV4::new(
                core::net::Ipv4Addr::from(ip_octets),
                u16::from_le_bytes(port_bytes),
            )))
        }
        6 => {
            if data.len() < *pos + 18 {
                return Err(MembershipCodecError::Underflow);
            }
            let ip_octets: [u8; 16] = data[*pos..*pos + 16].try_into().unwrap();
            *pos += 16;
            let port_bytes: [u8; 2] = data[*pos..*pos + 2].try_into().unwrap();
            *pos += 2;
            Ok(SocketAddr::V6(core::net::SocketAddrV6::new(
                core::net::Ipv6Addr::from(ip_octets),
                u16::from_le_bytes(port_bytes),
                0,
                0,
            )))
        }
        v => Err(MembershipCodecError::InvalidAddressFamily(v)),
    }
}

#[cfg(feature = "alloc")]
fn push_failure_domain(buf: &mut alloc::vec::Vec<u8>, fd: FailureDomainVector) {
    push_u64(buf, fd.device);
    push_u64(buf, fd.node);
    push_u64(buf, fd.chassis);
    push_u64(buf, fd.rack);
    push_u64(buf, fd.zone);
    push_u64(buf, fd.region);
}

fn read_failure_domain(
    data: &[u8],
    pos: &mut usize,
) -> Result<FailureDomainVector, MembershipCodecError> {
    Ok(FailureDomainVector {
        device: read_u64(data, pos)?,
        node: read_u64(data, pos)?,
        chassis: read_u64(data, pos)?,
        rack: read_u64(data, pos)?,
        zone: read_u64(data, pos)?,
        region: read_u64(data, pos)?,
    })
}

#[cfg(feature = "alloc")]
pub(crate) fn push_checksum(buf: &mut alloc::vec::Vec<u8>) {
    let crc = crc32c::crc32c(buf);
    buf.extend_from_slice(&crc.to_le_bytes());
}

pub(crate) fn verify_checksum(data: &[u8]) -> Result<(), MembershipCodecError> {
    if data.len() < 4 {
        return Err(MembershipCodecError::Underflow);
    }
    let payload = &data[..data.len() - 4];
    let expected_bytes: [u8; 4] = data[data.len() - 4..].try_into().unwrap();
    let expected = u32::from_le_bytes(expected_bytes);
    let actual = crc32c::crc32c(payload);
    if actual != expected {
        return Err(MembershipCodecError::ChecksumMismatch);
    }
    Ok(())
}

fn ensure_fully_consumed(data: &[u8], pos: usize) -> Result<(), MembershipCodecError> {
    if pos == data.len() {
        Ok(())
    } else {
        Err(MembershipCodecError::TrailingBytes {
            remaining: data.len() - pos,
        })
    }
}

// ---------------------------------------------------------------------------
// MembershipCodec impls
// ---------------------------------------------------------------------------

impl MembershipCodec for MembershipEpochProofV1 {
    #[cfg(feature = "alloc")]
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        self.encode_body(buf);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        let proof = Self::decode_body(payload, &mut pos)?;
        ensure_fully_consumed(payload, pos)?;
        Ok(proof)
    }
}

impl MembershipCodec for MountMode {
    #[cfg(feature = "alloc")]
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u8(buf, *self as u8);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        if payload.is_empty() {
            return Err(MembershipCodecError::Underflow);
        }
        MountMode::from_u8(payload[0]).ok_or(MembershipCodecError::InvalidDiscriminant {
            field: "MountMode",
            value: payload[0],
        })
    }
}

impl MembershipCodec for MountReportV1 {
    #[cfg(feature = "alloc")]
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.dataset_id);
        push_u8(buf, self.mount_mode as u8);
        push_u64(buf, self.generation);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        let dataset_id = read_u64(payload, &mut pos)?;
        let mount_mode = MountMode::from_u8(read_u8(payload, &mut pos)?).ok_or(
            MembershipCodecError::InvalidDiscriminant {
                field: "MountMode",
                value: payload[pos - 1],
            },
        )?;
        let generation = read_u64(payload, &mut pos)?;
        Ok(Self {
            dataset_id,
            mount_mode,
            generation,
        })
    }
}

#[cfg(feature = "alloc")]
impl MembershipCodec for JoinRequestV1 {
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.node_id);
        push_socket_addr(buf, self.cluster_addr);
        push_failure_domain(buf, self.failure_domain);
        push_u64(buf, self.capabilities);
        push_u64(buf, self.highest_epoch_seen);

        push_u32(buf, self.mount_reports.len() as u32);
        for mr in &self.mount_reports {
            mr.encode_body(buf);
        }

        // Optional peer capabilities blob (presence byte + length-prefixed payload).
        if let Some(ref caps) = self.peer_capabilities {
            buf.push(1u8);
            let mut caps_buf = alloc::vec::Vec::new();
            caps.encode(&mut caps_buf);
            push_u32(buf, caps_buf.len() as u32);
            buf.extend_from_slice(&caps_buf);
        } else {
            buf.push(0u8);
        }

        self.epoch_proof.encode_body(buf);
        push_u64(buf, self.nonce);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        let node_id = read_u64(payload, &mut pos)?;
        let cluster_addr = read_socket_addr(payload, &mut pos)?;
        let failure_domain = read_failure_domain(payload, &mut pos)?;
        let capabilities = read_u64(payload, &mut pos)?;
        let highest_epoch_seen = read_u64(payload, &mut pos)?;

        let mount_reports_len = read_u32(payload, &mut pos)? as usize;
        let mut mount_reports = alloc::vec::Vec::with_capacity(mount_reports_len);
        for _ in 0..mount_reports_len {
            mount_reports.push(MountReportV1::decode_body(payload, &mut pos)?);
        }

        // Optional peer capabilities blob
        let has_caps = read_u8(payload, &mut pos)?;
        let peer_capabilities = if has_caps != 0 {
            let caps_len = read_u32(payload, &mut pos)? as usize;
            if pos + caps_len > payload.len() {
                return Err(MembershipCodecError::Underflow);
            }
            let caps = PeerCapabilities::decode(&payload[pos..pos + caps_len])?;
            pos += caps_len;
            Some(caps)
        } else {
            None
        };

        let epoch_proof = MembershipEpochProofV1::decode_body(payload, &mut pos)?;
        let nonce = read_u64(payload, &mut pos)?;
        ensure_fully_consumed(payload, pos)?;
        Ok(Self {
            node_id,
            cluster_addr,
            failure_domain,
            capabilities,
            highest_epoch_seen,
            mount_reports,
            peer_capabilities,
            epoch_proof,
            nonce,
        })
    }
}

#[cfg(feature = "alloc")]
impl MembershipCodec for JoinResponseV1 {
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.node_id);
        push_u64(buf, self.term);
        push_u64(buf, self.incarnation.0);
        push_u64(buf, self.current_epoch);
        push_socket_addr(buf, self.leader_addr);

        push_u32(buf, self.peer_descriptors.len() as u32);
        for nd in &self.peer_descriptors {
            nd.encode_body(buf);
        }

        match &self.cluster_view {
            Some(cv) => {
                buf.push(1);
                cv.encode_body(buf);
            }
            None => {
                buf.push(0);
            }
        }

        push_u8(buf, self.config_class);
        self.epoch_proof.encode_body(buf);
        push_u64(buf, self.nonce);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        let node_id = read_u64(payload, &mut pos)?;
        let term = read_u64(payload, &mut pos)?;
        let incarnation = Incarnation(read_u64(payload, &mut pos)?);
        let current_epoch = read_u64(payload, &mut pos)?;
        let leader_addr = read_socket_addr(payload, &mut pos)?;

        let peer_descriptors_len = read_u32(payload, &mut pos)? as usize;
        let mut peer_descriptors = alloc::vec::Vec::with_capacity(peer_descriptors_len);
        for _ in 0..peer_descriptors_len {
            peer_descriptors.push(NodeDescriptorV1::decode_body(payload, &mut pos)?);
        }

        let cluster_view_has = read_u8(payload, &mut pos)?;
        let cluster_view = if cluster_view_has == 1 {
            Some(ClusterViewV1::decode_body(payload, &mut pos)?)
        } else {
            None
        };

        let config_class = read_u8(payload, &mut pos)?;
        let epoch_proof = MembershipEpochProofV1::decode_body(payload, &mut pos)?;
        let nonce = read_u64(payload, &mut pos)?;
        ensure_fully_consumed(payload, pos)?;
        Ok(Self {
            node_id,
            term,
            incarnation,
            current_epoch,
            leader_addr,
            peer_descriptors,
            cluster_view,
            config_class,
            epoch_proof,
            nonce,
        })
    }
}

impl MembershipCodec for LeaderRedirectV1 {
    #[cfg(feature = "alloc")]
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.leader_node_id);
        push_socket_addr(buf, self.leader_addr);
        push_u64(buf, self.term);
        push_u64(buf, self.nonce);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        Ok(Self {
            leader_node_id: read_u64(payload, &mut pos)?,
            leader_addr: read_socket_addr(payload, &mut pos)?,
            term: read_u64(payload, &mut pos)?,
            nonce: read_u64(payload, &mut pos)?,
        })
    }
}

#[cfg(feature = "alloc")]
impl MembershipCodec for HeartbeatV1 {
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.node_id);
        push_u64(buf, self.term);

        push_u32(buf, self.mount_reports.len() as u32);
        for mr in &self.mount_reports {
            mr.encode_body(buf);
        }

        push_u64(buf, self.sequence);
        self.epoch_proof.encode_body(buf);
        push_u64(buf, self.nonce);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        let node_id = read_u64(payload, &mut pos)?;
        let term = read_u64(payload, &mut pos)?;

        let mount_reports_len = read_u32(payload, &mut pos)? as usize;
        let mut mount_reports = alloc::vec::Vec::with_capacity(mount_reports_len);
        for _ in 0..mount_reports_len {
            mount_reports.push(MountReportV1::decode_body(payload, &mut pos)?);
        }

        let sequence = read_u64(payload, &mut pos)?;
        let epoch_proof = MembershipEpochProofV1::decode_body(payload, &mut pos)?;
        let nonce = read_u64(payload, &mut pos)?;
        ensure_fully_consumed(payload, pos)?;
        Ok(Self {
            node_id,
            term,
            mount_reports,
            sequence,
            epoch_proof,
            nonce,
        })
    }
}

impl MembershipCodec for HeartbeatAckV1 {
    #[cfg(feature = "alloc")]
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.node_id);
        push_u64(buf, self.term);
        push_u64(buf, self.sequence);
        push_bool(buf, self.accepted);
        push_opt_u64(buf, self.leader_hint);
        self.epoch_proof.encode_body(buf);
        push_u64(buf, self.nonce);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        let decoded = Self {
            node_id: read_u64(payload, &mut pos)?,
            term: read_u64(payload, &mut pos)?,
            sequence: read_u64(payload, &mut pos)?,
            accepted: read_bool(payload, &mut pos)?,
            leader_hint: read_opt_u64(payload, &mut pos)?,
            epoch_proof: MembershipEpochProofV1::decode_body(payload, &mut pos)?,
            nonce: read_u64(payload, &mut pos)?,
        };
        ensure_fully_consumed(payload, pos)?;
        Ok(decoded)
    }
}

impl MembershipCodec for NodeDescriptorV1 {
    #[cfg(feature = "alloc")]
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.node_id);
        push_socket_addr(buf, self.cluster_addr);
        push_failure_domain(buf, self.failure_domain);
        push_u64(buf, self.capabilities);
        push_u8(buf, self.member_class);
        push_bool(buf, self.is_alive);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        Ok(Self {
            node_id: read_u64(payload, &mut pos)?,
            cluster_addr: read_socket_addr(payload, &mut pos)?,
            failure_domain: read_failure_domain(payload, &mut pos)?,
            capabilities: read_u64(payload, &mut pos)?,
            member_class: read_u8(payload, &mut pos)?,
            is_alive: read_bool(payload, &mut pos)?,
        })
    }
}

#[cfg(feature = "alloc")]
impl MembershipCodec for DatasetViewV1 {
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.dataset_id);
        push_u8(buf, self.mount_mode as u8);
        push_opt_u64(buf, self.writer_node_id);

        push_u32(buf, self.reader_node_ids.len() as u32);
        for &id in &self.reader_node_ids {
            push_u64(buf, id);
        }

        push_u64(buf, self.generation);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        let dataset_id = read_u64(payload, &mut pos)?;
        let mount_mode = MountMode::from_u8(read_u8(payload, &mut pos)?).ok_or(
            MembershipCodecError::InvalidDiscriminant {
                field: "MountMode",
                value: payload[pos - 1],
            },
        )?;
        let writer_node_id = read_opt_u64(payload, &mut pos)?;

        let reader_node_ids_len = read_u32(payload, &mut pos)? as usize;
        let mut reader_node_ids = alloc::vec::Vec::with_capacity(reader_node_ids_len);
        for _ in 0..reader_node_ids_len {
            reader_node_ids.push(read_u64(payload, &mut pos)?);
        }

        let generation = read_u64(payload, &mut pos)?;
        Ok(Self {
            dataset_id,
            mount_mode,
            writer_node_id,
            reader_node_ids,
            generation,
        })
    }
}

#[cfg(feature = "alloc")]
impl MembershipCodec for ClusterViewV1 {
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.epoch);
        push_u64(buf, self.term);
        push_u64(buf, self.leader_node_id);

        push_u32(buf, self.nodes.len() as u32);
        for nd in &self.nodes {
            nd.encode_body(buf);
        }

        push_u32(buf, self.datasets.len() as u32);
        for ds in &self.datasets {
            ds.encode_body(buf);
        }

        push_u32(buf, self.transitions.len() as u32);
        for t in &self.transitions {
            t.encode_body(buf);
        }

        push_u8(buf, self.config_class);
        push_u64(buf, self.sequence);
        self.epoch_proof.encode_body(buf);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        let epoch = read_u64(payload, &mut pos)?;
        let term = read_u64(payload, &mut pos)?;
        let leader_node_id = read_u64(payload, &mut pos)?;

        let nodes_len = read_u32(payload, &mut pos)? as usize;
        let mut nodes = alloc::vec::Vec::with_capacity(nodes_len);
        for _ in 0..nodes_len {
            nodes.push(NodeDescriptorV1::decode_body(payload, &mut pos)?);
        }

        let datasets_len = read_u32(payload, &mut pos)? as usize;
        let mut datasets = alloc::vec::Vec::with_capacity(datasets_len);
        for _ in 0..datasets_len {
            datasets.push(DatasetViewV1::decode_body(payload, &mut pos)?);
        }

        let transitions_len = read_u32(payload, &mut pos)? as usize;
        let mut transitions = alloc::vec::Vec::with_capacity(transitions_len);
        for _ in 0..transitions_len {
            transitions.push(MembershipTransitionRecord::decode_body(payload, &mut pos)?);
        }

        let config_class = read_u8(payload, &mut pos)?;
        let sequence = read_u64(payload, &mut pos)?;
        let epoch_proof = MembershipEpochProofV1::decode_body(payload, &mut pos)?;
        ensure_fully_consumed(payload, pos)?;
        Ok(Self {
            epoch,
            term,
            leader_node_id,
            nodes,
            datasets,
            transitions,
            config_class,
            sequence,
            epoch_proof,
        })
    }
}

impl MembershipCodec for MembershipTransition {
    #[cfg(feature = "alloc")]
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u8(buf, *self as u8);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        if payload.is_empty() {
            return Err(MembershipCodecError::Underflow);
        }
        MembershipTransition::from_u8(payload[0]).ok_or(MembershipCodecError::InvalidDiscriminant {
            field: "MembershipTransition",
            value: payload[0],
        })
    }
}

impl MembershipCodec for MembershipTransitionRecord {
    #[cfg(feature = "alloc")]
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u8(buf, self.transition as u8);
        push_u64(buf, self.node_id);
        push_u64(buf, self.epoch);
        push_u64(buf, self.term);
        push_u8(buf, self.reason);
        push_u64(buf, self.timestamp_ms);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        let transition = MembershipTransition::from_u8(read_u8(payload, &mut pos)?).ok_or(
            MembershipCodecError::InvalidDiscriminant {
                field: "MembershipTransition",
                value: payload[pos - 1],
            },
        )?;
        Ok(Self {
            transition,
            node_id: read_u64(payload, &mut pos)?,
            epoch: read_u64(payload, &mut pos)?,
            term: read_u64(payload, &mut pos)?,
            reason: read_u8(payload, &mut pos)?,
            timestamp_ms: read_u64(payload, &mut pos)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Helper methods for nested encoding (without checksum)
// ---------------------------------------------------------------------------

impl MembershipEpochProofV1 {
    #[cfg(feature = "alloc")]
    fn encode_body(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.committed_epoch);
        push_u64(buf, self.token_generation);
    }

    fn decode_body(data: &[u8], pos: &mut usize) -> Result<Self, MembershipCodecError> {
        Ok(Self {
            committed_epoch: read_u64(data, pos)?,
            token_generation: read_u64(data, pos)?,
        })
    }
}

impl MountReportV1 {
    #[cfg(feature = "alloc")]
    fn encode_body(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.dataset_id);
        push_u8(buf, self.mount_mode as u8);
        push_u64(buf, self.generation);
    }

    #[cfg(feature = "alloc")]
    fn decode_body(data: &[u8], pos: &mut usize) -> Result<Self, MembershipCodecError> {
        let dataset_id = read_u64(data, pos)?;
        let mount_mode = MountMode::from_u8(read_u8(data, pos)?).ok_or(
            MembershipCodecError::InvalidDiscriminant {
                field: "MountMode",
                value: data[*pos - 1],
            },
        )?;
        let generation = read_u64(data, pos)?;
        Ok(Self {
            dataset_id,
            mount_mode,
            generation,
        })
    }
}

impl NodeDescriptorV1 {
    #[cfg(feature = "alloc")]
    fn encode_body(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.node_id);
        push_socket_addr(buf, self.cluster_addr);
        push_failure_domain(buf, self.failure_domain);
        push_u64(buf, self.capabilities);
        push_u8(buf, self.member_class);
        push_bool(buf, self.is_alive);
    }

    #[cfg(feature = "alloc")]
    fn decode_body(data: &[u8], pos: &mut usize) -> Result<Self, MembershipCodecError> {
        Ok(Self {
            node_id: read_u64(data, pos)?,
            cluster_addr: read_socket_addr(data, pos)?,
            failure_domain: read_failure_domain(data, pos)?,
            capabilities: read_u64(data, pos)?,
            member_class: read_u8(data, pos)?,
            is_alive: read_bool(data, pos)?,
        })
    }
}

#[cfg(feature = "alloc")]
impl DatasetViewV1 {
    fn encode_body(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.dataset_id);
        push_u8(buf, self.mount_mode as u8);
        push_opt_u64(buf, self.writer_node_id);

        push_u32(buf, self.reader_node_ids.len() as u32);
        for &id in &self.reader_node_ids {
            push_u64(buf, id);
        }

        push_u64(buf, self.generation);
    }

    fn decode_body(data: &[u8], pos: &mut usize) -> Result<Self, MembershipCodecError> {
        let dataset_id = read_u64(data, pos)?;
        let mount_mode = MountMode::from_u8(read_u8(data, pos)?).ok_or(
            MembershipCodecError::InvalidDiscriminant {
                field: "MountMode",
                value: data[*pos - 1],
            },
        )?;
        let writer_node_id = read_opt_u64(data, pos)?;

        let reader_node_ids_len = read_u32(data, pos)? as usize;
        let mut reader_node_ids = alloc::vec::Vec::with_capacity(reader_node_ids_len);
        for _ in 0..reader_node_ids_len {
            reader_node_ids.push(read_u64(data, pos)?);
        }

        let generation = read_u64(data, pos)?;
        Ok(Self {
            dataset_id,
            mount_mode,
            writer_node_id,
            reader_node_ids,
            generation,
        })
    }
}

#[cfg(feature = "alloc")]
impl ClusterViewV1 {
    fn encode_body(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u64(buf, self.epoch);
        push_u64(buf, self.term);
        push_u64(buf, self.leader_node_id);

        push_u32(buf, self.nodes.len() as u32);
        for nd in &self.nodes {
            nd.encode_body(buf);
        }

        push_u32(buf, self.datasets.len() as u32);
        for ds in &self.datasets {
            ds.encode_body(buf);
        }

        push_u32(buf, self.transitions.len() as u32);
        for t in &self.transitions {
            t.encode_body(buf);
        }

        push_u8(buf, self.config_class);
        push_u64(buf, self.sequence);
        self.epoch_proof.encode_body(buf);
    }

    fn decode_body(data: &[u8], pos: &mut usize) -> Result<Self, MembershipCodecError> {
        let epoch = read_u64(data, pos)?;
        let term = read_u64(data, pos)?;
        let leader_node_id = read_u64(data, pos)?;

        let nodes_len = read_u32(data, pos)? as usize;
        let mut nodes = alloc::vec::Vec::with_capacity(nodes_len);
        for _ in 0..nodes_len {
            nodes.push(NodeDescriptorV1::decode_body(data, pos)?);
        }

        let datasets_len = read_u32(data, pos)? as usize;
        let mut datasets = alloc::vec::Vec::with_capacity(datasets_len);
        for _ in 0..datasets_len {
            datasets.push(DatasetViewV1::decode_body(data, pos)?);
        }

        let transitions_len = read_u32(data, pos)? as usize;
        let mut transitions = alloc::vec::Vec::with_capacity(transitions_len);
        for _ in 0..transitions_len {
            transitions.push(MembershipTransitionRecord::decode_body(data, pos)?);
        }

        let config_class = read_u8(data, pos)?;
        let sequence = read_u64(data, pos)?;
        let epoch_proof = MembershipEpochProofV1::decode_body(data, pos)?;
        Ok(Self {
            epoch,
            term,
            leader_node_id,
            nodes,
            datasets,
            transitions,
            config_class,
            sequence,
            epoch_proof,
        })
    }
}

#[cfg(feature = "alloc")]
impl JoinRequestV1 {
    pub fn validate_epoch_proof(
        &self,
        current: MembershipEpochProofV1,
    ) -> Result<(), MembershipEpochProofError> {
        self.epoch_proof.validate_against(current)?;
        require_epoch_binding(
            self.epoch_proof,
            "JoinRequestV1::highest_epoch_seen",
            self.highest_epoch_seen,
        )
    }
}

#[cfg(feature = "alloc")]
impl JoinResponseV1 {
    pub fn validate_epoch_proof(
        &self,
        current: MembershipEpochProofV1,
    ) -> Result<(), MembershipEpochProofError> {
        self.epoch_proof.validate_against(current)?;
        require_epoch_binding(
            self.epoch_proof,
            "JoinResponseV1::current_epoch",
            self.current_epoch,
        )?;
        if let Some(cluster_view) = &self.cluster_view {
            cluster_view.validate_epoch_proof(current)?;
            require_epoch_binding(
                self.epoch_proof,
                "JoinResponseV1::cluster_view.epoch",
                cluster_view.epoch,
            )?;
        }
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl HeartbeatV1 {
    pub fn validate_epoch_proof(
        &self,
        current: MembershipEpochProofV1,
    ) -> Result<(), MembershipEpochProofError> {
        self.epoch_proof.validate_against(current)
    }
}

impl HeartbeatAckV1 {
    pub fn validate_epoch_proof(
        &self,
        current: MembershipEpochProofV1,
    ) -> Result<(), MembershipEpochProofError> {
        self.epoch_proof.validate_against(current)
    }
}

#[cfg(feature = "alloc")]
impl ClusterViewV1 {
    pub fn validate_epoch_proof(
        &self,
        current: MembershipEpochProofV1,
    ) -> Result<(), MembershipEpochProofError> {
        self.epoch_proof.validate_against(current)?;
        require_epoch_binding(self.epoch_proof, "ClusterViewV1::epoch", self.epoch)
    }
}

#[cfg(feature = "alloc")]
impl MembershipTransitionRecord {
    fn encode_body(&self, buf: &mut alloc::vec::Vec<u8>) {
        push_u8(buf, self.transition as u8);
        push_u64(buf, self.node_id);
        push_u64(buf, self.epoch);
        push_u64(buf, self.term);
        push_u8(buf, self.reason);
        push_u64(buf, self.timestamp_ms);
    }

    fn decode_body(data: &[u8], pos: &mut usize) -> Result<Self, MembershipCodecError> {
        let transition = MembershipTransition::from_u8(read_u8(data, pos)?).ok_or(
            MembershipCodecError::InvalidDiscriminant {
                field: "MembershipTransition",
                value: data[*pos - 1],
            },
        )?;
        Ok(Self {
            transition,
            node_id: read_u64(data, pos)?,
            epoch: read_u64(data, pos)?,
            term: read_u64(data, pos)?,
            reason: read_u8(data, pos)?,
            timestamp_ms: read_u64(data, pos)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
// Epoch Agreement Types — simple peer-to-peer proposal / ack / commit
// wire format for the epoch-agreement protocol.  No BLAKE3 or MAC
// overfit: integrity belongs at the transport security boundary;
// these carry only the consensus fields needed for quorum-based
// epoch advancement.
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
/// A proposal to advance the membership epoch, broadcast by a coordinator
/// to peer nodes over transport.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EpochAgreementProposal {
    /// The target epoch identifier.
    pub epoch_id: u64,
    /// Sorted, deduplicated member node ids in the proposed view.
    pub view: alloc::vec::Vec<u64>,
    /// Node identity of the coordinator that proposed this epoch.
    pub coordinator_id: u64,
}

#[cfg(feature = "alloc")]
/// A peer's acknowledgment of an [`EpochAgreementProposal`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EpochAgreementAck {
    /// The epoch identifier this ack targets.
    pub epoch_id: u64,
    /// The acknowledging peer's node identity.
    pub peer_id: u64,
    /// Whether the peer accepts the proposal.
    pub accepted: bool,
}

#[cfg(feature = "alloc")]
/// Notification emitted by the coordinator once quorum is reached.
///
/// Peers and local subscribers receive this message to learn that
/// the epoch transition has been committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EpochAgreementCommit {
    /// The epoch identifier that was committed.
    pub epoch_id: u64,
}

#[cfg(feature = "alloc")]
/// A roster-change proposal broadcast by the coordinator to all members.
///
/// Carries the proposed roster delta (added/removed members), a
/// monotonically increasing proposal_id, and the coordinator's current
/// epoch. Members validate and vote on the proposal before the
/// coordinator collects quorum and commits the change.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RosterChangeProposal {
    /// Monotonically increasing proposal identifier.
    pub proposal_id: u64,
    /// The coordinator that proposed this change.
    pub coordinator_id: u64,
    /// Current committed epoch when the proposal was created.
    pub current_epoch: u64,
    /// Members to add to the roster.
    pub added: alloc::vec::Vec<u64>,
    /// Members to remove from the roster.
    pub removed: alloc::vec::Vec<u64>,
    /// Millisecond timestamp when the proposal was created.
    pub created_at_millis: u64,
}

#[cfg(feature = "alloc")]
/// A member's vote on a [`RosterChangeProposal`].
///
/// Carries the proposal_id being voted on, the voter's identity,
/// an accept/reject decision, and an optional rejection reason.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RosterChangeVote {
    /// The proposal this vote targets.
    pub proposal_id: u64,
    /// The voting member's node identity.
    pub voter_id: u64,
    /// Whether the voter accepts the proposal.
    pub accepted: bool,
    /// Human-readable rejection reason when `accepted` is false.
    pub reject_reason: Option<String>,
    /// Millisecond timestamp when the vote was created.
    pub voted_at_millis: u64,
}

// ---------------------------------------------------------------------------
// RosterChangeVote — MembershipCodec impl (binary wire format)
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
impl MembershipCodec for RosterChangeVote {
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        // Wire format: proposal_id(u64) | voter_id(u64) | accepted(u8) |
        //              reject_reason_len(u32) | reject_reason(utf-8) |
        //              voted_at_millis(u64) | CRC32C
        push_u64(buf, self.proposal_id);
        push_u64(buf, self.voter_id);
        buf.push(if self.accepted { 1u8 } else { 0u8 });
        // Encode optional reject_reason: length-prefixed UTF-8.
        // Normalize empty string to None for wire efficiency.
        let reject_reason = self.reject_reason.as_ref().filter(|r| !r.is_empty());

        if let Some(reason) = reject_reason {
            let bytes = reason.as_bytes();
            push_u32(buf, bytes.len() as u32);
            buf.extend_from_slice(bytes);
        } else {
            push_u32(buf, 0u32);
        }
        push_u64(buf, self.voted_at_millis);
        push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        let proposal_id = read_u64(payload, &mut pos)?;
        let voter_id = read_u64(payload, &mut pos)?;
        let accepted_byte = read_u8(payload, &mut pos)?;
        let accepted = accepted_byte != 0;
        let reason_len = read_u32(payload, &mut pos)? as usize;
        let reject_reason = if reason_len > 0 {
            if pos + reason_len > payload.len() {
                return Err(MembershipCodecError::Underflow);
            }
            let reason = core::str::from_utf8(&payload[pos..pos + reason_len])
                .map_err(|_| MembershipCodecError::Underflow)?;
            pos += reason_len;
            Some(reason.to_string())
        } else {
            None
        };
        let voted_at_millis = read_u64(payload, &mut pos)?;
        Ok(Self {
            proposal_id,
            voter_id,
            accepted,
            reject_reason,
            voted_at_millis,
        })
    }
}
// ---------------------------------------------------------------------------
// ElectionTrigger
// ---------------------------------------------------------------------------

/// Why a coordinator election was triggered.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ElectionTrigger {
    /// The current coordinator's lease expired without renewal.
    LeaseExpired = 0,
    /// The current coordinator explicitly departed.
    CoordinatorDeparted = 1,
    /// Initial cluster formation: no prior coordinator exists.
    Bootstrap = 2,
}

impl ElectionTrigger {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::LeaseExpired),
            1 => Some(Self::CoordinatorDeparted),
            2 => Some(Self::Bootstrap),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// CoordinatorElectionOutcome
// ---------------------------------------------------------------------------

/// The result of a coordinator election.
///
/// Produced by `CoordinatorElection::promote` in `tidefs-membership-epoch`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CoordinatorElectionOutcome {
    /// The newly elected coordinator's peer identifier.
    pub new_coordinator: u64,
    /// The new incarnation counter (previous incarnation + 1).
    pub new_incarnation: u64,
    /// The epoch in which this election occurred.
    pub election_epoch: u64,
}

// ---------------------------------------------------------------------------
// Journal wire encoding — compact transition journal entry representation
// ---------------------------------------------------------------------------

/// Discriminant for transition journal entry kind on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalEntryKind {
    /// Join = 0x01
    Join = 0x01,
    /// Leave = 0x02
    Leave = 0x02,
    /// CoordinatorChange = 0x03
    CoordinatorChange = 0x03,
}

impl JournalEntryKind {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Join),
            0x02 => Some(Self::Leave),
            0x03 => Some(Self::CoordinatorChange),
            _ => None,
        }
    }

    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Compact wire encoding for a transition journal entry.
///
/// # Wire format (all fields)
///
/// ```text
/// [0]       entry_kind        u8 discriminant (0x01=Join, 0x02=Leave, 0x03=CoordinatorChange)
/// [1..]     transition_id     compact varint
/// [...]     epoch              compact varint
/// [...]     peer_id            compact varint
/// [...]     prepared_at_millis compact varint
/// [...]     finalised_at_millis compact varint (0 if not finalised)
/// [...]     status             u8 (0=Prepared, 1=Committed, 2=Aborted)
/// [...]     reason             u8 (LeaveReason discriminant, 0 for Join/CoordinatorChange)
/// ```
///
/// Compact varint encoding for `u64`:
/// - 0..253  → single byte
/// - 253..65535 → marker 0xFD + 2 bytes LE
/// - 65536..MAX → marker 0xFE + 8 bytes LE
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalWireEntry {
    pub entry_kind: JournalEntryKind,
    pub transition_id: u64,
    pub epoch: u64,
    pub peer_id: u64,
    pub prepared_at_millis: u64,
    pub finalised_at_millis: u64,
    pub status: u8,
    pub reason: u8,
}

impl JournalWireEntry {
    /// Encode this entry into `buf`.
    #[cfg(feature = "alloc")]
    pub fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        buf.push(self.entry_kind.to_u8());
        push_compact_u64(buf, self.transition_id);
        push_compact_u64(buf, self.epoch);
        push_compact_u64(buf, self.peer_id);
        push_compact_u64(buf, self.prepared_at_millis);
        push_compact_u64(buf, self.finalised_at_millis);
        buf.push(self.status);
        buf.push(self.reason);
    }

    /// Decode an entry from `data` starting at `pos`, advancing `pos`.
    pub fn decode(data: &[u8], pos: &mut usize) -> Result<Self, MembershipCodecError> {
        let kind_byte = read_u8(data, pos)?;
        let entry_kind = JournalEntryKind::from_u8(kind_byte).ok_or(
            MembershipCodecError::InvalidDiscriminant {
                field: "journal_entry_kind",
                value: kind_byte,
            },
        )?;
        let transition_id = read_compact_u64(data, pos)?;
        let epoch = read_compact_u64(data, pos)?;
        let peer_id = read_compact_u64(data, pos)?;
        let prepared_at_millis = read_compact_u64(data, pos)?;
        let finalised_at_millis = read_compact_u64(data, pos)?;
        let status = read_u8(data, pos)?;
        let reason = read_u8(data, pos)?;
        Ok(Self {
            entry_kind,
            transition_id,
            epoch,
            peer_id,
            prepared_at_millis,
            finalised_at_millis,
            status,
            reason,
        })
    }

    /// Size of this entry when encoded, in bytes.
    #[must_use]
    pub fn encoded_size(&self) -> usize {
        3 // kind (u8) + status (u8) + reason (u8)
            + compact_u64_size(self.transition_id)
            + compact_u64_size(self.epoch)
            + compact_u64_size(self.peer_id)
            + compact_u64_size(self.prepared_at_millis)
            + compact_u64_size(self.finalised_at_millis)
    }
}

/// Marker byte for compact-encoded u16 values.
const COMPACT_U16_MARKER: u8 = 0xFD;
/// Append a compact variable-length u64 to `buf`.
#[cfg(feature = "alloc")]
fn push_compact_u64(buf: &mut alloc::vec::Vec<u8>, v: u64) {
    if v < COMPACT_U16_MARKER as u64 {
        buf.push(v as u8);
    } else if v <= u16::MAX as u64 {
        buf.push(COMPACT_U16_MARKER);
        buf.extend_from_slice(&(v as u16).to_le_bytes());
    } else {
        buf.push(0xFE);
        buf.extend_from_slice(&v.to_le_bytes());
    }
}

/// Read a compact variable-length u64 from `data` at `pos`, advancing `pos`.
fn read_compact_u64(data: &[u8], pos: &mut usize) -> Result<u64, MembershipCodecError> {
    let first = read_u8(data, pos)?;
    if first < COMPACT_U16_MARKER {
        Ok(u64::from(first))
    } else if first == COMPACT_U16_MARKER {
        if *pos + 2 > data.len() {
            return Err(MembershipCodecError::Underflow);
        }
        let lo = u64::from(data[*pos]);
        let hi = u64::from(data[*pos + 1]);
        *pos += 2;
        Ok(lo | (hi << 8))
    } else {
        // Any marker byte >= 0xFE signals a full u64 follows.
        if *pos + 8 > data.len() {
            return Err(MembershipCodecError::Underflow);
        }
        let v = u64::from_le_bytes([
            data[*pos],
            data[*pos + 1],
            data[*pos + 2],
            data[*pos + 3],
            data[*pos + 4],
            data[*pos + 5],
            data[*pos + 6],
            data[*pos + 7],
        ]);
        *pos += 8;
        Ok(v)
    }
}

/// Return the encoded size of a compact u64 value.
#[must_use]
const fn compact_u64_size(v: u64) -> usize {
    if v < COMPACT_U16_MARKER as u64 {
        1
    } else if v <= u16::MAX as u64 {
        1 + 2
    } else {
        1 + 8
    }
}

pub mod departure;

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    fn roundtrip<T: MembershipCodec + core::fmt::Debug + PartialEq>(val: T) {
        let mut buf = alloc::vec::Vec::new();
        val.encode(&mut buf);
        let decoded = T::decode(&buf).expect("decode failed");
        assert_eq!(val, decoded, "roundtrip mismatch");
    }

    fn roundtrip_no_alloc_encode<T: MembershipCodec + core::fmt::Debug + PartialEq>(
        encode_fn: fn(&T, &mut alloc::vec::Vec<u8>),
        val: T,
    ) {
        let mut buf = alloc::vec::Vec::new();
        encode_fn(&val, &mut buf);
        let decoded = T::decode(&buf).expect("decode failed");
        assert_eq!(val, decoded, "roundtrip mismatch");
    }

    fn epoch_proof(epoch: u64) -> MembershipEpochProofV1 {
        MembershipEpochProofV1::new(epoch, epoch + 1000)
    }

    fn test_addr(octet: u8) -> core::net::SocketAddr {
        core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(10, 0, 0, octet),
            4200,
        ))
    }

    fn append_checked_trailing_byte(mut buf: alloc::vec::Vec<u8>) -> alloc::vec::Vec<u8> {
        let checksum_offset = buf.len() - 4;
        buf.truncate(checksum_offset);
        buf.push(0xAA);
        push_checksum(&mut buf);
        buf
    }

    fn legacy_join_request_without_epoch_proof() -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::new();
        push_u64(&mut buf, 1);
        push_socket_addr(&mut buf, test_addr(1));
        push_failure_domain(&mut buf, FailureDomainVector::ZERO);
        push_u64(&mut buf, 0xFFFF);
        push_u64(&mut buf, 7);
        push_u32(&mut buf, 0);
        push_u8(&mut buf, 0);
        push_u64(&mut buf, 999);
        push_checksum(&mut buf);
        buf
    }

    fn legacy_join_response_without_epoch_proof() -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::new();
        push_u64(&mut buf, 2);
        push_u64(&mut buf, 1);
        push_u64(&mut buf, 1);
        push_u64(&mut buf, 7);
        push_socket_addr(&mut buf, test_addr(2));
        push_u32(&mut buf, 0);
        push_u8(&mut buf, 0);
        push_u8(&mut buf, 0);
        push_u64(&mut buf, 777);
        push_checksum(&mut buf);
        buf
    }

    fn legacy_heartbeat_without_epoch_proof() -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::new();
        push_u64(&mut buf, 1);
        push_u64(&mut buf, 1);
        push_u32(&mut buf, 0);
        push_u64(&mut buf, 5);
        push_u64(&mut buf, 111);
        push_checksum(&mut buf);
        buf
    }

    fn legacy_cluster_view_without_epoch_proof() -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::new();
        push_u64(&mut buf, 7);
        push_u64(&mut buf, 1);
        push_u64(&mut buf, 1);
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 0);
        push_u8(&mut buf, 0);
        push_u64(&mut buf, 0);
        push_checksum(&mut buf);
        buf
    }

    #[test]
    fn mount_mode_roundtrip() {
        roundtrip(MountMode::ReadOnly);
        roundtrip(MountMode::ReadWrite);
    }

    #[test]
    fn mount_mode_invalid_discriminant() {
        let buf = [2u8, 0, 0, 0, 0];
        assert!(MountMode::decode(&buf).is_err());
    }

    #[test]
    fn mount_report_roundtrip() {
        roundtrip(MountReportV1 {
            dataset_id: 42,
            mount_mode: MountMode::ReadWrite,
            generation: 7,
        });
    }

    #[test]
    fn epoch_proof_roundtrip() {
        roundtrip(MembershipEpochProofV1::new(7, 42));
    }

    #[test]
    fn epoch_proof_checksum_corruption_detected() {
        let mut buf = alloc::vec::Vec::new();
        MembershipEpochProofV1::new(7, 42).encode(&mut buf);
        buf[0] ^= 0xFF;
        assert!(matches!(
            MembershipEpochProofV1::decode(&buf),
            Err(MembershipCodecError::ChecksumMismatch)
        ));
    }

    #[test]
    fn join_request_roundtrip() {
        let addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(10, 0, 0, 1),
            4200,
        ));
        roundtrip_no_alloc_encode(
            JoinRequestV1::encode,
            JoinRequestV1 {
                node_id: 1,
                cluster_addr: addr,
                failure_domain: FailureDomainVector::ZERO,
                capabilities: 0xFFFF,
                highest_epoch_seen: 100,
                mount_reports: alloc::vec![MountReportV1 {
                    dataset_id: 10,
                    mount_mode: MountMode::ReadWrite,
                    generation: 3,
                }],
                peer_capabilities: None,
                epoch_proof: epoch_proof(100),
                nonce: 999,
            },
        );
    }

    #[test]
    fn join_request_peer_capabilities_roundtrip_with_epoch_proof() {
        let addr = test_addr(11);
        roundtrip_no_alloc_encode(
            JoinRequestV1::encode,
            JoinRequestV1 {
                node_id: 11,
                cluster_addr: addr,
                failure_domain: FailureDomainVector::ZERO,
                capabilities: 0xF0F0,
                highest_epoch_seen: 11,
                mount_reports: alloc::vec![],
                peer_capabilities: Some(PeerCapabilities::new(1 << 30, 1 << 29)),
                epoch_proof: epoch_proof(11),
                nonce: 1234,
            },
        );
    }

    #[test]
    fn join_response_roundtrip() {
        let addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(10, 0, 0, 2),
            4200,
        ));
        roundtrip_no_alloc_encode(
            JoinResponseV1::encode,
            JoinResponseV1 {
                node_id: 2,
                term: 1,
                incarnation: Incarnation::new(1),
                current_epoch: 5,
                leader_addr: addr,
                peer_descriptors: alloc::vec![NodeDescriptorV1 {
                    node_id: 1,
                    cluster_addr: addr,
                    failure_domain: FailureDomainVector::ZERO,
                    capabilities: 0xFFFF,
                    member_class: 0,
                    is_alive: true,
                }],
                cluster_view: None,
                config_class: 0,
                epoch_proof: epoch_proof(5),
                nonce: 777,
            },
        );
    }

    #[test]
    fn leader_redirect_roundtrip() {
        let addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(10, 0, 0, 3),
            4200,
        ));
        roundtrip_no_alloc_encode(
            LeaderRedirectV1::encode,
            LeaderRedirectV1 {
                leader_node_id: 3,
                leader_addr: addr,
                term: 2,
                nonce: 555,
            },
        );
    }

    #[test]
    fn heartbeat_roundtrip() {
        roundtrip_no_alloc_encode(
            HeartbeatV1::encode,
            HeartbeatV1 {
                node_id: 1,
                term: 1,
                mount_reports: alloc::vec![],
                sequence: 0,
                epoch_proof: epoch_proof(1),
                nonce: 111,
            },
        );
    }

    #[test]
    fn heartbeat_ack_roundtrip() {
        roundtrip(HeartbeatAckV1 {
            node_id: 2,
            term: 1,
            sequence: 5,
            accepted: true,
            leader_hint: Some(3),
            epoch_proof: epoch_proof(1),
            nonce: 222,
        });
    }

    #[test]
    fn heartbeat_ack_reject() {
        let ack = HeartbeatAckV1 {
            node_id: 2,
            term: 1,
            sequence: 5,
            accepted: false,
            leader_hint: None,
            epoch_proof: epoch_proof(1),
            nonce: 333,
        };
        roundtrip(ack);
    }

    #[test]
    fn node_descriptor_roundtrip() {
        let addr = core::net::SocketAddr::V6(core::net::SocketAddrV6::new(
            core::net::Ipv6Addr::LOCALHOST,
            4200,
            0,
            0,
        ));
        roundtrip(NodeDescriptorV1 {
            node_id: 10,
            cluster_addr: addr,
            failure_domain: FailureDomainVector::new(1, 2, 3, 4, 5, 6),
            capabilities: 0xABCD,
            member_class: 1,
            is_alive: true,
        });
    }

    #[test]
    fn dataset_view_roundtrip() {
        roundtrip_no_alloc_encode(
            DatasetViewV1::encode,
            DatasetViewV1 {
                dataset_id: 100,
                mount_mode: MountMode::ReadWrite,
                writer_node_id: Some(5),
                reader_node_ids: alloc::vec![6, 7, 8],
                generation: 12,
            },
        );
    }

    #[test]
    fn cluster_view_roundtrip() {
        let addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(10, 0, 0, 1),
            4200,
        ));
        roundtrip_no_alloc_encode(
            ClusterViewV1::encode,
            ClusterViewV1 {
                epoch: 1,
                term: 1,
                leader_node_id: 1,
                nodes: alloc::vec![NodeDescriptorV1 {
                    node_id: 1,
                    cluster_addr: addr,
                    failure_domain: FailureDomainVector::ZERO,
                    capabilities: 0xFFFF,
                    member_class: 0,
                    is_alive: true,
                }],
                datasets: alloc::vec![],
                transitions: alloc::vec![],
                config_class: 0,
                sequence: 0,
                epoch_proof: epoch_proof(1),
            },
        );
    }

    #[test]
    fn current_epoch_proofs_validate_for_membership_messages() {
        let current = epoch_proof(7);
        let addr = test_addr(7);
        let join_request = JoinRequestV1 {
            node_id: 1,
            cluster_addr: addr,
            failure_domain: FailureDomainVector::ZERO,
            capabilities: 0,
            highest_epoch_seen: 7,
            mount_reports: alloc::vec![],
            peer_capabilities: None,
            epoch_proof: current,
            nonce: 1,
        };
        let cluster_view = ClusterViewV1 {
            epoch: 7,
            term: 1,
            leader_node_id: 2,
            nodes: alloc::vec![],
            datasets: alloc::vec![],
            transitions: alloc::vec![],
            config_class: 0,
            sequence: 1,
            epoch_proof: current,
        };
        let join_response = JoinResponseV1 {
            node_id: 2,
            term: 1,
            incarnation: Incarnation::new(1),
            current_epoch: 7,
            leader_addr: addr,
            peer_descriptors: alloc::vec![],
            cluster_view: Some(cluster_view.clone()),
            config_class: 0,
            epoch_proof: current,
            nonce: 2,
        };
        let heartbeat = HeartbeatV1 {
            node_id: 1,
            term: 1,
            mount_reports: alloc::vec![],
            sequence: 3,
            epoch_proof: current,
            nonce: 3,
        };
        let ack = HeartbeatAckV1 {
            node_id: 2,
            term: 1,
            sequence: 3,
            accepted: true,
            leader_hint: None,
            epoch_proof: current,
            nonce: 4,
        };

        assert_eq!(join_request.validate_epoch_proof(current), Ok(()));
        assert_eq!(join_response.validate_epoch_proof(current), Ok(()));
        assert_eq!(cluster_view.validate_epoch_proof(current), Ok(()));
        assert_eq!(heartbeat.validate_epoch_proof(current), Ok(()));
        assert_eq!(ack.validate_epoch_proof(current), Ok(()));
    }

    #[test]
    fn stale_epoch_proof_is_rejected_before_membership_state() {
        let heartbeat = HeartbeatV1 {
            node_id: 1,
            term: 1,
            mount_reports: alloc::vec![],
            sequence: 1,
            epoch_proof: epoch_proof(6),
            nonce: 1,
        };

        assert!(matches!(
            heartbeat.validate_epoch_proof(epoch_proof(7)),
            Err(MembershipEpochProofError::Stale {
                current_epoch: 7,
                received_epoch: 6,
            })
        ));
    }

    #[test]
    fn token_generation_mismatch_is_rejected() {
        let ack = HeartbeatAckV1 {
            node_id: 2,
            term: 1,
            sequence: 1,
            accepted: true,
            leader_hint: None,
            epoch_proof: MembershipEpochProofV1::new(7, 1),
            nonce: 1,
        };

        assert!(matches!(
            ack.validate_epoch_proof(MembershipEpochProofV1::new(7, 2)),
            Err(MembershipEpochProofError::TokenGenerationMismatch {
                current_generation: 2,
                received_generation: 1,
            })
        ));
    }

    #[test]
    fn message_epoch_mismatch_is_rejected() {
        let view = ClusterViewV1 {
            epoch: 6,
            term: 1,
            leader_node_id: 1,
            nodes: alloc::vec![],
            datasets: alloc::vec![],
            transitions: alloc::vec![],
            config_class: 0,
            sequence: 1,
            epoch_proof: epoch_proof(7),
        };

        assert!(matches!(
            view.validate_epoch_proof(epoch_proof(7)),
            Err(MembershipEpochProofError::MessageEpochMismatch {
                field: "ClusterViewV1::epoch",
                message_epoch: 6,
                proof_epoch: 7,
            })
        ));
    }

    #[test]
    fn missing_epoch_proof_legacy_layouts_are_rejected() {
        assert!(matches!(
            JoinRequestV1::decode(&legacy_join_request_without_epoch_proof()),
            Err(MembershipCodecError::Underflow)
        ));
        assert!(matches!(
            JoinResponseV1::decode(&legacy_join_response_without_epoch_proof()),
            Err(MembershipCodecError::Underflow)
        ));
        assert!(matches!(
            HeartbeatV1::decode(&legacy_heartbeat_without_epoch_proof()),
            Err(MembershipCodecError::Underflow)
        ));
        assert!(matches!(
            ClusterViewV1::decode(&legacy_cluster_view_without_epoch_proof()),
            Err(MembershipCodecError::Underflow)
        ));
    }

    #[test]
    fn proof_bearing_layout_rejects_checked_trailing_bytes() {
        let mut buf = alloc::vec::Vec::new();
        HeartbeatV1 {
            node_id: 1,
            term: 1,
            mount_reports: alloc::vec![],
            sequence: 1,
            epoch_proof: epoch_proof(7),
            nonce: 1,
        }
        .encode(&mut buf);
        let buf = append_checked_trailing_byte(buf);

        assert!(matches!(
            HeartbeatV1::decode(&buf),
            Err(MembershipCodecError::TrailingBytes { remaining: 1 })
        ));
    }

    #[test]
    fn membership_transition_roundtrip() {
        roundtrip(MembershipTransition::Join);
        roundtrip(MembershipTransition::Leave);
        roundtrip(MembershipTransition::PromoteLearner);
        roundtrip(MembershipTransition::DemoteVoter);
        roundtrip(MembershipTransition::Quarantine);
        roundtrip(MembershipTransition::ReleaseQuarantine);
        roundtrip(MembershipTransition::UpdateCapabilities);
    }

    #[test]
    fn membership_transition_invalid() {
        let buf = [7u8, 0, 0, 0, 0];
        assert!(MembershipTransition::decode(&buf).is_err());
    }

    #[test]
    fn transition_record_roundtrip() {
        roundtrip(MembershipTransitionRecord {
            transition: MembershipTransition::Join,
            node_id: 5,
            epoch: 3,
            term: 2,
            reason: 0,
            timestamp_ms: 1000000,
        });
    }

    #[test]
    fn checksum_mismatch_detected() {
        let mut buf = alloc::vec::Vec::new();
        MountMode::ReadOnly.encode(&mut buf);
        let last = buf.len() - 1;
        buf[last] ^= 0xFF;
        match MountMode::decode(&buf) {
            Err(MembershipCodecError::ChecksumMismatch) => {}
            other => panic!("expected ChecksumMismatch, got {:?}", other),
        }
    }

    #[test]
    fn underflow_detected() {
        let data = [];
        assert!(matches!(
            MountMode::decode(&data),
            Err(MembershipCodecError::Underflow)
        ));
    }

    // -------------------------------------------------------------------
    // Additional edge-case and error-path tests
    // -------------------------------------------------------------------

    #[test]
    fn checksum_mismatch_on_larger_type() {
        let mut buf = alloc::vec::Vec::new();
        MembershipTransitionRecord {
            transition: MembershipTransition::Leave,
            node_id: 99,
            epoch: 10,
            term: 3,
            reason: 1,
            timestamp_ms: 5_000_000,
        }
        .encode(&mut buf);
        let last = buf.len() - 1;
        buf[last] ^= 0xFF;
        match MembershipTransitionRecord::decode(&buf) {
            Err(MembershipCodecError::ChecksumMismatch) => {}
            other => panic!("expected ChecksumMismatch, got {:?}", other),
        }
    }

    #[test]
    fn checksum_mismatch_on_complex_type() {
        let addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(10, 0, 0, 1),
            4200,
        ));
        let mut buf = alloc::vec::Vec::new();
        JoinRequestV1 {
            node_id: 5,
            cluster_addr: addr,
            failure_domain: FailureDomainVector::new(1, 1, 1, 1, 1, 1),
            capabilities: 0xDEAD,
            highest_epoch_seen: 200,
            mount_reports: alloc::vec![
                MountReportV1 {
                    dataset_id: 10,
                    mount_mode: MountMode::ReadWrite,
                    generation: 3,
                },
                MountReportV1 {
                    dataset_id: 20,
                    mount_mode: MountMode::ReadOnly,
                    generation: 0,
                },
            ],
            peer_capabilities: None,
            epoch_proof: epoch_proof(200),
            nonce: 42,
        }
        .encode(&mut buf);
        buf[3] ^= 0xFF; // flip a byte in the middle of the payload
        assert!(JoinRequestV1::decode(&buf).is_err());
    }

    #[test]
    fn underflow_on_larger_type() {
        let data = [0u8; 3]; // shorter than 4-byte checksum
        assert!(matches!(
            MountReportV1::decode(&data),
            Err(MembershipCodecError::Underflow)
        ));
    }

    #[test]
    fn underflow_mid_decode() {
        let mut buf = alloc::vec::Vec::new();
        MountReportV1 {
            dataset_id: 1,
            mount_mode: MountMode::ReadWrite,
            generation: 1,
        }
        .encode(&mut buf);
        // Truncate so checksum hash covers fewer bytes than expected
        let short = &buf[..buf.len() - 6];
        assert!(MountReportV1::decode(short).is_err());
    }

    #[test]
    fn invalid_address_family_ipv4_decode() {
        // Manually craft a LeaderRedirectV1 with invalid address family
        let mut buf = alloc::vec::Vec::new();
        push_u64(&mut buf, 1); // leader_node_id
        push_u8(&mut buf, 99); // invalid address family
                               // enough bytes for IPv4 (6 bytes): 4 IP + 2 port
        buf.extend_from_slice(&[0u8; 6]);
        push_u64(&mut buf, 2); // term
        push_u64(&mut buf, 3); // nonce
        push_checksum(&mut buf);

        match LeaderRedirectV1::decode(&buf) {
            Err(MembershipCodecError::InvalidAddressFamily(99)) => {}
            other => panic!("expected InvalidAddressFamily(99), got {:?}", other),
        }
    }

    #[test]
    fn invalid_address_family_ipv6_decode() {
        let mut buf = alloc::vec::Vec::new();
        push_u64(&mut buf, 1); // leader_node_id
        push_u8(&mut buf, 255); // invalid address family
        buf.extend_from_slice(&[0u8; 18]); // enough bytes for IPv6
        push_u64(&mut buf, 2); // term
        push_u64(&mut buf, 3); // nonce
        push_checksum(&mut buf);

        assert!(matches!(
            LeaderRedirectV1::decode(&buf),
            Err(MembershipCodecError::InvalidAddressFamily(255))
        ));
    }

    #[test]
    fn mount_mode_invalid_discriminant_255() {
        let mut buf = alloc::vec::Vec::new();
        push_u8(&mut buf, 255); // invalid discriminant
        push_checksum(&mut buf);
        match MountMode::decode(&buf) {
            Err(MembershipCodecError::InvalidDiscriminant {
                field: "MountMode",
                value: 255,
            }) => {}
            other => panic!(
                "expected InvalidDiscriminant for MountMode(255), got {:?}",
                other
            ),
        }
    }
    #[test]
    fn codec_error_display_all_variants() {
        let e = MembershipCodecError::Underflow;
        assert!(alloc::format!("{e}").contains("underflow"));

        let e = MembershipCodecError::ChecksumMismatch;
        assert!(alloc::format!("{e}").contains("CRC32C"));

        let e = MembershipCodecError::InvalidDiscriminant {
            field: "TestField",
            value: 42,
        };
        let s = alloc::format!("{e}");
        assert!(s.contains("invalid discriminant"));
        assert!(s.contains("TestField"));
        assert!(s.contains("42"));

        let e = MembershipCodecError::InvalidAddressFamily(99);
        let s = alloc::format!("{e}");
        assert!(s.contains("invalid address family"));
        assert!(s.contains("99"));
    }

    #[test]
    fn failure_domain_vector_zero_constant() {
        let z = FailureDomainVector::ZERO;
        assert_eq!(z.device, 0);
        assert_eq!(z.node, 0);
        assert_eq!(z.chassis, 0);
        assert_eq!(z.rack, 0);
        assert_eq!(z.zone, 0);
        assert_eq!(z.region, 0);
    }

    #[test]
    fn failure_domain_vector_new_and_equality() {
        let fd = FailureDomainVector::new(1, 2, 3, 4, 5, 6);
        assert_eq!(fd.device, 1);
        assert_eq!(fd.node, 2);
        assert_eq!(fd.chassis, 3);
        assert_eq!(fd.rack, 4);
        assert_eq!(fd.zone, 5);
        assert_eq!(fd.region, 6);

        let copy = FailureDomainVector::new(1, 2, 3, 4, 5, 6);
        assert_eq!(fd, copy);
        assert_ne!(fd, FailureDomainVector::ZERO);
    }

    #[test]
    fn mount_mode_from_u8_full_sweep() {
        assert_eq!(MountMode::from_u8(0), Some(MountMode::ReadOnly));
        assert_eq!(MountMode::from_u8(1), Some(MountMode::ReadWrite));
        for v in 2u8..=255 {
            assert_eq!(MountMode::from_u8(v), None, "u8={v} must be None");
        }
    }

    #[test]
    fn membership_transition_from_u8_full_sweep() {
        assert_eq!(
            MembershipTransition::from_u8(0),
            Some(MembershipTransition::Join)
        );
        assert_eq!(
            MembershipTransition::from_u8(1),
            Some(MembershipTransition::Leave)
        );
        assert_eq!(
            MembershipTransition::from_u8(2),
            Some(MembershipTransition::PromoteLearner)
        );
        assert_eq!(
            MembershipTransition::from_u8(3),
            Some(MembershipTransition::DemoteVoter)
        );
        assert_eq!(
            MembershipTransition::from_u8(4),
            Some(MembershipTransition::Quarantine)
        );
        assert_eq!(
            MembershipTransition::from_u8(5),
            Some(MembershipTransition::ReleaseQuarantine)
        );
        assert_eq!(
            MembershipTransition::from_u8(6),
            Some(MembershipTransition::UpdateCapabilities)
        );
        for v in 7u8..=255 {
            assert_eq!(
                MembershipTransition::from_u8(v),
                None,
                "u8={v} must be None"
            );
        }
    }

    #[test]
    fn heartbeat_ack_leader_hint_zero() {
        let ack = HeartbeatAckV1 {
            node_id: 1,
            term: 1,
            sequence: 0,
            accepted: true,
            leader_hint: Some(0),
            epoch_proof: epoch_proof(1),
            nonce: 42,
        };
        roundtrip(ack);
    }

    #[test]
    fn heartbeat_ack_leader_hint_max() {
        let ack = HeartbeatAckV1 {
            node_id: 1,
            term: 1,
            sequence: 0,
            accepted: true,
            leader_hint: Some(u64::MAX),
            epoch_proof: epoch_proof(1),
            nonce: 42,
        };
        roundtrip(ack);
    }

    #[test]
    fn heartbeat_with_mount_reports() {
        roundtrip_no_alloc_encode(
            HeartbeatV1::encode,
            HeartbeatV1 {
                node_id: 10,
                term: 2,
                mount_reports: alloc::vec![
                    MountReportV1 {
                        dataset_id: 100,
                        mount_mode: MountMode::ReadWrite,
                        generation: 1,
                    },
                    MountReportV1 {
                        dataset_id: 200,
                        mount_mode: MountMode::ReadOnly,
                        generation: 5,
                    },
                ],
                sequence: 7,
                epoch_proof: epoch_proof(7),
                nonce: 999,
            },
        );
    }

    #[test]
    fn heartbeat_sequence_boundaries() {
        let test_seq = |seq: u64| {
            let mut buf = alloc::vec::Vec::new();
            HeartbeatV1 {
                node_id: 1,
                term: 1,
                mount_reports: alloc::vec![],
                sequence: seq,
                epoch_proof: epoch_proof(7),
                nonce: 1,
            }
            .encode(&mut buf);
            let decoded = HeartbeatV1::decode(&buf).expect("decode failed");
            assert_eq!(decoded.sequence, seq);
        };
        test_seq(0);
        test_seq(1);
        test_seq(u64::MAX);
    }

    #[test]
    fn join_response_with_cluster_view() {
        let addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(192, 168, 1, 1),
            4200,
        ));
        roundtrip_no_alloc_encode(
            JoinResponseV1::encode,
            JoinResponseV1 {
                node_id: 2,
                term: 1,
                incarnation: Incarnation::new(1),
                current_epoch: 5,
                leader_addr: addr,
                peer_descriptors: alloc::vec![NodeDescriptorV1 {
                    node_id: 1,
                    cluster_addr: addr,
                    failure_domain: FailureDomainVector::ZERO,
                    capabilities: 0,
                    member_class: 0,
                    is_alive: true,
                }],
                cluster_view: Some(ClusterViewV1 {
                    epoch: 5,
                    term: 1,
                    leader_node_id: 2,
                    nodes: alloc::vec![],
                    datasets: alloc::vec![],
                    transitions: alloc::vec![],
                    config_class: 0,
                    sequence: 0,
                    epoch_proof: epoch_proof(5),
                }),
                config_class: 0,
                epoch_proof: epoch_proof(5),
                nonce: 42,
            },
        );
    }

    #[test]
    fn join_request_multiple_mount_reports() {
        let addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(10, 0, 0, 1),
            4200,
        ));
        roundtrip_no_alloc_encode(
            JoinRequestV1::encode,
            JoinRequestV1 {
                node_id: 1,
                cluster_addr: addr,
                failure_domain: FailureDomainVector::ZERO,
                capabilities: 0xFFFF,
                highest_epoch_seen: 100,
                mount_reports: alloc::vec![
                    MountReportV1 {
                        dataset_id: 10,
                        mount_mode: MountMode::ReadWrite,
                        generation: 3,
                    },
                    MountReportV1 {
                        dataset_id: 20,
                        mount_mode: MountMode::ReadOnly,
                        generation: 0,
                    },
                    MountReportV1 {
                        dataset_id: 30,
                        mount_mode: MountMode::ReadWrite,
                        generation: 7,
                    },
                ],
                peer_capabilities: None,
                epoch_proof: epoch_proof(100),
                nonce: 888,
            },
        );
    }

    #[test]
    fn cluster_view_multi_everything() {
        let addr = core::net::SocketAddr::V6(core::net::SocketAddrV6::new(
            core::net::Ipv6Addr::LOCALHOST,
            4200,
            0,
            0,
        ));
        roundtrip_no_alloc_encode(
            ClusterViewV1::encode,
            ClusterViewV1 {
                epoch: 3,
                term: 2,
                leader_node_id: 1,
                nodes: alloc::vec![
                    NodeDescriptorV1 {
                        node_id: 1,
                        cluster_addr: addr,
                        failure_domain: FailureDomainVector::ZERO,
                        capabilities: 0xAAAA,
                        member_class: 0,
                        is_alive: true,
                    },
                    NodeDescriptorV1 {
                        node_id: 2,
                        cluster_addr: addr,
                        failure_domain: FailureDomainVector::new(1, 2, 0, 0, 0, 0),
                        capabilities: 0xBBBB,
                        member_class: 1,
                        is_alive: true,
                    },
                ],
                datasets: alloc::vec![DatasetViewV1 {
                    dataset_id: 100,
                    mount_mode: MountMode::ReadWrite,
                    writer_node_id: Some(1),
                    reader_node_ids: alloc::vec![2],
                    generation: 1,
                },],
                transitions: alloc::vec![
                    MembershipTransitionRecord {
                        transition: MembershipTransition::Join,
                        node_id: 1,
                        epoch: 1,
                        term: 1,
                        reason: 0,
                        timestamp_ms: 1000,
                    },
                    MembershipTransitionRecord {
                        transition: MembershipTransition::Join,
                        node_id: 2,
                        epoch: 2,
                        term: 1,
                        reason: 0,
                        timestamp_ms: 2000,
                    },
                ],
                config_class: 1,
                sequence: 42,
                epoch_proof: epoch_proof(3),
            },
        );
    }

    #[test]
    fn dataset_view_empty_readers() {
        roundtrip_no_alloc_encode(
            DatasetViewV1::encode,
            DatasetViewV1 {
                dataset_id: 42,
                mount_mode: MountMode::ReadOnly,
                writer_node_id: Some(1),
                reader_node_ids: alloc::vec![],
                generation: 0,
            },
        );
    }

    #[test]
    fn dataset_view_none_writer() {
        roundtrip_no_alloc_encode(
            DatasetViewV1::encode,
            DatasetViewV1 {
                dataset_id: 42,
                mount_mode: MountMode::ReadOnly,
                writer_node_id: None,
                reader_node_ids: alloc::vec![1, 2, 3],
                generation: 5,
            },
        );
    }

    #[test]
    fn mount_report_zero_values() {
        roundtrip(MountReportV1 {
            dataset_id: 0,
            mount_mode: MountMode::ReadOnly,
            generation: 0,
        });
    }

    #[test]
    fn mount_report_max_values() {
        roundtrip(MountReportV1 {
            dataset_id: u64::MAX,
            mount_mode: MountMode::ReadWrite,
            generation: u64::MAX,
        });
    }

    #[test]
    fn node_descriptor_dead() {
        let addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(10, 0, 0, 1),
            4200,
        ));
        roundtrip(NodeDescriptorV1 {
            node_id: 99,
            cluster_addr: addr,
            failure_domain: FailureDomainVector::ZERO,
            capabilities: 0,
            member_class: 0,
            is_alive: false,
        });
    }

    #[test]
    fn node_descriptor_max_fields() {
        let addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(255, 255, 255, 255),
            65535,
        ));
        roundtrip(NodeDescriptorV1 {
            node_id: u64::MAX,
            cluster_addr: addr,
            failure_domain: FailureDomainVector::new(
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
            ),
            capabilities: u64::MAX,
            member_class: 255,
            is_alive: true,
        });
    }

    #[test]
    fn transition_record_all_variants_roundtrip() {
        let transitions = [
            MembershipTransition::Join,
            MembershipTransition::Leave,
            MembershipTransition::PromoteLearner,
            MembershipTransition::DemoteVoter,
            MembershipTransition::Quarantine,
            MembershipTransition::ReleaseQuarantine,
            MembershipTransition::UpdateCapabilities,
        ];
        for (i, t) in transitions.iter().enumerate() {
            roundtrip(MembershipTransitionRecord {
                transition: *t,
                node_id: i as u64,
                epoch: (i * 10) as u64,
                term: 1,
                reason: i as u8,
                timestamp_ms: (i * 1000) as u64,
            });
        }
    }

    #[test]
    fn transition_record_checksum_corruption() {
        let mut buf = alloc::vec::Vec::new();
        MembershipTransitionRecord {
            transition: MembershipTransition::Quarantine,
            node_id: 50,
            epoch: 25,
            term: 4,
            reason: 3,
            timestamp_ms: 9_999_999,
        }
        .encode(&mut buf);
        // Flip a byte in the middle of the payload
        let mid = buf.len() / 2;
        buf[mid] ^= 0xFF;
        assert!(MembershipTransitionRecord::decode(&buf).is_err());
    }

    #[test]
    fn socket_addr_ipv4_roundtrip() {
        let addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(127, 0, 0, 1),
            8080,
        ));
        let desc = NodeDescriptorV1 {
            node_id: 1,
            cluster_addr: addr,
            failure_domain: FailureDomainVector::ZERO,
            capabilities: 0,
            member_class: 0,
            is_alive: true,
        };
        let mut buf = alloc::vec::Vec::new();
        desc.encode(&mut buf);
        let decoded = NodeDescriptorV1::decode(&buf).expect("decode failed");
        assert_eq!(decoded.cluster_addr, addr);
    }

    #[test]
    fn socket_addr_ipv6_roundtrip() {
        let addr = core::net::SocketAddr::V6(core::net::SocketAddrV6::new(
            core::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            443,
            0,
            0,
        ));
        let desc = NodeDescriptorV1 {
            node_id: 2,
            cluster_addr: addr,
            failure_domain: FailureDomainVector::ZERO,
            capabilities: 0,
            member_class: 0,
            is_alive: true,
        };
        let mut buf = alloc::vec::Vec::new();
        desc.encode(&mut buf);
        let decoded = NodeDescriptorV1::decode(&buf).expect("decode failed");
        assert_eq!(decoded.cluster_addr, addr);
    }

    #[test]
    fn leader_redirect_ipv6_roundtrip() {
        let addr = core::net::SocketAddr::V6(core::net::SocketAddrV6::new(
            core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            4200,
            0,
            0,
        ));
        roundtrip_no_alloc_encode(
            LeaderRedirectV1::encode,
            LeaderRedirectV1 {
                leader_node_id: 7,
                leader_addr: addr,
                term: 3,
                nonce: 111,
            },
        );
    }

    // ── RosterChangeProposal serde roundtrip ─────────────────────────

    #[test]
    fn roster_change_proposal_serde_roundtrip() {
        let proposal = RosterChangeProposal {
            proposal_id: 42,
            coordinator_id: 1,
            current_epoch: 5,
            added: alloc::vec![4, 5],
            removed: alloc::vec![2],
            created_at_millis: 1000,
        };
        let json = serde_json::to_string(&proposal).unwrap();
        let restored: RosterChangeProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.proposal_id, 42);
        assert_eq!(restored.coordinator_id, 1);
        assert_eq!(restored.current_epoch, 5);
        assert_eq!(restored.added, alloc::vec![4, 5]);
        assert_eq!(restored.removed, alloc::vec![2]);
        assert_eq!(restored.created_at_millis, 1000);
    }

    #[test]
    fn roster_change_proposal_empty_delta() {
        let proposal = RosterChangeProposal {
            proposal_id: 0,
            coordinator_id: 1,
            current_epoch: 0,
            added: alloc::vec![],
            removed: alloc::vec![],
            created_at_millis: 0,
        };
        let json = serde_json::to_string(&proposal).unwrap();
        let restored: RosterChangeProposal = serde_json::from_str(&json).unwrap();
        assert!(restored.added.is_empty());
        assert!(restored.removed.is_empty());
    }

    // ── RosterChangeVote serde roundtrip ─────────────────────────────

    #[test]
    fn roster_change_vote_serde_accept() {
        let vote = RosterChangeVote {
            proposal_id: 42,
            voter_id: 3,
            accepted: true,
            reject_reason: None,
            voted_at_millis: 2000,
        };
        let json = serde_json::to_string(&vote).unwrap();
        let restored: RosterChangeVote = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.proposal_id, 42);
        assert_eq!(restored.voter_id, 3);
        assert!(restored.accepted);
        assert!(restored.reject_reason.is_none());
        assert_eq!(restored.voted_at_millis, 2000);
    }

    #[test]
    fn roster_change_vote_serde_reject_with_reason() {
        let vote = RosterChangeVote {
            proposal_id: 7,
            voter_id: 5,
            accepted: false,
            reject_reason: Some("duplicate join".to_string()),
            voted_at_millis: 3000,
        };
        let json = serde_json::to_string(&vote).unwrap();
        let restored: RosterChangeVote = serde_json::from_str(&json).unwrap();
        assert!(!restored.accepted);
        assert_eq!(restored.reject_reason.unwrap(), "duplicate join");
    }

    // ── RosterChangeVote MembershipCodec roundtrip ──────────────────

    #[test]
    fn roster_change_vote_codec_accept_roundtrip() {
        let vote = RosterChangeVote {
            proposal_id: 42,
            voter_id: 3,
            accepted: true,
            reject_reason: None,
            voted_at_millis: 2000,
        };
        roundtrip(vote);
    }

    #[test]
    fn roster_change_vote_codec_reject_roundtrip() {
        let vote = RosterChangeVote {
            proposal_id: 7,
            voter_id: 5,
            accepted: false,
            reject_reason: Some("duplicate join".to_string()),
            voted_at_millis: 3000,
        };
        roundtrip(vote);
    }

    #[test]
    fn roster_change_vote_codec_empty_reason_roundtrip() {
        let vote = RosterChangeVote {
            proposal_id: 1,
            voter_id: 2,
            accepted: false,
            reject_reason: Some(String::new()),
            voted_at_millis: 0,
        };
        // Empty-string reason normalizes to None on encode.
        let mut buf = alloc::vec::Vec::new();
        vote.encode(&mut buf);
        let decoded = RosterChangeVote::decode(&buf).unwrap();
        assert_eq!(
            decoded.reject_reason, None,
            "empty reason normalizes to None"
        );
        assert_eq!(decoded.proposal_id, 1);
        assert_eq!(decoded.voter_id, 2);
        assert!(!decoded.accepted);
        assert_eq!(decoded.voted_at_millis, 0);
    }

    #[test]
    fn roster_change_vote_codec_long_reason_roundtrip() {
        let long_reason = "a".repeat(1024);
        let vote = RosterChangeVote {
            proposal_id: 99,
            voter_id: 100,
            accepted: false,
            reject_reason: Some(long_reason.clone()),
            voted_at_millis: u64::MAX,
        };
        let mut buf = alloc::vec::Vec::new();
        vote.encode(&mut buf);
        let decoded = RosterChangeVote::decode(&buf).unwrap();
        assert_eq!(decoded.reject_reason.unwrap(), long_reason);
    }

    #[test]
    fn roster_change_vote_codec_max_fields_roundtrip() {
        let vote = RosterChangeVote {
            proposal_id: u64::MAX,
            voter_id: u64::MAX,
            accepted: true,
            reject_reason: None,
            voted_at_millis: u64::MAX,
        };
        roundtrip(vote);
    }

    #[test]
    fn roster_change_vote_codec_checksum_corruption() {
        let vote = RosterChangeVote {
            proposal_id: 42,
            voter_id: 3,
            accepted: true,
            reject_reason: None,
            voted_at_millis: 2000,
        };
        let mut buf = alloc::vec::Vec::new();
        vote.encode(&mut buf);
        let last = buf.len() - 1;
        buf[last] ^= 0xFF;
        assert!(RosterChangeVote::decode(&buf).is_err());
    }

    #[test]
    fn roster_change_vote_codec_underflow() {
        let data = [0u8; 3];
        assert!(RosterChangeVote::decode(&data).is_err());
    }

    #[test]
    fn roster_change_vote_codec_mid_underflow_bad_reason_len() {
        let vote = RosterChangeVote {
            proposal_id: 1,
            voter_id: 2,
            accepted: false,
            reject_reason: Some("x".to_string()),
            voted_at_millis: 0,
        };
        let mut buf = alloc::vec::Vec::new();
        vote.encode(&mut buf);
        // Corrupt reason_len to be impossibly large
        // Layout: proposal_id(8) | voter_id(8) | accepted(1) | reason_len(4) | reason(N) | voted_at_millis(8) | CRC32C(4)
        // Set reason_len bytes (offset 17..21) to a huge value
        buf[17] = 0xFF;
        buf[18] = 0xFF;
        buf[19] = 0xFF;
        buf[20] = 0xFF;
        assert!(RosterChangeVote::decode(&buf).is_err());
    }
}

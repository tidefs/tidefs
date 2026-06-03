use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::EpochId;

/// The operational state of a membership lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseState {
    /// No lease held; ready to begin acquisition.
    Unleased,
    /// Lease acquisition in progress (request sent, awaiting grant).
    Acquiring,
    /// Lease is held and active.
    Held,
    /// Lease is held but renewal is in progress.
    Renewing,
    /// Lease TTL is approaching expiry; waiting for renewal response.
    Expiring,
    /// Lease has been voluntarily released.
    Released,
}

impl LeaseState {
    /// Returns true if the state represents an active (held or renewing) lease.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Held | Self::Renewing)
    }

    /// Returns true if the state is terminal (Unleased or Released).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Unleased | Self::Released)
    }
}

impl Default for DataPathCarrier {
    fn default() -> Self {
        Self::Unknown
    }
}

/// A membership lease binding a node to a cluster slot for a specific epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipLease {
    /// The node holding this lease.
    pub node_id: u64,
    /// The epoch this lease is valid for.
    pub epoch: EpochId,
    /// Lease term duration in milliseconds.
    pub lease_term_ms: u64,
    /// Wall-clock deadline (ms since epoch) when this lease expires.
    pub expiration_deadline_ms: u64,
    /// Slot index within the epoch roster.
    pub slot: u64,
    /// Unique lease identifier.
    pub lease_id: u64,
}

impl MembershipLease {
    /// Create a new lease with the given parameters.
    /// `now_ms` is the current wall-clock time in milliseconds since epoch.
    pub fn new(
        node_id: u64,
        epoch: EpochId,
        lease_term_ms: u64,
        slot: u64,
        lease_id: u64,
        now_ms: u64,
    ) -> Self {
        Self {
            node_id,
            epoch,
            lease_term_ms,
            expiration_deadline_ms: now_ms.saturating_add(lease_term_ms),
            slot,
            lease_id,
        }
    }

    /// Check if this lease is expired at the given `now_ms`.
    pub fn is_expired_at(&self, now_ms: u64) -> bool {
        now_ms >= self.expiration_deadline_ms
    }

    /// Remaining time in milliseconds before expiry.
    pub fn remaining_ms(&self, now_ms: u64) -> u64 {
        self.expiration_deadline_ms.saturating_sub(now_ms)
    }

    /// Renew the lease by extending the expiration deadline.
    pub fn renew(&mut self, now_ms: u64) {
        self.expiration_deadline_ms = now_ms.saturating_add(self.lease_term_ms);
    }
}

/// Errors returned by lease state transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LeaseTransitionError {
    #[error("cannot acquire: already holding a lease")]
    AlreadyHolding,
    #[error("cannot acquire: acquisition already in progress")]
    AlreadyAcquiring,
    #[error("cannot renew: lease is not held")]
    NotHeld,
    #[error("cannot renew: renewal already in progress")]
    AlreadyRenewing,
    #[error("cannot release: lease is not held")]
    NotHeldForRelease,
    #[error("lease has expired")]
    Expired,
    #[error("epoch mismatch: lease epoch {lease_epoch:?} != current epoch {current_epoch:?}")]
    EpochMismatch {
        lease_epoch: EpochId,
        current_epoch: EpochId,
    },
    #[error("node mismatch: expected {expected}, got {got}")]
    NodeMismatch { expected: u64, got: u64 },
    #[error("duplicate lease id: {0}")]
    DuplicateLeaseId(u64),
    #[error("slot already occupied: {0}")]
    SlotOccupied(u64),
}

/// Status query result for the cluster lease runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseStatus {
    pub node_id: u64,
    pub state: LeaseState,
    pub lease: Option<MembershipLease>,
    pub current_epoch: EpochId,
    pub state_digest: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════════════
// DataPathCarrier: carrier disclosure for data-path operations
// ═══════════════════════════════════════════════════════════════════════

/// Transport carrier used for a cluster data-path operation.
///
/// Defined locally to avoid a circular dependency on `tidefs-transport`.
/// Callers at the transport boundary translate between this enum and
/// `tidefs_transport::backend::TransportBackendKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataPathCarrier {
    /// RDMA verbs (SoftRoCE or hardware InfiniBand).
    Rdma,
    /// Plain TCP.
    Tcp,
    /// TCP fallback: RDMA was requested but unavailable.
    TcpFallback,
    /// TLS over TCP.
    Tls,
    /// Loopback within a single node.
    Loopback,
    /// Carrier unknown or not yet set.
    Unknown,
}

impl DataPathCarrier {
    /// Whether this carrier represents actual RDMA usage.
    #[must_use]
    pub fn is_rdma(self) -> bool {
        matches!(self, Self::Rdma)
    }

    /// Whether this is a TCP fallback (RDMA requested, TCP delivered).
    #[must_use]
    pub fn is_fallback(self) -> bool {
        matches!(self, Self::TcpFallback)
    }

    /// Human-readable label for validation and logs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Rdma => "rdma",
            Self::Tcp => "tcp",
            Self::TcpFallback => "tcp-fallback",
            Self::Tls => "tls",
            Self::Loopback => "loopback",
            Self::Unknown => "unknown",
        }
    }

    /// Construct from a transport backend discriminant.
    ///
    /// The discriminant matches `tidefs_transport::backend::TransportBackendKind`
    /// ordering: Tcp=0, Tls=1, Rdma=2. Callers at the transport boundary
    /// pass `TransportBackendKind as u8` here.
    #[must_use]
    pub fn from_transport_discriminant(disc: u8) -> Self {
        match disc {
            2 => Self::Rdma,
            1 => Self::Tls,
            0 => Self::Tcp,
            _ => Self::Unknown,
        }
    }

    /// Convert to the transport backend discriminant.
    ///
    /// Returns the `u8` discriminant matching `TransportBackendKind` ordering.
    /// Returns 0xFF for Unknown to ensure callers handle the Unknown case.
    #[must_use]
    pub fn to_transport_discriminant(self) -> u8 {
        match self {
            Self::Rdma => 2,
            Self::Tls => 1,
            Self::Tcp => 0,
            Self::TcpFallback => 0, // TCP fallback carries TCP data
            Self::Loopback => 0,    // loopback behaves like TCP
            Self::Unknown => 0xFF,
        }
    }
}

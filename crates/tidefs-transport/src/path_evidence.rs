// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport path evidence records for storage-intent consumers.
//!
//! This module exposes measured and configured transport path facts for
//! placement, acknowledgment planning, and preflight simulation without
//! making RDMA a semantic requirement. Transport owns session-local
//! mechanics and evidence; membership/runtime own roster, epoch, and
//! fencing decisions (see `docs/TRANSPORT_CLUSTER_AUTHORITY.md`).
//!
//! ## Evidence model
//!
//! Each [`TransportPathEvidence`] record captures a point-in-time snapshot
//! of a transport path between two identified peers. The record is a
//! transport-local fact: it does not decide membership, fencing,
//! trust-domain eligibility, storage guarantees, or placement by itself.
//!
//! ## Staleness and absence
//!
//! Stale, absent, or contradictory path evidence is explicit. Consumers
//! receive typed [`PathEvidenceStaleness`] markers and must not silently
//! satisfy a low-latency, quorum, or geo-intent receipt from stale data.
//!
//! ## RDMA position
//!
//! RDMA may improve path evidence but missing RDMA must not invalidate
//! TCP-class correctness (see `docs/RDMA_TRANSPORT_POSITION.md`).
//! RDMA-only assumptions are rejected through [`PathCarrierClass`]
//! tagging; TCP fallback remains a legal baseline.
//!
//! ## WAN/internet
//!
//! Internet/WAN paths expose bandwidth clamp, packet loss, jitter,
//! congestion/backpressure window, public/non-dedicated carrier class,
//! and cost/egress refs. Consumers must not mistake WAN paths for local
//! low-latency domains.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, SystemTime};

// ---------------------------------------------------------------------------
// Path evidence identity
// ---------------------------------------------------------------------------

/// Monotonic generation counter for transport path evidence records.
///
/// Incremented on each measurement cycle for a given peer pair so
/// consumers can detect reordering and staleness.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Hash,
)]
pub struct PathEvidenceGeneration(pub u64);

impl PathEvidenceGeneration {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for PathEvidenceGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pevgen:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Proximity domain
// ---------------------------------------------------------------------------

/// Proximity classification for a transport path.
///
/// Encodes the network-distance relationship between two peers without
/// requiring topology authority. Transport reports what it observes;
/// membership/runtime may refine the domain label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathProximityDomain {
    /// Distance unknown or not yet measured.
    Unknown,
    /// Same host, loopback, or co-resident embed (e0).
    Local,
    /// Same rack or top-of-rack switch.
    Rack,
    /// Same data center or campus but different racks.
    DataCenter,
    /// Regional/metro WAN (same cloud region, metro fiber).
    RegionalWan,
    /// Cross-region or long-haul WAN.
    LongHaulWan,
    /// Public internet path (no dedicated carrier).
    Internet,
}

impl PathProximityDomain {
    /// Stable diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Local => "local",
            Self::Rack => "rack",
            Self::DataCenter => "data-center",
            Self::RegionalWan => "regional-wan",
            Self::LongHaulWan => "long-haul-wan",
            Self::Internet => "internet",
        }
    }

    /// True when this domain represents a WAN or internet path that
    /// crosses administrative or geographic boundaries.
    #[must_use]
    pub const fn is_wan(self) -> bool {
        matches!(
            self,
            Self::RegionalWan | Self::LongHaulWan | Self::Internet
        )
    }

    /// True when this domain is a local or same-machine path.
    #[must_use]
    pub const fn is_local(self) -> bool {
        matches!(self, Self::Local)
    }
}

impl Default for PathProximityDomain {
    fn default() -> Self {
        Self::Unknown
    }
}

impl fmt::Display for PathProximityDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Carrier family
// ---------------------------------------------------------------------------

/// Transport carrier family observed or configured for this path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathCarrierFamily {
    /// Carrier not determined.
    Unknown,
    /// Standard TCP transport.
    Tcp,
    /// RDMA-capable transport (RoCE, InfiniBand, iWARP).
    Rdma,
    /// Unix domain socket (co-resident).
    Unix,
    /// Loopback or in-process transport.
    Loopback,
    /// TLS-wrapped TCP transport.
    Tls,
}

impl PathCarrierFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Tcp => "tcp",
            Self::Rdma => "rdma",
            Self::Unix => "unix",
            Self::Loopback => "loopback",
            Self::Tls => "tls",
        }
    }

    /// True when this carrier requires RDMA hardware or software support.
    #[must_use]
    pub const fn is_rdma(self) -> bool {
        matches!(self, Self::Rdma)
    }
}

impl Default for PathCarrierFamily {
    fn default() -> Self {
        Self::Unknown
    }
}

impl fmt::Display for PathCarrierFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Carrier class (public/dedicated)
// ---------------------------------------------------------------------------

/// Carrier ownership class for WAN/internet paths.
///
/// Public internet paths carry different reliability, cost, and
/// trust assumptions than dedicated or private carrier paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathCarrierClass {
    /// Not classified.
    Unknown,
    /// Dedicated private carrier (direct fiber, MPLS, VPN).
    Dedicated,
    /// Shared but managed carrier (cloud backbone, managed WAN).
    SharedManaged,
    /// Public internet (no dedicated circuit).
    PublicInternet,
}

impl PathCarrierClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Dedicated => "dedicated",
            Self::SharedManaged => "shared-managed",
            Self::PublicInternet => "public-internet",
        }
    }

    /// True when this is a public/non-dedicated internet path.
    #[must_use]
    pub const fn is_public_internet(self) -> bool {
        matches!(self, Self::PublicInternet)
    }
}

impl Default for PathCarrierClass {
    fn default() -> Self {
        Self::Unknown
    }
}

impl fmt::Display for PathCarrierClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Latency evidence
// ---------------------------------------------------------------------------

/// Round-trip time measurement for a transport path.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct PathLatency {
    /// Observed or configured round-trip time.
    pub rtt: Duration,
    /// Observed jitter (RTT variation) when available.
    pub jitter: Option<Duration>,
    /// True when this is a configured estimate, not a direct measurement.
    pub is_configured: bool,
}

impl PathLatency {
    /// Create a measured RTT entry.
    #[must_use]
    pub fn measured(rtt: Duration, jitter: Option<Duration>) -> Self {
        Self {
            rtt,
            jitter,
            is_configured: false,
        }
    }

    /// Create a configured/estimated RTT entry.
    #[must_use]
    pub fn configured(rtt: Duration, jitter: Option<Duration>) -> Self {
        Self {
            rtt,
            jitter,
            is_configured: true,
        }
    }
}

impl Default for PathLatency {
    fn default() -> Self {
        Self {
            rtt: Duration::ZERO,
            jitter: None,
            is_configured: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Bandwidth evidence
// ---------------------------------------------------------------------------

/// Bandwidth evidence for a transport path.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct PathBandwidth {
    /// Observed or configured throughput in bytes per second.
    pub bytes_per_second: u64,
    /// True when this is a configured estimate, not a direct measurement.
    pub is_configured: bool,
}

impl PathBandwidth {
    /// Create a measured bandwidth entry.
    #[must_use]
    pub const fn measured(bytes_per_second: u64) -> Self {
        Self {
            bytes_per_second,
            is_configured: false,
        }
    }

    /// Create a configured/estimated bandwidth entry.
    #[must_use]
    pub const fn configured(bytes_per_second: u64) -> Self {
        Self {
            bytes_per_second,
            is_configured: true,
        }
    }
}

impl Default for PathBandwidth {
    fn default() -> Self {
        Self {
            bytes_per_second: 0,
            is_configured: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Loss and error classification
// ---------------------------------------------------------------------------

/// Packet loss or error class for a transport path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathLossClass {
    /// Loss class not yet determined.
    Unknown,
    /// No detectable loss (clean path).
    None,
    /// Occasional loss below configured threshold (< 0.1%).
    Low,
    /// Moderate loss (0.1% – 1%).
    Moderate,
    /// High loss (> 1%).
    High,
    /// Path is currently unusable due to excessive loss.
    Unusable,
}

impl PathLossClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::None => "none",
            Self::Low => "low",
            Self::Moderate => "moderate",
            Self::High => "high",
            Self::Unusable => "unusable",
        }
    }

    /// True when loss renders the path unsuitable for durability-critical traffic.
    #[must_use]
    pub const fn is_degraded(self) -> bool {
        matches!(self, Self::High | Self::Unusable)
    }
}

impl Default for PathLossClass {
    fn default() -> Self {
        Self::Unknown
    }
}

impl fmt::Display for PathLossClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Queue and backpressure state
// ---------------------------------------------------------------------------

/// Queue depth and backpressure snapshot for a transport path.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct PathQueueState {
    /// Current send-queue depth in messages or bytes.
    pub current_depth: u64,
    /// Configured high-watermark for this path.
    pub high_watermark: u64,
    /// True when the path is under backpressure (depth >= threshold).
    pub under_pressure: bool,
    /// Approximate congestion window in bytes when available.
    pub congestion_window_bytes: Option<u64>,
}

impl PathQueueState {
    /// Create a queue-state snapshot.
    #[must_use]
    pub const fn new(
        current_depth: u64,
        high_watermark: u64,
        under_pressure: bool,
        congestion_window_bytes: Option<u64>,
    ) -> Self {
        Self {
            current_depth,
            high_watermark,
            under_pressure,
            congestion_window_bytes,
        }
    }

    /// Queue state is absent / not available.
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            current_depth: 0,
            high_watermark: 0,
            under_pressure: false,
            congestion_window_bytes: None,
        }
    }
}

impl Default for PathQueueState {
    fn default() -> Self {
        Self::absent()
    }
}

// ---------------------------------------------------------------------------
// Staleness and confidence
// ---------------------------------------------------------------------------

/// Evidence confidence tier for transport path measurements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathEvidenceConfidence {
    /// No measurement exists; evidence is absent.
    Absent,
    /// Configured/default estimate with no runtime measurement.
    Configured,
    /// Measurement exists but is older than the freshness window.
    Stale,
    /// Fresh runtime measurement within the configured freshness window.
    Fresh,
    /// Contradictory measurements exist (e.g., two probes disagree).
    Contradictory,
}

impl PathEvidenceConfidence {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Configured => "configured",
            Self::Stale => "stale",
            Self::Fresh => "fresh",
            Self::Contradictory => "contradictory",
        }
    }

    /// True when evidence is usable for low-latency or quorum decisions.
    #[must_use]
    pub const fn is_fresh(self) -> bool {
        matches!(self, Self::Fresh)
    }

    /// True when evidence is absent, stale, or contradictory — planners
    /// must fall back to conservative defaults or refuse.
    #[must_use]
    pub const fn is_unsafe_for_planning(self) -> bool {
        matches!(self, Self::Absent | Self::Stale | Self::Contradictory)
    }
}

impl Default for PathEvidenceConfidence {
    fn default() -> Self {
        Self::Absent
    }
}

impl fmt::Display for PathEvidenceConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Staleness detail
// ---------------------------------------------------------------------------

/// Detailed staleness information for path evidence consumers.
///
/// Attached to every [`TransportPathEvidence`] record so planners and
/// validation rows can detect stale, absent, or contradictory evidence
/// without guessing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PathEvidenceStaleness {
    /// Overall confidence tier for this evidence record.
    pub confidence: PathEvidenceConfidence,
    /// Wall-clock time when the underlying measurement was taken.
    pub measured_at: Option<SystemTime>,
    /// Maximum age beyond which evidence is considered stale.
    pub freshness_window: Option<Duration>,
    /// True when multiple measurements disagree (contradictory state).
    pub contradictory: bool,
    /// Human-readable reason when confidence is not Fresh.
    pub reason: Option<String>,
}

impl PathEvidenceStaleness {
    /// Create a fresh staleness marker.
    #[must_use]
    pub fn fresh(measured_at: SystemTime, freshness_window: Duration) -> Self {
        Self {
            confidence: PathEvidenceConfidence::Fresh,
            measured_at: Some(measured_at),
            freshness_window: Some(freshness_window),
            contradictory: false,
            reason: None,
        }
    }

    /// Create a stale marker from an old measurement.
    #[must_use]
    pub fn stale(
        measured_at: SystemTime,
        freshness_window: Duration,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            confidence: PathEvidenceConfidence::Stale,
            measured_at: Some(measured_at),
            freshness_window: Some(freshness_window),
            contradictory: false,
            reason: Some(reason.into()),
        }
    }

    /// Create an absent marker (no measurement exists).
    #[must_use]
    pub fn absent(reason: impl Into<String>) -> Self {
        Self {
            confidence: PathEvidenceConfidence::Absent,
            measured_at: None,
            freshness_window: None,
            contradictory: false,
            reason: Some(reason.into()),
        }
    }

    /// Create a configured/default marker.
    #[must_use]
    pub fn configured(reason: impl Into<String>) -> Self {
        Self {
            confidence: PathEvidenceConfidence::Configured,
            measured_at: None,
            freshness_window: None,
            contradictory: false,
            reason: Some(reason.into()),
        }
    }

    /// Create a contradictory marker (diverging measurements).
    #[must_use]
    pub fn contradictory(reason: impl Into<String>) -> Self {
        Self {
            confidence: PathEvidenceConfidence::Contradictory,
            measured_at: None,
            freshness_window: None,
            contradictory: true,
            reason: Some(reason.into()),
        }
    }
}

impl Default for PathEvidenceStaleness {
    fn default() -> Self {
        Self {
            confidence: PathEvidenceConfidence::Absent,
            measured_at: None,
            freshness_window: None,
            contradictory: false,
            reason: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Encryption / auth context
// ---------------------------------------------------------------------------

/// Encryption and authentication context for a transport path.
///
/// Transport exposes this context for storage-intent consumers that
/// need to know whether a path is encrypted or mutually authenticated.
/// Trust/domain eligibility decisions remain with #897.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathEncryptionContext {
    /// True when the transport session is encrypted (TLS or equivalent).
    pub encrypted: bool,
    /// True when mutual authentication (mTLS) completed successfully.
    pub mutually_authenticated: bool,
    /// Cipher suite label when available (e.g., "TLS_CHACHA20_POLY1305_SHA256").
    pub cipher_suite: Option<String>,
    /// Session security evidence reference when available (opaque ref for #897).
    pub session_security_evidence_ref: Option<String>,
}

impl PathEncryptionContext {
    /// Create an absent/unavailable encryption context.
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            encrypted: false,
            mutually_authenticated: false,
            cipher_suite: None,
            session_security_evidence_ref: None,
        }
    }

    /// Create a present encryption context.
    #[must_use]
    pub fn encrypted_session(
        cipher_suite: impl Into<String>,
        mutually_authenticated: bool,
        security_evidence_ref: Option<String>,
    ) -> Self {
        Self {
            encrypted: true,
            mutually_authenticated,
            cipher_suite: Some(cipher_suite.into()),
            session_security_evidence_ref: security_evidence_ref,
        }
    }

    /// True when the path has active encryption.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// True when the path has mutual authentication.
    #[must_use]
    pub const fn is_mutually_authenticated(&self) -> bool {
        self.mutually_authenticated
    }
}

impl Default for PathEncryptionContext {
    fn default() -> Self {
        Self::absent()
    }
}

// ---------------------------------------------------------------------------
// Peer / failure-domain relation
// ---------------------------------------------------------------------------

/// Failure-domain relation between two peers as supplied by membership
/// or runtime authority.
///
/// Transport carries this as an opaque ref slot; membership/runtime own
/// the roster, epoch, and fencing decisions. Transport must not originate
/// a failure-domain classification by itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathFailureDomainRelation {
    /// Opaque failure-domain identifier (e.g., rack, PDUs, switch).
    pub failure_domain_id: Option<String>,
    /// True when peers share a failure domain (same rack, same power).
    pub shared_failure_domain: Option<bool>,
    /// Membership epoch at which this relation was published.
    pub membership_epoch: Option<u64>,
    /// Membership evidence reference for epoch/roster authority.
    pub membership_evidence_ref: Option<String>,
}

impl PathFailureDomainRelation {
    /// Create an absent failure-domain relation (not yet supplied).
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            failure_domain_id: None,
            shared_failure_domain: None,
            membership_epoch: None,
            membership_evidence_ref: None,
        }
    }
}

impl Default for PathFailureDomainRelation {
    fn default() -> Self {
        Self::absent()
    }
}

// ---------------------------------------------------------------------------
// WAN / internet evidence
// ---------------------------------------------------------------------------

/// WAN- and internet-specific transport path evidence.
///
/// Provides bandwidth clamp, packet loss, jitter, congestion/backpressure
/// window, carrier class, and cost/egress references for paths that cross
/// administrative or geographic boundaries. Local paths omit this record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WanInternetEvidence {
    /// Observed packet loss fraction (0.0 – 1.0).
    pub packet_loss: Option<f64>,
    /// Observed jitter (RTT variation).
    pub observed_jitter: Option<Duration>,
    /// Effective bandwidth clamp in bytes per second (configured cap).
    pub bandwidth_clamp_bytes_per_second: Option<u64>,
    /// Current congestion window in bytes when available (TCP cwnd or
    /// equivalent transport-level backpressure window).
    pub congestion_window_bytes: Option<u64>,
    /// Current backpressure state (true when send is throttled).
    pub backpressure_active: bool,
    /// Public or dedicated carrier classification.
    pub carrier_class: PathCarrierClass,
    /// Opaque cost/egress reference from the cost ledger when available.
    /// #856 owns ledger semantics; this is an opaque snapshot ref.
    pub cost_egress_ref: Option<String>,
}

impl WanInternetEvidence {
    /// Create an absent WAN evidence record (non-WAN path).
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            packet_loss: None,
            observed_jitter: None,
            bandwidth_clamp_bytes_per_second: None,
            congestion_window_bytes: None,
            backpressure_active: false,
            carrier_class: PathCarrierClass::Unknown,
            cost_egress_ref: None,
        }
    }

    /// True when this WAN path uses public internet (non-dedicated).
    #[must_use]
    pub const fn is_public_internet(&self) -> bool {
        self.carrier_class.is_public_internet()
    }
}

impl Default for WanInternetEvidence {
    fn default() -> Self {
        Self::absent()
    }
}

// ---------------------------------------------------------------------------
// Transport path evidence — the main record
// ---------------------------------------------------------------------------

/// A point-in-time snapshot of transport path evidence between two peers.
///
/// This record captures measured and configured transport path facts for
/// storage-intent consumers. It is a transport-local fact record only;
/// it does not decide membership, fencing, trust-domain eligibility,
/// storage guarantees, or placement by itself.
///
/// ## Fields
///
/// | Field | Meaning |
/// |---|---|
/// | `generation` | Monotonic counter for staleness detection |
/// | `local_peer` | Local node identity (opaque ref) |
/// | `remote_peer` | Remote node identity (opaque ref) |
/// | `proximity_domain` | Local/rack/DC/WAN/internet classification |
/// | `latency` | Observed or configured RTT and jitter |
/// | `bandwidth` | Observed or configured throughput |
/// | `loss_class` | Packet loss severity class |
/// | `queue_state` | Send-queue depth and backpressure snapshot |
/// | `carrier_family` | TCP/RDMA/Unix/Loopback/TLS carrier |
/// | `staleness` | Measurement age, confidence, and contradiction marker |
/// | `encryption_context` | Encryption and auth context when available |
/// | `failure_domain` | Peer failure-domain relation from membership |
/// | `wan_evidence` | WAN/internet-specific evidence when applicable |
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransportPathEvidence {
    /// Monotonic evidence generation counter.
    pub generation: PathEvidenceGeneration,
    /// Local node identity (opaque string ref).
    pub local_peer: String,
    /// Remote node identity (opaque string ref).
    pub remote_peer: String,
    /// Proximity domain classification.
    pub proximity_domain: PathProximityDomain,
    /// Round-trip time and jitter evidence.
    pub latency: PathLatency,
    /// Bandwidth evidence.
    pub bandwidth: PathBandwidth,
    /// Packet loss or error classification.
    pub loss_class: PathLossClass,
    /// Queue depth and backpressure snapshot.
    pub queue_state: PathQueueState,
    /// Transport carrier family.
    pub carrier_family: PathCarrierFamily,
    /// Measurement age, confidence, and staleness.
    pub staleness: PathEvidenceStaleness,
    /// Encryption and authentication context.
    pub encryption_context: PathEncryptionContext,
    /// Peer failure-domain relation from membership authority.
    pub failure_domain: PathFailureDomainRelation,
    /// WAN/internet-specific evidence (absent for local paths).
    pub wan_evidence: WanInternetEvidence,
}

impl TransportPathEvidence {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a fresh, measured evidence record between two peers.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn fresh_measured(
        generation: PathEvidenceGeneration,
        local_peer: impl Into<String>,
        remote_peer: impl Into<String>,
        proximity_domain: PathProximityDomain,
        latency: PathLatency,
        bandwidth: PathBandwidth,
        loss_class: PathLossClass,
        queue_state: PathQueueState,
        carrier_family: PathCarrierFamily,
        measured_at: SystemTime,
        freshness_window: Duration,
    ) -> Self {
        Self {
            generation,
            local_peer: local_peer.into(),
            remote_peer: remote_peer.into(),
            proximity_domain,
            latency,
            bandwidth,
            loss_class,
            queue_state,
            carrier_family,
            staleness: PathEvidenceStaleness::fresh(measured_at, freshness_window),
            encryption_context: PathEncryptionContext::absent(),
            failure_domain: PathFailureDomainRelation::absent(),
            wan_evidence: WanInternetEvidence::absent(),
        }
    }

    /// Create an absent evidence record (no measurement exists for this peer pair).
    #[must_use]
    pub fn absent(
        generation: PathEvidenceGeneration,
        local_peer: impl Into<String>,
        remote_peer: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            generation,
            local_peer: local_peer.into(),
            remote_peer: remote_peer.into(),
            proximity_domain: PathProximityDomain::Unknown,
            latency: PathLatency::default(),
            bandwidth: PathBandwidth::default(),
            loss_class: PathLossClass::Unknown,
            queue_state: PathQueueState::absent(),
            carrier_family: PathCarrierFamily::Unknown,
            staleness: PathEvidenceStaleness::absent(reason),
            encryption_context: PathEncryptionContext::absent(),
            failure_domain: PathFailureDomainRelation::absent(),
            wan_evidence: WanInternetEvidence::absent(),
        }
    }

    /// Create a configured/estimated evidence record with no runtime measurement.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn configured(
        generation: PathEvidenceGeneration,
        local_peer: impl Into<String>,
        remote_peer: impl Into<String>,
        proximity_domain: PathProximityDomain,
        latency: PathLatency,
        bandwidth: PathBandwidth,
        carrier_family: PathCarrierFamily,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            generation,
            local_peer: local_peer.into(),
            remote_peer: remote_peer.into(),
            proximity_domain,
            latency,
            bandwidth,
            loss_class: PathLossClass::Unknown,
            queue_state: PathQueueState::absent(),
            carrier_family,
            staleness: PathEvidenceStaleness::configured(reason),
            encryption_context: PathEncryptionContext::absent(),
            failure_domain: PathFailureDomainRelation::absent(),
            wan_evidence: WanInternetEvidence::absent(),
        }
    }

    // -----------------------------------------------------------------------
    // Builder-style setters for optional evidence
    // -----------------------------------------------------------------------

    /// Attach encryption/auth context.
    #[must_use]
    pub fn with_encryption_context(mut self, ctx: PathEncryptionContext) -> Self {
        self.encryption_context = ctx;
        self
    }

    /// Attach failure-domain relation from membership authority.
    #[must_use]
    pub fn with_failure_domain(mut self, domain: PathFailureDomainRelation) -> Self {
        self.failure_domain = domain;
        self
    }

    /// Attach WAN/internet evidence.
    #[must_use]
    pub fn with_wan_evidence(mut self, wan: WanInternetEvidence) -> Self {
        self.wan_evidence = wan;
        self
    }

    /// Attach queue state evidence.
    #[must_use]
    pub fn with_queue_state(mut self, qs: PathQueueState) -> Self {
        self.queue_state = qs;
        self
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// True when evidence is fresh enough for latency-sensitive planning.
    #[must_use]
    pub const fn is_fresh(&self) -> bool {
        self.staleness.confidence.is_fresh()
    }

    /// True when evidence is absent, stale, or contradictory — cannot
    /// be used for low-latency, quorum, or geo-intent decisions.
    #[must_use]
    pub const fn is_unsafe_for_planning(&self) -> bool {
        self.staleness.confidence.is_unsafe_for_planning()
    }

    /// True when the carrier is RDMA.
    #[must_use]
    pub const fn is_rdma(&self) -> bool {
        self.carrier_family.is_rdma()
    }

    /// True when the proximity domain is same-host/local.
    #[must_use]
    pub const fn is_local(&self) -> bool {
        self.proximity_domain.is_local()
    }

    /// True when the path crosses a WAN or internet boundary.
    #[must_use]
    pub const fn is_wan(&self) -> bool {
        self.proximity_domain.is_wan()
    }

    /// True when this is a public internet path (non-dedicated carrier).
    #[must_use]
    pub const fn is_public_internet(&self) -> bool {
        self.wan_evidence.is_public_internet()
    }

    /// True when the session is encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.encryption_context.is_encrypted()
    }

    /// True when the session is mutually authenticated.
    #[must_use]
    pub const fn is_mutually_authenticated(&self) -> bool {
        self.encryption_context.is_mutually_authenticated()
    }
}

impl Default for TransportPathEvidence {
    fn default() -> Self {
        Self::absent(
            PathEvidenceGeneration::new(0),
            "",
            "",
            "default",
        )
    }
}

// ---------------------------------------------------------------------------
// Evidence registry (collection of per-peer path evidence)
// ---------------------------------------------------------------------------

/// A registry of transport path evidence records keyed by remote peer identity.
///
/// Consumers query this registry for path evidence when making placement,
/// acknowledgment, or preflight decisions. Absent peers return explicit
/// absent records rather than `None`, so planners never mistake a missing
/// entry for a fresh low-latency path.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransportPathEvidenceRegistry {
    entries: Vec<(String, TransportPathEvidence)>,
}

impl TransportPathEvidenceRegistry {
    /// Create an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert or replace a path evidence record.
    pub fn upsert(&mut self, evidence: TransportPathEvidence) {
        let key = evidence.remote_peer.clone();
        if let Some(pos) = self.entries.iter().position(|(k, _)| *k == key) {
            self.entries[pos] = (key, evidence);
        } else {
            self.entries.push((key, evidence));
        }
    }

    /// Look up path evidence for a remote peer.
    ///
    /// Returns the stored evidence or constructs an absent record when no
    /// entry exists. Callers never receive `None` and must handle absent
    /// evidence explicitly.
    #[must_use]
    pub fn get(&self, remote_peer: &str) -> TransportPathEvidence {
        self.entries
            .iter()
            .find(|(k, _)| k == remote_peer)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| {
                TransportPathEvidence::absent(
                    PathEvidenceGeneration::new(0),
                    "",
                    remote_peer,
                    "no path evidence registered",
                )
            })
    }

    /// Remove evidence for a departed peer.
    pub fn remove(&mut self, remote_peer: &str) {
        self.entries.retain(|(k, _)| k != remote_peer);
    }

    /// Number of entries in the registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all evidence records.
    pub fn iter(&self) -> impl Iterator<Item = &TransportPathEvidence> {
        self.entries.iter().map(|(_, v)| v)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    // -----------------------------------------------------------------------
    // Proximity domain
    // -----------------------------------------------------------------------

    #[test]
    fn proximity_domain_wan_detection() {
        assert!(!PathProximityDomain::Local.is_wan());
        assert!(!PathProximityDomain::Rack.is_wan());
        assert!(!PathProximityDomain::DataCenter.is_wan());
        assert!(PathProximityDomain::RegionalWan.is_wan());
        assert!(PathProximityDomain::LongHaulWan.is_wan());
        assert!(PathProximityDomain::Internet.is_wan());
    }

    #[test]
    fn proximity_domain_local_detection() {
        assert!(PathProximityDomain::Local.is_local());
        assert!(!PathProximityDomain::Rack.is_local());
        assert!(!PathProximityDomain::Internet.is_local());
    }

    #[test]
    fn proximity_domain_default_is_unknown() {
        assert_eq!(PathProximityDomain::default(), PathProximityDomain::Unknown);
    }

    // -----------------------------------------------------------------------
    // Carrier family
    // -----------------------------------------------------------------------

    #[test]
    fn carrier_family_rdma_detection() {
        assert!(PathCarrierFamily::Rdma.is_rdma());
        assert!(!PathCarrierFamily::Tcp.is_rdma());
        assert!(!PathCarrierFamily::Unix.is_rdma());
        assert!(!PathCarrierFamily::Loopback.is_rdma());
        assert!(!PathCarrierFamily::Tls.is_rdma());
    }

    #[test]
    fn carrier_family_default_is_unknown() {
        assert_eq!(PathCarrierFamily::default(), PathCarrierFamily::Unknown);
    }

    // -----------------------------------------------------------------------
    // Carrier class
    // -----------------------------------------------------------------------

    #[test]
    fn carrier_class_public_internet_detection() {
        assert!(PathCarrierClass::PublicInternet.is_public_internet());
        assert!(!PathCarrierClass::Dedicated.is_public_internet());
        assert!(!PathCarrierClass::SharedManaged.is_public_internet());
    }

    // -----------------------------------------------------------------------
    // Loss class
    // -----------------------------------------------------------------------

    #[test]
    fn loss_class_degraded_detection() {
        assert!(!PathLossClass::None.is_degraded());
        assert!(!PathLossClass::Low.is_degraded());
        assert!(!PathLossClass::Moderate.is_degraded());
        assert!(PathLossClass::High.is_degraded());
        assert!(PathLossClass::Unusable.is_degraded());
    }

    // -----------------------------------------------------------------------
    // Evidence confidence
    // -----------------------------------------------------------------------

    #[test]
    fn confidence_fresh_is_usable() {
        assert!(PathEvidenceConfidence::Fresh.is_fresh());
        assert!(!PathEvidenceConfidence::Stale.is_fresh());
        assert!(!PathEvidenceConfidence::Absent.is_fresh());
    }

    #[test]
    fn confidence_unsafe_for_planning() {
        assert!(PathEvidenceConfidence::Absent.is_unsafe_for_planning());
        assert!(PathEvidenceConfidence::Stale.is_unsafe_for_planning());
        assert!(PathEvidenceConfidence::Contradictory.is_unsafe_for_planning());
        assert!(!PathEvidenceConfidence::Fresh.is_unsafe_for_planning());
        assert!(!PathEvidenceConfidence::Configured.is_unsafe_for_planning());
    }

    // -----------------------------------------------------------------------
    // Staleness markers
    // -----------------------------------------------------------------------

    #[test]
    fn staleness_fresh() {
        let now = SystemTime::now();
        let window = Duration::from_secs(60);
        let s = PathEvidenceStaleness::fresh(now, window);
        assert_eq!(s.confidence, PathEvidenceConfidence::Fresh);
        assert_eq!(s.measured_at, Some(now));
        assert_eq!(s.freshness_window, Some(window));
        assert!(!s.contradictory);
    }

    #[test]
    fn staleness_stale() {
        let now = SystemTime::now();
        let window = Duration::from_secs(60);
        let s = PathEvidenceStaleness::stale(now, window, "measurement aged out");
        assert_eq!(s.confidence, PathEvidenceConfidence::Stale);
        assert_eq!(s.reason.as_deref(), Some("measurement aged out"));
    }

    #[test]
    fn staleness_absent() {
        let s = PathEvidenceStaleness::absent("no probe completed");
        assert_eq!(s.confidence, PathEvidenceConfidence::Absent);
        assert!(s.measured_at.is_none());
    }

    #[test]
    fn staleness_contradictory() {
        let s = PathEvidenceStaleness::contradictory("RTT probes diverge");
        assert_eq!(s.confidence, PathEvidenceConfidence::Contradictory);
        assert!(s.contradictory);
    }

    #[test]
    fn staleness_configured() {
        let s = PathEvidenceStaleness::configured("operator estimate");
        assert_eq!(s.confidence, PathEvidenceConfidence::Configured);
    }

    // -----------------------------------------------------------------------
    // Encryption context
    // -----------------------------------------------------------------------

    #[test]
    fn encryption_context_absent() {
        let ctx = PathEncryptionContext::absent();
        assert!(!ctx.is_encrypted());
        assert!(!ctx.is_mutually_authenticated());
        assert!(ctx.cipher_suite.is_none());
        assert!(ctx.session_security_evidence_ref.is_none());
    }

    #[test]
    fn encryption_context_present() {
        let ctx = PathEncryptionContext::encrypted_session(
            "TLS_CHACHA20_POLY1305_SHA256",
            true,
            Some("sec-evidence-ref:0xdead".into()),
        );
        assert!(ctx.is_encrypted());
        assert!(ctx.is_mutually_authenticated());
        assert_eq!(
            ctx.cipher_suite.as_deref(),
            Some("TLS_CHACHA20_POLY1305_SHA256")
        );
        assert_eq!(
            ctx.session_security_evidence_ref.as_deref(),
            Some("sec-evidence-ref:0xdead")
        );
    }

    // -----------------------------------------------------------------------
    // TransportPathEvidence — construction and queries
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_fresh_measured() {
        let now = SystemTime::now();
        let window = Duration::from_secs(30);
        let evidence = TransportPathEvidence::fresh_measured(
            PathEvidenceGeneration::new(1),
            "node-a",
            "node-b",
            PathProximityDomain::Rack,
            PathLatency::measured(Duration::from_micros(50), None),
            PathBandwidth::measured(10_000_000_000),
            PathLossClass::None,
            PathQueueState::absent(),
            PathCarrierFamily::Tcp,
            now,
            window,
        );

        assert!(evidence.is_fresh());
        assert!(!evidence.is_unsafe_for_planning());
        assert!(!evidence.is_rdma());
        assert!(!evidence.is_wan());
        assert!(!evidence.is_public_internet());
        assert!(!evidence.is_encrypted());
    }

    #[test]
    fn evidence_absent_explicit() {
        let evidence = TransportPathEvidence::absent(
            PathEvidenceGeneration::new(0),
            "node-a",
            "node-b",
            "no probe yet",
        );

        assert!(!evidence.is_fresh());
        assert!(evidence.is_unsafe_for_planning());
        assert_eq!(evidence.proximity_domain, PathProximityDomain::Unknown);
    }

    #[test]
    fn evidence_with_rdma_carrier() {
        let now = SystemTime::now();
        let window = Duration::from_secs(30);
        let evidence = TransportPathEvidence::fresh_measured(
            PathEvidenceGeneration::new(2),
            "node-a",
            "node-c",
            PathProximityDomain::Rack,
            PathLatency::measured(Duration::from_micros(10), None),
            PathBandwidth::measured(100_000_000_000),
            PathLossClass::None,
            PathQueueState::absent(),
            PathCarrierFamily::Rdma,
            now,
            window,
        );
        assert!(evidence.is_rdma());
    }

    #[test]
    fn evidence_tcp_fallback_is_legal() {
        // Issue #846 acceptance: TCP fallback remains legal baseline.
        let now = SystemTime::now();
        let window = Duration::from_secs(30);
        let evidence = TransportPathEvidence::fresh_measured(
            PathEvidenceGeneration::new(3),
            "node-a",
            "node-d",
            PathProximityDomain::Rack,
            PathLatency::measured(Duration::from_micros(200), None),
            PathBandwidth::measured(1_000_000_000),
            PathLossClass::None,
            PathQueueState::absent(),
            PathCarrierFamily::Tcp,
            now,
            window,
        );
        assert!(!evidence.is_rdma());
        assert!(evidence.is_fresh());
        // RDMA absent — this is correct, not a failure.
        assert!(!evidence.is_unsafe_for_planning());
    }

    #[test]
    fn evidence_wan_internet_path_not_local() {
        let now = SystemTime::now();
        let window = Duration::from_secs(60);
        let evidence = TransportPathEvidence::fresh_measured(
            PathEvidenceGeneration::new(4),
            "node-a",
            "node-e",
            PathProximityDomain::Internet,
            PathLatency::measured(Duration::from_millis(50), Some(Duration::from_millis(10))),
            PathBandwidth::measured(100_000_000),
            PathLossClass::Moderate,
            PathQueueState::new(500, 1000, true, Some(65536)),
            PathCarrierFamily::Tcp,
            now,
            window,
        )
        .with_wan_evidence(WanInternetEvidence {
            packet_loss: Some(0.02),
            observed_jitter: Some(Duration::from_millis(10)),
            bandwidth_clamp_bytes_per_second: Some(50_000_000),
            congestion_window_bytes: Some(65536),
            backpressure_active: true,
            carrier_class: PathCarrierClass::PublicInternet,
            cost_egress_ref: Some("cost-ledger:egress:ref-1".into()),
        });

        assert!(evidence.is_wan());
        assert!(evidence.is_public_internet());
        assert!(!evidence.is_local());
        assert!(!evidence.is_rdma());
    }

    #[test]
    fn evidence_stale_must_not_silently_satisfy_low_latency() {
        let now = SystemTime::now();
        let window = Duration::from_secs(30);
        let mut evidence = TransportPathEvidence::fresh_measured(
            PathEvidenceGeneration::new(5),
            "node-a",
            "node-f",
            PathProximityDomain::DataCenter,
            PathLatency::measured(Duration::from_micros(100), None),
            PathBandwidth::measured(5_000_000_000),
            PathLossClass::Low,
            PathQueueState::absent(),
            PathCarrierFamily::Tcp,
            now,
            window,
        );

        // Artificially age the staleness to simulate stale evidence.
        evidence.staleness = PathEvidenceStaleness::stale(
            now - Duration::from_secs(120),
            window,
            "last probe 120s ago",
        );

        assert!(!evidence.is_fresh());
        // Stale evidence cannot silently satisfy low-latency, quorum,
        // or geo-intent planning.
        assert!(evidence.is_unsafe_for_planning());
        assert_eq!(
            evidence.staleness.confidence,
            PathEvidenceConfidence::Stale
        );
    }

    #[test]
    fn evidence_contradictory_explicit() {
        let now = SystemTime::now();
        let window = Duration::from_secs(30);
        let mut evidence = TransportPathEvidence::fresh_measured(
            PathEvidenceGeneration::new(6),
            "node-a",
            "node-g",
            PathProximityDomain::Rack,
            PathLatency::measured(Duration::from_micros(100), None),
            PathBandwidth::measured(10_000_000_000),
            PathLossClass::None,
            PathQueueState::absent(),
            PathCarrierFamily::Tcp,
            now,
            window,
        );

        evidence.staleness = PathEvidenceStaleness::contradictory("RTT probes diverge: 50us vs 500us");
        assert!(evidence.is_unsafe_for_planning());
    }

    // -----------------------------------------------------------------------
    // TransportPathEvidenceRegistry
    // -----------------------------------------------------------------------

    #[test]
    fn registry_absent_peer_returns_explicit_absent() {
        let registry = TransportPathEvidenceRegistry::new();
        let evidence = registry.get("unknown-peer");
        assert!(!evidence.is_fresh());
        assert!(evidence.is_unsafe_for_planning());
        assert_eq!(
            evidence.staleness.confidence,
            PathEvidenceConfidence::Absent
        );
    }

    #[test]
    fn registry_upsert_and_lookup() {
        let mut registry = TransportPathEvidenceRegistry::new();
        let now = SystemTime::now();
        let window = Duration::from_secs(30);
        let e1 = TransportPathEvidence::fresh_measured(
            PathEvidenceGeneration::new(1),
            "node-a",
            "node-b",
            PathProximityDomain::Rack,
            PathLatency::measured(Duration::from_micros(50), None),
            PathBandwidth::measured(10_000_000_000),
            PathLossClass::None,
            PathQueueState::absent(),
            PathCarrierFamily::Tcp,
            now,
            window,
        );

        registry.upsert(e1);
        assert_eq!(registry.len(), 1);

        let looked_up = registry.get("node-b");
        assert!(looked_up.is_fresh());
        assert_eq!(looked_up.proximity_domain, PathProximityDomain::Rack);

        // Unknown peer still returns explicit absent.
        let absent = registry.get("node-z");
        assert!(absent.is_unsafe_for_planning());
    }

    #[test]
    fn registry_remove() {
        let mut registry = TransportPathEvidenceRegistry::new();
        let now = SystemTime::now();
        let window = Duration::from_secs(30);
        registry.upsert(TransportPathEvidence::fresh_measured(
            PathEvidenceGeneration::new(1),
            "node-a",
            "node-b",
            PathProximityDomain::Rack,
            PathLatency::measured(Duration::from_micros(50), None),
            PathBandwidth::measured(10_000_000_000),
            PathLossClass::None,
            PathQueueState::absent(),
            PathCarrierFamily::Tcp,
            now,
            window,
        ));

        assert_eq!(registry.len(), 1);
        registry.remove("node-b");
        assert_eq!(registry.len(), 0);

        let evidence = registry.get("node-b");
        assert!(!evidence.is_fresh());
    }

    #[test]
    fn registry_iter() {
        let mut registry = TransportPathEvidenceRegistry::new();
        let now = SystemTime::now();
        let window = Duration::from_secs(30);

        registry.upsert(TransportPathEvidence::fresh_measured(
            PathEvidenceGeneration::new(1),
            "node-a",
            "node-b",
            PathProximityDomain::Rack,
            PathLatency::measured(Duration::from_micros(50), None),
            PathBandwidth::measured(10_000_000_000),
            PathLossClass::None,
            PathQueueState::absent(),
            PathCarrierFamily::Tcp,
            now,
            window,
        ));

        registry.upsert(TransportPathEvidence::fresh_measured(
            PathEvidenceGeneration::new(2),
            "node-a",
            "node-c",
            PathProximityDomain::DataCenter,
            PathLatency::measured(Duration::from_micros(200), None),
            PathBandwidth::measured(5_000_000_000),
            PathLossClass::Low,
            PathQueueState::absent(),
            PathCarrierFamily::Tcp,
            now,
            window,
        ));

        let collected: Vec<_> = registry.iter().collect();
        assert_eq!(collected.len(), 2);
    }
}

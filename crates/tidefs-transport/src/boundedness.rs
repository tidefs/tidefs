/// Transport boundedness: per-connection limits, per-tick delivery budgets,
/// and frame-level accounting per CLUSTER_TRANSPORT_BOUNDNESS_DESIGN (#1210).
///
/// This module provides compile-time constants and runtime validators that
/// ensure the TideFS transport layer is provably bounded in memory, CPU, and
/// fairness.
use std::time::Duration;

use tidefs_types_transport_session::{
    CohortClass, EndpointFamily, LaneClass, MessageFamily, SessionClass,
    TRANSPORT_SESSION_COHORT_GRAPH_P8_01,
};

// ---------------------------------------------------------------------------
// Boundedness constants (§12)
// ---------------------------------------------------------------------------

/// Default maximum serialized frame size (header + payload) per connection: 1 MiB.
pub const MAX_FRAME_BYTES: u32 = 1_048_576;

/// Default maximum unacknowledged frames inflight per connection.
pub const MAX_INFLIGHT_FRAMES: u16 = 64;

/// Default maximum concurrent bulk transfer tokens per connection.
pub const MAX_INFLIGHT_BULK_TOKENS: u8 = 4;

/// Default dedup sliding window size (ops) per connection.
pub const DEDUP_WINDOW_OPS: u16 = 1024;

/// Maximum cached response size stored in a dedup entry.
pub const DEDUP_ENTRY_MAX_BYTES: u16 = 256;

/// Size of FrameHeaderV1 in bytes.
pub const FRAME_HEADER_SIZE: u16 = 40;

/// CONTROL lane delivery cap per tick (unlimited).
pub const CONTROL_LANE_CAP: u32 = u32::MAX;

/// METADATA lane delivery cap per tick.
pub const METADATA_LANE_CAP: u32 = 256;

/// BULK lane delivery cap per tick.
pub const BULK_LANE_CAP: u32 = 64;

/// BACKGROUND lane delivery cap per tick.
pub const BACKGROUND_LANE_CAP: u32 = 32;

/// Maximum total deliveries per transport tick.
pub const GLOBAL_MAX_DELIVERIES_PER_TICK: u32 = 512;

/// Maximum total bytes per transport tick: 16 MiB.
pub const GLOBAL_MAX_BYTES_PER_TICK: u64 = 16_777_216;

/// Minimum interval between transport ticks: 10 ms.
pub const TRANSPORT_TICK_INTERVAL_MS: u64 = 10;

/// Timeout for HELLO/HELLO_ACK handshake: 5000 ms.
pub const HELLO_TIMEOUT_MS: u64 = 5_000;

/// Default bulk transfer deadline: 30 s.
pub const BULK_DEADLINE_DEFAULT_MS: u64 = 30_000;

/// Default chunk size for bulk transfers: 256 KiB.
pub const BULK_CHUNK_SIZE_DEFAULT: u32 = 262_144;

// ---------------------------------------------------------------------------
// TransportLane — budget lane for per-tick delivery (§5.1)
// ---------------------------------------------------------------------------

/// Delivery-budget lane used for per-tick bounded scheduling.
///
/// Maps the five P8-01 lane classes into four budget lanes:
///   CONTROL  -> CONTROL   (highest priority)
///   Metadata -> METADATA
///   Demand   -> BULK
///   Speculative -> BACKGROUND
///   Background -> BACKGROUND
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum TransportLane {
    Control = 0,
    Metadata = 1,
    Bulk = 2,
    Background = 3,
}

impl TransportLane {
    /// Number of budget lane classes.
    pub const COUNT: usize = 4;

    /// All budget lanes in priority order (highest first).
    pub const fn all() -> [TransportLane; 4] {
        [
            TransportLane::Control,
            TransportLane::Metadata,
            TransportLane::Bulk,
            TransportLane::Background,
        ]
    }

    /// Default per-tick delivery cap for this lane.
    #[must_use]
    pub const fn default_cap(self) -> u32 {
        match self {
            TransportLane::Control => CONTROL_LANE_CAP,
            TransportLane::Metadata => METADATA_LANE_CAP,
            TransportLane::Bulk => BULK_LANE_CAP,
            TransportLane::Background => BACKGROUND_LANE_CAP,
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionBounds — per-connection limits (§4.1)
// ---------------------------------------------------------------------------

/// Per-connection bounds enforced at both sender and receiver.
///
/// Every transport connection maintains a `ConnectionBounds` that governs
/// frame size, inflight count, bulk tokens, and dedup window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionBounds {
    /// Maximum serialized frame size (header + payload).
    /// Frames exceeding this are rejected before decode.
    pub max_frame_bytes: u32,

    /// Maximum number of unacknowledged frames inflight.
    /// Sender blocks when this count is reached.
    pub max_inflight_frames: u16,

    /// Maximum number of concurrent bulk transfer tokens.
    pub max_inflight_bulk_tokens: u8,

    /// Size of the deduplication sliding window (ops).
    pub dedup_window_ops: u16,
}

impl ConnectionBounds {
    /// Default boundedness limits.
    #[must_use]
    pub const fn default_bounds() -> Self {
        Self {
            max_frame_bytes: MAX_FRAME_BYTES,
            max_inflight_frames: MAX_INFLIGHT_FRAMES,
            max_inflight_bulk_tokens: MAX_INFLIGHT_BULK_TOKENS,
            dedup_window_ops: DEDUP_WINDOW_OPS,
        }
    }

    /// Shrink inflight frame cap by factor (used under backpressure).
    /// Returns the new `ConnectionBounds` with halved inflight limit.
    #[must_use]
    pub fn shrink_inflight(&self, factor: u16) -> Self {
        let mut bounds = self.clone();
        bounds.max_inflight_frames = self.max_inflight_frames.saturating_div(factor.max(1));
        bounds.max_inflight_frames = bounds.max_inflight_frames.max(1);
        bounds
    }

    /// Validate that a frame size is within bounds.
    pub fn validate_frame_size(&self, size: u32) -> Result<(), String> {
        if size > self.max_frame_bytes {
            Err(format!(
                "frame size {} exceeds max_frame_bytes {}",
                size, self.max_frame_bytes
            ))
        } else {
            Ok(())
        }
    }
}

impl Default for ConnectionBounds {
    fn default() -> Self {
        Self::default_bounds()
    }
}

// ---------------------------------------------------------------------------
// DeliveryBudget — per-tick delivery bounds (§5)
// ---------------------------------------------------------------------------

/// Per-tick delivery budget with lane-priority ordering.
///
/// Each transport tick, the budget is replenished. Messages are drained from
/// the highest-priority lane first (CONTROL -> METADATA -> BULK -> BACKGROUND).
#[derive(Clone, Debug)]
pub struct DeliveryBudget {
    /// Remaining deliveries this tick.
    pub remaining_deliveries: u32,

    /// Remaining bytes this tick.
    pub remaining_bytes: u64,

    /// Per-lane delivery counts this tick.
    pub lane_deliveries: [u32; TransportLane::COUNT],

    /// Per-lane caps.
    pub lane_caps: [u32; TransportLane::COUNT],
}

impl DeliveryBudget {
    /// Create a new delivery budget with global and per-lane caps.
    #[must_use]
    pub fn new() -> Self {
        let mut lane_caps = [0u32; TransportLane::COUNT];
        for lane in TransportLane::all() {
            lane_caps[lane as usize] = lane.default_cap();
        }
        Self {
            remaining_deliveries: GLOBAL_MAX_DELIVERIES_PER_TICK,
            remaining_bytes: GLOBAL_MAX_BYTES_PER_TICK,
            lane_deliveries: [0u32; TransportLane::COUNT],
            lane_caps,
        }
    }

    /// Whether any delivery can be made this tick.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.remaining_deliveries == 0 || self.remaining_bytes == 0
    }

    /// Whether a specific lane is exhausted this tick.
    #[must_use]
    pub fn lane_exhausted(&self, lane: TransportLane) -> bool {
        self.lane_deliveries[lane as usize] >= self.lane_caps[lane as usize]
    }

    /// Reserve budget for a delivery of `bytes` on `lane`.
    /// Returns `true` if the delivery was accepted.
    pub fn reserve(&mut self, lane: TransportLane, bytes: u64) -> bool {
        if self.is_exhausted() || self.lane_exhausted(lane) {
            return false;
        }
        if bytes > self.remaining_bytes {
            return false;
        }
        self.remaining_deliveries -= 1;
        self.remaining_bytes -= bytes;
        self.lane_deliveries[lane as usize] += 1;
        true
    }

    /// Replenish the budget for a new tick.
    pub fn replenish(&mut self) {
        self.remaining_deliveries = GLOBAL_MAX_DELIVERIES_PER_TICK;
        self.remaining_bytes = GLOBAL_MAX_BYTES_PER_TICK;
        self.lane_deliveries = [0u32; TransportLane::COUNT];
    }

    /// Operator-configurable lane cap override.
    pub fn set_lane_cap(&mut self, lane: TransportLane, cap: u32) {
        self.lane_caps[lane as usize] = cap;
    }
}

impl Default for DeliveryBudget {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Transport tick interval helper
// ---------------------------------------------------------------------------

/// Return the transport tick interval as a Duration.
#[must_use]
pub fn transport_tick_interval() -> Duration {
    Duration::from_millis(TRANSPORT_TICK_INTERVAL_MS)
}

/// Return the HELLO timeout as a Duration.
#[must_use]
pub fn hello_timeout() -> Duration {
    Duration::from_millis(HELLO_TIMEOUT_MS)
}

/// Return the default bulk transfer deadline as a Duration.
#[must_use]
pub fn bulk_deadline_default() -> Duration {
    Duration::from_millis(BULK_DEADLINE_DEFAULT_MS)
}

// ---------------------------------------------------------------------------
// Validation assertions
// ---------------------------------------------------------------------------

/// Validate that all boundedness constants are within their design ranges.
/// Called at crate init or test time to catch misconfiguration early.
pub fn validate_boundedness_constants() -> Result<(), String> {
    // max_frame_bytes must be at least FRAME_HEADER_SIZE
    if MAX_FRAME_BYTES < FRAME_HEADER_SIZE as u32 {
        return Err(format!(
            "MAX_FRAME_BYTES ({MAX_FRAME_BYTES}) must be >= FRAME_HEADER_SIZE ({FRAME_HEADER_SIZE})"
        ));
    }

    // GLOBAL_MAX_DELIVERIES_PER_TICK must exceed sum of per-lane caps
    // Skip lanes with u32::MAX cap (means unlimited / not bounded)
    let lane_cap_sum: u64 = TransportLane::all()
        .iter()
        .map(|l| l.default_cap())
        .filter(|&c| c != u32::MAX)
        .map(|c| c as u64)
        .sum();
    if (GLOBAL_MAX_DELIVERIES_PER_TICK as u64) < lane_cap_sum {
        return Err(format!(
            "GLOBAL_MAX_DELIVERIES_PER_TICK ({GLOBAL_MAX_DELIVERIES_PER_TICK}) must be >= sum of lane caps ({lane_cap_sum})"
        ));
    }

    // BULK_CHUNK_SIZE_DEFAULT must not exceed MAX_FRAME_BYTES
    if BULK_CHUNK_SIZE_DEFAULT > MAX_FRAME_BYTES {
        return Err(format!(
            "BULK_CHUNK_SIZE_DEFAULT ({BULK_CHUNK_SIZE_DEFAULT}) must be <= MAX_FRAME_BYTES ({MAX_FRAME_BYTES})"
        ));
    }

    // TRANSPORT_TICK_INTERVAL_MS must be > 0
    if TRANSPORT_TICK_INTERVAL_MS == 0 {
        return Err("TRANSPORT_TICK_INTERVAL_MS must be > 0".to_string());
    }

    // HELLO_TIMEOUT_MS must be > 0
    if HELLO_TIMEOUT_MS == 0 {
        return Err("HELLO_TIMEOUT_MS must be > 0".to_string());
    }

    // DEDUP_ENTRY_MAX_BYTES must be > 0
    if DEDUP_ENTRY_MAX_BYTES == 0 {
        return Err("DEDUP_ENTRY_MAX_BYTES must be > 0".to_string());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Design-spec cross-validation: validate transport crate against P8-01
// transport/session/cohort graph and Cluster Transport Boundedness design.
// ---------------------------------------------------------------------------

/// Validates the transport crate implementation against the P8-01
/// transport/session/cohort graph design document and the
/// Cluster Transport Boundedness design spec.
///
/// Checks:
/// - Boundedness constants via `validate_boundedness_constants`
/// - P8-01 family counts (4 endpoints, 6 session classes, 8 cohort
///   classes, 5 lane classes, 10 message families)
/// - TransportLane to P8-01 LaneClass mapping consistency
/// - Lane priority ordering invariants
/// - Design anchor string existence and prefix
pub fn validate_transport_against_design_documents() -> Result<(), String> {
    // 1. Boundedness constants
    validate_boundedness_constants()?;

    // 2. P8-01 §8: 4 stable endpoint families
    let endpoints: &[EndpointFamily] = &[
        EndpointFamily::LocalEmbed,
        EndpointFamily::Control,
        EndpointFamily::Data,
        EndpointFamily::Shadow,
    ];
    if endpoints.len() != 4 {
        return Err(format!(
            "P8-01 §8 requires 4 endpoint families; got {}",
            endpoints.len()
        ));
    }
    for ep in endpoints {
        let s = ep.as_str();
        if s.is_empty() {
            return Err(format!("endpoint family {ep:?} has empty as_str()"));
        }
        if !s.starts_with("endpoint.transport_session_0.") {
            return Err(format!(
                "endpoint family {ep:?}: as_str() does not start with expected prefix: {s}"
            ));
        }
    }

    // 3. P8-01 §9: 6 stable session classes
    let sessions: &[SessionClass] = &[
        SessionClass::Bootstrap,
        SessionClass::Control,
        SessionClass::ReplicationMeta,
        SessionClass::TransferBulk,
        SessionClass::ShadowValidation,
        SessionClass::TransitionOrchestration,
    ];
    if sessions.len() != 6 {
        return Err(format!(
            "P8-01 §9 requires 6 session classes; got {}",
            sessions.len()
        ));
    }
    for sc in sessions {
        let s = sc.as_str();
        if s.is_empty() {
            return Err(format!("session class {sc:?} has empty as_str()"));
        }
        if !s.starts_with("session.transport_session_0.") {
            return Err(format!(
                "session class {sc:?}: as_str() does not start with expected prefix: {s}"
            ));
        }
    }

    // 4. P8-01 §6: 8 stable cohort classes (k0-k7)
    let cohorts: &[CohortClass] = &[
        CohortClass::PeerPair,
        CohortClass::AuthorityDomainControl,
        CohortClass::FenceTarget,
        CohortClass::ReplicaSet,
        CohortClass::StateTransfer,
        CohortClass::ShadowCompare,
        CohortClass::TransitionStage,
        CohortClass::LocalRuntime,
    ];
    if cohorts.len() != 8 {
        return Err(format!(
            "P8-01 §6 requires 8 cohort classes; got {}",
            cohorts.len()
        ));
    }
    for cc in cohorts {
        let s = cc.as_str();
        if s.is_empty() {
            return Err(format!("cohort class {cc:?} has empty as_str()"));
        }
        if !s.starts_with("cohort.transport_session_0.") {
            return Err(format!(
                "cohort class {cc:?}: as_str() does not start with expected prefix: {s}"
            ));
        }
    }

    // 5. P8-01 §4: 5 stable lane classes with priority ordering
    let lanes: &[LaneClass] = &[
        LaneClass::Control,
        LaneClass::Metadata,
        LaneClass::Demand,
        LaneClass::Speculative,
        LaneClass::Background,
    ];
    if lanes.len() != 5 {
        return Err(format!(
            "P8-01 §4 requires 5 lane classes; got {}",
            lanes.len()
        ));
    }
    for i in 1..lanes.len() {
        if (lanes[i - 1] as u8) >= (lanes[i] as u8) {
            return Err(format!(
                "P8-01 lane priority ordering violated: {:?} (idx {}) >= {:?} (idx {})",
                lanes[i - 1],
                i - 1,
                lanes[i],
                i
            ));
        }
    }

    // 6. P8-01 §7: 10 stable message families (m0-m9)
    let msgs: &[MessageFamily] = &[
        MessageFamily::HelloClose,
        MessageFamily::HeartbeatAck,
        MessageFamily::ElectionControl,
        MessageFamily::LeaseFenceDeadline,
        MessageFamily::PublicationProgress,
        MessageFamily::LogSyncMetadata,
        MessageFamily::StateTransfer,
        MessageFamily::ReplicaTransferVerify,
        MessageFamily::ShadowValidation,
        MessageFamily::TransitionHoldResume,
    ];
    if msgs.len() != 10 {
        return Err(format!(
            "P8-01 §7 requires 10 message families; got {}",
            msgs.len()
        ));
    }
    for mf in msgs {
        let s = mf.as_str();
        if s.is_empty() {
            return Err(format!("message family {mf:?} has empty as_str()"));
        }
        if !s.starts_with("msg.transport_session_0.") {
            return Err(format!(
                "message family {mf:?}: as_str() does not start with expected prefix: {s}"
            ));
        }
    }

    // 7. TransportLane to P8-01 LaneClass mapping consistency
    // Budget lanes (4) map from P8-01 lane classes (5).
    if TransportLane::COUNT != 4 {
        return Err(format!(
            "Transport budget lanes must be 4 (P8-01 has 5 lane classes); got {}",
            TransportLane::COUNT
        ));
    }
    let budget_lanes = TransportLane::all();
    if budget_lanes[0] != TransportLane::Control {
        return Err("TransportLane::Control must be highest priority".to_string());
    }

    // 8. Design anchor string check
    if TRANSPORT_SESSION_COHORT_GRAPH_P8_01.is_empty() {
        return Err("P8-01 anchor string must not be empty".to_string());
    }
    if !TRANSPORT_SESSION_COHORT_GRAPH_P8_01.starts_with("family.transport_session_cohort_graph.") {
        return Err(format!(
            "P8-01 anchor string has unexpected prefix: {TRANSPORT_SESSION_COHORT_GRAPH_P8_01}"
        ));
    }

    // 9. P8-01 §4.2: endpoint family allowed_session_classes invariants
    // e0 (LocalEmbed) is for co-resident services only — admits all session classes
    {
        let allowed = EndpointFamily::LocalEmbed.allowed_session_classes();
        if allowed.is_empty() {
            return Err("P8-01 §4.2: e0 (LocalEmbed) must admit session classes".to_string());
        }
        if !allowed.contains(&SessionClass::Bootstrap) {
            return Err("P8-01 §4.2: e0 (LocalEmbed) must admit Bootstrap".to_string());
        }
        if !allowed.contains(&SessionClass::Control) {
            return Err("P8-01 §4.2: e0 (LocalEmbed) must admit Control".to_string());
        }
    }
    // e1 (Control): must admit Bootstrap, Control, ReplicationMeta, TransitionOrchestration
    {
        let allowed = EndpointFamily::Control.allowed_session_classes();
        if allowed.is_empty() {
            return Err("P8-01 §4.2: e1 (Control) must admit session classes".to_string());
        }
        for must_have in &[
            SessionClass::Bootstrap,
            SessionClass::Control,
            SessionClass::ReplicationMeta,
            SessionClass::TransitionOrchestration,
        ] {
            if !allowed.contains(must_have) {
                return Err(format!("P8-01 §4.2: e1 (Control) must admit {must_have:?}"));
            }
        }
        // e1 must never admit bulk or shadow sessions
        if allowed.contains(&SessionClass::TransferBulk) {
            return Err("P8-01 §4.2: e1 (Control) must not admit TransferBulk".to_string());
        }
        if allowed.contains(&SessionClass::ShadowValidation) {
            return Err("P8-01 §4.2: e1 (Control) must not admit ShadowValidation".to_string());
        }
    }
    // e2 (Data): must only admit TransferBulk
    {
        let allowed = EndpointFamily::Data.allowed_session_classes();
        if allowed.len() != 1 {
            return Err(format!(
                "P8-01 §4.2: e2 (Data) must admit exactly 1 session class; got {}",
                allowed.len()
            ));
        }
        if !allowed.contains(&SessionClass::TransferBulk) {
            return Err("P8-01 §4.2: e2 (Data) must admit TransferBulk".to_string());
        }
    }
    // e3 (Shadow): must only admit ShadowValidation
    {
        let allowed = EndpointFamily::Shadow.allowed_session_classes();
        if allowed.len() != 1 {
            return Err(format!(
                "P8-01 §4.2: e3 (Shadow) must admit exactly 1 session class; got {}",
                allowed.len()
            ));
        }
        if !allowed.contains(&SessionClass::ShadowValidation) {
            return Err("P8-01 §4.2: e3 (Shadow) must admit ShadowValidation".to_string());
        }
    }

    // 10. P8-01 §5.2: session class primary_endpoint pair-law validation
    {
        let expected_primary: &[(SessionClass, EndpointFamily)] = &[
            (SessionClass::Bootstrap, EndpointFamily::Control),
            (SessionClass::Control, EndpointFamily::Control),
            (SessionClass::ReplicationMeta, EndpointFamily::Control),
            (SessionClass::TransferBulk, EndpointFamily::Data),
            (SessionClass::ShadowValidation, EndpointFamily::Shadow),
            (
                SessionClass::TransitionOrchestration,
                EndpointFamily::Control,
            ),
        ];
        for (sc, expected_ep) in expected_primary {
            let actual = sc.primary_endpoint();
            if actual != *expected_ep {
                return Err(format!(
                    "P8-01 §5.2: session class {sc:?} primary_endpoint is {actual:?}, expected {expected_ep:?}"
                ));
            }
            // The primary endpoint must itself admit this session class
            if !actual.allowed_session_classes().contains(sc) {
                return Err(format!(
                    "P8-01 §5.2: primary endpoint {actual:?} does not admit session class {sc:?}"
                ));
            }
        }
    }

    // 11. P8-01 §5.2: Bootstrap must promote to all long-lived session classes
    {
        let promotions = SessionClass::Bootstrap.can_promote_to();
        let must_promote: &[SessionClass] = &[
            SessionClass::Control,
            SessionClass::ReplicationMeta,
            SessionClass::TransferBulk,
            SessionClass::ShadowValidation,
            SessionClass::TransitionOrchestration,
        ];
        for sc in must_promote {
            if !promotions.contains(sc) {
                return Err(format!("P8-01 §5.2: Bootstrap must promote to {sc:?}"));
            }
        }
        // Non-Bootstrap session classes must not promote
        let non_bootstrap: &[SessionClass] = &[
            SessionClass::Control,
            SessionClass::ReplicationMeta,
            SessionClass::TransferBulk,
            SessionClass::ShadowValidation,
            SessionClass::TransitionOrchestration,
        ];
        for sc in non_bootstrap {
            if !sc.can_promote_to().is_empty() {
                return Err(format!(
                    "P8-01 §5.2: non-Bootstrap session class {sc:?} must not promote"
                ));
            }
        }
    }

    // 12. P8-01 §7.1: lane starvation protection (Control and Metadata must never be starved)
    if !LaneClass::Control.may_not_be_starved() {
        return Err("P8-01 §7.1: Control lane must be starvation-protected".to_string());
    }
    if !LaneClass::Metadata.may_not_be_starved() {
        return Err("P8-01 §7.1: Metadata lane must be starvation-protected".to_string());
    }

    // 13. P8-01 §7.2: message family primary lane class mapping
    {
        let expected_lane: &[(MessageFamily, LaneClass)] = &[
            (MessageFamily::HelloClose, LaneClass::Control),
            (MessageFamily::HeartbeatAck, LaneClass::Control),
            (MessageFamily::ElectionControl, LaneClass::Control),
            (MessageFamily::LeaseFenceDeadline, LaneClass::Control),
            (MessageFamily::PublicationProgress, LaneClass::Metadata),
            (MessageFamily::LogSyncMetadata, LaneClass::Metadata),
            (MessageFamily::StateTransfer, LaneClass::Demand),
            (MessageFamily::ReplicaTransferVerify, LaneClass::Demand),
            (MessageFamily::ShadowValidation, LaneClass::Speculative),
            (MessageFamily::TransitionHoldResume, LaneClass::Control),
        ];
        for (mf, expected_lc) in expected_lane {
            let actual = mf.primary_lane_class();
            if actual != *expected_lc {
                return Err(format!(
                    "P8-01 §7.2: message family {mf:?} primary_lane_class is {actual:?}, expected {expected_lc:?}"
                ));
            }
        }
    }

    // 14. P8-01 §7.1: lane class default_priority ordering (Control=0, Metadata=1, ...)
    if LaneClass::Control.default_priority() != 0 {
        return Err("P8-01 §7.1: Control lane priority must be 0".to_string());
    }
    if LaneClass::Metadata.default_priority() != 1 {
        return Err("P8-01 §7.1: Metadata lane priority must be 1".to_string());
    }
    if LaneClass::Demand.default_priority() != 2 {
        return Err("P8-01 §7.1: Demand lane priority must be 2".to_string());
    }
    if LaneClass::Speculative.default_priority() != 3 {
        return Err("P8-01 §7.1: Speculative lane priority must be 3".to_string());
    }
    if LaneClass::Background.default_priority() != 4 {
        return Err("P8-01 §7.1: Background lane priority must be 4".to_string());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_bounds_within_range() {
        let bounds = ConnectionBounds::default_bounds();
        assert!(bounds.max_frame_bytes > 0);
        assert!(bounds.max_frame_bytes >= FRAME_HEADER_SIZE as u32);
        assert!(bounds.max_inflight_frames > 0);
        assert!(bounds.max_inflight_bulk_tokens > 0);
        assert!(bounds.dedup_window_ops > 0);
    }

    #[test]
    fn test_validate_frame_size() {
        let bounds = ConnectionBounds::default_bounds();
        assert!(bounds.validate_frame_size(1024).is_ok());
        assert!(bounds
            .validate_frame_size(bounds.max_frame_bytes + 1)
            .is_err());
    }

    #[test]
    fn test_shrink_inflight() {
        let bounds = ConnectionBounds::default_bounds();
        let shrunk = bounds.shrink_inflight(2);
        assert_eq!(shrunk.max_inflight_frames, 32);
        assert_eq!(shrunk.max_frame_bytes, bounds.max_frame_bytes);
    }

    #[test]
    fn test_shrink_inflight_never_zero() {
        let mut bounds = ConnectionBounds::default_bounds();
        bounds.max_inflight_frames = 1;
        let shrunk = bounds.shrink_inflight(2);
        assert!(shrunk.max_inflight_frames >= 1);
    }

    #[test]
    fn test_delivery_budget_reserve_and_exhaust_lane() {
        let mut budget = DeliveryBudget::new();
        assert!(!budget.is_exhausted());

        // METADATA has a finite cap (256) so we can test lane exhaustion
        for _ in 0..METADATA_LANE_CAP {
            assert!(budget.reserve(TransportLane::Metadata, 1024));
        }
        assert!(budget.lane_exhausted(TransportLane::Metadata));
        // CONTROL lane is still unlimited
        assert!(!budget.is_exhausted());
    }

    #[test]
    fn test_delivery_budget_replenish() {
        let mut budget = DeliveryBudget::new();
        budget.reserve(TransportLane::Control, 1024);
        budget.replenish();
        assert!(!budget.is_exhausted());
        assert_eq!(budget.lane_deliveries[TransportLane::Control as usize], 0);
    }

    #[test]
    fn test_transport_lane_ordering() {
        let lanes = TransportLane::all();
        assert_eq!(lanes[0], TransportLane::Control);
        assert_eq!(lanes[1], TransportLane::Metadata);
        assert_eq!(lanes[2], TransportLane::Bulk);
        assert_eq!(lanes[3], TransportLane::Background);
    }

    #[test]
    fn test_validate_boundedness_constants() {
        assert!(validate_boundedness_constants().is_ok());
    }

    #[test]
    fn test_duration_helpers() {
        assert_eq!(
            transport_tick_interval(),
            Duration::from_millis(TRANSPORT_TICK_INTERVAL_MS)
        );
        assert_eq!(hello_timeout(), Duration::from_millis(HELLO_TIMEOUT_MS));
        assert_eq!(
            bulk_deadline_default(),
            Duration::from_millis(BULK_DEADLINE_DEFAULT_MS)
        );
    }

    #[test]

    fn test_validate_transport_against_design_documents() {
        assert!(validate_transport_against_design_documents().is_ok());
    }

    #[test]
    fn test_default_caps_match_design() {
        assert_eq!(TransportLane::Control.default_cap(), CONTROL_LANE_CAP);
        assert_eq!(TransportLane::Metadata.default_cap(), METADATA_LANE_CAP);
        assert_eq!(TransportLane::Bulk.default_cap(), BULK_LANE_CAP);
        assert_eq!(TransportLane::Background.default_cap(), BACKGROUND_LANE_CAP);
    }
}

//! Networked shard placement dispatch with transport sessions and admission control.
//!
//! Phase 2 of erasure coding placement: dispatches shards to target nodes over
//! transport sessions, enforces admission control with backpressure, retries
//! transient failures with exponential backoff, and confirms or aborts placements.
//!
//! ## Architecture
//!
//! 1. [`ShardDispatcher`] takes a [`PlacementPlan`] and shard data, opens transport
//!    sessions to each target node, sends [`ShardPlacementRequest`] messages, and
//!    awaits [`ShardPlacementResponse`] replies.
//! 2. [`PlacementAdmissionControl`] enforces per-node shard admission quotas and
//!    backpressure.
//! 3. [`PlacementConfirmation`] commits on all-shards-accepted or aborts on any
//!    rejection, freeing accepted shards from target nodes.
//! 4. [`ShardDispatcherStats`] tracks shards_sent, shards_accepted, shards_rejected,
//!    retries, and avg_dispatch_latency_ms.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tidefs_placement_planner::placement_plan::{
    DeviceCandidate, PlacementPlan, PlacementPlanError,
};

// ---------------------------------------------------------------------------
// Shard placement request/response messages
// ---------------------------------------------------------------------------

/// Request to place a single shard on a target node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardPlacementRequest {
    /// Placement key — scopes this shard to a particular placement operation.
    pub placement_key: u64,
    /// 0-based shard index within the object layout.
    pub shard_index: u8,
    /// The shard payload.
    pub shard_data: Vec<u8>,
    /// BLAKE3 checksum of shard_data for integrity verification at the target.
    pub checksum: [u8; 32],
}

impl ShardPlacementRequest {
    /// Create a new shard placement request, computing the BLAKE3 checksum.
    #[must_use]
    pub fn new(placement_key: u64, shard_index: u8, shard_data: Vec<u8>) -> Self {
        let checksum = blake3::hash(&shard_data);
        Self {
            placement_key,
            shard_index,
            shard_data,
            checksum: checksum.into(),
        }
    }

    /// Verify the stored checksum matches the shard_data.
    #[must_use]
    pub fn verify_checksum(&self) -> bool {
        let computed = blake3::hash(&self.shard_data);
        computed.as_bytes() == &self.checksum
    }
}

/// Response from a target node after a shard placement attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardPlacementResponse {
    /// Whether the shard was accepted for placement.
    pub accepted: bool,
    /// Human-readable reason for rejection (if any).
    pub reason: Option<String>,
}

impl ShardPlacementResponse {
    /// Accepted response.
    #[must_use]
    pub fn accepted() -> Self {
        Self {
            accepted: true,
            reason: None,
        }
    }

    /// Rejected response with a reason.
    #[must_use]
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            accepted: false,
            reason: Some(reason.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Shard transport abstraction
// ---------------------------------------------------------------------------

/// Trait for sending shard placement requests to target nodes.
///
/// The transport layer maps node_ids to concrete network sessions and
/// handles serialization, session lifecycle, and error propagation.
/// Implementations may use TCP, RDMA, or in-memory channels.
pub trait ShardTransport {
    /// Send a shard placement request to a target node and await a response.
    ///
    /// Returns `Ok(response)` on a successful round-trip, or `Err(...)` on
    /// transport failure (connection broken, timeout, etc.).
    fn send_shard(
        &mut self,
        node_id: u64,
        request: &ShardPlacementRequest,
    ) -> Result<ShardPlacementResponse, ShardTransportError>;

    /// Notify a target node to commit a placement (all shards accepted).
    fn commit_placement(
        &mut self,
        node_id: u64,
        placement_key: u64,
    ) -> Result<(), ShardTransportError>;

    /// Notify a target node to abort a placement and free accepted shards.
    fn abort_placement(
        &mut self,
        node_id: u64,
        placement_key: u64,
    ) -> Result<(), ShardTransportError>;
}

/// Errors from the transport layer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShardTransportError {
    #[error("connection to node {node_id} failed: {msg}")]
    ConnectionFailed { node_id: u64, msg: String },
    #[error("timeout waiting for response from node {node_id}")]
    Timeout { node_id: u64 },
    #[error("transport error on node {node_id}: {msg}")]
    TransportError { node_id: u64, msg: String },
    #[error("node {node_id} refused the session")]
    SessionRefused { node_id: u64 },
}

// ---------------------------------------------------------------------------
// Retry configuration
// ---------------------------------------------------------------------------

/// Exponential backoff retry configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Initial backoff duration.
    pub initial_backoff_ms: u64,
    /// Maximum backoff duration ceiling.
    pub max_backoff_ms: u64,
    /// Multiplier for exponential growth.
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff_ms: 50,
            max_backoff_ms: 2000,
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Compute the backoff duration for a given attempt number (0-based).
    #[must_use]
    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        let ms =
            (self.initial_backoff_ms as f64 * self.backoff_multiplier.powi(attempt as i32)) as u64;
        let capped = ms.min(self.max_backoff_ms);
        Duration::from_millis(capped)
    }

    /// Whether a given attempt is retryable.
    #[must_use]
    pub fn can_retry(&self, attempt: u32) -> bool {
        attempt < self.max_retries
    }
}

// ---------------------------------------------------------------------------
// Placement admission control
// ---------------------------------------------------------------------------

/// Per-node shard admission quotas with backpressure.
///
/// Tracks inflight shard counts per node. When a node is at capacity,
/// new shard placements are queued or rejected. When a shard completes
/// (accepted or rejected), the inflight count is decremented.
#[derive(Debug, Clone)]
pub struct PlacementAdmissionControl {
    /// Maximum concurrent inflight shards per node.
    max_inflight_per_node: usize,
    /// Current inflight shard count per node.
    inflight: HashMap<u64, usize>,
    /// Per-node shard admission quotas (max total shards admitted).
    quotas: HashMap<u64, usize>,
    /// Total shards admitted to each node.
    admitted: HashMap<u64, usize>,
}

impl PlacementAdmissionControl {
    /// Create new admission control with the given per-node inflight limit.
    #[must_use]
    pub fn new(max_inflight_per_node: usize) -> Self {
        Self {
            max_inflight_per_node,
            inflight: HashMap::new(),
            quotas: HashMap::new(),
            admitted: HashMap::new(),
        }
    }

    /// Set a per-node total admission quota.
    pub fn set_quota(&mut self, node_id: u64, max_shards: usize) {
        self.quotas.insert(node_id, max_shards);
    }

    /// Check whether a node can accept another shard.
    ///
    /// Returns `false` if the node is at its inflight limit or quota.
    #[must_use]
    pub fn can_admit(&self, node_id: u64) -> bool {
        let inflight = self.inflight.get(&node_id).copied().unwrap_or(0);
        if inflight >= self.max_inflight_per_node {
            return false;
        }
        if let Some(quota) = self.quotas.get(&node_id) {
            let admitted = self.admitted.get(&node_id).copied().unwrap_or(0);
            if admitted >= *quota {
                return false;
            }
        }
        true
    }

    /// Admit a shard to a node, incrementing inflight and admitted counts.
    ///
    /// Returns `false` if admission is refused.
    pub fn admit(&mut self, node_id: u64) -> bool {
        if !self.can_admit(node_id) {
            return false;
        }
        *self.inflight.entry(node_id).or_insert(0) += 1;
        *self.admitted.entry(node_id).or_insert(0) += 1;
        true
    }

    /// Release an inflight slot after a shard completes (success or failure).
    pub fn release(&mut self, node_id: u64) {
        if let Some(count) = self.inflight.get_mut(&node_id) {
            *count = count.saturating_sub(1);
        }
    }

    /// Get current inflight count for a node.
    #[must_use]
    pub fn inflight_count(&self, node_id: u64) -> usize {
        self.inflight.get(&node_id).copied().unwrap_or(0)
    }

    /// Get total admitted count for a node.
    #[must_use]
    pub fn admitted_count(&self, node_id: u64) -> usize {
        self.admitted.get(&node_id).copied().unwrap_or(0)
    }

    /// Reset all counters (e.g., after placement cycle complete).
    pub fn reset(&mut self) {
        self.inflight.clear();
        self.admitted.clear();
    }
}

// ---------------------------------------------------------------------------
// Dispatch errors
// ---------------------------------------------------------------------------

/// Errors returned by the shard dispatcher.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("placement plan error: {0}")]
    PlanError(#[from] PlacementPlanError),
    #[error("admission refused for node {node_id}")]
    AdmissionRefused { node_id: u64 },
    #[error("shard dispatch failed for node {node_id} after {retries} retries: {reason}")]
    ShardDispatchFailed {
        node_id: u64,
        retries: u32,
        reason: String,
    },
    #[error("shard rejection from node {node_id}: {reason}")]
    ShardRejected { node_id: u64, reason: String },
    #[error("transport error: {0}")]
    Transport(#[from] ShardTransportError),
    #[error("inconsistent node mapping: device {device_id} has no node_id")]
    NoNodeMapping { device_id: u64 },
}

// ---------------------------------------------------------------------------
// Dispatch result
// ---------------------------------------------------------------------------

/// Per-shard outcome from a dispatch operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardDispatchOutcome {
    pub shard_index: u8,
    pub device_id: u64,
    pub node_id: u64,
    pub accepted: bool,
    pub retries: u32,
}

/// Result of a full placement dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchResult {
    pub outcomes: Vec<ShardDispatchOutcome>,
    pub all_accepted: bool,
    pub total_retries: u32,
    pub elapsed_ms: u64,
}

// ---------------------------------------------------------------------------
// Shard dispatcher stats
// ---------------------------------------------------------------------------

/// Statistics for the shard dispatcher.
#[derive(Debug, Clone, Default)]
pub struct ShardDispatcherStats {
    /// Total shards sent.
    pub shards_sent: u64,
    /// Total shards accepted by target nodes.
    pub shards_accepted: u64,
    /// Total shards rejected by target nodes.
    pub shards_rejected: u64,
    /// Total retry attempts across all dispatches.
    pub retries: u64,
    /// Number of placement dispatch operations completed.
    pub dispatch_count: u64,
    /// Cumulative dispatch latency in milliseconds.
    pub total_dispatch_latency_ms: u64,
}

impl ShardDispatcherStats {
    /// Create empty stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Average dispatch latency in milliseconds.
    #[must_use]
    pub fn avg_dispatch_latency_ms(&self) -> f64 {
        if self.dispatch_count == 0 {
            return 0.0;
        }
        self.total_dispatch_latency_ms as f64 / self.dispatch_count as f64
    }

    /// Acceptance rate (0.0 – 1.0).
    #[must_use]
    pub fn acceptance_rate(&self) -> f64 {
        if self.shards_sent == 0 {
            return 1.0;
        }
        self.shards_accepted as f64 / self.shards_sent as f64
    }
}

// ---------------------------------------------------------------------------
// Shard dispatcher
// ---------------------------------------------------------------------------

/// Dispatches shard placements to target nodes via a transport layer.
///
/// Takes a [`PlacementPlan`] and shard data, maps devices to nodes,
/// dispatches shards with admission control, retries transient failures,
/// and collects outcomes.
pub struct ShardDispatcher<T: ShardTransport> {
    transport: T,
    admission: PlacementAdmissionControl,
    stats: ShardDispatcherStats,
    retry_config: RetryConfig,
}

impl<T: ShardTransport> ShardDispatcher<T> {
    /// Create a new shard dispatcher.
    #[must_use]
    pub fn new(transport: T, max_inflight_per_node: usize) -> Self {
        Self {
            transport,
            admission: PlacementAdmissionControl::new(max_inflight_per_node),
            stats: ShardDispatcherStats::new(),
            retry_config: RetryConfig::default(),
        }
    }

    /// Create a new shard dispatcher with custom retry configuration.
    #[must_use]
    pub fn with_retry_config(
        transport: T,
        max_inflight_per_node: usize,
        retry_config: RetryConfig,
    ) -> Self {
        Self {
            transport,
            admission: PlacementAdmissionControl::new(max_inflight_per_node),
            stats: ShardDispatcherStats::new(),
            retry_config,
        }
    }

    /// Set per-node admission quota.
    pub fn set_node_quota(&mut self, node_id: u64, max_shards: usize) {
        self.admission.set_quota(node_id, max_shards);
    }

    /// Return a reference to the dispatcher statistics.
    #[must_use]
    pub fn stats(&self) -> &ShardDispatcherStats {
        &self.stats
    }

    /// Build a mapping from device_id to node_id from candidate devices.
    ///
    /// Falls back to using device_id as node_id when node_id is None.
    #[must_use]
    fn build_node_map(candidates: &[DeviceCandidate]) -> HashMap<u64, u64> {
        candidates
            .iter()
            .map(|c| (c.device_id, c.node_id.unwrap_or(c.device_id)))
            .collect()
    }

    /// Dispatch shards according to the placement plan.
    ///
    /// 1. Assigns devices via the plan using `placement_key`.
    /// 2. Maps each assigned device to a target node.
    /// 3. For each shard, sends a placement request via the transport.
    /// 4. Retries on transient failures with exponential backoff.
    /// 5. Collects outcomes.
    ///
    /// # Arguments
    ///
    /// * `placement_key` — scopes all shards to a single placement operation.
    /// * `plan` — the placement plan from TideCRUSH.
    /// * `candidates` — available device candidates.
    /// * `shard_data` — data for each shard slice, indexed by shard_index.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError` if the plan fails to assign devices, admission
    /// is refused, or all retry attempts are exhausted.
    pub fn dispatch(
        &mut self,
        placement_key: u64,
        plan: &PlacementPlan,
        candidates: &[DeviceCandidate],
        shard_data: &[Vec<u8>],
    ) -> Result<DispatchResult, DispatchError> {
        let start = Instant::now();

        // 1. Assign devices from the plan.
        let assignments = plan.assign_devices_for_key(candidates, placement_key)?;

        // 2. Build device→node mapping.
        let node_map = Self::build_node_map(candidates);

        // 3. Dispatch each shard to its target node.
        let mut outcomes = Vec::with_capacity(assignments.len());
        let mut total_retries: u32 = 0;

        for assignment in &assignments {
            let shard_index = assignment.shard_index as usize;

            // Look up the node for this device.
            let node_id = node_map.get(&assignment.device_id).copied().ok_or(
                DispatchError::NoNodeMapping {
                    device_id: assignment.device_id,
                },
            )?;

            // Admission control.
            if !self.admission.admit(node_id) {
                return Err(DispatchError::AdmissionRefused { node_id });
            }

            // Get the shard data slice.
            let data = shard_data.get(shard_index).cloned().unwrap_or_default();

            // Create the placement request.
            let request = ShardPlacementRequest::new(placement_key, assignment.shard_index, data);

            // Send with retries.
            let mut retries: u32 = 0;
            let mut last_error: Option<String> = None;

            let response = loop {
                match self.transport.send_shard(node_id, &request) {
                    Ok(resp) => break resp,
                    Err(ShardTransportError::Timeout { .. })
                    | Err(ShardTransportError::ConnectionFailed { .. }) => {
                        if self.retry_config.can_retry(retries) {
                            let backoff = self.retry_config.backoff_for_attempt(retries);
                            std::thread::sleep(backoff);
                            retries += 1;
                            continue;
                        }
                        let err = match last_error.take() {
                            Some(msg) => msg,
                            None => format!("transport failure after {retries} retries"),
                        };
                        self.admission.release(node_id);
                        return Err(DispatchError::ShardDispatchFailed {
                            node_id,
                            retries,
                            reason: err,
                        });
                    }
                    Err(e) => {
                        last_error = Some(e.to_string());
                        if self.retry_config.can_retry(retries) {
                            let backoff = self.retry_config.backoff_for_attempt(retries);
                            std::thread::sleep(backoff);
                            retries += 1;
                            continue;
                        }
                        self.admission.release(node_id);
                        return Err(DispatchError::ShardDispatchFailed {
                            node_id,
                            retries,
                            reason: last_error.unwrap_or_else(|| format!("{e}")),
                        });
                    }
                }
            };

            total_retries += retries;
            self.admission.release(node_id);

            // Record outcome.
            let accepted = response.accepted;
            outcomes.push(ShardDispatchOutcome {
                shard_index: assignment.shard_index,
                device_id: assignment.device_id,
                node_id,
                accepted,
                retries,
            });

            // Update stats.
            self.stats.shards_sent += 1;
            if accepted {
                self.stats.shards_accepted += 1;
            } else {
                self.stats.shards_rejected += 1;
                // Don't fail immediately — collect all outcomes first.
            }
            self.stats.retries += retries as u64;

            // If a shard was rejected by the target (not transport), fail fast
            // after recording the outcome.
            if !accepted {
                let _reason = response.reason.unwrap_or_else(|| "shard rejected".into());
                // Release any remaining inflight slots and return error.
                // We don't return here — collect all outcomes first, then the
                // caller decides via PlacementConfirmation.
            }
        }

        let elapsed_ms = start.elapsed().as_millis() as u64;
        self.stats.dispatch_count += 1;
        self.stats.total_dispatch_latency_ms += elapsed_ms;

        let all_accepted = outcomes.iter().all(|o| o.accepted);

        Ok(DispatchResult {
            outcomes,
            all_accepted,
            total_retries,
            elapsed_ms,
        })
    }
}

// ---------------------------------------------------------------------------
// Placement confirmation
// ---------------------------------------------------------------------------

/// Result of a placement confirmation (commit or abort).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementConfirmationResult {
    /// Whether the placement was committed (true) or aborted (false).
    pub committed: bool,
    /// Number of shards accepted by target nodes.
    pub accepted_shards: usize,
    /// Number of shards rejected by target nodes.
    pub rejected_shards: usize,
    /// Reason for abort, if any.
    pub abort_reason: Option<String>,
}

/// Confirms or aborts a shard placement across all target nodes.
///
/// On all shards accepted: calls `commit_placement` on each unique node.
/// On any shard rejected: calls `abort_placement` on each unique node that
/// accepted shards, freeing those resources.
pub struct PlacementConfirmation;

impl PlacementConfirmation {
    /// Confirm or abort a placement based on dispatch outcomes.
    ///
    /// If all shards were accepted, commits the placement on each unique
    /// target node. If any shard was rejected, aborts the placement on all
    /// nodes that accepted at least one shard.
    pub fn confirm<T: ShardTransport>(
        transport: &mut T,
        placement_key: u64,
        outcomes: &[ShardDispatchOutcome],
    ) -> Result<PlacementConfirmationResult, ShardTransportError> {
        let accepted: Vec<&ShardDispatchOutcome> = outcomes.iter().filter(|o| o.accepted).collect();
        let rejected: Vec<&ShardDispatchOutcome> =
            outcomes.iter().filter(|o| !o.accepted).collect();

        // Collect unique node IDs that accepted shards.
        let accepted_nodes: std::collections::BTreeSet<u64> =
            accepted.iter().map(|o| o.node_id).collect();

        if rejected.is_empty() {
            // All accepted: commit.
            for node_id in &accepted_nodes {
                transport.commit_placement(*node_id, placement_key)?;
            }
            Ok(PlacementConfirmationResult {
                committed: true,
                accepted_shards: accepted.len(),
                rejected_shards: 0,
                abort_reason: None,
            })
        } else {
            // Some rejected: abort on all accepting nodes.
            let abort_reason = rejected
                .first()
                .map(|o| format!("shard {} rejected on node {}", o.shard_index, o.node_id));

            for node_id in &accepted_nodes {
                // Best-effort abort — don't fail on abort errors.
                let _ = transport.abort_placement(*node_id, placement_key);
            }
            Ok(PlacementConfirmationResult {
                committed: false,
                accepted_shards: accepted.len(),
                rejected_shards: rejected.len(),
                abort_reason,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// In-memory mock transport for testing
// ---------------------------------------------------------------------------

/// A mock transport that stores shards in memory for testing.
#[derive(Debug, Clone, Default)]
pub struct MockShardTransport {
    /// Shards accepted, keyed by (node_id, placement_key, shard_index).
    pub accepted_shards: HashMap<(u64, u64, u8), ShardPlacementRequest>,
    /// Committed placements, keyed by (node_id, placement_key).
    pub committed_placements: HashMap<(u64, u64), ()>,
    /// Aborted placements, keyed by (node_id, placement_key).
    pub aborted_placements: HashMap<(u64, u64), ()>,
    /// Nodes configured to reject all shards.
    pub rejecting_nodes: std::collections::BTreeSet<u64>,
    /// Nodes configured to be transient-failure (fail N times then succeed).
    pub flaky_nodes: HashMap<u64, u32>,
    /// Count of attempts per flaky node.
    flaky_attempts: HashMap<u64, u32>,
}

impl MockShardTransport {
    /// Create a new mock transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure a node to reject all shards (simulating "node full").
    pub fn set_rejecting(&mut self, node_id: u64) {
        self.rejecting_nodes.insert(node_id);
    }

    /// Configure a node to fail `fail_count` times before succeeding.
    pub fn set_flaky(&mut self, node_id: u64, fail_count: u32) {
        self.flaky_nodes.insert(node_id, fail_count);
    }
}

impl ShardTransport for MockShardTransport {
    fn send_shard(
        &mut self,
        node_id: u64,
        request: &ShardPlacementRequest,
    ) -> Result<ShardPlacementResponse, ShardTransportError> {
        // Handle flaky nodes.
        if let Some(&fail_count) = self.flaky_nodes.get(&node_id) {
            let attempts = self.flaky_attempts.entry(node_id).or_insert(0);
            if *attempts < fail_count {
                *attempts += 1;
                return Err(ShardTransportError::ConnectionFailed {
                    node_id,
                    msg: format!("simulated flaky failure attempt {attempts}/{fail_count}"),
                });
            }
        }

        // Handle rejecting nodes.
        if self.rejecting_nodes.contains(&node_id) {
            return Ok(ShardPlacementResponse::rejected("node full"));
        }

        // Accept the shard.
        self.accepted_shards.insert(
            (node_id, request.placement_key, request.shard_index),
            request.clone(),
        );
        Ok(ShardPlacementResponse::accepted())
    }

    fn commit_placement(
        &mut self,
        node_id: u64,
        placement_key: u64,
    ) -> Result<(), ShardTransportError> {
        self.committed_placements
            .insert((node_id, placement_key), ());
        Ok(())
    }

    fn abort_placement(
        &mut self,
        node_id: u64,
        placement_key: u64,
    ) -> Result<(), ShardTransportError> {
        self.aborted_placements.insert((node_id, placement_key), ());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_durability_layout::{DurabilityLayoutV1, FailureDomainLevel, FailureDomainV1};
    use tidefs_placement_planner::placement_plan::DeviceCandidate;

    // --- Helpers ---

    fn dev_node(device_id: u64, node_id: u64) -> DeviceCandidate {
        DeviceCandidate {
            device_id,
            node_id: Some(node_id),
            rack_id: None,
            datacenter_id: None,
        }
    }

    fn mirror_plan(copies: u8, domains: u8) -> PlacementPlan {
        let layout = DurabilityLayoutV1::mirror(copies).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, domains).unwrap();
        PlacementPlan::from_layout(layout, fd)
    }

    // --- ShardPlacementRequest ---

    #[test]
    fn test_request_checksum_verification() {
        let data = b"hello shard world".to_vec();
        let req = ShardPlacementRequest::new(42, 0, data.clone());
        assert!(req.verify_checksum());

        // Corrupted data should fail verification.
        let mut bad = req.clone();
        bad.shard_data[0] ^= 0xff;
        assert!(!bad.verify_checksum());
    }

    // --- Shard dispatch: all accepted ---

    #[test]
    fn test_dispatch_all_accepted_4_shards() {
        let transport = MockShardTransport::new();
        let mut dispatcher = ShardDispatcher::new(transport, 16);

        let plan = mirror_plan(4, 4);
        let candidates: Vec<_> = (1..=4).map(|i| dev_node(i, i * 10)).collect();
        let shard_data: Vec<Vec<u8>> = (0..4).map(|i| format!("shard_{i}").into_bytes()).collect();

        let result = dispatcher
            .dispatch(1, &plan, &candidates, &shard_data)
            .expect("dispatch should succeed");

        assert_eq!(result.outcomes.len(), 4);
        assert!(result.all_accepted);
        assert_eq!(result.total_retries, 0);
        assert_eq!(dispatcher.stats().shards_sent, 4);
        assert_eq!(dispatcher.stats().shards_accepted, 4);
        assert_eq!(dispatcher.stats().shards_rejected, 0);
        assert!(dispatcher.stats().avg_dispatch_latency_ms() >= 0.0);
        assert!((dispatcher.stats().acceptance_rate() - 1.0).abs() < f64::EPSILON);
    }

    // --- Shard dispatch: 4+2 erasure ---

    #[test]
    fn test_dispatch_all_accepted_6_shards() {
        let transport = MockShardTransport::new();
        let mut dispatcher = ShardDispatcher::new(transport, 16);

        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 6).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates: Vec<_> = (1..=6).map(|i| dev_node(i, i * 10)).collect();
        let shard_data: Vec<Vec<u8>> = (0..6).map(|i| format!("shard_{i}").into_bytes()).collect();

        let result = dispatcher
            .dispatch(1, &plan, &candidates, &shard_data)
            .expect("dispatch should succeed");

        assert_eq!(result.outcomes.len(), 6);
        assert!(result.all_accepted);
        assert_eq!(dispatcher.stats().shards_sent, 6);
        assert_eq!(dispatcher.stats().shards_accepted, 6);
        assert_eq!(dispatcher.stats().shards_rejected, 0);
    }

    // --- Shard rejection (node full) ---

    #[test]
    fn test_dispatch_shard_rejection_node_full() {
        let mut transport = MockShardTransport::new();
        // Node 20 rejects all shards ("full").
        transport.set_rejecting(20);

        let mut dispatcher = ShardDispatcher::new(transport, 16);

        let plan = mirror_plan(2, 2);
        let candidates = vec![dev_node(1, 10), dev_node(2, 20)];
        let shard_data: Vec<Vec<u8>> = vec![b"shard_0".to_vec(), b"shard_1".to_vec()];

        let result = dispatcher
            .dispatch(1, &plan, &candidates, &shard_data)
            .expect("dispatch should succeed");

        assert_eq!(result.outcomes.len(), 2);
        assert!(!result.all_accepted);
        assert_eq!(dispatcher.stats().shards_sent, 2);
        assert_eq!(dispatcher.stats().shards_accepted, 1);
        assert_eq!(dispatcher.stats().shards_rejected, 1);
    }

    // --- Retry on transient failure ---

    #[test]
    fn test_dispatch_retry_on_transient_failure() {
        let mut transport = MockShardTransport::new();
        // Node 10 fails first 2 attempts, then succeeds.
        transport.set_flaky(10, 2);

        let retry_config = RetryConfig {
            max_retries: 3,
            initial_backoff_ms: 1,
            max_backoff_ms: 10,
            backoff_multiplier: 2.0,
        };
        let mut dispatcher = ShardDispatcher::with_retry_config(transport, 16, retry_config);

        let plan = mirror_plan(2, 2);
        let candidates = vec![dev_node(1, 10), dev_node(2, 20)];
        let shard_data: Vec<Vec<u8>> = vec![b"shard_0".to_vec(), b"shard_1".to_vec()];

        let result = dispatcher
            .dispatch(1, &plan, &candidates, &shard_data)
            .expect("dispatch should succeed");

        assert_eq!(result.outcomes.len(), 2);
        assert!(result.all_accepted);
        // Total retries should be 2 (for node 10).
        assert_eq!(result.total_retries, 2);
        assert_eq!(dispatcher.stats().retries, 2);
    }

    // --- Placement confirmation: commit ---

    #[test]
    fn test_placement_commit() {
        let transport = MockShardTransport::new();
        let mut dispatcher = ShardDispatcher::new(transport, 16);

        let plan = mirror_plan(2, 2);
        let candidates = vec![dev_node(1, 10), dev_node(2, 20)];
        let shard_data: Vec<Vec<u8>> = vec![b"shard_0".to_vec(), b"shard_1".to_vec()];

        let result = dispatcher
            .dispatch(42, &plan, &candidates, &shard_data)
            .expect("dispatch should succeed");
        assert!(result.all_accepted);

        let confirm_result =
            PlacementConfirmation::confirm(&mut dispatcher.transport, 42, &result.outcomes)
                .expect("confirm should succeed");

        assert!(confirm_result.committed);
        assert_eq!(confirm_result.accepted_shards, 2);
        assert_eq!(confirm_result.rejected_shards, 0);

        // Both nodes should have committed.
        assert!(dispatcher
            .transport
            .committed_placements
            .contains_key(&(10, 42)));
        assert!(dispatcher
            .transport
            .committed_placements
            .contains_key(&(20, 42)));
    }

    // --- Placement confirmation: abort ---

    #[test]
    fn test_placement_abort_on_rejection() {
        let mut transport = MockShardTransport::new();
        transport.set_rejecting(20);

        let mut dispatcher = ShardDispatcher::new(transport, 16);

        let plan = mirror_plan(2, 2);
        let candidates = vec![dev_node(1, 10), dev_node(2, 20)];
        let shard_data: Vec<Vec<u8>> = vec![b"shard_0".to_vec(), b"shard_1".to_vec()];

        let result = dispatcher
            .dispatch(99, &plan, &candidates, &shard_data)
            .expect("dispatch should succeed");
        assert!(!result.all_accepted);

        let confirm_result =
            PlacementConfirmation::confirm(&mut dispatcher.transport, 99, &result.outcomes)
                .expect("confirm should succeed");

        assert!(!confirm_result.committed);
        assert_eq!(confirm_result.accepted_shards, 1);
        assert_eq!(confirm_result.rejected_shards, 1);
        assert!(confirm_result.abort_reason.is_some());

        // Node 10 accepted a shard, so it should have been aborted.
        assert!(dispatcher
            .transport
            .aborted_placements
            .contains_key(&(10, 99)));
        // Node 20 had no accepted shards, so no abort needed.
    }

    // --- Admission control ---

    #[test]
    fn test_admission_control_inflight_limit() {
        let mut ac = PlacementAdmissionControl::new(2);

        assert!(ac.can_admit(10));
        assert!(ac.admit(10));
        assert!(ac.can_admit(10));
        assert!(ac.admit(10));
        // At inflight limit of 2.
        assert!(!ac.can_admit(10));
        assert!(!ac.admit(10));

        // Release one.
        ac.release(10);
        assert!(ac.can_admit(10));
        assert!(ac.admit(10));
    }

    #[test]
    fn test_admission_control_quota() {
        let mut ac = PlacementAdmissionControl::new(16);
        ac.set_quota(10, 3);

        assert!(ac.admit(10));
        assert!(ac.admit(10));
        assert!(ac.admit(10));
        // Quota exhausted.
        assert!(!ac.can_admit(10));
        assert!(!ac.admit(10));

        // Reset clears quota tracking.
        ac.reset();
        assert_eq!(ac.admitted_count(10), 0);
    }

    // --- Retry config ---

    #[test]
    fn test_retry_backoff_grows_exponentially() {
        let config = RetryConfig::default();
        let b0 = config.backoff_for_attempt(0);
        let b1 = config.backoff_for_attempt(1);
        let b2 = config.backoff_for_attempt(2);

        assert_eq!(b0, Duration::from_millis(50));
        assert_eq!(b1, Duration::from_millis(100));
        assert_eq!(b2, Duration::from_millis(200));
    }

    #[test]
    fn test_retry_capped_at_max_backoff() {
        let config = RetryConfig {
            max_retries: 10,
            initial_backoff_ms: 100,
            max_backoff_ms: 500,
            backoff_multiplier: 2.0,
        };
        // Attempt 3 would be 800ms, but capped at 500ms.
        let b3 = config.backoff_for_attempt(3);
        assert_eq!(b3, Duration::from_millis(500));
    }

    #[test]
    fn test_retry_limit() {
        let config = RetryConfig {
            max_retries: 3,
            ..Default::default()
        };
        assert!(config.can_retry(0));
        assert!(config.can_retry(2));
        assert!(!config.can_retry(3));
    }

    // --- Multiple concurrent placements ---

    #[test]
    fn test_multiple_concurrent_placements() {
        let transport = MockShardTransport::new();
        let mut dispatcher = ShardDispatcher::new(transport, 16);

        let plan = mirror_plan(2, 2);
        let candidates = vec![dev_node(1, 10), dev_node(2, 20)];

        let shard_data_a: Vec<Vec<u8>> = vec![b"a_0".to_vec(), b"a_1".to_vec()];
        let shard_data_b: Vec<Vec<u8>> = vec![b"b_0".to_vec(), b"b_1".to_vec()];

        let r1 = dispatcher
            .dispatch(100, &plan, &candidates, &shard_data_a)
            .expect("first dispatch should succeed");
        let r2 = dispatcher
            .dispatch(200, &plan, &candidates, &shard_data_b)
            .expect("second dispatch should succeed");

        assert!(r1.all_accepted);
        assert!(r2.all_accepted);
        assert_eq!(dispatcher.stats().shards_sent, 4);
        assert_eq!(dispatcher.stats().shards_accepted, 4);
        assert_eq!(dispatcher.stats().dispatch_count, 2);
    }

    // --- Node map fallback: device_id when node_id is None ---

    #[test]
    fn test_node_map_falls_back_to_device_id() {
        let candidates = vec![
            DeviceCandidate {
                device_id: 5,
                node_id: None,
                rack_id: None,
                datacenter_id: None,
            },
            dev_node(2, 20),
        ];
        let map = ShardDispatcher::<MockShardTransport>::build_node_map(&candidates);
        assert_eq!(map.get(&5), Some(&5));
        assert_eq!(map.get(&2), Some(&20));
    }

    // --- ShardPlacementResponse constructors ---

    #[test]
    fn test_response_constructors() {
        let accepted = ShardPlacementResponse::accepted();
        assert!(accepted.accepted);
        assert!(accepted.reason.is_none());

        let rejected = ShardPlacementResponse::rejected("disk full");
        assert!(!rejected.accepted);
        assert_eq!(rejected.reason, Some("disk full".into()));
    }
}

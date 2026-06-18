// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Per-channel send-path backpressure enforcement with configurable depth
//! limits and overflow rejection.
//!
//! This module prevents unbounded memory growth under receiver slowdown by
//! gating message submission through a slot-acquire/release protocol. Each
//! channel has an independent depth counter; callers that exceed the
//! per-channel limit receive an immediate [`BackpressureRejected`] error
//! instead of being allowed to queue unbounded messages.
//!
//! The backpressure-depth signal feeds the connection health score (#5885)
//! via [`BackpressureController::backpressure_snapshot`], which provides
//! a read-only view of per-channel depth, high-watermark, and stall state.
//!
//! ## Quick start
//!
//! ```ignore
//! use tidefs_transport::backpressure::{
//!     BackpressureController, ChannelBackpressureConfig,
//! };
//! use tidefs_transport::channel::ChannelId;
//!
//! let config = ChannelBackpressureConfig {
//!     max_depth: 128,
//!     stall_threshold_fraction: 0.75,
//!     byte_budget: None,
//! };
//! let mut ctrl = BackpressureController::new(config);
//!
//! let ch = ChannelId::new(1);
//! let slot = ctrl.try_acquire_send_slot(ch).unwrap();
//! // ... enqueue message for send ...
//! ctrl.release_send_slot(slot);
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::channel::ChannelId;

// ---------------------------------------------------------------
// OutboundBackpressureConfig / BackpressureMode
// ---------------------------------------------------------------

/// Backpressure enforcement mode for the connection-level outbound queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackpressureMode {
    Notify,
    Block,
    DropTail,
}

/// Connection-level outbound backpressure configuration.
#[derive(Clone, Debug)]
pub struct OutboundBackpressureConfig {
    pub high_watermark: usize,
    pub mode: BackpressureMode,
}

impl Default for OutboundBackpressureConfig {
    fn default() -> Self {
        Self {
            high_watermark: 1024,
            mode: BackpressureMode::Notify,
        }
    }
}

// ---------------------------------------------------------------
// BackpressureStatus
// ---------------------------------------------------------------

/// Read-only snapshot of connection-level backpressure state.
#[derive(Clone, Copy, Debug)]
pub struct BackpressureStatus {
    pub current_depth: usize,
    pub high_watermark: usize,
    pub under_pressure: bool,
    pub mode: BackpressureMode,
}

// ---------------------------------------------------------------
// BackpressureCallback
// ---------------------------------------------------------------

/// Callback trait for connection-level backpressure transitions.
pub trait BackpressureCallback: Send + Sync {
    fn on_backpressure(&self, conn_id: u64, depth: usize);
    fn on_drained(&self, conn_id: u64);
}

// ---------------------------------------------------------------
// WouldBlock
// ---------------------------------------------------------------

/// Returned by non-blocking send attempts under backpressure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WouldBlock;

impl fmt::Display for WouldBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("outbound queue backpressure: would block")
    }
}

impl std::error::Error for WouldBlock {}

// ---------------------------------------------------------------------------
// ChannelBackpressureConfig
// ---------------------------------------------------------------------------

/// Per-channel backpressure configuration.
///
/// Each channel independently enforces the depth limit. The stall threshold
/// is a fraction of `max_depth` at or above which the channel is considered
/// stalled — this feeds the connection health score and can trigger
/// [`crate::error_classification::TransportErrorKind::BackpressureStall`].
#[derive(Clone, Debug)]
pub struct ChannelBackpressureConfig {
    /// Maximum number of in-flight (queued but not yet sent/completed)
    /// messages per channel.
    pub max_depth: usize,

    /// Fraction of `max_depth` (0.0–1.0) at which the channel is flagged
    /// as stalled.  Values outside [0.0, 1.0] are clamped.
    pub stall_threshold_fraction: f64,

    /// Optional absolute per-channel byte budget.  When `Some(n)`, acquires
    /// also deduct from the byte budget so that large payloads are gated
    /// independently of the message-count limit.  `None` disables size-aware
    /// gating (only message counts are enforced).
    pub byte_budget: Option<usize>,
}

impl Default for ChannelBackpressureConfig {
    fn default() -> Self {
        Self {
            max_depth: 256,
            stall_threshold_fraction: 0.75,
            byte_budget: None,
        }
    }
}

impl ChannelBackpressureConfig {
    /// The depth at which the channel is considered stalled.
    #[must_use]
    pub fn stall_depth(&self) -> usize {
        let frac = self.stall_threshold_fraction.clamp(0.0, 1.0);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let depth = (self.max_depth as f64 * frac) as usize;
        // At least 1, unless max_depth is 0.
        if self.max_depth == 0 {
            0
        } else {
            depth.max(1)
        }
    }
}

// ---------------------------------------------------------------------------
// ChannelBackpressureState
// ---------------------------------------------------------------------------

/// Tracks current queue depth, high watermark, and stall status for a single
/// channel.
#[derive(Clone, Debug)]
struct ChannelBackpressureState {
    /// Current number of acquired-but-not-yet-released send slots.
    depth: usize,

    /// Peak depth observed since the last reset.
    high_watermark: usize,

    /// Whether the channel is currently flagged as stalled.
    stalled: bool,

    /// Current byte usage (only meaningful when `byte_budget` is `Some`).
    byte_usage: usize,
}

impl ChannelBackpressureState {
    fn new() -> Self {
        Self {
            depth: 0,
            high_watermark: 0,
            stalled: false,
            byte_usage: 0,
        }
    }

    fn acquire(
        &mut self,
        cfg: &ChannelBackpressureConfig,
        byte_hint: usize,
    ) -> Result<(), BackpressureRejected> {
        if self.depth >= cfg.max_depth {
            return Err(BackpressureRejected {
                channel: ChannelId::default(), // filled in by the controller
                current_depth: self.depth,
                limit: cfg.max_depth,
            });
        }
        if let Some(budget) = cfg.byte_budget {
            if self.byte_usage + byte_hint > budget {
                return Err(BackpressureRejected {
                    channel: ChannelId::default(),
                    current_depth: self.depth,
                    limit: cfg.max_depth,
                });
            }
        }
        self.depth = self.depth.saturating_add(1);
        self.byte_usage = self.byte_usage.saturating_add(byte_hint);
        self.high_watermark = self.high_watermark.max(self.depth);
        self.stalled = self.depth >= cfg.stall_depth();
        Ok(())
    }

    fn release(&mut self, cfg: &ChannelBackpressureConfig, byte_hint: usize) {
        self.depth = self.depth.saturating_sub(1);
        self.byte_usage = self.byte_usage.saturating_sub(byte_hint);
        self.stalled = self.depth >= cfg.stall_depth();
    }

    fn snapshot(&self) -> ChannelSnapshot {
        ChannelSnapshot {
            depth: self.depth,
            high_watermark: self.high_watermark,
            stalled: self.stalled,
            byte_usage: self.byte_usage,
        }
    }
}

// ---------------------------------------------------------------------------
// SendSlot
// ---------------------------------------------------------------------------

/// An opaque token representing an acquired send slot.
///
/// Dropping a `SendSlot` without calling [`BackpressureController::release_send_slot`]
/// leaks the slot (the depth counter is not decremented).  Callers must
/// release slots explicitly after the send pipeline completes.
#[derive(Debug)]
pub struct SendSlot {
    channel: ChannelId,
    /// Byte hint recorded at acquire time for accurate byte-budget release.
    byte_hint: usize,
}

impl SendSlot {
    fn new(channel: ChannelId, byte_hint: usize) -> Self {
        Self { channel, byte_hint }
    }
}

// ---------------------------------------------------------------------------
// BackpressureRejected
// ---------------------------------------------------------------------------

/// Returned when a send-slot acquire fails because the channel is at capacity.
#[derive(Clone, Copy, Debug)]
pub struct BackpressureRejected {
    /// The channel whose depth limit was hit.
    pub channel: ChannelId,
    /// Current in-flight depth at rejection time.
    pub current_depth: usize,
    /// Configured maximum depth for this channel.
    pub limit: usize,
}

impl fmt::Display for BackpressureRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "backpressure rejected on {}: depth {}/{}",
            self.channel, self.current_depth, self.limit
        )
    }
}

// ---------------------------------------------------------------------------
// ChannelSnapshot / BackpressureSnapshot
// ---------------------------------------------------------------------------

/// Read-only per-channel backpressure state.
#[derive(Clone, Copy, Debug)]
pub struct ChannelSnapshot {
    /// Current in-flight depth.
    pub depth: usize,
    /// Highest depth observed since the last reset.
    pub high_watermark: usize,
    /// Whether the channel is flagged as stalled.
    pub stalled: bool,
    /// Current byte usage (0 when `byte_budget` is `None`).
    pub byte_usage: usize,
}

/// Read-only snapshot of backpressure state across all channels.
///
/// Consumed by the connection health score aggregator (#5885).
#[derive(Clone, Debug)]
pub struct BackpressureSnapshot {
    /// Per-channel snapshots.
    pub channels: HashMap<ChannelId, ChannelSnapshot>,
    /// Total in-flight messages across all channels.
    pub total_depth: usize,
    /// Number of channels currently flagged as stalled.
    pub stalled_channels: usize,
}

// ---------------------------------------------------------------------------
// BackpressureController
// ---------------------------------------------------------------------------

/// Owns per-channel backpressure state and enforces depth limits on send-slot
/// acquisition.
///
/// One `BackpressureController` is instantiated per transport connection
/// during setup and torn down on disconnect.  Every send submission consults
/// the controller before the message is allowed into the send pipeline.
#[derive(Clone, Debug)]
pub struct BackpressureController {
    config: ChannelBackpressureConfig,
    states: HashMap<ChannelId, ChannelBackpressureState>,
}

impl BackpressureController {
    /// Create a new controller with the given configuration.
    #[must_use]
    pub fn new(config: ChannelBackpressureConfig) -> Self {
        Self {
            config,
            states: HashMap::new(),
        }
    }

    /// Attempt to acquire a send slot for `channel`.
    ///
    /// Returns `Ok(SendSlot)` when a slot is available.  Returns
    /// `Err(BackpressureRejected)` when the channel's depth limit or byte
    /// budget would be exceeded.
    ///
    /// The `byte_hint` is an estimate of the message payload size used for
    /// byte-budget accounting.  Pass 0 when `byte_budget` is `None` or when
    /// size information is not available.
    pub fn try_acquire_send_slot(
        &mut self,
        channel: ChannelId,
    ) -> Result<SendSlot, BackpressureRejected> {
        self.try_acquire_send_slot_with_hint(channel, 0)
    }

    /// Attempt to acquire a send slot with a byte-size hint.
    pub fn try_acquire_send_slot_with_hint(
        &mut self,
        channel: ChannelId,
        byte_hint: usize,
    ) -> Result<SendSlot, BackpressureRejected> {
        let state = self
            .states
            .entry(channel)
            .or_insert_with(ChannelBackpressureState::new);
        state.acquire(&self.config, byte_hint).map_err(|mut e| {
            e.channel = channel;
            e
        })?;
        Ok(SendSlot::new(channel, byte_hint))
    }

    /// Release a previously acquired send slot.
    ///
    /// Must be called after the send pipeline completes (success or failure)
    /// so the depth counter is decremented and the slot becomes available
    /// for a new caller.
    pub fn release_send_slot(&mut self, slot: SendSlot) {
        if let Some(state) = self.states.get_mut(&slot.channel) {
            state.release(&self.config, slot.byte_hint);
        }
    }

    /// Return a read-only snapshot of all per-channel backpressure state.
    ///
    /// This snapshot is consumed by the connection health score aggregator
    /// (#5885) to incorporate backpressure depth as a multi-signal input.
    #[must_use]
    pub fn backpressure_snapshot(&self) -> BackpressureSnapshot {
        let mut total_depth = 0usize;
        let mut stalled_channels = 0usize;
        let channels: HashMap<ChannelId, ChannelSnapshot> = self
            .states
            .iter()
            .map(|(ch, state)| {
                let snap = state.snapshot();
                total_depth = total_depth.saturating_add(snap.depth);
                if snap.stalled {
                    stalled_channels = stalled_channels.saturating_add(1);
                }
                (*ch, snap)
            })
            .collect();

        BackpressureSnapshot {
            channels,
            total_depth,
            stalled_channels,
        }
    }

    /// Reset all per-channel state to zero (for connection teardown /
    /// re-initialization).
    pub fn reset(&mut self) {
        self.states.clear();
    }

    /// Return the number of tracked channels.
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.states.len()
    }

    /// Return a reference to the configuration.
    #[must_use]
    pub fn config(&self) -> &ChannelBackpressureConfig {
        &self.config
    }
}

// ---------------------------------------------------------------
// OutboundBackpressure: connection-level wrapper
// ---------------------------------------------------------------

/// Connection-level backpressure manager wrapping [`BackpressureController`].
#[derive(Clone)]
pub struct OutboundBackpressure {
    controller: BackpressureController,
    config: OutboundBackpressureConfig,
    callbacks: Arc<std::sync::Mutex<Vec<Arc<dyn BackpressureCallback>>>>,
    under_pressure: Arc<std::sync::Mutex<bool>>,
    dropped_count: Arc<std::sync::atomic::AtomicU64>,
    conn_id: u64,
}

impl OutboundBackpressure {
    #[must_use]
    pub fn new(cc: ChannelBackpressureConfig, cfg: OutboundBackpressureConfig) -> Self {
        Self::with_conn_id(cc, cfg, 0)
    }

    /// Create with an explicit connection identifier for callback dispatch.
    #[must_use]
    pub fn with_conn_id(
        cc: ChannelBackpressureConfig,
        cfg: OutboundBackpressureConfig,
        conn_id: u64,
    ) -> Self {
        Self {
            controller: BackpressureController::new(cc),
            config: cfg,
            callbacks: Arc::new(std::sync::Mutex::new(Vec::new())),
            under_pressure: Arc::new(std::sync::Mutex::new(false)),
            dropped_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            conn_id,
        }
    }

    #[must_use]
    pub fn with_config(cfg: OutboundBackpressureConfig) -> Self {
        Self::with_conn_id(ChannelBackpressureConfig::default(), cfg, 0)
    }

    pub fn register_callback(&self, cb: Arc<dyn BackpressureCallback>) {
        if let Ok(mut g) = self.callbacks.lock() {
            g.push(cb);
        }
    }

    #[must_use]
    pub fn status(&self) -> BackpressureStatus {
        let t = self.controller.backpressure_snapshot().total_depth;
        BackpressureStatus {
            current_depth: t,
            high_watermark: self.config.high_watermark,
            under_pressure: t >= self.config.high_watermark && self.config.high_watermark > 0,
            mode: self.config.mode,
        }
    }

    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn try_acquire(&mut self, ch: ChannelId, hint: usize) -> Result<SendSlot, WouldBlock> {
        let snap = self.controller.backpressure_snapshot();
        if snap.total_depth >= self.config.high_watermark && self.config.high_watermark > 0 {
            match self.config.mode {
                BackpressureMode::Notify | BackpressureMode::DropTail => {}
                BackpressureMode::Block => return Err(WouldBlock),
            }
        }
        match self.controller.try_acquire_send_slot_with_hint(ch, hint) {
            Ok(s) => {
                self._fire_bp();
                Ok(s)
            }
            Err(_) => Err(WouldBlock),
        }
    }

    pub fn release(&mut self, slot: SendSlot) {
        self.controller.release_send_slot(slot);
        self._fire_drain();
    }

    pub fn record_drop_tail(&self) {
        self.dropped_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> BackpressureSnapshot {
        self.controller.backpressure_snapshot()
    }

    #[must_use]
    pub fn controller(&self) -> &BackpressureController {
        &self.controller
    }
    #[must_use]
    pub fn controller_mut(&mut self) -> &mut BackpressureController {
        &mut self.controller
    }

    pub fn reset(&mut self) {
        self.controller.reset();
        if let Ok(mut g) = self.under_pressure.lock() {
            *g = false;
        }
    }

    #[must_use]
    pub fn outbound_config(&self) -> &OutboundBackpressureConfig {
        &self.config
    }

    /// Return the connection identifier assigned by the connection manager.
    #[must_use]
    pub fn conn_id(&self) -> u64 {
        self.conn_id
    }

    fn _fire_bp(&self) {
        let t = self.controller.backpressure_snapshot().total_depth;
        if t >= self.config.high_watermark && self.config.high_watermark > 0 {
            let mut u = self.under_pressure.lock().unwrap();
            if !*u {
                *u = true;
                drop(u);
                if let Ok(cbs) = self.callbacks.lock() {
                    for cb in cbs.iter() {
                        cb.on_backpressure(self.conn_id, t);
                    }
                }
            }
        }
    }

    fn _fire_drain(&self) {
        if self.controller.backpressure_snapshot().total_depth == 0 {
            let mut u = self.under_pressure.lock().unwrap();
            if *u {
                *u = false;
                drop(u);
                if let Ok(cbs) = self.callbacks.lock() {
                    for cb in cbs.iter() {
                        cb.on_drained(self.conn_id);
                    }
                }
            }
        }
    }
}

impl fmt::Debug for OutboundBackpressure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundBackpressure")
            .field("conn_id", &self.conn_id)
            .field("config", &self.config)
            .field("status", &self.status())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Config
    // -----------------------------------------------------------------------

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = ChannelBackpressureConfig::default();
        assert_eq!(cfg.max_depth, 256);
        assert!((cfg.stall_threshold_fraction - 0.75).abs() < f64::EPSILON);
        assert!(cfg.byte_budget.is_none());
    }

    #[test]
    fn stall_depth_computes_correctly() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 100,
            stall_threshold_fraction: 0.3,
            ..Default::default()
        };
        assert_eq!(cfg.stall_depth(), 30);
    }

    #[test]
    fn stall_depth_at_least_one() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 10,
            stall_threshold_fraction: 0.01,
            ..Default::default()
        };
        assert_eq!(cfg.stall_depth(), 1);
    }

    #[test]
    fn stall_depth_zero_for_zero_max_depth() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 0,
            stall_threshold_fraction: 0.75,
            ..Default::default()
        };
        assert_eq!(cfg.stall_depth(), 0);
    }

    #[test]
    fn stall_depth_clamped_to_max_depth() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 100,
            stall_threshold_fraction: 1.0,
            ..Default::default()
        };
        assert_eq!(cfg.stall_depth(), 100);
    }

    #[test]
    fn stall_threshold_out_of_range_clamped() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 50,
            stall_threshold_fraction: 1.5,
            ..Default::default()
        };
        assert_eq!(cfg.stall_depth(), 50);

        let cfg2 = ChannelBackpressureConfig {
            max_depth: 50,
            stall_threshold_fraction: -0.5,
            ..Default::default()
        };
        assert_eq!(cfg2.stall_depth(), 1);
    }

    // -----------------------------------------------------------------------
    // Acquire / release / reject
    // -----------------------------------------------------------------------

    #[test]
    fn acquire_up_to_limit_succeeds() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 5,
            stall_threshold_fraction: 0.75,
            ..Default::default()
        };
        let mut ctrl = BackpressureController::new(cfg);
        let ch = ChannelId::new(1);

        let mut slots = Vec::new();
        for _ in 0..5 {
            let slot = ctrl.try_acquire_send_slot(ch).unwrap();
            slots.push(slot);
        }
        assert_eq!(slots.len(), 5);
    }

    #[test]
    fn acquire_beyond_limit_rejects() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 3,
            ..Default::default()
        };
        let mut ctrl = BackpressureController::new(cfg);
        let ch = ChannelId::new(1);

        ctrl.try_acquire_send_slot(ch).unwrap();
        ctrl.try_acquire_send_slot(ch).unwrap();
        ctrl.try_acquire_send_slot(ch).unwrap();

        let err = ctrl.try_acquire_send_slot(ch).unwrap_err();
        assert_eq!(err.channel, ch);
        assert_eq!(err.current_depth, 3);
        assert_eq!(err.limit, 3);
    }

    #[test]
    fn rejection_error_display_contains_context() {
        let err = BackpressureRejected {
            channel: ChannelId::new(7),
            current_depth: 10,
            limit: 10,
        };
        let s = err.to_string();
        assert!(s.contains("ch7"));
        assert!(s.contains("10/10"));
    }

    #[test]
    fn release_frees_slot_for_reacquire() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 2,
            ..Default::default()
        };
        let mut ctrl = BackpressureController::new(cfg);
        let ch = ChannelId::new(1);

        let s1 = ctrl.try_acquire_send_slot(ch).unwrap();
        let s2 = ctrl.try_acquire_send_slot(ch).unwrap();

        assert!(ctrl.try_acquire_send_slot(ch).is_err());

        ctrl.release_send_slot(s1);
        let s3 = ctrl.try_acquire_send_slot(ch).unwrap();
        ctrl.release_send_slot(s2);
        ctrl.release_send_slot(s3);

        // Back to empty
        for _ in 0..2 {
            ctrl.try_acquire_send_slot(ch).unwrap();
        }
    }

    #[test]
    fn stall_flag_transitions_at_threshold() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 10,
            stall_threshold_fraction: 0.5,
            ..Default::default()
        };
        let mut ctrl = BackpressureController::new(cfg);
        let ch = ChannelId::new(1);

        let mut slots = Vec::new();
        for _ in 0..4 {
            slots.push(ctrl.try_acquire_send_slot(ch).unwrap());
        }
        let snap = ctrl.backpressure_snapshot();
        let ch_snap = snap.channels.get(&ch).unwrap();
        assert!(!ch_snap.stalled);

        slots.push(ctrl.try_acquire_send_slot(ch).unwrap());
        let snap = ctrl.backpressure_snapshot();
        let ch_snap = snap.channels.get(&ch).unwrap();
        assert!(ch_snap.stalled);

        ctrl.release_send_slot(slots.pop().unwrap());
        let snap = ctrl.backpressure_snapshot();
        let ch_snap = snap.channels.get(&ch).unwrap();
        assert!(!ch_snap.stalled);
    }

    #[test]
    fn snapshot_accuracy_across_acquire_release_cycles() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 100,
            stall_threshold_fraction: 0.75,
            ..Default::default()
        };
        let mut ctrl = BackpressureController::new(cfg);
        let ch_a = ChannelId::new(1);
        let ch_b = ChannelId::new(2);

        ctrl.try_acquire_send_slot(ch_a).unwrap();
        ctrl.try_acquire_send_slot(ch_a).unwrap();
        ctrl.try_acquire_send_slot(ch_b).unwrap();

        let snap = ctrl.backpressure_snapshot();
        assert_eq!(snap.total_depth, 3);
        assert_eq!(snap.stalled_channels, 0);
        assert_eq!(snap.channels.get(&ch_a).unwrap().depth, 2);
        assert_eq!(snap.channels.get(&ch_a).unwrap().high_watermark, 2);
        assert_eq!(snap.channels.get(&ch_b).unwrap().depth, 1);
        assert_eq!(snap.channels.get(&ch_b).unwrap().high_watermark, 1);
    }

    #[test]
    fn high_watermark_tracks_peak() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 10,
            ..Default::default()
        };
        let mut ctrl = BackpressureController::new(cfg);
        let ch = ChannelId::new(1);

        let mut slots = Vec::new();
        for _ in 0..7 {
            slots.push(ctrl.try_acquire_send_slot(ch).unwrap());
        }

        let snap = ctrl.backpressure_snapshot();
        assert_eq!(snap.channels.get(&ch).unwrap().high_watermark, 7);

        for _ in 0..4 {
            ctrl.release_send_slot(slots.pop().unwrap());
        }

        let snap = ctrl.backpressure_snapshot();
        assert_eq!(snap.channels.get(&ch).unwrap().depth, 3);
        assert_eq!(snap.channels.get(&ch).unwrap().high_watermark, 7);
    }

    #[test]
    fn concurrent_interleaving_correctness() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 5,
            ..Default::default()
        };
        let mut ctrl = BackpressureController::new(cfg);
        let ch1 = ChannelId::new(1);
        let ch2 = ChannelId::new(2);

        ctrl.try_acquire_send_slot(ch1).unwrap();
        ctrl.try_acquire_send_slot(ch2).unwrap();
        ctrl.try_acquire_send_slot(ch1).unwrap();
        ctrl.try_acquire_send_slot(ch2).unwrap();

        let snap = ctrl.backpressure_snapshot();
        assert_eq!(snap.channels.get(&ch1).unwrap().depth, 2);
        assert_eq!(snap.channels.get(&ch2).unwrap().depth, 2);
        assert_eq!(snap.total_depth, 4);

        ctrl.try_acquire_send_slot(ch1).unwrap();
        ctrl.try_acquire_send_slot(ch1).unwrap();
        ctrl.try_acquire_send_slot(ch1).unwrap(); // depth 5

        assert!(ctrl.try_acquire_send_slot(ch1).is_err());
        ctrl.try_acquire_send_slot(ch2).unwrap();
    }

    #[test]
    fn reset_clears_all_state() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 10,
            ..Default::default()
        };
        let mut ctrl = BackpressureController::new(cfg);
        ctrl.try_acquire_send_slot(ChannelId::new(1)).unwrap();
        ctrl.try_acquire_send_slot(ChannelId::new(2)).unwrap();

        assert_eq!(ctrl.channel_count(), 2);

        ctrl.reset();
        assert_eq!(ctrl.channel_count(), 0);

        let snap = ctrl.backpressure_snapshot();
        assert!(snap.channels.is_empty());
        assert_eq!(snap.total_depth, 0);
        assert_eq!(snap.stalled_channels, 0);
    }

    #[test]
    fn independent_channels_have_independent_limits() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 2,
            ..Default::default()
        };
        let mut ctrl = BackpressureController::new(cfg);

        ctrl.try_acquire_send_slot(ChannelId::new(1)).unwrap();
        ctrl.try_acquire_send_slot(ChannelId::new(1)).unwrap();
        assert!(ctrl.try_acquire_send_slot(ChannelId::new(1)).is_err());

        ctrl.try_acquire_send_slot(ChannelId::new(2)).unwrap();
    }

    #[test]
    fn release_unknown_channel_is_noop() {
        let cfg = ChannelBackpressureConfig::default();
        let mut ctrl = BackpressureController::new(cfg);
        let slot = SendSlot::new(ChannelId::new(99), 0);
        ctrl.release_send_slot(slot); // should not panic
    }

    // -----------------------------------------------------------------------
    // Byte budget
    // -----------------------------------------------------------------------

    #[test]
    fn byte_budget_rejects_when_exceeded() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 100,
            byte_budget: Some(1024),
            ..Default::default()
        };
        let mut ctrl = BackpressureController::new(cfg);
        let ch = ChannelId::new(1);

        ctrl.try_acquire_send_slot_with_hint(ch, 600).unwrap();
        ctrl.try_acquire_send_slot_with_hint(ch, 400).unwrap(); // 1000 used
        ctrl.try_acquire_send_slot_with_hint(ch, 100).unwrap_err(); // 1100 > 1024
    }

    #[test]
    fn byte_budget_release_frees_bytes() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 100,
            byte_budget: Some(1024),
            ..Default::default()
        };
        let mut ctrl = BackpressureController::new(cfg);
        let ch = ChannelId::new(1);

        let s1 = ctrl.try_acquire_send_slot_with_hint(ch, 600).unwrap();
        let _s2 = ctrl.try_acquire_send_slot_with_hint(ch, 400).unwrap();

        assert!(ctrl.try_acquire_send_slot_with_hint(ch, 100).is_err());

        ctrl.release_send_slot(s1);
        ctrl.try_acquire_send_slot_with_hint(ch, 500).unwrap();
    }

    #[test]
    fn byte_usage_in_snapshot() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 100,
            byte_budget: Some(4096),
            ..Default::default()
        };
        let mut ctrl = BackpressureController::new(cfg);
        let ch = ChannelId::new(3);

        ctrl.try_acquire_send_slot_with_hint(ch, 800).unwrap();
        ctrl.try_acquire_send_slot_with_hint(ch, 300).unwrap();

        let snap = ctrl.backpressure_snapshot();
        assert_eq!(snap.channels.get(&ch).unwrap().byte_usage, 1100);
    }

    #[test]
    fn config_accessor_works() {
        let cfg = ChannelBackpressureConfig {
            max_depth: 42,
            ..Default::default()
        };
        let ctrl = BackpressureController::new(cfg);
        assert_eq!(ctrl.config().max_depth, 42);
    }

    // -- OutboundBackpressure --

    #[test]
    fn ob_default_config() {
        let c = OutboundBackpressureConfig::default();
        assert_eq!(c.high_watermark, 1024);
        assert_eq!(c.mode, BackpressureMode::Notify);
    }

    #[test]
    fn ob_status_initially_clear() {
        let bp = OutboundBackpressure::with_config(OutboundBackpressureConfig {
            high_watermark: 10,
            mode: BackpressureMode::Notify,
        });
        let s = bp.status();
        assert_eq!(s.current_depth, 0);
        assert!(!s.under_pressure);
    }

    #[test]
    fn ob_notify_always_acquires() {
        let mut bp = OutboundBackpressure::new(
            ChannelBackpressureConfig {
                max_depth: 100,
                ..Default::default()
            },
            OutboundBackpressureConfig {
                high_watermark: 5,
                mode: BackpressureMode::Notify,
            },
        );
        let ch = ChannelId::new(1);
        let mut slots = Vec::new();
        for _ in 0..10 {
            slots.push(bp.try_acquire(ch, 0).unwrap());
        }
        assert!(bp.status().under_pressure);
        for s in slots {
            bp.release(s);
        }
        assert!(!bp.status().under_pressure);
    }

    #[test]
    fn ob_block_rejects() {
        let mut bp = OutboundBackpressure::new(
            ChannelBackpressureConfig {
                max_depth: 100,
                ..Default::default()
            },
            OutboundBackpressureConfig {
                high_watermark: 3,
                mode: BackpressureMode::Block,
            },
        );
        let ch = ChannelId::new(1);
        bp.try_acquire(ch, 0).unwrap();
        bp.try_acquire(ch, 0).unwrap();
        bp.try_acquire(ch, 0).unwrap();
        assert!(bp.try_acquire(ch, 0).is_err());
    }

    #[test]
    fn ob_droptail_accepts_above_watermark() {
        let mut bp = OutboundBackpressure::new(
            ChannelBackpressureConfig {
                max_depth: 100,
                ..Default::default()
            },
            OutboundBackpressureConfig {
                high_watermark: 2,
                mode: BackpressureMode::DropTail,
            },
        );
        let ch = ChannelId::new(1);
        // DropTail always accepts; pipeline discards oldest when under pressure
        bp.try_acquire(ch, 0).unwrap();
        bp.try_acquire(ch, 0).unwrap();
        bp.try_acquire(ch, 0).unwrap();
        assert!(bp.status().under_pressure);
        // dropped_count is set by pipeline, not by try_acquire
    }

    #[test]
    fn ob_release_drains() {
        let mut bp = OutboundBackpressure::with_config(OutboundBackpressureConfig {
            high_watermark: 2,
            mode: BackpressureMode::Notify,
        });
        let ch = ChannelId::new(1);
        // Fill above hwm: 3 slots at hwm=2
        let s1 = bp.try_acquire(ch, 0).unwrap();
        let s2 = bp.try_acquire(ch, 0).unwrap();
        let s3 = bp.try_acquire(ch, 0).unwrap();
        assert!(bp.status().under_pressure);
        // Release to hwm edge: depth=2, still at hwm
        bp.release(s1);
        assert!(bp.status().under_pressure);
        // Release below hwm: depth=1 < 2
        bp.release(s2);
        assert!(!bp.status().under_pressure);
        // Full drain: depth=0
        bp.release(s3);
        assert!(!bp.status().under_pressure);
    }

    #[test]
    fn ob_dropped_count() {
        let bp = OutboundBackpressure::with_config(OutboundBackpressureConfig {
            high_watermark: 10,
            mode: BackpressureMode::DropTail,
        });
        assert_eq!(bp.dropped_count(), 0);
        bp.record_drop_tail();
        bp.record_drop_tail();
        assert_eq!(bp.dropped_count(), 2);
    }

    #[test]
    fn ob_snapshot_delegates() {
        let mut bp = OutboundBackpressure::with_config(OutboundBackpressureConfig::default());
        let ch = ChannelId::new(1);
        bp.try_acquire(ch, 0).unwrap();
        bp.try_acquire(ch, 0).unwrap();
        assert_eq!(bp.snapshot().total_depth, 2);
    }

    #[test]
    fn ob_reset_clears() {
        let mut bp = OutboundBackpressure::with_config(OutboundBackpressureConfig {
            high_watermark: 5,
            mode: BackpressureMode::Notify,
        });
        let ch = ChannelId::new(1);
        for _ in 0..6 {
            bp.try_acquire(ch, 0).unwrap();
        }
        assert!(bp.status().under_pressure);
        bp.reset();
        assert!(!bp.status().under_pressure);
    }

    #[test]
    fn ob_hwm_zero_disables() {
        let mut bp = OutboundBackpressure::with_config(OutboundBackpressureConfig {
            high_watermark: 0,
            mode: BackpressureMode::Block,
        });
        for _ in 0..10 {
            bp.try_acquire(ChannelId::new(1), 0).unwrap();
        }
        assert!(!bp.status().under_pressure);
    }

    #[test]
    fn ob_per_channel_limit_enforced() {
        let mut bp = OutboundBackpressure::new(
            ChannelBackpressureConfig {
                max_depth: 3,
                ..Default::default()
            },
            OutboundBackpressureConfig::default(),
        );
        let ch = ChannelId::new(1);
        bp.try_acquire(ch, 0).unwrap();
        bp.try_acquire(ch, 0).unwrap();
        bp.try_acquire(ch, 0).unwrap();
        assert!(bp.try_acquire(ch, 0).is_err());
    }

    #[test]
    fn wouldblock_display_debug() {
        assert!(WouldBlock.to_string().contains("backpressure"));
        assert_eq!(format!("{WouldBlock:?}"), "WouldBlock");
    }
}

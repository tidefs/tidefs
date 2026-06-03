//! Transport per-session receive-side flow control with credit-based
//! windowing for inbound frame backpressure.
//!
//! ## Design
//!
//! The credit protocol is a simple byte-count sliding window between the
//! receiver and sender on a single transport session:
//!
//! 1. At session establishment, the receiver grants an initial credit window
//!    to the sender.
//! 2. The sender decrements credits on each outbound frame transmission.
//! 3. The receiver consumes credits from inbound frames as they are processed.
//! 4. When the receiver's available credits drop below a configurable
//!    refresh threshold, it sends a [`ReceiveCredit`] message back to the
//!    sender piggybacked on the session's outbound frames.
//! 5. The sender adds the received credits and resumes transmission if
//!    it was stalled.
//!
//! This module operates within the existing transport session security
//! boundary. Credit messages are simple 8-byte LE u64 values carried in
//! the data path; integrity and authenticity are delegated to the session
//! transport security layer.
//!
//! ## Integration points
//!
//! - **Receiver side** ([`ReceiveFlowController`]): Called from the inbound
//!   receive loop after each frame is dispatched. The controller tracks
//!   consumed bytes and emits credit-refresh frames via the outbound
//!   send pipeline.
//! - **Sender side** ([`SenderCreditTracker`]): Shared atomic credit state
//!   checked by the outbound [`SendPipeline`](crate::outbound_send::SendPipeline)
//!   before transmitting frames. When credits are exhausted, the pipeline
//!   stalls until the inbound path delivers a credit refresh.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default initial credit window: 1 MiB.
pub const DEFAULT_INITIAL_CREDITS: u64 = 1_048_576;

/// Default maximum credit window: 16 MiB.
pub const DEFAULT_MAX_CREDITS: u64 = 16_777_216;

/// Default credit refresh threshold: when available credits drop below
/// this value, a credit refresh is sent (256 KiB).
pub const DEFAULT_REFRESH_THRESHOLD: u64 = 262_144;

/// Default credit refresh amount: how many bytes to grant per refresh
/// (1 MiB).
pub const DEFAULT_REFRESH_AMOUNT: u64 = 1_048_576;

/// Size of an encoded [`ReceiveCredit`] on the wire: 8 bytes (LE u64).
pub const RECEIVE_CREDIT_FRAME_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// ReceiveFlowConfig
// ---------------------------------------------------------------------------

/// Per-session configuration for receive-side credit flow control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveFlowConfig {
    /// Initial credits granted to the sender at session start.
    pub initial_credits: u64,
    /// Maximum credit window the receiver will grant (upper bound).
    pub max_credits: u64,
    /// When the receiver's available credits drop below this threshold,
    /// a [`ReceiveCredit`] refresh is emitted.
    pub refresh_threshold: u64,
    /// How many bytes to grant in each credit refresh.
    pub refresh_amount: u64,
    /// Minimum interval between credit refreshes to prevent bursty
    /// advertisement under rapid receive processing.
    pub min_refresh_interval: Duration,
}

impl Default for ReceiveFlowConfig {
    fn default() -> Self {
        Self {
            initial_credits: DEFAULT_INITIAL_CREDITS,
            max_credits: DEFAULT_MAX_CREDITS,
            refresh_threshold: DEFAULT_REFRESH_THRESHOLD,
            refresh_amount: DEFAULT_REFRESH_AMOUNT,
            min_refresh_interval: Duration::from_micros(100),
        }
    }
}

impl ReceiveFlowConfig {
    /// Validate the configuration. Returns `Err` with a message on invalid
    /// values.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.initial_credits == 0 {
            return Err("initial_credits must be non-zero");
        }
        if self.max_credits == 0 {
            return Err("max_credits must be non-zero");
        }
        if self.initial_credits > self.max_credits {
            return Err("initial_credits must not exceed max_credits");
        }
        if self.refresh_threshold == 0 {
            return Err("refresh_threshold must be non-zero");
        }
        if self.refresh_threshold > self.max_credits {
            return Err("refresh_threshold must not exceed max_credits");
        }
        if self.refresh_amount == 0 {
            return Err("refresh_amount must be non-zero");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ReceiveCredit -- wire format
// ---------------------------------------------------------------------------

/// A receive credit grant sent from the receiver back to the sender.
///
/// Wire format: 16 bytes — bytes 0..8 are the credit amount as a LE u64,
/// bytes 8..16 are zero-filled for protocol disambiguation from the
/// 8-byte [`WindowAdvertisement`](crate::flow_control::WindowAdvertisement).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveCredit {
    /// Number of bytes the sender is newly permitted to transmit.
    pub credits: u64,
}

impl ReceiveCredit {
    /// Create a new credit grant for `credits` bytes.
    #[must_use]
    pub fn new(credits: u64) -> Self {
        Self { credits }
    }

    /// Encode this credit grant into a 16-byte buffer (8-byte LE u64 + 8 zero bytes).
    #[must_use]
    pub fn encode(&self) -> [u8; RECEIVE_CREDIT_FRAME_SIZE] {
        let mut buf = [0u8; RECEIVE_CREDIT_FRAME_SIZE];
        buf[..8].copy_from_slice(&self.credits.to_le_bytes());
        buf
    }

    /// Encode into an existing buffer (must be exactly [`RECEIVE_CREDIT_FRAME_SIZE`] bytes).
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() != RECEIVE_CREDIT_FRAME_SIZE`.
    pub fn encode_into(&self, buf: &mut [u8]) {
        assert_eq!(buf.len(), RECEIVE_CREDIT_FRAME_SIZE);
        buf[..8].copy_from_slice(&self.credits.to_le_bytes());
        buf[8..].fill(0);
    }

    /// Decode a credit grant from a buffer of exactly [`RECEIVE_CREDIT_FRAME_SIZE`] bytes.
    ///
    /// Returns `None` if `buf.len() != RECEIVE_CREDIT_FRAME_SIZE`.
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != RECEIVE_CREDIT_FRAME_SIZE {
            return None;
        }
        let credits = u64::from_le_bytes(buf[..8].try_into().ok()?);
        Some(Self { credits })
    }
}

/// Encode `credits` into a 16-byte [`Vec<u8>`] ready for transmission.
#[must_use]
pub fn build_receive_credit(credits: u64) -> Vec<u8> {
    ReceiveCredit::new(credits).encode().to_vec()
}

// ---------------------------------------------------------------------------
// ReceiveFlowController -- receiver side
// ---------------------------------------------------------------------------

/// Receiver-side flow control state machine.
///
/// Tracks credits available to the sender and emits credit-refresh messages
/// when the window drains below the configured threshold.
///
/// # Usage
///
/// Called from the inbound receive loop after each frame is dispatched:
///
/// ```text
/// controller.consume(payload_len);
/// if let Some(credit) = controller.needs_refresh(Instant::now()) {
///     let frame = credit.encode();
///     outbound_tx.send(frame).ok();
///     controller.mark_refreshed(Instant::now());
/// }
/// ```
#[derive(Clone, Debug)]
pub struct ReceiveFlowController {
    config: ReceiveFlowConfig,
    /// Currently available credits (bytes the sender may still transmit).
    available_credits: u64,
    /// Total bytes consumed since the last credit refresh.
    pub bytes_consumed_since_refresh: u64,
    /// Last time a credit refresh was sent.
    last_refresh: Instant,
}

impl ReceiveFlowController {
    /// Create a new controller with the given configuration.
    ///
    /// Initially, the full `initial_credits` window is available to the sender.
    #[must_use]
    pub fn new(config: ReceiveFlowConfig) -> Self {
        let initial = config.initial_credits;
        Self {
            available_credits: initial,
            bytes_consumed_since_refresh: 0,
            last_refresh: Instant::now()
                .checked_sub(config.min_refresh_interval.saturating_mul(2))
                .unwrap_or_else(Instant::now),
            config,
        }
    }

    /// Consume `bytes` from the receiver's credit window.
    ///
    /// Called after an inbound frame is successfully processed. Returns
    /// the remaining available credits.
    pub fn consume(&mut self, bytes: u64) -> u64 {
        self.available_credits = self.available_credits.saturating_sub(bytes);
        self.bytes_consumed_since_refresh = self.bytes_consumed_since_refresh.saturating_add(bytes);
        self.available_credits
    }

    /// Release `bytes` back into the receive window (e.g., after a frame
    /// is dropped without processing).
    pub fn release(&mut self, bytes: u64) -> u64 {
        self.available_credits = self
            .available_credits
            .saturating_add(bytes)
            .min(self.config.max_credits);
        self.available_credits
    }

    /// Check whether a credit refresh should be sent to the sender.
    ///
    /// Returns `Some(ReceiveCredit)` when available credits have dropped
    /// below the refresh threshold and the minimum refresh interval has
    /// elapsed since the last refresh.
    #[must_use]
    pub fn needs_refresh(&self, now: Instant) -> Option<ReceiveCredit> {
        if self.available_credits >= self.config.refresh_threshold {
            return None;
        }
        if now.saturating_duration_since(self.last_refresh) < self.config.min_refresh_interval {
            return None;
        }
        let grant = self.config.refresh_amount.min(
            self.config
                .max_credits
                .saturating_sub(self.available_credits),
        );
        if grant == 0 {
            return None;
        }
        Some(ReceiveCredit::new(grant))
    }

    /// Mark that a credit refresh has been sent.
    ///
    /// Replenishes the local credit window by the granted amount and
    /// records the refresh timestamp.
    pub fn mark_refreshed(&mut self, now: Instant) {
        let grant = self.config.refresh_amount.min(
            self.config
                .max_credits
                .saturating_sub(self.available_credits),
        );
        self.available_credits = self
            .available_credits
            .saturating_add(grant)
            .min(self.config.max_credits);
        self.last_refresh = now;
        self.bytes_consumed_since_refresh = 0;
    }

    /// Currently available credits (for diagnostics).
    #[must_use]
    pub fn available_credits(&self) -> u64 {
        self.available_credits
    }

    /// Whether the window is fully exhausted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.available_credits == 0
    }

    /// The configured maximum credit window.
    #[must_use]
    pub fn max_credits(&self) -> u64 {
        self.config.max_credits
    }
}

// ---------------------------------------------------------------------------
// SenderCreditTracker -- sender side
// ---------------------------------------------------------------------------

/// Shared sender-side credit tracker that gates outbound frame transmission.
///
/// The tracker holds the sender's view of how many bytes the receiver has
/// permitted it to transmit. It is designed to be shared between the
/// outbound send pipeline (which checks/acquires credits before writing)
/// and the inbound receive loop (which adds credits when a [`ReceiveCredit`]
/// arrives from the peer).
///
/// Uses an [`AtomicU64`] for lock-free credit accounting on the hot send
/// path and a [`tokio::sync::Notify`] to wake the send pipeline when
/// credits are replenished from zero.
#[derive(Debug)]
pub struct SenderCreditTracker {
    /// Currently available credits for transmission.
    available: AtomicU64,
    /// Maximum credits the tracker will hold (caps credit accumulation).
    max_credits: u64,
    /// Notifies the send pipeline when credits are added (useful when
    /// the pipeline is stalled at zero credits).
    notify: tokio::sync::Notify,
}

impl SenderCreditTracker {
    /// Create a new tracker with an initial credit grant.
    #[must_use]
    pub fn new(initial_credits: u64, max_credits: u64) -> Self {
        Self {
            available: AtomicU64::new(initial_credits.min(max_credits)),
            max_credits,
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Try to acquire `bytes` credits before transmitting a frame.
    ///
    /// Returns `true` if sufficient credits were available and have been
    /// consumed. Returns `false` if not enough credits remain -- the caller
    /// should stall and wait for a credit refresh.
    pub fn try_acquire(&self, bytes: u64) -> bool {
        let mut current = self.available.load(Ordering::Acquire);
        loop {
            if current < bytes {
                return false;
            }
            match self.available.compare_exchange_weak(
                current,
                current - bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Add credits received from the peer via a [`ReceiveCredit`] message.
    ///
    /// Caps at `max_credits`. Notifies any task waiting on
    /// [`wait_for_credits`](Self::wait_for_credits).
    pub fn add_credits(&self, bytes: u64) {
        let prev = self.available.fetch_add(bytes, Ordering::AcqRel);
        let new = prev.saturating_add(bytes);
        if new > self.max_credits {
            let _ = self
                .available
                .fetch_min(self.max_credits, Ordering::Release);
        }
        self.notify.notify_one();
    }

    /// Available credits (for diagnostic use).
    #[must_use]
    pub fn available_credits(&self) -> u64 {
        self.available.load(Ordering::Acquire)
    }

    /// Returns a future that completes when credits are added.
    ///
    /// Used by the send pipeline to efficiently wait when credits are
    /// exhausted instead of busy-polling.
    pub async fn wait_for_credits(&self) {
        self.notify.notified().await;
    }

    /// Check if there are enough credits and, if not, asynchronously
    /// wait until credits are available.
    pub async fn acquire_or_wait(&self, bytes: u64) {
        loop {
            if self.try_acquire(bytes) {
                return;
            }
            self.wait_for_credits().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // -------------------------------------------------------------------
    // ReceiveFlowConfig tests
    // -------------------------------------------------------------------

    #[test]
    fn config_defaults_are_valid() {
        let cfg = ReceiveFlowConfig::default();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.initial_credits, DEFAULT_INITIAL_CREDITS);
        assert_eq!(cfg.max_credits, DEFAULT_MAX_CREDITS);
        assert_eq!(cfg.refresh_threshold, DEFAULT_REFRESH_THRESHOLD);
        assert_eq!(cfg.refresh_amount, DEFAULT_REFRESH_AMOUNT);
    }

    #[test]
    fn config_zero_initial_rejected() {
        let cfg = ReceiveFlowConfig {
            initial_credits: 0,
            ..ReceiveFlowConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_zero_max_rejected() {
        let cfg = ReceiveFlowConfig {
            max_credits: 0,
            ..ReceiveFlowConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_initial_exceeds_max_rejected() {
        let cfg = ReceiveFlowConfig {
            initial_credits: 2000,
            max_credits: 1000,
            ..ReceiveFlowConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_zero_threshold_rejected() {
        let cfg = ReceiveFlowConfig {
            refresh_threshold: 0,
            ..ReceiveFlowConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_threshold_exceeds_max_rejected() {
        let cfg = ReceiveFlowConfig {
            max_credits: 1000,
            refresh_threshold: 2000,
            ..ReceiveFlowConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_zero_refresh_amount_rejected() {
        let cfg = ReceiveFlowConfig {
            refresh_amount: 0,
            ..ReceiveFlowConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    // -------------------------------------------------------------------
    // ReceiveCredit encode / decode tests
    // -------------------------------------------------------------------

    #[test]
    fn receive_credit_encode_decode_roundtrip() {
        let credit = ReceiveCredit::new(42);
        let encoded = credit.encode();
        assert_eq!(encoded.len(), 16);
        assert_eq!(&encoded[..8], &42u64.to_le_bytes());

        let decoded = ReceiveCredit::decode(&encoded).unwrap();
        assert_eq!(decoded, credit);
    }

    #[test]
    fn receive_credit_decode_wrong_size() {
        assert!(ReceiveCredit::decode(&[]).is_none());
        assert!(ReceiveCredit::decode(&[0u8; 8]).is_none());
        assert!(ReceiveCredit::decode(&[0u8; 15]).is_none());
        assert!(ReceiveCredit::decode(&[0u8; 17]).is_none());
    }

    #[test]
    fn receive_credit_zero() {
        let credit = ReceiveCredit::new(0);
        let encoded = credit.encode();
        let decoded = ReceiveCredit::decode(&encoded).unwrap();
        assert_eq!(decoded.credits, 0);
    }

    #[test]
    fn receive_credit_max() {
        let credit = ReceiveCredit::new(u64::MAX);
        let encoded = credit.encode();
        assert_eq!(encoded.len(), 16);
        let decoded = ReceiveCredit::decode(&encoded).unwrap();
        assert_eq!(decoded.credits, u64::MAX);
    }

    #[test]
    fn receive_credit_encode_into() {
        let credit = ReceiveCredit::new(0xDEAD_BEEF);
        let mut buf = [0u8; 16];
        credit.encode_into(&mut buf);
        assert_eq!(&buf[..8], &0xDEAD_BEEFu64.to_le_bytes());

        let decoded = ReceiveCredit::decode(&buf).unwrap();
        assert_eq!(decoded.credits, 0xDEAD_BEEF);
    }

    #[test]
    fn build_receive_credit_helper() {
        let frame = build_receive_credit(1024);
        assert_eq!(frame.len(), 16);
        let decoded = ReceiveCredit::decode(&frame).unwrap();
        assert_eq!(decoded.credits, 1024);
    }

    // -------------------------------------------------------------------
    // ReceiveFlowController tests
    // -------------------------------------------------------------------

    fn test_config() -> ReceiveFlowConfig {
        ReceiveFlowConfig {
            initial_credits: 1000,
            max_credits: 2000,
            refresh_threshold: 300,
            refresh_amount: 800,
            min_refresh_interval: Duration::from_millis(0),
        }
    }

    fn fake_now() -> Instant {
        Instant::now()
    }

    #[test]
    fn controller_starts_with_initial_credits() {
        let ctrl = ReceiveFlowController::new(test_config());
        assert_eq!(ctrl.available_credits(), 1000);
        assert!(!ctrl.is_exhausted());
    }

    #[test]
    fn controller_consume_reduces_credits() {
        let mut ctrl = ReceiveFlowController::new(test_config());
        let remaining = ctrl.consume(200);
        assert_eq!(remaining, 800);
        assert_eq!(ctrl.available_credits(), 800);
    }

    #[test]
    fn controller_consume_saturates_at_zero() {
        let mut ctrl = ReceiveFlowController::new(test_config());
        ctrl.consume(2000);
        assert_eq!(ctrl.available_credits(), 0);
        assert!(ctrl.is_exhausted());
    }

    #[test]
    fn controller_release_restores_credits() {
        let mut ctrl = ReceiveFlowController::new(test_config());
        ctrl.consume(500);
        assert_eq!(ctrl.available_credits(), 500);
        ctrl.release(200);
        assert_eq!(ctrl.available_credits(), 700);
    }

    #[test]
    fn controller_release_capped_at_max() {
        let mut ctrl = ReceiveFlowController::new(test_config());
        ctrl.release(1500);
        assert_eq!(ctrl.available_credits(), 2000); // capped at max
    }

    #[test]
    fn controller_no_refresh_when_above_threshold() {
        let ctrl = ReceiveFlowController::new(test_config());
        assert!(ctrl.needs_refresh(fake_now()).is_none());
    }

    #[test]
    fn controller_emits_refresh_when_below_threshold() {
        let mut ctrl = ReceiveFlowController::new(test_config());
        ctrl.consume(800); // 200 remaining < 300 threshold
        let refresh = ctrl.needs_refresh(fake_now());
        assert!(refresh.is_some());
        assert_eq!(refresh.unwrap().credits, 800);
    }

    #[test]
    fn controller_refresh_respects_min_interval() {
        let cfg = ReceiveFlowConfig {
            initial_credits: 1000,
            max_credits: 2000,
            refresh_threshold: 500,
            refresh_amount: 400,
            min_refresh_interval: Duration::from_millis(100),
        };
        let mut ctrl = ReceiveFlowController::new(cfg);

        ctrl.consume(600); // 400 < 500
        let now = Instant::now();
        let refresh = ctrl.needs_refresh(now);
        assert!(refresh.is_some());
        ctrl.mark_refreshed(now);

        ctrl.consume(500); // 300 < 500 threshold
        assert!(ctrl.needs_refresh(now).is_none());

        let later = now.checked_add(Duration::from_millis(150)).unwrap();
        assert!(ctrl.needs_refresh(later).is_some());
    }

    #[test]
    fn controller_mark_refreshed_replenishes() {
        let mut ctrl = ReceiveFlowController::new(test_config());
        ctrl.consume(900); // 100 remaining
        let now = Instant::now();
        assert!(ctrl.needs_refresh(now).is_some());
        ctrl.mark_refreshed(now);
        assert_eq!(ctrl.available_credits(), 900); // 100 + 800
    }

    #[test]
    fn controller_refresh_capped_by_max() {
        let cfg = ReceiveFlowConfig {
            initial_credits: 1000,
            max_credits: 1500,
            refresh_threshold: 300,
            refresh_amount: 800,
            min_refresh_interval: Duration::from_millis(0),
        };
        let mut ctrl = ReceiveFlowController::new(cfg);
        ctrl.consume(900); // 100 remaining < 300
        let now = Instant::now();
        let refresh = ctrl.needs_refresh(now).unwrap();
        assert_eq!(refresh.credits, 800); // min(800, 1500-100=1400) = 800
        ctrl.mark_refreshed(now);
        assert_eq!(ctrl.available_credits(), 900);
    }

    #[test]
    fn controller_bytes_consumed_since_refresh_resets() {
        let mut ctrl = ReceiveFlowController::new(test_config());
        assert_eq!(ctrl.bytes_consumed_since_refresh, 0);
        ctrl.consume(100);
        assert_eq!(ctrl.bytes_consumed_since_refresh, 100);
        ctrl.consume(200);
        assert_eq!(ctrl.bytes_consumed_since_refresh, 300);
        let now = Instant::now();
        ctrl.mark_refreshed(now);
        assert_eq!(ctrl.bytes_consumed_since_refresh, 0);
    }

    // -------------------------------------------------------------------
    // SenderCreditTracker tests
    // -------------------------------------------------------------------

    #[test]
    fn sender_tracker_initial_credits() {
        let tracker = SenderCreditTracker::new(1000, 5000);
        assert_eq!(tracker.available_credits(), 1000);
    }

    #[test]
    fn sender_tracker_acquire_success() {
        let tracker = SenderCreditTracker::new(1000, 5000);
        assert!(tracker.try_acquire(500));
        assert_eq!(tracker.available_credits(), 500);
    }

    #[test]
    fn sender_tracker_acquire_insufficient() {
        let tracker = SenderCreditTracker::new(100, 5000);
        assert!(!tracker.try_acquire(200));
        assert_eq!(tracker.available_credits(), 100);
    }

    #[test]
    fn sender_tracker_acquire_exact() {
        let tracker = SenderCreditTracker::new(100, 5000);
        assert!(tracker.try_acquire(100));
        assert_eq!(tracker.available_credits(), 0);
    }

    #[test]
    fn sender_tracker_acquire_zero_credits() {
        let tracker = SenderCreditTracker::new(0, 5000);
        assert!(!tracker.try_acquire(1));
    }

    #[test]
    fn sender_tracker_add_credits() {
        let tracker = SenderCreditTracker::new(100, 5000);
        tracker.add_credits(400);
        assert_eq!(tracker.available_credits(), 500);
    }

    #[test]
    fn sender_tracker_add_credits_capped() {
        let tracker = SenderCreditTracker::new(100, 500);
        tracker.add_credits(1000);
        let avail = tracker.available_credits();
        assert!(avail <= 500, "capped at max, got {avail}");
    }

    #[test]
    fn sender_tracker_initial_capped_by_max() {
        let tracker = SenderCreditTracker::new(1000, 500);
        assert_eq!(tracker.available_credits(), 500);
    }

    #[test]
    fn sender_tracker_concurrent_acquires() {
        use std::thread;

        let tracker = Arc::new(SenderCreditTracker::new(1000, 5000));
        let t1 = {
            let t = Arc::clone(&tracker);
            thread::spawn(move || {
                for _ in 0..100 {
                    while !t.try_acquire(5) {
                        thread::yield_now();
                    }
                }
            })
        };
        let t2 = {
            let t = Arc::clone(&tracker);
            thread::spawn(move || {
                for _ in 0..100 {
                    while !t.try_acquire(5) {
                        thread::yield_now();
                    }
                }
            })
        };

        t1.join().unwrap();
        t2.join().unwrap();
        assert_eq!(tracker.available_credits(), 0);
    }

    #[tokio::test]
    async fn sender_tracker_wait_for_credits_wakes() {
        let tracker = Arc::new(SenderCreditTracker::new(0, 5000));
        let tracker_clone = Arc::clone(&tracker);

        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            tracker_clone.add_credits(200);
        });

        tracker.acquire_or_wait(100).await;
        let remaining = tracker.available_credits();
        assert!(remaining >= 100, "expected >=100 credits, got {remaining}");

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn sender_tracker_acquire_or_wait_immediate() {
        let tracker = SenderCreditTracker::new(1000, 5000);
        let start = Instant::now();
        tracker.acquire_or_wait(500).await;
        assert!(start.elapsed() < Duration::from_millis(5));
        assert_eq!(tracker.available_credits(), 500);
    }

    #[test]
    fn sender_tracker_zero_acquire_always_succeeds() {
        let tracker = SenderCreditTracker::new(0, 5000);
        assert!(tracker.try_acquire(0));
        assert_eq!(tracker.available_credits(), 0);
    }
}

// -------------------------------------------------------------------
// Integration tests: credit protocol end-to-end simulations
// -------------------------------------------------------------------

/// Simulates a fast sender exhausting credits, then receiving a
/// credit refresh from the receiver that unblocks the sender.
#[test]
fn integration_sender_stalled_by_exhausted_credits() {
    // Receiver grants 1000 bytes initially.
    let config = ReceiveFlowConfig {
        initial_credits: 1000,
        max_credits: 5000,
        refresh_threshold: 300,
        refresh_amount: 800,
        min_refresh_interval: Duration::from_millis(0),
    };
    let mut controller = ReceiveFlowController::new(config);
    let tracker = SenderCreditTracker::new(1000, 5000);

    // Sender transmits 900 bytes (100 credits remain).
    assert!(tracker.try_acquire(900));
    assert_eq!(tracker.available_credits(), 100);

    // Receiver processes 900 bytes -- this drains the window.
    controller.consume(900);
    assert_eq!(controller.available_credits(), 100);
    assert!(controller.available_credits() < controller.config.refresh_threshold);

    // Receiver should emit a credit refresh.
    let now = Instant::now();
    let credit = controller.needs_refresh(now);
    assert!(credit.is_some());
    assert_eq!(credit.unwrap().credits, 800);

    // Sender tries to send another 500 bytes but only has 100 credits.
    assert!(!tracker.try_acquire(500));

    // Receiver sends the credit refresh; sender receives it.
    controller.mark_refreshed(now);
    tracker.add_credits(800);

    // Sender now has enough credits.
    let avail = tracker.available_credits();
    assert!(avail >= 800, "expected >=800 after refresh, got {avail}");
    assert!(tracker.try_acquire(500));
}

/// Simulates multiple credit-refresh cycles as the receiver processes
/// data faster than the sender transmits, ensuring the credit window
/// never grows beyond max_credits.
#[test]
fn integration_multiple_refresh_cycles() {
    let config = ReceiveFlowConfig {
        initial_credits: 1000,
        max_credits: 2000,
        refresh_threshold: 300,
        refresh_amount: 800,
        min_refresh_interval: Duration::from_millis(0),
    };
    let mut controller = ReceiveFlowController::new(config);
    let tracker = SenderCreditTracker::new(1000, 2000);

    for cycle in 0..10 {
        let now = Instant::now();

        // Receiver processes some data.
        let consumed = 200; // small chunks each cycle
        controller.consume(consumed);

        // If credits are low, emit refresh.
        if let Some(credit) = controller.needs_refresh(now) {
            controller.mark_refreshed(now);
            tracker.add_credits(credit.credits);
        }

        // Sender transmits.
        let to_send = 150;
        assert!(
            tracker.try_acquire(to_send),
            "cycle {}: should have credits for {} bytes, have {}",
            cycle,
            to_send,
            tracker.available_credits()
        );
    }

    // Credit window should never exceed max.
    let final_credits = tracker.available_credits();
    assert!(
        final_credits <= 2000,
        "credits {final_credits} should not exceed max 2000"
    );
}

/// Verifies that the receive-flow controller and sender tracker
/// maintain symmetric credit accounting: what the receiver grants
/// minus what the sender consumes stays in sync.
#[test]
fn integration_credit_accounting_symmetry() {
    let initial: u64 = 10_000;
    let config = ReceiveFlowConfig {
        initial_credits: initial,
        max_credits: 50_000,
        refresh_threshold: 3000,
        refresh_amount: 10_000,
        min_refresh_interval: Duration::from_millis(0),
    };
    let mut controller = ReceiveFlowController::new(config.clone());
    let tracker = SenderCreditTracker::new(initial, 50_000);

    let mut total_sent: u64 = 0;
    let mut _total_received: u64 = 0;
    let mut total_refreshed: u64 = 0;

    for _ in 0..100 {
        let now = Instant::now();

        // Receiver processes some bytes.
        let recv = 1234;
        controller.consume(recv);
        _total_received += recv;

        // Check for credit refresh.
        if let Some(credit) = controller.needs_refresh(now) {
            let granted = credit.credits;
            controller.mark_refreshed(now);
            tracker.add_credits(granted);
            total_refreshed += granted;
        }

        // Sender sends some bytes.
        let send = 789;
        if tracker.try_acquire(send) {
            total_sent += send;
        } else {
            // Stalled; wait for refresh (simulated by loop).
            tracker.add_credits(config.refresh_amount);
            total_refreshed += config.refresh_amount;
            assert!(tracker.try_acquire(send));
            total_sent += send;
        }
    }

    // The sender should never have sent more than initial + refreshes.
    let max_possible = initial + total_refreshed;
    assert!(
        total_sent <= max_possible,
        "total_sent {total_sent} > max_possible {max_possible} (initial {initial} + refreshes {total_refreshed})"
    );

    // Final available credits should be max_possible - total_sent,
    // capped at max_credits (the tracker caps credits on add_credits).
    // The controller grants can exceed max_credits, but the tracker
    // truncates to max_credits, so available_credits <= expected_remaining.
    let expected_remaining = max_possible.saturating_sub(total_sent);
    let actual = tracker.available_credits();
    assert!(
        actual <= expected_remaining,
        "available_credits {actual} should not exceed expected_remaining {expected_remaining}"
    );
    assert!(
        actual <= 50_000,
        "available_credits {actual} should not exceed max_credits 50000"
    );
}

/// Ensures a zero-window scenario: receiver grants no additional
/// credits when the sender has consumed all initial credits and
/// the receiver is not processing data.
#[test]
fn integration_zero_window_no_refresh_when_idle() {
    let config = ReceiveFlowConfig {
        initial_credits: 100,
        max_credits: 500,
        refresh_threshold: 30,
        refresh_amount: 100,
        min_refresh_interval: Duration::from_millis(0),
    };
    let mut controller = ReceiveFlowController::new(config);
    let tracker = SenderCreditTracker::new(100, 500);

    // Sender exhausts all credits.
    assert!(tracker.try_acquire(100));
    assert_eq!(tracker.available_credits(), 0);

    // Sender cannot send more.
    assert!(!tracker.try_acquire(1));

    // Receiver hasn't processed anything, so no refresh pending.
    let now = Instant::now();
    assert!(controller.needs_refresh(now).is_none());

    // Receiver processes data.
    controller.consume(80); // 100 - 80 = 20 < 30 threshold
    let credit = controller.needs_refresh(now);
    assert!(credit.is_some());
    controller.mark_refreshed(now);

    // Sender receives the refresh.
    tracker.add_credits(100);
    assert!(tracker.try_acquire(50));
}

/// Tests that concurrent acquires by multiple sender threads are
/// correctly serialized and never exceed available credits.
#[tokio::test]
async fn integration_concurrent_senders_throttled() {
    use std::sync::Arc;
    use tokio::sync::Notify;

    let tracker = Arc::new(SenderCreditTracker::new(5000, 10000));
    let done = Arc::new(Notify::new());
    let stop = Arc::new(Notify::new());
    let done_clone = Arc::clone(&done);
    let _stop_clone = Arc::clone(&stop);
    let tracker_clone = Arc::clone(&tracker);

    // Spawn a simulated receiver that adds credits periodically.
    let receiver = tokio::spawn(async move {
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            tracker_clone.add_credits(2000);
        }
        done_clone.notify_one();
    });

    // Spawn two sender tasks that try to send data.
    let mut handles = Vec::new();
    for _ in 0..2 {
        let t = Arc::clone(&tracker);
        let stop = Arc::clone(&stop);
        handles.push(tokio::spawn(async move {
            let mut total_sent: u64 = 0;
            loop {
                if t.try_acquire(100) {
                    total_sent += 100;
                } else {
                    // Check if receiver is done.
                    // Simple heuristic: if we can't acquire, the
                    // receiver might be done.
                    if total_sent > 0 {
                        tokio::select! {
                            _ = stop.notified() => break,
                            _ = tokio::time::sleep(Duration::from_millis(2)) => continue,
                        }
                    }
                    break;
                }
            }
            total_sent
        }));
    }

    // Wait for receiver to finish adding credits.
    done.notified().await;

    // Allow some time for senders to consume remaining credits.
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Signal senders to stop.
    stop.notify_waiters();

    let total_sent: u64 = {
        let mut sum = 0;
        for h in handles {
            sum += h.await.unwrap_or(0);
        }
        sum
    };

    receiver.await.unwrap();

    // Total sent should never exceed initial + 5 * 2000 = 15000.
    assert!(
        total_sent <= 15000,
        "total_sent {total_sent} should not exceed max possible 15000"
    );
}

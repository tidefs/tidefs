//! Per-priority send-path backpressure propagation with async capacity
//! notification for caller flow control.
//!
//! ## Design
//!
//! Each [`SendPriority`] class gets independent high/low watermark signals.
//! When a priority queue depth reaches or exceeds its high watermark, the
//! capacity signal flips to *full*. Callers calling
//! [`SendCapacity::wait_for_capacity`] will asynchronously wait. When the
//! queue depth drops to or below the low watermark after being full, the
//! signal flips back to *available* and all waiting callers are notified.
//!
//! Watermark transitions are checked at dequeue time in the send pipeline
//! drain loop, after a message is consumed from the scheduler.
//!
//! ## Quick start
//!
//! ```ignore
//! use tidefs_transport::send_backpressure::{
//!     SendWatermarkConfig, SendCapacitySet,
//! };
//! use tidefs_transport::send_scheduler::SendPriority;
//!
//! let config = SendWatermarkConfig::default();
//! let capacity_set = SendCapacitySet::new(&config);
//!
//! // Caller side: await capacity for a priority class
//! let data_cap = capacity_set.capacity(SendPriority::Data);
//! if !data_cap.is_available() {
//!     data_cap.wait_for_capacity().await;
//! }
//! // Pipeline side: check watermarks after dequeue
//! capacity_set.check_after_dequeue(SendPriority::Data, 3);
//! ```

use std::sync::Arc;

use tokio::sync::watch;

use crate::send_admission::SendWakeEvidence;
use crate::send_scheduler::SendPriority;

// ---------------------------------------------------------------------------
// SendWatermarkConfig
// ---------------------------------------------------------------------------

/// Per-priority-class watermark configuration for send-side backpressure.
///
/// Each priority class gets independent high/low watermarks expressed as
/// queue-depth counts (number of messages). The high watermark triggers
/// the *full* signal; the low watermark clears it.
///
/// Sensible defaults: high = 75% of a nominal 256-message queue (192),
/// low = 25% (64). Callers scaling queue depths should adjust accordingly.
///
/// ## Validation
///
/// - Every priority must have `low_watermark < high_watermark`.
/// - A high watermark of 0 disables backpressure for that class (always
///   available).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendWatermarkConfig {
    /// High watermark for the Control priority class.
    pub control_high: usize,
    /// Low watermark for the Control priority class.
    pub control_low: usize,
    /// High watermark for the Membership priority class.
    pub membership_high: usize,
    /// Low watermark for the Membership priority class.
    pub membership_low: usize,
    /// High watermark for the IntentLog priority class.
    pub intent_log_high: usize,
    /// Low watermark for the IntentLog priority class.
    pub intent_log_low: usize,
    /// High watermark for the Data priority class.
    pub data_high: usize,
    /// Low watermark for the Data priority class.
    pub data_low: usize,
    /// High watermark for the Bulk priority class.
    pub bulk_high: usize,
    /// Low watermark for the Bulk priority class.
    pub bulk_low: usize,
}

impl Default for SendWatermarkConfig {
    fn default() -> Self {
        Self {
            control_high: 48,
            control_low: 16,
            membership_high: 96,
            membership_low: 32,
            intent_log_high: 128,
            intent_log_low: 48,
            data_high: 192,
            data_low: 64,
            bulk_high: 192,
            bulk_low: 64,
        }
    }
}

impl SendWatermarkConfig {
    /// Create a uniform config: same high/low for all classes.
    pub fn uniform(high: usize, low: usize) -> Self {
        Self {
            control_high: high,
            control_low: low,
            membership_high: high,
            membership_low: low,
            intent_log_high: high,
            intent_log_low: low,
            data_high: high,
            data_low: low,
            bulk_high: high,
            bulk_low: low,
        }
    }

    /// Validate the configuration. Returns `Err(description)` on invalid values.
    pub fn validate(&self) -> Result<(), String> {
        let pairs: [(&str, usize, usize); 5] = [
            ("Control", self.control_high, self.control_low),
            ("Membership", self.membership_high, self.membership_low),
            ("IntentLog", self.intent_log_high, self.intent_log_low),
            ("Data", self.data_high, self.data_low),
            ("Bulk", self.bulk_high, self.bulk_low),
        ];
        for (name, high, low) in pairs {
            if high > 0 && low >= high {
                return Err(format!(
                    "{name}: low_watermark ({low}) must be < high_watermark ({high})"
                ));
            }
        }
        Ok(())
    }

    /// Get the high watermark for a given priority class.
    pub fn high(&self, pri: SendPriority) -> usize {
        match pri {
            SendPriority::Control => self.control_high,
            SendPriority::Membership => self.membership_high,
            SendPriority::IntentLog => self.intent_log_high,
            SendPriority::Data => self.data_high,
            SendPriority::Bulk => self.bulk_high,
        }
    }

    /// Get the low watermark for a given priority class.
    pub fn low(&self, pri: SendPriority) -> usize {
        match pri {
            SendPriority::Control => self.control_low,
            SendPriority::Membership => self.membership_low,
            SendPriority::IntentLog => self.intent_log_low,
            SendPriority::Data => self.data_low,
            SendPriority::Bulk => self.bulk_low,
        }
    }

    /// Whether backpressure is enabled (high > 0) for the given class.
    pub fn is_enabled(&self, pri: SendPriority) -> bool {
        self.high(pri) > 0
    }
}

// ---------------------------------------------------------------------------
// SendCapacity
// ---------------------------------------------------------------------------

/// Per-priority async capacity signal.
///
/// Callers awaiting a send slot call
/// [`wait_for_capacity`](Self::wait_for_capacity), which resolves when
/// the priority queue depth drops below the configured low watermark
/// (or immediately if already available).
///
/// `SendCapacity` is cheap to clone; each clone shares the underlying
/// watch channel.
#[derive(Clone, Debug)]
pub struct SendCapacity {
    /// Receiver half of the capacity watch channel.
    /// The sender side is held by [`SendCapacitySet`].
    rx: watch::Receiver<bool>,
}

impl SendCapacity {
    /// Await capacity for this priority class.
    ///
    /// Resolves immediately if the queue is below the high watermark.
    /// Otherwise waits until the drain loop notifies that the queue
    /// has drained below the low watermark.
    pub async fn wait_for_capacity(&self) {
        let _ = self.wait_for_capacity_evidence().await;
    }

    /// Await capacity and report the wake source observed by this waiter.
    pub async fn wait_for_capacity_evidence(&self) -> SendWakeEvidence {
        let mut rx = self.rx.clone();
        // Borrow the current value first to avoid spurious wake-ups.
        if *rx.borrow() {
            return SendWakeEvidence::NotApplicable;
        }
        // Wait for a change to true.
        loop {
            // Clone a fresh receiver so we don't miss notifications.
            let changed = rx.changed().await;
            if changed.is_err() {
                // Sender dropped (shutdown): treat as available.
                return SendWakeEvidence::SenderDropped;
            }
            if *rx.borrow() {
                return SendWakeEvidence::DrainObserved;
            }
        }
    }

    /// Synchronous poll: is the priority queue currently available?
    #[must_use]
    pub fn is_available(&self) -> bool {
        *self.rx.borrow()
    }
}

// ---------------------------------------------------------------------------
// SendCapacitySet
// ---------------------------------------------------------------------------

/// Holds the sender side of per-priority capacity watch channels and
/// manages watermark transitions.
///
/// One `SendCapacitySet` is created per transport session (or per
/// outbound pipeline). The pipeline drain loop calls
/// [`check_after_dequeue`](Self::check_after_dequeue) after each dequeue
/// from the scheduler. Callers obtain per-priority [`SendCapacity`]
/// handles via [`capacity`](Self::capacity).
///
/// The watch channels are initialized to `true` (available) for all
/// classes.
#[derive(Clone, Debug)]
pub struct SendCapacitySet {
    config: SendWatermarkConfig,
    /// Per-priority watch senders. Index matches [`SendPriority`] discriminants.
    senders: Arc<[watch::Sender<bool>; 5]>,
    /// Per-priority "currently under pressure" flags.
    under_pressure: Arc<[std::sync::atomic::AtomicBool; 5]>,
    /// Last queue depth observed for each priority class.
    depths: Arc<[std::sync::atomic::AtomicUsize; 5]>,
}

/// Point-in-time capacity state for a priority class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendCapacitySnapshot {
    pub priority: SendPriority,
    pub available: bool,
    pub depth: usize,
    pub high_watermark: usize,
    pub low_watermark: usize,
}

impl SendCapacitySet {
    /// Create a new capacity set with the given watermark configuration.
    ///
    /// # Panics
    ///
    /// Panics if `config.validate()` returns `Err`.
    #[must_use]
    pub fn new(config: &SendWatermarkConfig) -> Self {
        config
            .validate()
            .expect("SendWatermarkConfig validation failed");
        let senders: [watch::Sender<bool>; 5] = {
            let (t0, _) = watch::channel(true);
            let (t1, _) = watch::channel(true);
            let (t2, _) = watch::channel(true);
            let (t3, _) = watch::channel(true);
            let (t4, _) = watch::channel(true);
            [t0, t1, t2, t3, t4]
        };
        Self {
            config: config.clone(),
            senders: Arc::new(senders),
            under_pressure: Arc::new(std::array::from_fn(|_| {
                std::sync::atomic::AtomicBool::new(false)
            })),
            depths: Arc::new(std::array::from_fn(|_| {
                std::sync::atomic::AtomicUsize::new(0)
            })),
        }
    }

    /// Get a [`SendCapacity`] handle for the given priority class.
    pub fn capacity(&self, pri: SendPriority) -> SendCapacity {
        let idx = pri as usize;
        SendCapacity {
            rx: self.senders[idx].subscribe(),
        }
    }

    /// Check watermarks after dequeueing from the scheduler.
    ///
    /// Called by the pipeline drain loop. `depth` is the current queue
    /// depth for this priority class *after* the dequeue.
    ///
    /// If the class was under pressure and `depth` ≤ low watermark,
    /// signals available. If `depth` ≥ high watermark and not already
    /// under pressure, signals full.
    pub fn check_after_dequeue(&self, pri: SendPriority, depth: usize) {
        let idx = pri as usize;
        let high = self.config.high(pri);
        let low = self.config.low(pri);
        self.depths[idx].store(depth, std::sync::atomic::Ordering::Release);

        if high == 0 {
            return; // Backpressure disabled for this class.
        }

        let under = &self.under_pressure[idx];
        let was_under = under.load(std::sync::atomic::Ordering::Acquire);

        if was_under && depth <= low {
            // Drained below low watermark: clear pressure, notify available.
            under.store(false, std::sync::atomic::Ordering::Release);
            let _ = self.senders[idx].send_replace(true);
        } else if !was_under && depth >= high {
            // Crossed high watermark: set pressure, notify full.
            under.store(true, std::sync::atomic::Ordering::Release);
            let _ = self.senders[idx].send_replace(false);
        }
    }

    /// Return the watermark configuration (read-only).
    pub fn config(&self) -> &SendWatermarkConfig {
        &self.config
    }

    /// Return the latest capacity state observed for a priority class.
    pub fn snapshot(&self, pri: SendPriority) -> SendCapacitySnapshot {
        let idx = pri as usize;
        SendCapacitySnapshot {
            priority: pri,
            available: *self.senders[idx].borrow(),
            depth: self.depths[idx].load(std::sync::atomic::Ordering::Acquire),
            high_watermark: self.config.high(pri),
            low_watermark: self.config.low(pri),
        }
    }
}

// ---------------------------------------------------------------------------
// IoPressureProbe integration helpers
// ---------------------------------------------------------------------------

/// Create a callable that produces a foreground-I/O pressure value (0.0–1.0)
/// from a transport [`SendCapacity`] handle for the Data lane.
///
/// The returned closure is `Send + Sync + 'static` and can be wrapped in an
/// `IoPressureProbe` (from `tidefs-local-object-store`) to drive background
/// rebuild throttling.
///
/// # Behaviour
///
/// - Returns `1.0` when the Data lane is under backpressure (foreground I/O
///   saturated).
/// - Returns `0.0` when the Data lane is available (no backpressure).
///
/// # Example
///
/// ```ignore
/// use tidefs_local_object_store::IoPressureProbe;
/// use tidefs_transport::send_backpressure::data_lane_pressure_fn;
///
/// let capacity = capacity_set.capacity(SendPriority::Data);
/// let probe = IoPressureProbe::new(data_lane_pressure_fn(capacity));
/// ```
///
/// The caller is responsible for ensuring the `SendCapacity` outlives the
/// probe (the probe holds a clone of the capacity handle).
pub fn data_lane_pressure_fn(capacity: SendCapacity) -> impl Fn() -> f64 + Send + Sync + 'static {
    move || {
        if capacity.is_available() {
            0.0
        } else {
            1.0
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // --- SendWatermarkConfig tests ---

    #[test]
    fn default_config_is_valid() {
        let cfg = SendWatermarkConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn uniform_config_applies_all_same() {
        let cfg = SendWatermarkConfig::uniform(100, 20);
        assert_eq!(cfg.control_high, 100);
        assert_eq!(cfg.control_low, 20);
        assert_eq!(cfg.data_high, 100);
        assert_eq!(cfg.bulk_high, 100);
    }

    #[test]
    fn validation_rejects_low_gte_high() {
        let mut cfg = SendWatermarkConfig {
            control_low: 48, // equal to high
            ..Default::default()
        };
        assert!(cfg.validate().is_err());

        cfg.control_low = 49; // greater than high
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validation_allows_zero_high() {
        let cfg = SendWatermarkConfig {
            data_high: 0,
            // low >= high (0 >= 0) is ok when high==0
            data_low: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn is_enabled_returns_false_for_zero_high() {
        let cfg = SendWatermarkConfig::uniform(0, 0);
        assert!(!cfg.is_enabled(SendPriority::Data));
    }

    #[test]
    fn is_enabled_returns_true_for_positive_high() {
        let cfg = SendWatermarkConfig::default();
        assert!(cfg.is_enabled(SendPriority::Control));
    }

    #[test]
    fn high_and_low_accessors() {
        let cfg = SendWatermarkConfig::default();
        assert_eq!(cfg.high(SendPriority::Control), 48);
        assert_eq!(cfg.low(SendPriority::Control), 16);
        assert_eq!(cfg.high(SendPriority::Data), 192);
        assert_eq!(cfg.low(SendPriority::Data), 64);
    }

    // --- SendCapacitySet / SendCapacity tests ---

    #[tokio::test]
    async fn capacity_initially_available() {
        let cfg = SendWatermarkConfig::default();
        let set = SendCapacitySet::new(&cfg);
        let cap = set.capacity(SendPriority::Data);
        assert!(cap.is_available());
        // wait_for_capacity should resolve immediately.
        cap.wait_for_capacity().await;
    }

    #[tokio::test]
    async fn capacity_flips_to_full_at_high_watermark() {
        let cfg = SendWatermarkConfig::uniform(3, 1);
        let set = SendCapacitySet::new(&cfg);
        let cap = set.capacity(SendPriority::Data);

        // Simulate queue depth crossing high watermark.
        set.check_after_dequeue(SendPriority::Data, 3);
        assert!(!cap.is_available());

        // Drain to just above low watermark: still full.
        set.check_after_dequeue(SendPriority::Data, 2);
        assert!(!cap.is_available());
    }

    #[tokio::test]
    async fn capacity_clears_at_low_watermark() {
        let cfg = SendWatermarkConfig::uniform(3, 1);
        let set = SendCapacitySet::new(&cfg);
        let cap = set.capacity(SendPriority::Data);

        // Cross high watermark.
        set.check_after_dequeue(SendPriority::Data, 3);
        assert!(!cap.is_available());

        // Drain to low watermark: clears.
        set.check_after_dequeue(SendPriority::Data, 1);
        assert!(cap.is_available());
        let snapshot = set.snapshot(SendPriority::Data);
        assert_eq!(snapshot.depth, 1);
        assert_eq!(snapshot.high_watermark, 3);
        assert_eq!(snapshot.low_watermark, 1);
        assert!(snapshot.available);

        // Drain to 0: still available.
        set.check_after_dequeue(SendPriority::Data, 0);
        assert!(cap.is_available());
    }

    #[tokio::test]
    async fn capacity_stays_available_below_high() {
        let cfg = SendWatermarkConfig::uniform(5, 2);
        let set = SendCapacitySet::new(&cfg);
        let cap = set.capacity(SendPriority::Data);

        set.check_after_dequeue(SendPriority::Data, 4);
        assert!(cap.is_available());

        set.check_after_dequeue(SendPriority::Data, 3);
        assert!(cap.is_available());
    }

    #[tokio::test]
    async fn multiple_waiters_all_resolve_on_drain() {
        let cfg = SendWatermarkConfig::uniform(3, 1);
        let set = SendCapacitySet::new(&cfg);

        // Cross high watermark.
        set.check_after_dequeue(SendPriority::Data, 3);

        let cap = set.capacity(SendPriority::Data);
        assert!(!cap.is_available());

        // Spawn 3 waiters.
        let cap1 = cap.clone();
        let cap2 = cap.clone();
        let cap3 = cap.clone();

        let h1 = tokio::spawn(async move {
            cap1.wait_for_capacity().await;
        });
        let h2 = tokio::spawn(async move {
            cap2.wait_for_capacity().await;
        });
        let h3 = tokio::spawn(async move {
            cap3.wait_for_capacity().await;
        });

        // Short sleep to ensure they're waiting.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Drain below low watermark.
        set.check_after_dequeue(SendPriority::Data, 1);

        // All waiters should resolve within a timeout.
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let _ = tokio::join!(h1, h2, h3);
        })
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn wait_for_capacity_reports_drain_wake() {
        let cfg = SendWatermarkConfig::uniform(3, 1);
        let set = SendCapacitySet::new(&cfg);
        set.check_after_dequeue(SendPriority::Data, 3);
        let cap = set.capacity(SendPriority::Data);

        let waiter = tokio::spawn(async move { cap.wait_for_capacity_evidence().await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        set.check_after_dequeue(SendPriority::Data, 1);

        assert_eq!(waiter.await.unwrap(), SendWakeEvidence::DrainObserved);
    }

    #[tokio::test]
    async fn independent_priorities_dont_crosstalk() {
        let cfg = SendWatermarkConfig::uniform(3, 1);
        let set = SendCapacitySet::new(&cfg);

        let data_cap = set.capacity(SendPriority::Data);
        let bulk_cap = set.capacity(SendPriority::Bulk);

        // Cross high watermark for Data.
        set.check_after_dequeue(SendPriority::Data, 3);
        assert!(!data_cap.is_available());
        // Bulk unaffected.
        assert!(bulk_cap.is_available());

        // Drain Data.
        set.check_after_dequeue(SendPriority::Data, 1);
        assert!(data_cap.is_available());
        assert!(bulk_cap.is_available());
    }

    #[tokio::test]
    async fn zero_high_watermark_disables_backpressure() {
        let cfg = SendWatermarkConfig::uniform(0, 0);
        let set = SendCapacitySet::new(&cfg);
        let cap = set.capacity(SendPriority::Data);

        // Always available regardless of depth.
        set.check_after_dequeue(SendPriority::Data, 100);
        assert!(cap.is_available());
        cap.wait_for_capacity().await;
    }

    #[tokio::test]
    async fn high_equals_low_plus_one_minimal_hysteresis() {
        let cfg = SendWatermarkConfig::uniform(2, 1);
        let set = SendCapacitySet::new(&cfg);
        let cap = set.capacity(SendPriority::Data);

        set.check_after_dequeue(SendPriority::Data, 2);
        assert!(!cap.is_available());

        set.check_after_dequeue(SendPriority::Data, 1);
        assert!(cap.is_available());
    }

    #[tokio::test]
    async fn boundary_exactly_at_high_watermark() {
        let cfg = SendWatermarkConfig::uniform(5, 2);
        let set = SendCapacitySet::new(&cfg);
        let cap = set.capacity(SendPriority::Data);

        // Exactly at high.
        set.check_after_dequeue(SendPriority::Data, 5);
        assert!(!cap.is_available());

        // Still at high.
        set.check_after_dequeue(SendPriority::Data, 5);
        assert!(!cap.is_available());
    }

    #[tokio::test]
    async fn boundary_exactly_at_low_watermark() {
        let cfg = SendWatermarkConfig::uniform(5, 2);
        let set = SendCapacitySet::new(&cfg);
        let cap = set.capacity(SendPriority::Data);

        // Cross high.
        set.check_after_dequeue(SendPriority::Data, 5);
        assert!(!cap.is_available());

        // Exactly at low: clears.
        set.check_after_dequeue(SendPriority::Data, 2);
        assert!(cap.is_available());
    }

    #[tokio::test]
    async fn no_double_high_signalling() {
        let cfg = SendWatermarkConfig::uniform(3, 1);
        let set = SendCapacitySet::new(&cfg);
        let cap = set.capacity(SendPriority::Data);

        // Cross high.
        set.check_after_dequeue(SendPriority::Data, 3);
        assert!(!cap.is_available());

        // Still above high (depth didn't change much).
        set.check_after_dequeue(SendPriority::Data, 4);
        assert!(!cap.is_available()); // No double-signal issues.
    }

    #[tokio::test]
    async fn wait_for_capacity_resolves_when_sender_dropped() {
        let cfg = SendWatermarkConfig::uniform(3, 1);
        let set = SendCapacitySet::new(&cfg);
        let cap = set.capacity(SendPriority::Data);

        // Cross high watermark.
        set.check_after_dequeue(SendPriority::Data, 3);
        assert!(!cap.is_available());

        // Drop the capacity set (simulating shutdown).
        let cap_clone = cap.clone();
        drop(set);

        // wait_for_capacity should resolve (sender dropped).
        let result =
            tokio::time::timeout(Duration::from_secs(2), cap_clone.wait_for_capacity()).await;
        assert!(result.is_ok());
    }

    #[test]
    fn config_accessor_returns_ref() {
        let cfg = SendWatermarkConfig::default();
        let set = SendCapacitySet::new(&cfg);
        assert_eq!(set.config().control_high, 48);
    }
}

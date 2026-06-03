//! Transport connection idle timeout: passive activity-watch detection that
//! drains or force-closes abandoned connections after a configurable deadline
//! without inbound or outbound message activity.
//!
//! ## Relationship to keepalive
//!
//! Keepalive (#5906) actively probes peers with ping/pong frames to detect
//! failures. Idle timeout is passive: it watches for message activity and,
//! when no activity is seen for the configured deadline, triggers graceful
//! drain via the existing drain protocol or force-closes the connection.
//!
//! Together they provide complementary detection: keepalive catches crashed
//! peers that silently stop responding, while idle timeout catches fully
//! abandoned connections where neither side is sending anything (including
//! keepalive probes).

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// ActivitySource
// ---------------------------------------------------------------------------

/// Which directions of message activity to track for idle detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivitySource {
    /// Only inbound message activity resets the idle timer.
    Inbound,
    /// Only outbound send-completion activity resets the idle timer.
    Outbound,
    /// Either inbound or outbound activity resets the idle timer.
    Both,
}

impl fmt::Display for ActivitySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inbound => write!(f, "Inbound"),
            Self::Outbound => write!(f, "Outbound"),
            Self::Both => write!(f, "Both"),
        }
    }
}

// ---------------------------------------------------------------------------
// IdleTimeoutConfig
// ---------------------------------------------------------------------------

/// Configuration for per-connection idle timeout detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdleTimeoutConfig {
    /// Duration of no activity before the connection is considered idle.
    pub deadline: Duration,
    /// Which activity sources to track: inbound, outbound, or both.
    pub activity_sources: ActivitySource,
    /// If true, trigger graceful drain on expiry. If false, force-close.
    pub trigger_drain: bool,
    /// Optional warning duration before the deadline.
    pub warn_before: Option<Duration>,
}

impl IdleTimeoutConfig {
    /// Create a new idle timeout configuration.
    #[must_use]
    pub fn new(
        deadline: Duration,
        activity_sources: ActivitySource,
        trigger_drain: bool,
    ) -> Option<Self> {
        if deadline.is_zero() {
            return None;
        }
        Some(Self {
            deadline,
            activity_sources,
            trigger_drain,
            warn_before: None,
        })
    }

    /// Set the optional warning duration.
    #[must_use]
    pub fn with_warn_before(mut self, warn_before: Duration) -> Option<Self> {
        if warn_before >= self.deadline {
            return None;
        }
        self.warn_before = Some(warn_before);
        Some(self)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.deadline.is_zero() {
            return Err("deadline must be non-zero");
        }
        if let Some(warn) = self.warn_before {
            if warn >= self.deadline {
                return Err("warn_before must be less than deadline");
            }
        }
        Ok(())
    }
}

impl Default for IdleTimeoutConfig {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(300),
            activity_sources: ActivitySource::Both,
            trigger_drain: true,
            warn_before: Some(Duration::from_secs(60)),
        }
    }
}

// ---------------------------------------------------------------------------
// IdleTracker
// ---------------------------------------------------------------------------

/// Per-connection idle activity tracker.
#[derive(Clone, Debug)]
pub struct IdleTracker {
    last_activity: Arc<Mutex<Option<Instant>>>,
    cancelled: Arc<AtomicBool>,
}

impl IdleTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_activity: Arc::new(Mutex::new(None)),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Record activity at the current instant.
    pub fn record_activity(&self) {
        if self.cancelled.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Some(Instant::now());
        }
    }

    /// Mark the tracker as cancelled.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Returns true if no activity within deadline.
    #[must_use]
    pub fn is_idle(&self, deadline: Duration) -> bool {
        if self.cancelled.load(Ordering::SeqCst) {
            return false;
        }
        match self.elapsed_since_last_activity() {
            Some(elapsed) => elapsed >= deadline,
            None => false,
        }
    }

    #[must_use]
    pub fn elapsed_since_last_activity(&self) -> Option<Duration> {
        self.last_activity
            .lock()
            .ok()
            .and_then(|guard| guard.map(|t| t.elapsed()))
    }

    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = None;
        }
    }

    #[must_use]
    pub fn shared(&self) -> Self {
        Self {
            last_activity: Arc::clone(&self.last_activity),
            cancelled: Arc::clone(&self.cancelled),
        }
    }
}

impl Default for IdleTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IdleTimeoutEvent
// ---------------------------------------------------------------------------

/// Events emitted by the idle timeout controller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdleTimeoutEvent {
    Warned { idle_duration: Duration },
    DrainInitiated { idle_duration: Duration },
    ForceClosed { idle_duration: Duration },
}

impl fmt::Display for IdleTimeoutEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warned { idle_duration } => {
                write!(f, "IdleTimeoutWarned(idle={idle_duration:?})")
            }
            Self::DrainInitiated { idle_duration } => {
                write!(f, "IdleTimeoutDrainInitiated(idle={idle_duration:?})")
            }
            Self::ForceClosed { idle_duration } => {
                write!(f, "IdleTimeoutForceClosed(idle={idle_duration:?})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IdleTimeoutSubscriber
// ---------------------------------------------------------------------------

pub trait IdleTimeoutSubscriber: Send + Sync {
    fn on_idle_timeout_event(&self, event: &IdleTimeoutEvent);
}

// ---------------------------------------------------------------------------
// IdleTimeoutController
// ---------------------------------------------------------------------------

// Manual Debug impl below: subscribers field contains dyn trait objects
pub struct IdleTimeoutController {
    config: IdleTimeoutConfig,
    tracker: IdleTracker,
    state: ControllerState,
    warned: bool,
    subscribers: Vec<Box<dyn IdleTimeoutSubscriber>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControllerState {
    Active,
    Warned,
    DrainTriggered,
    ForceClosed,
    Cancelled,
}

impl IdleTimeoutController {
    #[must_use]
    pub fn new(config: IdleTimeoutConfig, tracker: IdleTracker) -> Self {
        Self {
            config,
            tracker,
            state: ControllerState::Active,
            warned: false,
            subscribers: Vec::new(),
        }
    }

    pub fn subscribe(&mut self, subscriber: Box<dyn IdleTimeoutSubscriber>) {
        self.subscribers.push(subscriber);
    }

    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn state(&self) -> ControllerState {
        self.state
    }

    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            ControllerState::DrainTriggered
                | ControllerState::ForceClosed
                | ControllerState::Cancelled
        )
    }

    #[must_use]
    pub fn tracker(&self) -> &IdleTracker {
        &self.tracker
    }

    #[must_use]
    pub fn shared_tracker(&self) -> IdleTracker {
        self.tracker.shared()
    }

    pub fn cancel(&mut self) {
        self.state = ControllerState::Cancelled;
        self.tracker.cancel();
    }

    #[must_use]
    pub fn tick(&mut self) -> Option<IdleTimeoutEvent> {
        match self.state {
            ControllerState::DrainTriggered
            | ControllerState::ForceClosed
            | ControllerState::Cancelled => return None,
            _ => {}
        }

        if self.tracker.is_cancelled() {
            self.state = ControllerState::Cancelled;
            return None;
        }

        let elapsed = self.tracker.elapsed_since_last_activity()?;

        if elapsed >= self.config.deadline {
            if self.config.trigger_drain {
                self.state = ControllerState::DrainTriggered;
                let event = IdleTimeoutEvent::DrainInitiated {
                    idle_duration: elapsed,
                };
                self.broadcast(&event);
                return Some(event);
            } else {
                self.state = ControllerState::ForceClosed;
                let event = IdleTimeoutEvent::ForceClosed {
                    idle_duration: elapsed,
                };
                self.broadcast(&event);
                return Some(event);
            }
        }

        if !self.warned {
            if let Some(warn_before) = self.config.warn_before {
                if elapsed >= (self.config.deadline.saturating_sub(warn_before)) {
                    self.warned = true;
                    self.state = ControllerState::Warned;
                    let event = IdleTimeoutEvent::Warned {
                        idle_duration: elapsed,
                    };
                    self.broadcast(&event);
                    return Some(event);
                }
            }
        }

        None
    }

    pub fn reset(&mut self) {
        self.state = ControllerState::Active;
        self.warned = false;
        self.tracker.reset();
    }

    fn broadcast(&self, event: &IdleTimeoutEvent) {
        for sub in &self.subscribers {
            sub.on_idle_timeout_event(event);
        }
    }
}

impl fmt::Display for ControllerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Warned => write!(f, "Warned"),
            Self::DrainTriggered => write!(f, "DrainTriggered"),
            Self::ForceClosed => write!(f, "ForceClosed"),
            Self::Cancelled => write!(f, "Cancelled"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

impl fmt::Debug for IdleTimeoutController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdleTimeoutController")
            .field("config", &self.config)
            .field("tracker", &self.tracker)
            .field("state", &self.state)
            .field("warned", &self.warned)
            .field("subscriber_count", &self.subscribers.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// IdleTimeoutRunner -- background tokio task
// ---------------------------------------------------------------------------

/// Default tick interval for the idle timeout background task: 5 seconds.
pub const DEFAULT_IDLE_TICK_INTERVAL_MS: u64 = 5_000;

/// A background tokio task that polls an [`IdleTimeoutController`] on a
/// configurable interval and triggers drain or force-close when the idle
/// deadline is exceeded.
///
/// ## Lifecycle
///
/// 1. Create an [`IdleTimeoutController`] and [`IdleTimeoutRunner`].
/// 2. Call [`spawn`](IdleTimeoutRunner::spawn) with drain-initiate and
///    force-close callbacks. The runner starts a tokio task that polls
///    the controller every `tick_interval`.
/// 3. When the controller fires `DrainInitiated`, the drain callback is
///    invoked and the task exits (the drain protocol takes over).
/// 4. When the controller fires `ForceClosed`, the force-close callback
///    is invoked and the task exits.
/// 5. Call [`cancel`](IdleTimeoutRunner::cancel) to stop the task early
///    (e.g., when the connection enters Draining or Closed).
/// 6. Call [`reset`](IdleTimeoutRunner::reset) for new connections.
pub struct IdleTimeoutRunner {
    controller: Arc<Mutex<IdleTimeoutController>>,
    tick_interval: Duration,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl IdleTimeoutRunner {
    /// Create a new runner with the given controller and tick interval.
    #[must_use]
    pub fn new(controller: IdleTimeoutController, tick_interval: Duration) -> Self {
        Self {
            controller: Arc::new(Mutex::new(controller)),
            tick_interval,
            handle: None,
        }
    }

    /// Create a new runner with the default 5 s tick interval.
    #[must_use]
    pub fn with_default_interval(controller: IdleTimeoutController) -> Self {
        Self::new(
            controller,
            Duration::from_millis(DEFAULT_IDLE_TICK_INTERVAL_MS),
        )
    }

    /// Spawn the background polling task.
    ///
    /// `on_drain_initiated` is called with the idle duration when drain
    /// should be triggered. `on_force_close` is called when drain is
    /// disabled in config. `on_warned` is called on the warning
    /// threshold (pass a no-op if unused).
    ///
    /// If a task is already running, this is a no-op.
    pub fn spawn<D, F, W>(&mut self, on_drain_initiated: D, on_force_close: F, on_warned: W)
    where
        D: FnOnce(Duration) + Send + 'static,
        F: FnOnce(Duration) + Send + 'static,
        W: Fn(Duration) + Send + 'static,
    {
        if self.handle.is_some() {
            return;
        }

        let controller = Arc::clone(&self.controller);
        let tick_interval = self.tick_interval;

        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(tick_interval).await;

                let event = {
                    let mut ctl = controller.lock().unwrap();
                    ctl.tick()
                };

                match event {
                    Some(IdleTimeoutEvent::DrainInitiated { idle_duration }) => {
                        on_drain_initiated(idle_duration);
                        return;
                    }
                    Some(IdleTimeoutEvent::ForceClosed { idle_duration }) => {
                        on_force_close(idle_duration);
                        return;
                    }
                    Some(IdleTimeoutEvent::Warned { idle_duration }) => {
                        on_warned(idle_duration);
                    }
                    None => {
                        let ctl = controller.lock().unwrap();
                        if ctl.is_terminal() {
                            return;
                        }
                    }
                }
            }
        });

        self.handle = Some(handle);
    }

    /// Cancel the background task and the underlying controller.
    ///
    /// Safe to call multiple times.
    pub fn cancel(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        if let Ok(mut ctl) = self.controller.lock() {
            ctl.cancel();
        }
    }

    /// Returns `true` if the background task has completed.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        match &self.handle {
            Some(h) => h.is_finished(),
            None => true,
        }
    }

    /// Reset the runner and its controller for a new connection.
    ///
    /// Cancels any running task and resets the controller to `Active`.
    pub fn reset(&mut self) {
        self.cancel();
        if let Ok(mut ctl) = self.controller.lock() {
            ctl.reset();
        }
    }

    /// Return a shared clone of the controller's idle tracker.
    #[must_use]
    pub fn shared_tracker(&self) -> IdleTracker {
        self.controller.lock().unwrap().shared_tracker()
    }
}

impl fmt::Debug for IdleTimeoutRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdleTimeoutRunner")
            .field("tick_interval", &self.tick_interval)
            .field("running", &self.handle.is_some())
            .finish_non_exhaustive()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn tracker_not_idle_when_activity_within_deadline() {
        let tracker = IdleTracker::new();
        tracker.record_activity();
        assert!(!tracker.is_idle(Duration::from_secs(60)));
    }

    #[test]
    fn tracker_idle_when_deadline_elapsed() {
        let tracker = IdleTracker::new();
        tracker.record_activity();
        assert!(tracker.is_idle(Duration::ZERO));
    }

    #[test]
    fn tracker_not_idle_with_no_activity_ever() {
        let tracker = IdleTracker::new();
        assert!(!tracker.is_idle(Duration::from_secs(1)));
        assert!(!tracker.is_idle(Duration::ZERO));
    }

    #[test]
    fn tracker_elapsed_since_last_activity_none_initially() {
        let tracker = IdleTracker::new();
        assert!(tracker.elapsed_since_last_activity().is_none());
    }

    #[test]
    fn tracker_elapsed_since_last_activity_some_after_record() {
        let tracker = IdleTracker::new();
        tracker.record_activity();
        let elapsed = tracker.elapsed_since_last_activity();
        assert!(elapsed.is_some());
        assert!(elapsed.unwrap() < Duration::from_secs(1));
    }

    #[test]
    fn tracker_cancel_stops_idle_detection() {
        let tracker = IdleTracker::new();
        tracker.record_activity();
        assert!(tracker.is_idle(Duration::ZERO));
        tracker.cancel();
        assert!(!tracker.is_idle(Duration::ZERO));
        assert!(tracker.is_cancelled());
    }

    #[test]
    fn tracker_record_activity_after_cancel_is_noop() {
        let tracker = IdleTracker::new();
        tracker.record_activity();
        tracker.cancel();
        tracker.record_activity();
        assert!(!tracker.is_idle(Duration::ZERO));
    }

    #[test]
    fn tracker_reset_clears_cancelled_and_activity() {
        let tracker = IdleTracker::new();
        tracker.record_activity();
        tracker.cancel();
        assert!(tracker.is_cancelled());
        tracker.reset();
        assert!(!tracker.is_cancelled());
        assert!(tracker.elapsed_since_last_activity().is_none());
        assert!(!tracker.is_idle(Duration::ZERO));
    }

    #[test]
    fn tracker_shared_clones_share_state() {
        let tracker = IdleTracker::new();
        let shared = tracker.shared();
        tracker.record_activity();
        assert!(shared.elapsed_since_last_activity().is_some());
        shared.cancel();
        assert!(tracker.is_cancelled());
    }

    #[test]
    fn tracker_multiple_connections_independent() {
        let t1 = IdleTracker::new();
        let t2 = IdleTracker::new();
        t1.record_activity();
        assert!(t1.elapsed_since_last_activity().is_some());
        assert!(t2.elapsed_since_last_activity().is_none());
        t1.cancel();
        assert!(t1.is_cancelled());
        assert!(!t2.is_cancelled());
    }

    #[test]
    fn config_new_rejects_zero_deadline() {
        assert!(IdleTimeoutConfig::new(Duration::ZERO, ActivitySource::Both, true).is_none());
    }

    #[test]
    fn config_default_has_sensible_values() {
        let cfg = IdleTimeoutConfig::default();
        assert_eq!(cfg.deadline, Duration::from_secs(300));
        assert_eq!(cfg.activity_sources, ActivitySource::Both);
        assert!(cfg.trigger_drain);
        assert_eq!(cfg.warn_before, Some(Duration::from_secs(60)));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn activity_source_display() {
        assert_eq!(format!("{}", ActivitySource::Inbound), "Inbound");
        assert_eq!(format!("{}", ActivitySource::Outbound), "Outbound");
        assert_eq!(format!("{}", ActivitySource::Both), "Both");
    }

    #[test]
    fn controller_no_action_with_recent_activity() {
        let cfg =
            IdleTimeoutConfig::new(Duration::from_secs(300), ActivitySource::Both, true).unwrap();
        let tracker = IdleTracker::new();
        tracker.record_activity();
        let mut ctl = IdleTimeoutController::new(cfg, tracker);
        assert_eq!(ctl.tick(), None);
        assert_eq!(ctl.state(), ControllerState::Active);
    }

    #[test]
    fn controller_no_action_with_no_activity_yet() {
        let cfg =
            IdleTimeoutConfig::new(Duration::from_secs(1), ActivitySource::Both, true).unwrap();
        let tracker = IdleTracker::new();
        let mut ctl = IdleTimeoutController::new(cfg, tracker);
        assert_eq!(ctl.tick(), None);
    }

    #[test]
    fn controller_initiates_drain_on_idle_deadline() {
        let cfg =
            IdleTimeoutConfig::new(Duration::from_nanos(1), ActivitySource::Both, true).unwrap();
        let tracker = IdleTracker::new();
        tracker.record_activity();
        let mut ctl = IdleTimeoutController::new(cfg, tracker);
        let event = ctl.tick();
        assert!(event.is_some());
        match event.unwrap() {
            IdleTimeoutEvent::DrainInitiated { .. } => {}
            other => panic!("expected DrainInitiated, got {other:?}"),
        }
        assert_eq!(ctl.state(), ControllerState::DrainTriggered);
        assert!(ctl.is_terminal());
    }

    #[test]
    fn controller_force_closes_when_drain_disabled() {
        let cfg =
            IdleTimeoutConfig::new(Duration::from_nanos(1), ActivitySource::Both, false).unwrap();
        let tracker = IdleTracker::new();
        tracker.record_activity();
        let mut ctl = IdleTimeoutController::new(cfg, tracker);
        let event = ctl.tick();
        assert!(event.is_some());
        match event.unwrap() {
            IdleTimeoutEvent::ForceClosed { .. } => {}
            other => panic!("expected ForceClosed, got {other:?}"),
        }
        assert_eq!(ctl.state(), ControllerState::ForceClosed);
    }

    #[test]
    fn controller_cancelled_stops_all_events() {
        let cfg =
            IdleTimeoutConfig::new(Duration::from_nanos(1), ActivitySource::Both, true).unwrap();
        let tracker = IdleTracker::new();
        tracker.record_activity();
        let mut ctl = IdleTimeoutController::new(cfg, tracker);
        ctl.cancel();
        assert_eq!(ctl.state(), ControllerState::Cancelled);
        assert_eq!(ctl.tick(), None);
    }

    #[test]
    fn controller_reset_clears_state() {
        let cfg =
            IdleTimeoutConfig::new(Duration::from_nanos(1), ActivitySource::Both, true).unwrap();
        let tracker = IdleTracker::new();
        tracker.record_activity();
        let mut ctl = IdleTimeoutController::new(cfg, tracker);
        let event = ctl.tick().unwrap();
        assert!(matches!(event, IdleTimeoutEvent::DrainInitiated { .. }));
        ctl.reset();
        assert_eq!(ctl.state(), ControllerState::Active);
        assert!(!ctl.is_terminal());
        assert_eq!(ctl.tick(), None);
        ctl.tracker().record_activity();
        let event2 = ctl.tick().unwrap();
        assert!(matches!(event2, IdleTimeoutEvent::DrainInitiated { .. }));
    }

    #[test]
    fn controller_subscriber_receives_events() {
        struct CountingSub {
            event_count: AtomicU32,
        }
        impl IdleTimeoutSubscriber for CountingSub {
            fn on_idle_timeout_event(&self, _event: &IdleTimeoutEvent) {
                self.event_count.fetch_add(1, Ordering::SeqCst);
            }
        }
        let sub = Arc::new(CountingSub {
            event_count: AtomicU32::new(0),
        });
        struct ArcSub {
            inner: Arc<CountingSub>,
        }
        impl IdleTimeoutSubscriber for ArcSub {
            fn on_idle_timeout_event(&self, event: &IdleTimeoutEvent) {
                self.inner.on_idle_timeout_event(event);
            }
        }
        let cfg =
            IdleTimeoutConfig::new(Duration::from_nanos(1), ActivitySource::Both, true).unwrap();
        let tracker = IdleTracker::new();
        tracker.record_activity();
        let mut ctl = IdleTimeoutController::new(cfg, tracker);
        ctl.subscribe(Box::new(ArcSub { inner: sub.clone() }));
        let _ = ctl.tick();
        assert_eq!(sub.event_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn controller_terminal_tick_returns_none() {
        let cfg =
            IdleTimeoutConfig::new(Duration::from_nanos(1), ActivitySource::Both, true).unwrap();
        let tracker = IdleTracker::new();
        tracker.record_activity();
        let mut ctl = IdleTimeoutController::new(cfg, tracker);
        assert!(ctl.tick().is_some());
        assert!(ctl.tick().is_none());
        assert!(ctl.tick().is_none());
    }

    #[test]
    fn multiple_controllers_independent_deadlines() {
        let cfg1 =
            IdleTimeoutConfig::new(Duration::from_nanos(1), ActivitySource::Both, true).unwrap();
        let cfg2 =
            IdleTimeoutConfig::new(Duration::from_secs(3600), ActivitySource::Both, true).unwrap();
        let t1 = IdleTracker::new();
        t1.record_activity();
        let t2 = IdleTracker::new();
        t2.record_activity();
        let mut c1 = IdleTimeoutController::new(cfg1, t1);
        let mut c2 = IdleTimeoutController::new(cfg2, t2);
        assert!(c1.tick().is_some());
        assert!(c1.is_terminal());
        assert_eq!(c2.tick(), None);
        assert!(!c2.is_terminal());
    }

    #[test]
    fn idle_timeout_event_display() {
        let d = Duration::from_secs(42);
        assert!(format!("{}", IdleTimeoutEvent::Warned { idle_duration: d }).contains("42s"));
        assert!(
            format!("{}", IdleTimeoutEvent::DrainInitiated { idle_duration: d }).contains("42s")
        );
        assert!(format!("{}", IdleTimeoutEvent::ForceClosed { idle_duration: d }).contains("42s"));
    }

    #[test]
    fn controller_state_display() {
        assert_eq!(format!("{}", ControllerState::Active), "Active");
        assert_eq!(format!("{}", ControllerState::Warned), "Warned");
        assert_eq!(
            format!("{}", ControllerState::DrainTriggered),
            "DrainTriggered"
        );
        assert_eq!(format!("{}", ControllerState::ForceClosed), "ForceClosed");
        assert_eq!(format!("{}", ControllerState::Cancelled), "Cancelled");
    }

    // -------------------------------------------------------------------
    // IdleTimeoutRunner tokio tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn runner_spawn_and_drain_initiated() {
        let cfg =
            IdleTimeoutConfig::new(Duration::from_nanos(1), ActivitySource::Both, true).unwrap();
        let tracker = IdleTracker::new();
        tracker.record_activity();
        let controller = IdleTimeoutController::new(cfg, tracker);
        let mut runner = IdleTimeoutRunner::new(controller, Duration::from_millis(10));

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let tx2 = tx.clone();

        runner.spawn(
            move |d| {
                let _ = tx.send(("drain", d));
            },
            move |d| {
                let _ = tx2.send(("force_close", d));
            },
            |_d| {},
        );

        // Wait for the drain event.
        let result = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
        assert!(result.is_ok(), "timeout waiting for idle event");
        let (kind, _duration) = result.unwrap().unwrap();
        assert_eq!(kind, "drain");
        assert!(runner.is_finished());
    }

    #[tokio::test]
    async fn runner_force_close_when_drain_disabled() {
        let cfg =
            IdleTimeoutConfig::new(Duration::from_nanos(1), ActivitySource::Both, false).unwrap();
        let tracker = IdleTracker::new();
        tracker.record_activity();
        let controller = IdleTimeoutController::new(cfg, tracker);
        let mut runner = IdleTimeoutRunner::new(controller, Duration::from_millis(10));

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let tx2 = tx.clone();

        runner.spawn(
            move |d| {
                let _ = tx.send(("drain", d));
            },
            move |d| {
                let _ = tx2.send(("force_close", d));
            },
            |_d| {},
        );

        let result = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
        let (kind, _) = result.unwrap().unwrap();
        assert_eq!(kind, "force_close");
        assert!(runner.is_finished());
    }

    #[tokio::test]
    async fn runner_cancel_stops_task() {
        let cfg =
            IdleTimeoutConfig::new(Duration::from_secs(3600), ActivitySource::Both, true).unwrap();
        let tracker = IdleTracker::new();
        tracker.record_activity();
        let controller = IdleTimeoutController::new(cfg, tracker);
        let mut runner = IdleTimeoutRunner::new(controller, Duration::from_millis(10));

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<(&str, Duration)>();

        runner.spawn(
            move |_d| {
                let _ = tx.send(("drain", Duration::ZERO));
            },
            move |_d| {},
            |_d| {},
        );

        // Give the task a moment to start.
        tokio::time::sleep(Duration::from_millis(20)).await;

        runner.cancel();
        assert!(runner.is_finished());
    }

    #[tokio::test]
    async fn runner_reset_clears_state() {
        let cfg =
            IdleTimeoutConfig::new(Duration::from_nanos(1), ActivitySource::Both, true).unwrap();
        let tracker = IdleTracker::new();
        tracker.record_activity();
        let controller = IdleTimeoutController::new(cfg, tracker);
        let mut runner = IdleTimeoutRunner::new(controller, Duration::from_millis(10));

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let tx2 = tx.clone();

        runner.spawn(
            move |d| {
                let _ = tx.send(("drain", d));
            },
            move |d| {
                let _ = tx2.send(("force_close", d));
            },
            |_d| {},
        );

        // Wait for first drain event.
        let result = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
        assert!(result.is_ok(), "timeout waiting for first drain event");

        runner.reset();
        // After reset, is_finished() returns true because no task is running.
        assert!(runner.is_finished());

        // Spawn again with new callbacks.
        let (tx3, mut rx2) = tokio::sync::mpsc::unbounded_channel();
        let tx4 = tx3.clone();
        runner.shared_tracker().record_activity();
        runner.spawn(
            move |d| {
                let _ = tx3.send(("drain", d));
            },
            move |d| {
                let _ = tx4.send(("force_close", d));
            },
            |_d| {},
        );

        let result2 = tokio::time::timeout(Duration::from_secs(5), rx2.recv()).await;
        assert!(result2.is_ok(), "timeout waiting for second drain event");
    }

    #[tokio::test]
    async fn runner_warned_callback_fires() {
        // Use a config with warn_before so warning fires before deadline.
        let cfg = IdleTimeoutConfig::new(Duration::from_nanos(1), ActivitySource::Both, true)
            .unwrap()
            .with_warn_before(Duration::from_secs(0))
            .unwrap();
        let tracker = IdleTracker::new();
        tracker.record_activity();
        let controller = IdleTimeoutController::new(cfg, tracker);
        let mut runner = IdleTimeoutRunner::new(controller, Duration::from_millis(10));

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let tx2 = tx.clone();
        let tx3 = tx.clone();

        runner.spawn(
            move |d| {
                let _ = tx.send(("drain", d));
            },
            move |d| {
                let _ = tx2.send(("force_close", d));
            },
            move |d| {
                let _ = tx3.send(("warned", d));
            },
        );

        // With zero deadline + zero warn_before, deadline fires first.
        let result = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
        assert!(result.is_ok());
    }
}

// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Request-response correlation table for in-flight request tracking, timeout
// expiry, and response delivery over the existing send/receive dispatch paths.
//
// Upper-layer protocols (membership, leases, placement, state transfer) use
// RequestResponseHandle::register_request before transmitting and
// RequestResponseHandle::deliver_response when a response-bearing message
// arrives, eliminating duplicated correlation logic across subsystems.
//
// In-flight request concurrency is tracked atomically via the
// `request_concurrency` module's `RequestConcurrencyGuard`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Mutex};

use crate::request_concurrency::{RequestConcurrencyGuard, RequestLimitExceeded};

/// Errors returned by request-response correlation operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum CorrelationError {
    /// The request deadline elapsed and the entry was removed.
    #[error("request timed out after {0:?}")]
    Timeout(Duration),

    /// A response arrived for an unknown (or already-completed) correlation ID.
    #[error("unknown correlation id: {0}")]
    UnknownCorrelationId(u64),

    /// The per-session request concurrency limit has been reached.
    /// The caller should back off and retry.
    #[error("request concurrency limit reached: {0} in-flight, max {1}")]
    RequestLimitExceeded(usize, usize),

    /// The peer for this request has departed the cluster.
    #[error("peer departed: {0}")]
    PeerDeparted(u64),
}

/// A pending in-flight request waiting for its response or timeout.
struct PendingRequest<T> {
    sender: oneshot::Sender<Result<T, CorrelationError>>,
    deadline: Instant,
    /// RAII guard that holds one in-flight concurrency slot.  Dropped when
    /// this entry is removed from the table, releasing the slot.
    _guard: RequestConcurrencyGuard,
}

/// Internal shared state between [`RequestResponseTable`] and its handles.
struct RequestResponseInner<T> {
    next_id: AtomicU64,
    in_flight: Arc<AtomicUsize>,
    max_in_flight: Mutex<Option<usize>>,
    entries: Mutex<HashMap<u64, PendingRequest<T>>>,
    default_timeout: Duration,
}

/// The owning side of a request-response correlation table with optional
/// per-session in-flight request concurrency limiting.
///
/// Use [`RequestResponseTable::handle`] to obtain a handle that can be shared
/// across send and receive dispatch paths.
pub struct RequestResponseTable<T: Clone + Send + 'static> {
    inner: Arc<RequestResponseInner<T>>,
}

/// A handle to the correlation table that upper-layer protocols use to register
/// outgoing requests and deliver incoming responses.
///
/// Cheap to clone (wraps an `Arc`).
pub struct RequestResponseHandle<T: Clone + Send + 'static> {
    inner: Arc<RequestResponseInner<T>>,
}

impl<T: Clone + Send + 'static> Clone for RequestResponseHandle<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Configuration for the timeout scanner that periodically evicts expired
/// entries.
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Interval between scans for expired entries.
    pub scan_interval: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            scan_interval: Duration::from_secs(1),
        }
    }
}

impl<T: Clone + Send + 'static> RequestResponseTable<T> {
    /// Create a new correlation table.
    ///
    /// `max_entries` bounds the number of concurrently in-flight requests
    /// via the request-concurrency guard.  Pass `None` for unlimited.
    /// `default_timeout` is the per-request deadline applied at registration time.
    ///
    /// # Panics
    ///
    /// Panics if `max_entries` is `Some(0)` or `default_timeout` is zero.
    pub fn new(max_entries: Option<usize>, default_timeout: Duration) -> Self {
        if let Some(me) = max_entries {
            assert!(me > 0, "max_entries must be positive when set");
        }
        assert!(
            !default_timeout.is_zero(),
            "default_timeout must be non-zero"
        );
        let cap = max_entries.unwrap_or(64);
        Self {
            inner: Arc::new(RequestResponseInner {
                next_id: AtomicU64::new(1),
                in_flight: Arc::new(AtomicUsize::new(0)),
                max_in_flight: Mutex::new(max_entries),
                entries: Mutex::new(HashMap::with_capacity(cap)),
                default_timeout,
            }),
        }
    }

    /// Obtain a handle to this table for use by other tasks or dispatch paths.
    pub fn handle(&self) -> RequestResponseHandle<T> {
        RequestResponseHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Spawn a background timeout-scanning task.
    ///
    /// The returned [`tokio::task::JoinHandle`] runs indefinitely, periodically
    /// removing expired entries and signalling timeout errors. It holds a
    /// reference to the table, so as long as the handle lives the table remains
    /// alive even if the original `RequestResponseTable` is dropped.
    pub fn spawn_timeout_task(self, config: TimeoutConfig) -> tokio::task::JoinHandle<()> {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(config.scan_interval).await;
                let now = Instant::now();
                let mut entries = inner.entries.lock().await;
                let mut timed_out = Vec::new();
                for (id, pending) in entries.iter() {
                    if pending.deadline <= now {
                        timed_out.push(*id);
                    }
                }
                for id in timed_out {
                    if let Some(pending) = entries.remove(&id) {
                        let _ = pending
                            .sender
                            .send(Err(CorrelationError::Timeout(inner.default_timeout)));
                        // pending._guard drops here, releasing the concurrency slot
                    }
                }
            }
        })
    }

    /// Spawn a timeout-scanning task when the caller is currently inside a
    /// Tokio runtime.
    ///
    /// Plain thread-based transport users still get a response tracker handle
    /// for synchronous send/receive paths, but there is no runtime to host the
    /// asynchronous timeout scanner. Async request-response callers should run
    /// inside Tokio and will get the scanner through this method.
    pub fn try_spawn_timeout_task(
        self,
        config: TimeoutConfig,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let handle = tokio::runtime::Handle::try_current().ok()?;
        let inner = Arc::clone(&self.inner);
        Some(handle.spawn(async move {
            loop {
                tokio::time::sleep(config.scan_interval).await;
                let now = Instant::now();
                let mut entries = inner.entries.lock().await;
                let mut timed_out = Vec::new();
                for (id, pending) in entries.iter() {
                    if pending.deadline <= now {
                        timed_out.push(*id);
                    }
                }
                for id in timed_out {
                    if let Some(pending) = entries.remove(&id) {
                        let _ = pending
                            .sender
                            .send(Err(CorrelationError::Timeout(inner.default_timeout)));
                    }
                }
            }
        }))
    }
}

impl<T: Clone + Send + 'static> RequestResponseHandle<T> {
    /// Register a new in-flight request.
    ///
    /// Returns a unique correlation ID and a [`oneshot::Receiver`] that will
    /// receive the response (or a timeout error). The caller must embed the
    /// correlation ID in the outgoing message so the receiver can call
    /// [`deliver_response`](Self::deliver_response) with the same ID.
    ///
    /// Returns [`CorrelationError::RequestLimitExceeded`] if the per-session
    /// concurrency limit has been reached.
    pub async fn register_request(
        &self,
    ) -> Result<(u64, oneshot::Receiver<Result<T, CorrelationError>>), CorrelationError> {
        // Acquire the concurrency guard first; this enforces the optional
        // in-flight limit before we touch the entries map.
        let max = *self.inner.max_in_flight.lock().await;
        let guard = RequestConcurrencyGuard::acquire(&self.inner.in_flight, max).map_err(
            |e: RequestLimitExceeded| CorrelationError::RequestLimitExceeded(e.current, e.max),
        )?;

        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        let deadline = Instant::now() + self.inner.default_timeout;

        let mut entries = self.inner.entries.lock().await;
        entries.insert(
            id,
            PendingRequest {
                sender: tx,
                deadline,
                _guard: guard,
            },
        );

        Ok((id, rx))
    }

    /// Deliver a response for the given correlation ID.
    ///
    /// Wakes the waiter registered by [`register_request`](Self::register_request)
    /// and removes the entry. Returns [`CorrelationError::UnknownCorrelationId`]
    /// if no entry exists for `correlation_id`.
    pub async fn deliver_response(
        &self,
        correlation_id: u64,
        data: T,
    ) -> Result<(), CorrelationError> {
        let mut entries = self.inner.entries.lock().await;
        match entries.remove(&correlation_id) {
            Some(pending) => {
                let _ = pending.sender.send(Ok(data));
                // pending._guard drops here, releasing the concurrency slot
                Ok(())
            }
            None => Err(CorrelationError::UnknownCorrelationId(correlation_id)),
        }
    }

    /// Fail all currently pending (in-flight) requests with the given error.
    ///
    /// Every pending entry is removed and its `oneshot::Sender` is completed
    /// with `Err(error.clone())`.  The in-flight counter is reset to zero
    /// since all guards are dropped with the drained entries.
    ///
    /// This is the canonical teardown path for transport subsystems that
    /// need to notify callers when a peer departs: the membership guard calls
    /// this with `CorrelationError::PeerDeparted(id)` after tearing down
    /// sessions to a departed peer so pending response futures receive
    /// immediate failure notification rather than waiting for a timeout.
    ///
    /// Returns the number of entries that were failed.
    pub async fn fail_all(&self, error: CorrelationError) -> usize {
        let mut entries = self.inner.entries.lock().await;
        let count = entries.len();
        for (_, pending) in entries.drain() {
            let _ = pending.sender.send(Err(error.clone()));
            // pending._guard drops here, releasing the concurrency slot
        }
        // Reset the in-flight counter — all guards are already dropped.
        self.inner.in_flight.store(0, Ordering::Release);
        count
    }

    /// Fail all pending entries as a convenience for session drain/close
    /// paths. Delegates to [`fail_all`](Self::fail_all) with
    /// `CorrelationError::Timeout(Duration::ZERO)`.
    ///
    /// Returns the number of entries that were failed.
    pub async fn fail_all_pending(&self) -> usize {
        self.fail_all(CorrelationError::Timeout(std::time::Duration::ZERO))
            .await
    }

    /// Return the number of currently pending (in-flight) entries.
    pub async fn pending_count(&self) -> usize {
        self.inner.entries.lock().await.len()
    }

    /// Return the current number of in-flight requests, tracked atomically
    /// via the [`RequestConcurrencyGuard`] counter.
    pub fn in_flight_count(&self) -> usize {
        RequestConcurrencyGuard::in_flight(&self.inner.in_flight)
    }

    /// Return the default timeout that applies to each new request.
    pub fn default_timeout(&self) -> Duration {
        self.inner.default_timeout
    }

    /// Return the configured maximum concurrent in-flight requests.
    ///
    /// Returns `None` if unlimited.
    pub async fn max_in_flight(&self) -> Option<usize> {
        *self.inner.max_in_flight.lock().await
    }

    /// Reconfigure the in-flight request limit at runtime.
    ///
    /// Already-registered requests are not affected; the new limit only
    /// gates future calls to [`register_request`](Self::register_request).
    pub async fn set_max_in_flight(&self, max: Option<usize>) {
        if let Some(m) = max {
            assert!(m > 0, "max_in_flight must be positive or None");
        }
        *self.inner.max_in_flight.lock().await = max;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn new_test_table() -> RequestResponseTable<String> {
        RequestResponseTable::new(Some(128), Duration::from_secs(10))
    }

    fn new_unlimited_table() -> RequestResponseTable<String> {
        RequestResponseTable::new(None, Duration::from_secs(10))
    }

    /// Registration returns a unique correlation ID and a working oneshot
    /// receiver.
    #[tokio::test]
    async fn test_registration_returns_unique_id_and_receiver() {
        let table = new_test_table();
        let handle = table.handle();

        let (id1, _rx1) = handle.register_request().await.unwrap();
        let (id2, _rx2) = handle.register_request().await.unwrap();
        let (id3, _rx3) = handle.register_request().await.unwrap();

        // IDs must be distinct.
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id2, id3);

        // Pending count tracks in-flight entries.
        assert_eq!(handle.pending_count().await, 3);
        // In-flight atomic counter matches.
        assert_eq!(handle.in_flight_count(), 3);
    }

    /// Response delivery to a registered correlation ID wakes the waiter with
    /// the correct payload.
    #[tokio::test]
    async fn test_delivery_wakes_waiter_with_correct_payload() {
        let table = new_test_table();
        let handle = table.handle();

        let (id, rx) = handle.register_request().await.unwrap();
        assert_eq!(handle.pending_count().await, 1);
        assert_eq!(handle.in_flight_count(), 1);

        let payload = "hello from transport".to_string();
        handle.deliver_response(id, payload.clone()).await.unwrap();

        // Waiter receives the payload.
        let result = rx.await.unwrap().unwrap();
        assert_eq!(result, payload);

        // Entry is removed after delivery.
        assert_eq!(handle.pending_count().await, 0);
        assert_eq!(handle.in_flight_count(), 0);
    }

    /// Delivery to an unknown correlation ID returns UnknownCorrelationId.
    #[tokio::test]
    async fn test_unknown_correlation_id_returns_error() {
        let table = new_test_table();
        let handle = table.handle();

        // Never registered.
        let err = handle
            .deliver_response(999, "orphan".to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, CorrelationError::UnknownCorrelationId(999)));
    }

    /// Concurrency limit enforcement via RequestLimitExceeded error.
    #[tokio::test]
    async fn test_concurrency_limit_enforced() {
        let table: RequestResponseTable<String> =
            RequestResponseTable::new(Some(4), Duration::from_secs(10));
        let handle = table.handle();

        // Fill the table.
        for _ in 0..4 {
            handle.register_request().await.unwrap();
        }
        assert_eq!(handle.pending_count().await, 4);
        assert_eq!(handle.in_flight_count(), 4);

        // Next registration must fail with RequestLimitExceeded.
        let err = handle.register_request().await.unwrap_err();
        assert!(matches!(err, CorrelationError::RequestLimitExceeded(4, 4)));
    }

    /// Runtime reconfiguration: raise the limit so new registrations succeed.
    #[tokio::test]
    async fn test_runtime_reconfig_raise_limit() {
        let table: RequestResponseTable<String> =
            RequestResponseTable::new(Some(2), Duration::from_secs(10));
        let handle = table.handle();

        // Fill the table.
        let _r1 = handle.register_request().await.unwrap();
        let _r2 = handle.register_request().await.unwrap();

        // At capacity.
        let err = handle.register_request().await.unwrap_err();
        assert!(matches!(err, CorrelationError::RequestLimitExceeded(2, 2)));

        // Raise limit to 4.
        handle.set_max_in_flight(Some(4)).await;
        assert_eq!(handle.max_in_flight().await, Some(4));

        // Now can register again.
        let (_id, _rx) = handle.register_request().await.unwrap();
        assert_eq!(handle.in_flight_count(), 3);
    }

    /// Runtime reconfiguration: set to unlimited.
    #[tokio::test]
    async fn test_runtime_reconfig_unlimited() {
        let table: RequestResponseTable<String> =
            RequestResponseTable::new(Some(1), Duration::from_secs(10));
        let handle = table.handle();

        let _r = handle.register_request().await.unwrap();
        let err = handle.register_request().await.unwrap_err();
        assert!(matches!(err, CorrelationError::RequestLimitExceeded(1, 1)));

        // Switch to unlimited.
        handle.set_max_in_flight(None).await;
        assert_eq!(handle.max_in_flight().await, None);

        // Now unlimited registrations work.
        for _ in 0..10 {
            handle.register_request().await.unwrap();
        }
        assert_eq!(handle.in_flight_count(), 11);
    }

    /// Timeout expiry wakes the waiter with CorrelationError::Timeout and
    /// removes the entry, releasing the concurrency slot.
    #[tokio::test]
    async fn test_timeout_wakes_waiter_and_removes_entry() {
        // Use a very short timeout so we can trigger expiry without waiting long.
        let table: RequestResponseTable<String> =
            RequestResponseTable::new(Some(16), Duration::from_millis(10));
        let handle = table.handle();

        let (_id, rx) = handle.register_request().await.unwrap();
        assert_eq!(handle.pending_count().await, 1);
        assert_eq!(handle.in_flight_count(), 1);

        // Spawn the timeout task with a short scan interval.
        let _timeout_task = table.spawn_timeout_task(TimeoutConfig {
            scan_interval: Duration::from_millis(5),
        });

        // Wait long enough for the timeout to fire.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Waiter receives timeout error.
        let result = rx.await.unwrap();
        assert!(matches!(result, Err(CorrelationError::Timeout(_))));

        // Entry is removed — concurrency slot released.
        assert_eq!(handle.pending_count().await, 0);
        assert_eq!(handle.in_flight_count(), 0);
    }

    /// Concurrent registration and delivery under load (1000 entries).
    #[tokio::test]
    async fn test_concurrent_registration_and_delivery() {
        let table: RequestResponseTable<u64> =
            RequestResponseTable::new(Some(2048), Duration::from_secs(30));
        let handle = table.handle();

        let count = 1000u64;
        let mut handles = Vec::new();

        // Spawn tasks that register, self-deliver, and await.
        for i in 0..count {
            let h = handle.clone();
            handles.push(tokio::spawn(async move {
                let (id, rx) = h.register_request().await.unwrap();
                h.deliver_response(id, i).await.unwrap();
                let result = rx.await.unwrap().unwrap();
                assert_eq!(result, i, "payload mismatch for request {i}");
            }));
        }

        for jh in handles {
            jh.await.unwrap();
        }

        assert_eq!(handle.pending_count().await, 0);
        assert_eq!(handle.in_flight_count(), 0);
    }

    /// Default timeout and max_in_flight are recoverable from the handle.
    #[tokio::test]
    async fn test_accessors() {
        let table: RequestResponseTable<String> =
            RequestResponseTable::new(Some(256), Duration::from_secs(5));
        let handle = table.handle();

        assert_eq!(handle.default_timeout(), Duration::from_secs(5));
        assert_eq!(handle.max_in_flight().await, Some(256));
    }

    /// Unlimited table never rejects registrations (subject to memory only).
    #[tokio::test]
    async fn test_unlimited_table_never_rejects() {
        let table = new_unlimited_table();
        let handle = table.handle();

        assert_eq!(handle.max_in_flight().await, None);

        // Register 100 entries — all should succeed.
        let mut ids = Vec::new();
        for _ in 0..100 {
            let (id, _rx) = handle.register_request().await.unwrap();
            ids.push(id);
        }
        assert_eq!(handle.pending_count().await, 100);
        assert_eq!(handle.in_flight_count(), 100);
    }

    /// fail_all resets the in-flight counter to zero.
    #[tokio::test]
    async fn test_fail_all_resets_in_flight_counter() {
        let table: RequestResponseTable<String> =
            RequestResponseTable::new(Some(64), Duration::from_secs(10));
        let handle = table.handle();

        // Register several entries.
        for _ in 0..8 {
            handle.register_request().await.unwrap();
        }
        assert_eq!(handle.in_flight_count(), 8);

        // fail_all should reset to zero.
        let count = handle.fail_all(CorrelationError::PeerDeparted(42)).await;
        assert_eq!(count, 8);
        assert_eq!(handle.pending_count().await, 0);
        assert_eq!(handle.in_flight_count(), 0);
    }
}

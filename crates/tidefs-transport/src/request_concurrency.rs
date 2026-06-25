// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Request-concurrency guard for per-session in-flight request limiting.
//
// Provides an RAII guard that atomically tracks in-flight request counts
// and enforces a configurable limit. The guard releases its slot on drop,
// ensuring the in-flight count is always accurate regardless of whether
// the request completes normally, times out, or is cancelled.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tidefs_cache_core::Governor;

use crate::send_admission::{
    admit_cluster_queue_budget, ClusterQueueAdmissionClass, ClusterQueueAllocationKind,
    ClusterQueueBudgetGuard, SendAdmission, SendAdmissionEvidence, SendAdmissionOutcome,
    SendAdmissionPolicy, SendCapacityClass, SendCapacityEvidence,
};

/// Error returned when the request-concurrency limit is exceeded.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("request concurrency limit exceeded: {current} in-flight, max {max}")]
pub struct RequestLimitExceeded {
    /// Current in-flight count when the limit was hit.
    pub current: usize,
    /// Configured maximum.
    pub max: usize,
}

/// An RAII guard that occupies one in-flight slot.
///
/// The slot is released automatically when the guard is dropped. This
/// ensures that the in-flight count is always accurate regardless of
/// whether the tracked request completes normally, times out, or is
/// cancelled (e.g. via a session drain).
///
/// The guard is cheap to move (`Arc` + copy) and is `Send + Sync`.
#[derive(Debug)]
pub struct RequestConcurrencyGuard {
    counter: Arc<AtomicUsize>,
}

/// A request-concurrency slot paired with governor `cluster_queues` budget.
#[derive(Debug)]
pub struct BudgetedRequestConcurrencyGuard {
    request_guard: RequestConcurrencyGuard,
    cluster_budget: ClusterQueueBudgetGuard,
}

impl BudgetedRequestConcurrencyGuard {
    /// Try to acquire one in-flight slot and charge the request's transport
    /// bytes to `BudgetCategory::ClusterQueues`.
    ///
    /// Dropping the returned guard releases both the request slot and the
    /// cluster-queue budget, covering completion, cancellation, timeout, and
    /// peer-drain paths.
    #[must_use]
    pub fn acquire(
        counter: &Arc<AtomicUsize>,
        max: Option<usize>,
        governor: &Governor,
        bytes: u64,
        admission_class: ClusterQueueAdmissionClass,
    ) -> SendAdmission<Self> {
        let budget = admit_cluster_queue_budget(
            governor,
            bytes,
            ClusterQueueAllocationKind::RpcFrame,
            admission_class,
        );
        let budget_pressure = budget.evidence.pressure_reason;
        let Some(cluster_budget) = budget.value else {
            return SendAdmission::without_value(budget.evidence);
        };

        match RequestConcurrencyGuard::acquire(counter, max) {
            Ok(request_guard) => {
                let evidence = match budget_pressure {
                    Some(reason) => budget.evidence.with_pressure_reason(reason),
                    None => budget.evidence,
                };
                SendAdmission::with_value(
                    evidence,
                    Self {
                        request_guard,
                        cluster_budget,
                    },
                )
            }
            Err(err) => {
                drop(cluster_budget);
                let evidence = SendAdmissionEvidence::new(SendAdmissionOutcome::Backpressured)
                    .with_policy(SendAdmissionPolicy::Concurrency)
                    .with_capacity(SendCapacityEvidence::new(
                        SendCapacityClass::Concurrency,
                        err.current,
                        Some(1),
                        Some(err.max),
                    ));
                SendAdmission::without_value(evidence)
            }
        }
    }

    /// Return the number of bytes still charged to cluster queues.
    #[must_use]
    pub fn budgeted_bytes(&self) -> u64 {
        self.cluster_budget.bytes()
    }

    /// Return true while this guard owns a request slot.
    #[must_use]
    pub fn holds_request_slot(&self) -> bool {
        let _ = &self.request_guard;
        true
    }
}

impl RequestConcurrencyGuard {
    /// Try to acquire one in-flight slot.
    ///
    /// If `max` is `Some(n)` and the current count is at least `n`, the
    /// call fails with [`RequestLimitExceeded`].
    ///
    /// If `max` is `None` (unlimited), acquisition always succeeds.
    pub fn acquire(
        counter: &Arc<AtomicUsize>,
        max: Option<usize>,
    ) -> Result<Self, RequestLimitExceeded> {
        // Optimistic fast path: read current value.
        loop {
            let current = counter.load(Ordering::Relaxed);

            if let Some(limit) = max {
                if current >= limit {
                    return Err(RequestLimitExceeded {
                        current,
                        max: limit,
                    });
                }
            }

            // Try to CAS-increment.  If the CAS fails, another thread
            // raced us; retry the loop.
            match counter.compare_exchange_weak(
                current,
                current.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(Self {
                        counter: Arc::clone(counter),
                    });
                }
                Err(_) => {
                    // CAS failed — another thread updated the counter.
                    // Loop back to re-read.
                }
            }
        }
    }

    /// Return the current in-flight count (for diagnostics / tests).
    pub fn in_flight(counter: &Arc<AtomicUsize>) -> usize {
        counter.load(Ordering::Acquire)
    }
}

impl Drop for RequestConcurrencyGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Release);
    }
}

// The guard must not implement Clone — each in-flight slot is unique.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tidefs_cache_core::{BudgetCategory, GovernorConfig};

    fn new_counter() -> Arc<AtomicUsize> {
        Arc::new(AtomicUsize::new(0))
    }

    fn cluster_only_governor() -> Governor {
        Governor::new(GovernorConfig {
            total_budget_bytes: 1_000,
            data_cache_fraction: 0.0,
            meta_cache_fraction: 0.0,
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 1.0,
            misc_fraction: 0.0,
            auto_tune: false,
        })
        .unwrap()
    }

    /// Unlimited mode always succeeds and increments the counter.
    #[test]
    fn unlimited_always_acquires() {
        let c = new_counter();
        let g1 = RequestConcurrencyGuard::acquire(&c, None).unwrap();
        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 1);
        let g2 = RequestConcurrencyGuard::acquire(&c, None).unwrap();
        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 2);
        drop(g1);
        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 1);
        drop(g2);
        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 0);
    }

    /// With a limit of 1, the second acquire must fail.
    #[test]
    fn limit_enforced() {
        let c = new_counter();
        let _g = RequestConcurrencyGuard::acquire(&c, Some(1)).unwrap();
        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 1);

        let err = RequestConcurrencyGuard::acquire(&c, Some(1)).unwrap_err();
        assert_eq!(err.current, 1);
        assert_eq!(err.max, 1);
    }

    /// After the guard is dropped, a new acquire at the same limit succeeds.
    #[test]
    fn release_on_drop_allows_reacquire() {
        let c = new_counter();
        {
            let _g = RequestConcurrencyGuard::acquire(&c, Some(2)).unwrap();
            assert_eq!(RequestConcurrencyGuard::in_flight(&c), 1);
        }
        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 0);

        // Can re-acquire now that the slot was released.
        let _g = RequestConcurrencyGuard::acquire(&c, Some(2)).unwrap();
        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 1);
    }

    /// Runtime reconfiguration: lower the limit while already at capacity.
    #[test]
    fn runtime_reconfig_lower_limit() {
        let c = new_counter();
        // Acquire with a limit of 3.
        let g1 = RequestConcurrencyGuard::acquire(&c, Some(3)).unwrap();
        let g2 = RequestConcurrencyGuard::acquire(&c, Some(3)).unwrap();
        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 2);

        // Lower the limit to 1 — the next acquire should fail even though
        // we have 2 in-flight (the limit check uses the new value).
        let err = RequestConcurrencyGuard::acquire(&c, Some(1)).unwrap_err();
        assert_eq!(err.max, 1);

        drop(g1);
        drop(g2);
        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 0);
    }

    /// Runtime reconfiguration: raise the limit so previously-rejected acquire now succeeds.
    #[test]
    fn runtime_reconfig_raise_limit() {
        let c = new_counter();
        let _g = RequestConcurrencyGuard::acquire(&c, Some(1)).unwrap();

        // At limit=1, can't acquire another.
        let err = RequestConcurrencyGuard::acquire(&c, Some(1)).unwrap_err();
        assert_eq!(err.max, 1);

        // Raise limit to 2 — now it works.
        let _g2 = RequestConcurrencyGuard::acquire(&c, Some(2)).unwrap();
        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 2);
    }

    /// Concurrent acquires under moderate contention.
    #[test]
    fn concurrent_acquires() {
        use std::thread;

        let c = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&c);
        let max = Some(8usize);

        // Spawn 8 threads, each acquiring a guard, holding it briefly,
        // then dropping.  We start 16 acquires across 8 threads — half
        // of them will need to retry because of the CAS loop.
        let mut handles = Vec::new();
        for _ in 0..8 {
            let c2 = Arc::clone(&counter);
            handles.push(thread::spawn(move || {
                let mut guards = Vec::new();
                for _attempt in 0..2 {
                    match RequestConcurrencyGuard::acquire(&c2, max) {
                        Ok(g) => guards.push(g),
                        Err(_) => break,
                    }
                }
                // Hold guards briefly.
                thread::sleep(std::time::Duration::from_micros(100));
                drop(guards);
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // After all threads finish, counter must be back to zero.
        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 0);
    }

    /// Verify that the guard is Send + Sync (needed for async contexts).
    #[test]
    fn guard_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<RequestConcurrencyGuard>();
        assert_sync::<RequestConcurrencyGuard>();
    }

    #[test]
    fn budgeted_guard_releases_request_and_cluster_budget_on_drop() {
        let c = new_counter();
        let governor = cluster_only_governor();

        let admission = BudgetedRequestConcurrencyGuard::acquire(
            &c,
            Some(1),
            &governor,
            64,
            ClusterQueueAdmissionClass::Normal,
        );

        assert!(admission.admitted());
        let guard = admission.value.unwrap();
        assert!(guard.holds_request_slot());
        assert_eq!(guard.budgeted_bytes(), 64);
        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 1);
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 64);

        drop(guard);

        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 0);
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 0);
    }

    #[test]
    fn budgeted_guard_releases_budget_when_concurrency_is_full() {
        let c = new_counter();
        let governor = cluster_only_governor();
        let _held = RequestConcurrencyGuard::acquire(&c, Some(1)).unwrap();

        let admission = BudgetedRequestConcurrencyGuard::acquire(
            &c,
            Some(1),
            &governor,
            64,
            ClusterQueueAdmissionClass::Normal,
        );

        assert!(!admission.admitted());
        assert_eq!(
            admission.evidence.outcome,
            SendAdmissionOutcome::Backpressured
        );
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 0);
        assert_eq!(RequestConcurrencyGuard::in_flight(&c), 1);
    }
}

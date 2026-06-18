// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BackfillProgress: per-task state machine tracking lifecycle from
//! creation through scheduling, transfer, verification, and terminal
//! completion or failure.

use serde::{Deserialize, Serialize};

/// Lifecycle state of a single backfill task.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TaskState {
    /// Created but not yet admitted by the scheduler.
    Pending,
    /// Admitted by the scheduler and waiting for a transfer slot.
    Scheduled,
    /// Data transfer is in progress.
    InFlight,
    /// Transfer complete; BLAKE3 source->destination verification passed.
    Verified,
    /// Transfer and verification succeeded; durable placement confirmed.
    Complete,
    /// Transfer failed with remaining retry budget; will be rescheduled.
    Retry,
    /// All retries exhausted or unrecoverable error; terminal failure.
    Failed,
}

impl TaskState {
    /// Whether the task has reached a terminal state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed)
    }

    /// Whether the task is currently active (consuming resources).
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::InFlight)
    }

    /// Whether the task can be retried.
    #[must_use]
    pub fn can_retry_from(self) -> bool {
        matches!(self, Self::Scheduled | Self::InFlight)
    }
}

/// Tracks progress of a single backfill task through its lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackfillProgress {
    /// Current state.
    pub state: TaskState,
    /// Bytes transferred so far within the current attempt.
    pub bytes_transferred: u64,
    /// Total payload bytes expected.
    pub total_bytes: u64,
    /// Elapsed wall-clock time in milliseconds for the current attempt.
    pub elapsed_ms: u64,
    /// Number of retries consumed for this task.
    pub retries_consumed: u32,
    /// Maximum retries allowed.
    pub max_retries: u32,
    /// Error message from the last failed attempt (if any).
    pub last_error: Option<String>,
}

impl BackfillProgress {
    /// Create a new progress tracker starting in the `Pending` state.
    #[must_use]
    pub fn new(total_bytes: u64, max_retries: u32) -> Self {
        Self {
            state: TaskState::Pending,
            bytes_transferred: 0,
            total_bytes,
            elapsed_ms: 0,
            retries_consumed: 0,
            max_retries,
            last_error: None,
        }
    }

    /// Transition to `Scheduled`. Only valid from `Pending` or `Retry`.
    pub fn schedule(&mut self) -> Result<(), &'static str> {
        match self.state {
            TaskState::Pending | TaskState::Retry => {
                self.state = TaskState::Scheduled;
                self.bytes_transferred = 0;
                self.elapsed_ms = 0;
                self.last_error = None;
                Ok(())
            }
            _ => Err("cannot schedule from current state"),
        }
    }

    /// Transition to `InFlight`. Only valid from `Scheduled`.
    pub fn start_transfer(&mut self) -> Result<(), &'static str> {
        match self.state {
            TaskState::Scheduled => {
                self.state = TaskState::InFlight;
                Ok(())
            }
            _ => Err("cannot start transfer from current state"),
        }
    }

    /// Record transfer progress (bytes). Stays in `InFlight`.
    pub fn record_progress(&mut self, bytes: u64) -> Result<(), &'static str> {
        if self.state != TaskState::InFlight {
            return Err("not in flight");
        }
        self.bytes_transferred = self.bytes_transferred.saturating_add(bytes);
        Ok(())
    }

    /// Transition to `Verified` after successful BLAKE3 check.
    pub fn verify(&mut self) -> Result<(), &'static str> {
        match self.state {
            TaskState::InFlight => {
                self.state = TaskState::Verified;
                Ok(())
            }
            _ => Err("can only verify from InFlight"),
        }
    }

    /// Transition to `Complete`. Only valid from `Verified`.
    pub fn complete(&mut self) -> Result<(), &'static str> {
        match self.state {
            TaskState::Verified => {
                self.state = TaskState::Complete;
                Ok(())
            }
            _ => Err("can only complete from Verified"),
        }
    }

    /// Transition to `Retry` if budget remains, else `Failed`.
    pub fn fail(&mut self, error: &str) {
        self.last_error = Some(error.to_string());
        if self.retries_consumed < self.max_retries {
            self.retries_consumed += 1;
            self.state = TaskState::Retry;
        } else {
            self.state = TaskState::Failed;
        }
    }

    /// Progress fraction as a value in [0.0, 1.0].
    #[must_use]
    pub fn fraction(&self) -> f64 {
        if self.total_bytes == 0 {
            return if self.state == TaskState::Complete {
                1.0
            } else {
                0.0
            };
        }
        if self.state == TaskState::Complete {
            return 1.0;
        }
        (self.bytes_transferred as f64 / self.total_bytes as f64).min(1.0)
    }

    /// Whether the task is done (complete or failed).
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.state.is_terminal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_pending_to_complete() {
        let mut p = BackfillProgress::new(4096, 3);
        assert_eq!(p.state, TaskState::Pending);

        p.schedule().unwrap();
        assert_eq!(p.state, TaskState::Scheduled);

        p.start_transfer().unwrap();
        assert_eq!(p.state, TaskState::InFlight);

        p.record_progress(2048).unwrap();
        assert_eq!(p.bytes_transferred, 2048);

        p.record_progress(2048).unwrap();
        assert_eq!(p.bytes_transferred, 4096);

        p.verify().unwrap();
        assert_eq!(p.state, TaskState::Verified);

        p.complete().unwrap();
        assert_eq!(p.state, TaskState::Complete);
        assert!(p.is_done());
        assert!((p.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn retry_path() {
        let mut p = BackfillProgress::new(8192, 2);
        p.schedule().unwrap();
        p.start_transfer().unwrap();
        p.record_progress(4096).unwrap();
        p.fail("network timeout");
        assert_eq!(p.state, TaskState::Retry);
        assert_eq!(p.retries_consumed, 1);
        assert_eq!(p.last_error.as_deref(), Some("network timeout"));

        // Retry: schedule -> inflight -> success
        p.schedule().unwrap();
        assert_eq!(p.state, TaskState::Scheduled);
        assert_eq!(p.bytes_transferred, 0);
        p.start_transfer().unwrap();
        p.record_progress(8192).unwrap();
        p.verify().unwrap();
        p.complete().unwrap();
        assert_eq!(p.state, TaskState::Complete);
    }

    #[test]
    fn retry_exhaustion_leads_to_failed() {
        let mut p = BackfillProgress::new(4096, 1);
        p.schedule().unwrap();
        p.start_transfer().unwrap();
        p.fail("checksum mismatch");
        assert_eq!(p.state, TaskState::Retry);

        p.schedule().unwrap();
        p.start_transfer().unwrap();
        p.fail("checksum mismatch again");
        assert_eq!(p.state, TaskState::Failed);
        assert!(p.is_done());
    }

    #[test]
    fn invalid_transitions_rejected() {
        let mut p = BackfillProgress::new(4096, 3);

        assert!(p.start_transfer().is_err());
        assert!(p.verify().is_err());
        assert!(p.complete().is_err());

        p.schedule().unwrap();
        assert!(p.complete().is_err());
        assert!(p.schedule().is_err());
    }

    #[test]
    fn fraction_zero_bytes() {
        let p = BackfillProgress::new(0, 3);
        assert!((p.fraction() - 0.0).abs() < f64::EPSILON);

        let mut p = BackfillProgress::new(0, 3);
        p.schedule().unwrap();
        p.start_transfer().unwrap();
        p.verify().unwrap();
        p.complete().unwrap();
        assert!((p.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn terminal_states() {
        assert!(TaskState::Complete.is_terminal());
        assert!(TaskState::Failed.is_terminal());
        assert!(!TaskState::Pending.is_terminal());
        assert!(!TaskState::Scheduled.is_terminal());
        assert!(!TaskState::InFlight.is_terminal());
        assert!(!TaskState::Verified.is_terminal());
        assert!(!TaskState::Retry.is_terminal());
    }
}

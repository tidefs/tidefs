// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use std::collections::BTreeSet;

/// Errors returned by [`DurabilitySequence`] operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurabilityError {
    /// Sequence number has already been marked durable.
    AlreadyDurable,
    /// Sequence number is unknown (never submitted).
    UnknownSequence,
    /// A barrier is active; no new durable marks are allowed beyond it.
    BarrierActive,
    /// The supplied sequence is not the active barrier.
    NotActiveBarrier,
    /// Earlier sequence numbers have not reached durability yet.
    OutOfOrderSubmission,
}

/// Monotonic durability authority for commit and barrier publication.
///
/// `durable_high` is the highest contiguous durable prefix. Out-of-order
/// completions remain recorded but cannot advance that recovery checkpoint
/// until every preceding sequence completes. An active barrier prevents
/// later sequences from becoming durable until all earlier work and the
/// barrier itself are acknowledged.
#[derive(Clone, Debug)]
pub struct DurabilitySequence {
    next_seq: u64,
    durable_high: u64,
    durable: BTreeSet<u64>,
    active_barrier_seq: Option<u64>,
    completed_barriers: BTreeSet<u64>,
}

impl DurabilitySequence {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_seq: 1,
            durable_high: 0,
            durable: BTreeSet::new(),
            active_barrier_seq: None,
            completed_barriers: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn submit(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    #[must_use]
    pub fn submit_batch(&mut self, count: u64) -> Vec<u64> {
        let start = self.next_seq;
        self.next_seq += count;
        (start..start + count).collect()
    }

    pub fn mark_durable(&mut self, seq: u64) -> Result<(), DurabilityError> {
        if seq >= self.next_seq {
            return Err(DurabilityError::UnknownSequence);
        }
        if self.durable.contains(&seq) {
            return Err(DurabilityError::AlreadyDurable);
        }
        if self
            .active_barrier_seq
            .is_some_and(|barrier_seq| seq > barrier_seq)
        {
            return Err(DurabilityError::BarrierActive);
        }

        self.durable.insert(seq);
        self.advance_durable_high();
        Ok(())
    }

    pub fn submit_barrier(&mut self) -> Result<u64, DurabilityError> {
        if self.active_barrier_seq.is_some() {
            return Err(DurabilityError::BarrierActive);
        }

        let seq = self.next_seq;
        self.next_seq += 1;
        self.active_barrier_seq = Some(seq);
        Ok(seq)
    }

    pub fn ack_barrier(&mut self, seq: u64) -> Result<(), DurabilityError> {
        if self.active_barrier_seq != Some(seq) {
            return Err(DurabilityError::NotActiveBarrier);
        }
        if self.durable_high < seq.saturating_sub(1) {
            return Err(DurabilityError::OutOfOrderSubmission);
        }

        self.active_barrier_seq = None;
        self.completed_barriers.insert(seq);
        self.durable.insert(seq);
        self.advance_durable_high();
        Ok(())
    }

    /// Remove `from_seq` and every later submission for recovery replay.
    pub fn truncate_from(&mut self, from_seq: u64) {
        self.durable.retain(|&seq| seq < from_seq);
        if self.next_seq > from_seq {
            self.next_seq = from_seq;
        }
        if self
            .active_barrier_seq
            .is_some_and(|barrier_seq| barrier_seq >= from_seq)
        {
            self.active_barrier_seq = None;
        }
        self.completed_barriers.retain(|&seq| seq < from_seq);
        self.durable_high = 0;
        self.advance_durable_high();
    }

    #[must_use]
    pub fn durable_high(&self) -> u64 {
        self.durable_high
    }

    #[must_use]
    pub fn barrier_active(&self) -> bool {
        self.active_barrier_seq.is_some()
    }

    #[must_use]
    pub fn active_barrier_seq(&self) -> Option<u64> {
        self.active_barrier_seq
    }

    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    #[must_use]
    pub fn is_durable(&self, seq: u64) -> bool {
        seq <= self.durable_high
    }

    fn advance_durable_high(&mut self) {
        while self.durable.contains(&(self.durable_high + 1)) {
            self.durable_high += 1;
        }
    }
}

impl Default for DurabilitySequence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_order_completion_advances_only_a_contiguous_prefix() {
        let mut sequence = DurabilitySequence::new();
        assert_eq!(sequence.submit_batch(5), [1, 2, 3, 4, 5]);

        sequence.mark_durable(5).unwrap();
        sequence.mark_durable(2).unwrap();
        assert_eq!(sequence.durable_high(), 0);
        sequence.mark_durable(1).unwrap();
        assert_eq!(sequence.durable_high(), 2);
        sequence.mark_durable(4).unwrap();
        sequence.mark_durable(3).unwrap();
        assert_eq!(sequence.durable_high(), 5);
    }

    #[test]
    fn barrier_requires_prior_durability_and_gates_later_completion() {
        let mut sequence = DurabilitySequence::new();
        let first = sequence.submit();
        let second = sequence.submit();
        let barrier = sequence.submit_barrier().unwrap();
        let later = sequence.submit();

        assert_eq!(
            sequence.mark_durable(later),
            Err(DurabilityError::BarrierActive)
        );
        sequence.mark_durable(first).unwrap();
        assert_eq!(
            sequence.ack_barrier(barrier),
            Err(DurabilityError::OutOfOrderSubmission)
        );
        sequence.mark_durable(second).unwrap();
        sequence.ack_barrier(barrier).unwrap();
        sequence.mark_durable(later).unwrap();
        assert_eq!(sequence.durable_high(), later);
    }

    #[test]
    fn truncation_reuses_uncommitted_sequences_and_clears_cut_barrier() {
        let mut sequence = DurabilitySequence::new();
        let first = sequence.submit();
        sequence.mark_durable(first).unwrap();
        let barrier = sequence.submit_barrier().unwrap();
        let _later = sequence.submit();

        sequence.truncate_from(barrier);
        assert_eq!(sequence.durable_high(), first);
        assert_eq!(sequence.next_seq(), barrier);
        assert!(!sequence.barrier_active());
        assert_eq!(sequence.submit(), barrier);
    }

    #[test]
    fn invalid_and_duplicate_completions_fail_closed() {
        let mut sequence = DurabilitySequence::new();
        assert_eq!(
            sequence.mark_durable(1),
            Err(DurabilityError::UnknownSequence)
        );
        let first = sequence.submit();
        sequence.mark_durable(first).unwrap();
        assert_eq!(
            sequence.mark_durable(first),
            Err(DurabilityError::AlreadyDurable)
        );
        assert_eq!(
            sequence.ack_barrier(first),
            Err(DurabilityError::NotActiveBarrier)
        );
    }
}

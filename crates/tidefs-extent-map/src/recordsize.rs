//! Per-file-handle workload detection and recordsize adaptation.
//!
//! `WorkloadDetector` observes write offsets on a per-fd basis and
//! classifies the access pattern as sequential, random, or strided.
//! `RecordsizeStats` tracks the current effective recordsize, the
//! detected pattern, and the count of adjustments made.
//!
//! This module implements the detection and stats portions of the
//! #3459 RECORDSIZE-P1 spec. The per-dataset property integration
//! is tracked by Review debt TFR-005 (historical issue #3460).

use crate::RecordsizePolicy;

/// Classified write-access pattern for a single file descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WritePattern {
    /// Writes arrive at monotonically increasing offsets.
    Sequential,
    /// Writes arrive at scattered, unpredictable offsets.
    Random,
    /// Writes arrive at regular interval offsets with gaps between them.
    Strided {
        /// Detected stride interval in bytes.
        stride: u64,
    },
    /// Insufficient observations to classify.
    Unknown,
}

/// Accumulator state for per-fd write-pattern detection.
///
/// `WorkloadDetector` tracks the last few write offsets and uses
/// simple heuristics to classify the access pattern. It is designed
/// for cheap per-operation updates on the hot write path.
#[derive(Clone, Debug)]
pub struct WorkloadDetector {
    /// Number of observations collected so far.
    observations: u64,
    /// Offset of the most recent write start.
    last_offset: u64,
    /// End offset of the most recent write (start + length).
    last_end: u64,
    /// Running count of sequential writes (forward, non-overlapping).
    sequential_count: u64,
    /// Running count of random writes (backward or overlapping).
    random_count: u64,
    /// Last detected stride interval, if any.
    last_stride: Option<u64>,
    /// Running count of writes matching the current stride interval.
    strided_count: u64,
    /// Minimum observations before classification is emitted.
    min_observations: u64,
}

impl Default for WorkloadDetector {
    fn default() -> Self {
        Self {
            observations: 0,
            last_offset: 0,
            last_end: 0,
            sequential_count: 0,
            random_count: 0,
            last_stride: None,
            strided_count: 0,
            min_observations: 8,
        }
    }
}

impl WorkloadDetector {
    /// Create a detector that requires at least `n` observations
    /// before emitting a classification.
    #[must_use]
    pub fn with_min_observations(n: u64) -> Self {
        Self {
            min_observations: n,
            ..Default::default()
        }
    }

    /// Feed one write observation: `offset` and `length` in bytes.
    ///
    /// This is the hot-path method. It is allocation-free and uses
    /// only integer arithmetic.
    pub fn observe_write(&mut self, offset: u64, length: u64) {
        let end = offset.saturating_add(length);
        if self.observations == 0 {
            self.last_offset = offset;
            self.last_end = end;
            self.observations = 1;
            return;
        }

        if offset >= self.last_end {
            // Forward write: always sequential.
            self.sequential_count += 1;

            // Stride detection only for non-contiguous writes
            // (contiguous writes with offset == last_end are purely
            // sequential, not strided).
            if offset > self.last_end {
                let stride_candidate = offset.saturating_sub(self.last_offset);
                if stride_candidate > 0 {
                    if let Some(prev_stride) = self.last_stride {
                        if stride_candidate == prev_stride {
                            self.strided_count += 1;
                        } else {
                            self.last_stride = Some(stride_candidate);
                            self.strided_count = 1;
                        }
                    } else {
                        self.last_stride = Some(stride_candidate);
                        self.strided_count = 1;
                    }
                }
            }
        } else {
            // Backward or overlapping write: random.
            self.random_count += 1;
            self.last_stride = None;
        }

        self.last_offset = offset;
        self.last_end = end;
        self.observations += 1;
    }

    /// Classify the current access pattern.
    ///
    /// Returns `Unknown` when fewer than `min_observations` writes
    /// have been observed.
    #[must_use]
    pub fn classify(&self) -> WritePattern {
        if self.observations < self.min_observations {
            return WritePattern::Unknown;
        }

        let fwd = self.sequential_count as f64;
        let bwd = self.random_count as f64;
        let total = fwd + bwd;
        if total == 0.0 {
            return WritePattern::Unknown;
        }

        let seq_frac = fwd / total;
        let rnd_frac = bwd / total;

        // Strided is a sub-pattern of sequential: require a
        // consistent stride within the forward writes AND at
        // least one gap (non-contiguous).
        if seq_frac >= 0.6
            && self.strided_count >= 4
            && self.last_stride.is_some()
            && (self.strided_count as f64) / fwd >= 0.6
        {
            WritePattern::Strided {
                stride: self.last_stride.unwrap_or(0),
            }
        } else if rnd_frac >= 0.6 {
            WritePattern::Random
        } else if seq_frac >= 0.6 {
            WritePattern::Sequential
        } else {
            // Mixed: classify by plurality.
            if fwd >= bwd {
                WritePattern::Sequential
            } else {
                WritePattern::Random
            }
        }
    }

    /// Map the classified pattern to a recommended [`RecordsizePolicy`].
    ///
    /// Returns `None` when the pattern is `Unknown` or when there is
    /// no policy override (caller should use the dataset default).
    #[must_use]
    pub fn recommended_policy(&self) -> Option<RecordsizePolicy> {
        match self.classify() {
            WritePattern::Unknown => None,
            WritePattern::Sequential => {
                Some(RecordsizePolicy::Fixed(1 << 20)) // 1 MiB
            }
            WritePattern::Random => {
                Some(RecordsizePolicy::Fixed(4096)) // 4 KiB
            }
            WritePattern::Strided { stride } => {
                let rs = stride.clamp(4096, 1 << 20);
                Some(RecordsizePolicy::Fixed(rs))
            }
        }
    }

    /// Number of observations collected.
    #[must_use]
    pub fn observation_count(&self) -> u64 {
        self.observations
    }

    /// Reset all counters (e.g. on file close/reopen or pattern shift).
    pub fn reset(&mut self) {
        *self = Self {
            min_observations: self.min_observations,
            ..Default::default()
        };
    }
}

/// Running statistics for recordsize adaptation on one file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordsizeStats {
    /// Current effective recordsize in bytes.
    pub current_recordsize: u64,
    /// Currently detected write pattern.
    pub pattern_detected: Option<WritePattern>,
    /// Number of times the recordsize was adjusted.
    pub adjustments_made: u64,
}

impl RecordsizeStats {
    /// Create stats with an initial recordsize.
    #[must_use]
    pub fn new(initial_recordsize: u64) -> Self {
        Self {
            current_recordsize: initial_recordsize,
            pattern_detected: None,
            adjustments_made: 0,
        }
    }

    /// Record a policy change and return the new recordsize.
    pub fn apply_policy(&mut self, policy: &RecordsizePolicy, pattern: WritePattern) -> u64 {
        let new_rs = policy.effective_max();
        if new_rs != self.current_recordsize {
            self.adjustments_made += 1;
            self.current_recordsize = new_rs;
        }
        self.pattern_detected = Some(pattern);
        self.current_recordsize
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::RecordsizePolicy;
    use tidefs_types_extent_map_core::{RecordsizeProperty, DATASET_DEFAULT_RECORDSIZE};

    // -- WritePattern classification --

    #[test]
    fn unknown_below_min_observations() {
        let d = WorkloadDetector::with_min_observations(8);
        assert_eq!(d.classify(), WritePattern::Unknown);
        assert!(d.recommended_policy().is_none());
    }

    #[test]
    fn sequential_detection() {
        let mut d = WorkloadDetector::with_min_observations(4);
        // Contiguous sequence: 0-4K, 4K-8K, 8K-12K, ...
        for i in 0..6 {
            d.observe_write(i * 4096, 4096);
        }
        assert_eq!(d.classify(), WritePattern::Sequential);
        let policy = d.recommended_policy().unwrap();
        assert_eq!(policy.effective_max(), 1 << 20); // 1 MiB
    }

    #[test]
    fn random_detection() {
        let mut d = WorkloadDetector::with_min_observations(4);
        // Mostly backward/overlapping writes.
        d.observe_write(0, 4096);
        d.observe_write(100_000, 4096);
        d.observe_write(30_000, 4096); // backward
        d.observe_write(200_000, 4096);
        d.observe_write(20_000, 4096); // backward
        d.observe_write(50_000, 4096); // forward
        d.observe_write(15_000, 4096); // backward (15k < 54k)
        d.observe_write(10_000, 4096); // backward (10k < 19k)
        d.observe_write(5_000, 4096); // backward (5k < 14k)
        assert_eq!(d.classify(), WritePattern::Random);
        let policy = d.recommended_policy().unwrap();
        assert_eq!(policy.effective_max(), 4096);
    }

    #[test]
    fn strided_detection() {
        let mut d = WorkloadDetector::with_min_observations(4);
        // Writes at regular 16 KiB intervals with gaps.
        for i in 0..8 {
            d.observe_write(i * 16384, 4096);
        }
        assert!(matches!(d.classify(), WritePattern::Strided { .. }));
        let policy = d.recommended_policy().unwrap();
        assert_eq!(policy.effective_max(), 16384);
    }

    #[test]
    fn strided_with_holes() {
        let mut d = WorkloadDetector::with_min_observations(4);
        // Same interval between starts, short writes → large holes.
        d.observe_write(0, 256);
        d.observe_write(16384, 256);
        d.observe_write(32768, 256);
        d.observe_write(49152, 256);
        d.observe_write(65536, 256);
        assert!(matches!(d.classify(), WritePattern::Strided { .. }));
        let policy = d.recommended_policy().unwrap();
        assert_eq!(policy.effective_max(), 16384);
    }

    #[test]
    fn mixed_plurality_sequential() {
        let mut d = WorkloadDetector::with_min_observations(4);
        // 4 sequential, 2 random — plurality stays sequential.
        d.observe_write(0, 4096);
        d.observe_write(4096, 4096);
        d.observe_write(8192, 4096);
        d.observe_write(12288, 4096);
        d.observe_write(100_000, 512);
        d.observe_write(50_000, 256); // backward
        assert_eq!(d.classify(), WritePattern::Sequential);
    }

    // -- WorkloadDetector lifecycle --

    #[test]
    fn reset_clears_counters() {
        let mut d = WorkloadDetector::with_min_observations(4);
        for i in 0..6 {
            d.observe_write(i * 4096, 4096);
        }
        assert_eq!(d.classify(), WritePattern::Sequential);

        d.reset();
        assert_eq!(d.observation_count(), 0);
        assert_eq!(d.classify(), WritePattern::Unknown);
        assert!(d.recommended_policy().is_none());
    }

    #[test]
    fn observation_count_increments() {
        let mut d = WorkloadDetector::with_min_observations(8);
        assert_eq!(d.observation_count(), 0);
        d.observe_write(0, 4096);
        assert_eq!(d.observation_count(), 1);
        d.observe_write(4096, 4096);
        assert_eq!(d.observation_count(), 2);
    }

    // -- RecordsizeStats --

    #[test]
    fn stats_initial_state() {
        let s = RecordsizeStats::new(4096);
        assert_eq!(s.current_recordsize, 4096);
        assert_eq!(s.pattern_detected, None);
        assert_eq!(s.adjustments_made, 0);
    }

    #[test]
    fn stats_apply_policy_no_change() {
        let mut s = RecordsizeStats::new(4096);
        let policy = RecordsizePolicy::Fixed(4096);
        let rs = s.apply_policy(&policy, WritePattern::Sequential);
        assert_eq!(rs, 4096);
        assert_eq!(s.current_recordsize, 4096);
        assert_eq!(s.adjustments_made, 0);
        assert_eq!(s.pattern_detected, Some(WritePattern::Sequential));
    }

    #[test]
    fn stats_apply_policy_change() {
        let mut s = RecordsizeStats::new(4096);
        let policy = RecordsizePolicy::Fixed(1 << 20);
        let rs = s.apply_policy(&policy, WritePattern::Sequential);
        assert_eq!(rs, 1 << 20);
        assert_eq!(s.current_recordsize, 1 << 20);
        assert_eq!(s.adjustments_made, 1);
    }

    #[test]
    fn stats_multiple_adjustments() {
        let mut s = RecordsizeStats::new(4096);
        s.apply_policy(&RecordsizePolicy::Fixed(1 << 20), WritePattern::Sequential);
        s.apply_policy(&RecordsizePolicy::Fixed(4096), WritePattern::Random);
        s.apply_policy(&RecordsizePolicy::Fixed(1 << 20), WritePattern::Sequential);
        assert_eq!(s.adjustments_made, 3);
        assert_eq!(s.current_recordsize, 1 << 20);
    }

    #[test]
    fn adaptive_policy_uses_max() {
        let mut s = RecordsizeStats::new(4096);
        let policy = RecordsizePolicy::Adaptive {
            min: 4096,
            max: 65536,
        };
        let rs = s.apply_policy(&policy, WritePattern::Sequential);
        assert_eq!(rs, 65536);
        assert_eq!(s.current_recordsize, 65536);
    }

    // -- Edge cases --

    #[test]
    fn zero_length_write_counted() {
        let mut d = WorkloadDetector::with_min_observations(4);
        d.observe_write(0, 4096);
        d.observe_write(4096, 0);
        d.observe_write(4096, 4096);
        d.observe_write(8192, 4096);
        d.observe_write(12288, 4096);
        assert_eq!(d.classify(), WritePattern::Sequential);
    }

    #[test]
    fn single_observation_unknown() {
        let mut d = WorkloadDetector::with_min_observations(4);
        d.observe_write(0, 4096);
        assert_eq!(d.classify(), WritePattern::Unknown);
    }

    #[test]
    fn saturating_offset_handled() {
        let mut d = WorkloadDetector::with_min_observations(4);
        d.observe_write(u64::MAX, 1);
        d.observe_write(0, 4096);
        assert_eq!(d.classify(), WritePattern::Unknown);
    }

    // -- RecordsizePolicy::from_property --

    #[test]
    fn from_property_default_is_128k() {
        let policy = RecordsizePolicy::from_property(RecordsizeProperty::Default);
        assert_eq!(policy.effective_max(), DATASET_DEFAULT_RECORDSIZE);
    }

    #[test]
    fn from_property_fixed_is_exact() {
        let policy = RecordsizePolicy::from_property(RecordsizeProperty::Fixed(65536));
        assert_eq!(policy.effective_max(), 65536);
    }

    #[test]
    fn from_property_inherit_falls_back_to_default() {
        let policy = RecordsizePolicy::from_property(RecordsizeProperty::Inherit);
        assert_eq!(policy.effective_max(), DATASET_DEFAULT_RECORDSIZE);
    }

    #[test]
    fn from_property_roundtrip_with_resolve() {
        let prop = RecordsizeProperty::Inherit.resolve(Some(RecordsizeProperty::Fixed(1_048_576)));
        let policy = RecordsizePolicy::from_property(prop);
        assert_eq!(policy.effective_max(), 1_048_576);
    }
}

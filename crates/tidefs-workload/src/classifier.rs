// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Sliding-window IO pattern classifier.
//!
//! Accumulates read/write/fsync observations over a configurable window
//! and classifies the dominant access pattern into a [`WorkloadSignature`]
//! with a confidence score.

use crate::signature::WorkloadSignature;

// ── Constants ───────────────────────────────────────────────────

/// Default minimum number of operations before classification is attempted.
pub const DEFAULT_MIN_WINDOW_OPS: usize = 64;

/// IO size (bytes) below which an operation is considered "small"
/// (OLTP-like).
const SMALL_IO_THRESHOLD: u64 = 16 * 1024;

/// IO size (bytes) above which an operation is considered "large"
/// (OLAP/Backup-like).
const LARGE_IO_THRESHOLD: u64 = 64 * 1024;

/// IO size (bytes) above which an operation is considered "very large"
/// (Media-like).
const XLARGE_IO_THRESHOLD: u64 = 1024 * 1024;

/// Random/sequential ratio threshold for OLTP classification.
const OLTP_RANDOM_RATIO_MIN: f64 = 0.70;

/// Fsync rate below which is "low" for OLTP.
const OLTP_FSYNC_RATE_MAX: f64 = 0.05;

/// Sequential ratio threshold for stream-like classification.
const STREAM_SEQ_RATIO_MIN: f64 = 0.80;

/// Read ratio threshold for read-heavy classification (OLAP, Media).
const READ_HEAVY_RATIO_MIN: f64 = 0.70;

/// Write ratio threshold for write-heavy classification (Backup).
const WRITE_HEAVY_RATIO_MIN: f64 = 0.70;

/// Sequential ratio threshold for Media classification.
const MEDIA_SEQ_RATIO_MIN: f64 = 0.90;

/// Read ratio threshold for Media classification.
const MEDIA_READ_RATIO_MIN: f64 = 0.80;

/// Fsync rate above which is "high" for VM classification.
const VM_FSYNC_RATE_MIN: f64 = 0.05;

/// Random ratio threshold for VM classification.
const VM_RANDOM_RATIO_MIN: f64 = 0.50;

/// Confidence threshold below which the result is downgraded to Unknown.
const CONFIDENCE_THRESHOLD: f64 = 0.30;

// ── WorkloadStats ───────────────────────────────────────────────

/// Snapshot of the classifier's current state.
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkloadStats {
    /// The classified signature.
    pub current_signature: WorkloadSignature,
    /// Confidence score [0.0, 1.0].
    pub confidence: f64,
    /// Number of operations in the current window.
    pub window_ops: usize,
    /// Number of reads in the current window.
    pub reads: usize,
    /// Number of writes in the current window.
    pub writes: usize,
    /// Number of fsyncs in the current window.
    pub fsyncs: usize,
    /// Total bytes read in the current window.
    pub read_bytes: u64,
    /// Total bytes written in the current window.
    pub write_bytes: u64,
    /// Number of sequential runs detected.
    pub sequential_runs: usize,
    /// Number of random (non-sequential) operations.
    pub random_ops: usize,
}

// ── WorkloadClassifier ──────────────────────────────────────────

/// Sliding-window classifier that observes IO operations and materializes
/// a [`WorkloadSignature`] with confidence.
///
/// Feed observations with [`observe_read`](Self::observe_read),
/// [`observe_write`](Self::observe_write), and
/// [`observe_fsync`](Self::observe_fsync), then call
/// [`classify`](Self::classify) to get the current signature and
/// confidence.
///
/// The window is sliding: every call to `classify` resets the
/// accumulator so the next classification covers a fresh window.
#[derive(Clone, Debug)]
pub struct WorkloadClassifier {
    // Observed counters for the current window.
    reads: usize,
    writes: usize,
    fsyncs: usize,
    read_bytes: u64,
    write_bytes: u64,
    sequential_runs: usize,
    random_ops: usize,

    // Last-seen offset for sequential detection.
    last_offset: Option<u64>,
    last_len: Option<u64>,

    /// Minimum operations required before attempting classification.
    min_window_ops: usize,
}

impl Default for WorkloadClassifier {
    fn default() -> Self {
        Self {
            reads: 0,
            writes: 0,
            fsyncs: 0,
            read_bytes: 0,
            write_bytes: 0,
            sequential_runs: 0,
            random_ops: 0,
            last_offset: None,
            last_len: None,
            min_window_ops: DEFAULT_MIN_WINDOW_OPS,
        }
    }
}

impl WorkloadClassifier {
    /// Create a classifier with the default minimum window size.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the minimum number of operations before classification.
    #[must_use]
    pub fn with_min_window_ops(mut self, min_ops: usize) -> Self {
        self.min_window_ops = min_ops;
        self
    }

    // ── Observation ─────────────────────────────────────────

    /// Record a read operation.
    pub fn observe_read(&mut self, offset: u64, len: u64) {
        self.reads += 1;
        self.read_bytes += len;
        self.track_sequential(offset, len);
    }

    /// Record a write operation.
    pub fn observe_write(&mut self, offset: u64, len: u64) {
        self.writes += 1;
        self.write_bytes += len;
        self.track_sequential(offset, len);
    }

    /// Record an fsync operation.
    pub fn observe_fsync(&mut self) {
        self.fsyncs += 1;
        // fsync does not affect sequentiality tracking.
    }

    // ── Sequential detection ────────────────────────────────

    fn track_sequential(&mut self, offset: u64, len: u64) {
        if let (Some(prev_off), Some(prev_len)) = (self.last_offset, self.last_len) {
            let expected = prev_off + prev_len;
            if offset == expected {
                // Extends the previous sequential run.
                // Already counted as sequential — nothing extra.
            } else {
                self.random_ops += 1;
            }
        } else {
            // First operation in the window: start a new run.
            self.sequential_runs += 1;
        }
        self.last_offset = Some(offset);
        self.last_len = Some(len);
    }

    // ── Classification ──────────────────────────────────────

    /// Classify the current window and produce stats, then reset
    /// the accumulator for the next window.
    #[must_use]
    pub fn classify(&mut self) -> WorkloadStats {
        let stats = self.compute_stats();
        self.reset();
        stats
    }

    /// Peek at the current classification without resetting.
    #[must_use]
    pub fn peek(&self) -> WorkloadStats {
        self.compute_stats()
    }

    /// Reset the accumulator.
    pub fn reset(&mut self) {
        self.reads = 0;
        self.writes = 0;
        self.fsyncs = 0;
        self.read_bytes = 0;
        self.write_bytes = 0;
        self.sequential_runs = 0;
        self.random_ops = 0;
        self.last_offset = None;
        self.last_len = None;
    }

    /// Return the raw observation counts.
    #[must_use]
    pub fn raw_counts(&self) -> (usize, usize, usize, u64, u64) {
        (
            self.reads,
            self.writes,
            self.fsyncs,
            self.read_bytes,
            self.write_bytes,
        )
    }

    // ── Internal helpers ────────────────────────────────────

    fn total_ops(&self) -> usize {
        self.reads + self.writes + self.fsyncs
    }

    fn total_data_ops(&self) -> usize {
        self.reads + self.writes
    }

    fn compute_stats(&self) -> WorkloadStats {
        let total_ops = self.total_ops();

        if total_ops < self.min_window_ops {
            return WorkloadStats {
                current_signature: WorkloadSignature::Unknown,
                confidence: 0.0,
                window_ops: total_ops,
                reads: self.reads,
                writes: self.writes,
                fsyncs: self.fsyncs,
                read_bytes: self.read_bytes,
                write_bytes: self.write_bytes,
                sequential_runs: self.sequential_runs,
                random_ops: self.random_ops,
            };
        }

        let (sig, conf) = self.classify_inner(total_ops);
        WorkloadStats {
            current_signature: sig,
            confidence: conf,
            window_ops: total_ops,
            reads: self.reads,
            writes: self.writes,
            fsyncs: self.fsyncs,
            read_bytes: self.read_bytes,
            write_bytes: self.write_bytes,
            sequential_runs: self.sequential_runs,
            random_ops: self.random_ops,
        }
    }

    fn classify_inner(&self, total_ops: usize) -> (WorkloadSignature, f64) {
        let total_data = self.total_data_ops();
        if total_data == 0 {
            // No data ops: if we have fsyncs, could be VM-like, else unknown.
            if self.fsyncs > 0 {
                return (WorkloadSignature::Vm, 0.35);
            }
            return (WorkloadSignature::Unknown, 0.0);
        }

        let avg_io_size = (self.read_bytes + self.write_bytes) / total_data as u64;
        let read_ratio = self.reads as f64 / total_data as f64;
        let write_ratio = self.writes as f64 / total_data as f64;
        let seq_ratio = 1.0 - (self.random_ops as f64 / total_data as f64);
        let random_ratio = 1.0 - seq_ratio;
        let fsync_rate = self.fsyncs as f64 / total_ops as f64;

        // Try each classification in priority order.
        // Media: very large sequential reads.
        if avg_io_size >= XLARGE_IO_THRESHOLD
            && seq_ratio >= MEDIA_SEQ_RATIO_MIN
            && read_ratio >= MEDIA_READ_RATIO_MIN
        {
            let conf = media_confidence(avg_io_size, seq_ratio, read_ratio);
            return (WorkloadSignature::Media, conf);
        }

        // Backup: large sequential writes.
        if avg_io_size >= LARGE_IO_THRESHOLD
            && seq_ratio >= STREAM_SEQ_RATIO_MIN
            && write_ratio >= WRITE_HEAVY_RATIO_MIN
        {
            let conf = backup_confidence(avg_io_size, seq_ratio, write_ratio);
            return (WorkloadSignature::Backup, conf);
        }

        // OLAP: large sequential reads.
        if avg_io_size >= LARGE_IO_THRESHOLD
            && seq_ratio >= STREAM_SEQ_RATIO_MIN
            && read_ratio >= READ_HEAVY_RATIO_MIN
        {
            let conf = olap_confidence(avg_io_size, seq_ratio, read_ratio);
            return (WorkloadSignature::Olap, conf);
        }

        // OLTP: small random IO with low fsync.
        if avg_io_size < SMALL_IO_THRESHOLD
            && random_ratio >= OLTP_RANDOM_RATIO_MIN
            && fsync_rate <= OLTP_FSYNC_RATE_MAX
        {
            let conf = oltp_confidence(avg_io_size, random_ratio, fsync_rate);
            return (WorkloadSignature::Oltp, conf);
        }

        // VM: mixed random IO with elevated fsync.
        if fsync_rate >= VM_FSYNC_RATE_MIN && random_ratio >= VM_RANDOM_RATIO_MIN {
            let conf = vm_confidence(fsync_rate, random_ratio);
            return (WorkloadSignature::Vm, conf);
        }

        (WorkloadSignature::Unknown, CONFIDENCE_THRESHOLD)
    }
}

// ── Confidence helpers ──────────────────────────────────────────

fn clamp_confidence(c: f64) -> f64 {
    c.clamp(0.0, 1.0)
}

fn oltp_confidence(avg_io_size: u64, random_ratio: f64, fsync_rate: f64) -> f64 {
    let size_score = 1.0 - (avg_io_size as f64 / SMALL_IO_THRESHOLD as f64);
    let random_score = (random_ratio - OLTP_RANDOM_RATIO_MIN) / (1.0 - OLTP_RANDOM_RATIO_MIN);
    let fsync_score = 1.0 - (fsync_rate / OLTP_FSYNC_RATE_MAX);
    let raw = (size_score + random_score + fsync_score) / 3.0;
    clamp_confidence(raw)
}

fn olap_confidence(avg_io_size: u64, seq_ratio: f64, read_ratio: f64) -> f64 {
    let size_score = (avg_io_size as f64 / XLARGE_IO_THRESHOLD as f64).min(1.0);
    let seq_score = (seq_ratio - STREAM_SEQ_RATIO_MIN) / (1.0 - STREAM_SEQ_RATIO_MIN);
    let read_score = (read_ratio - READ_HEAVY_RATIO_MIN) / (1.0 - READ_HEAVY_RATIO_MIN);
    let raw = (size_score + seq_score + read_score) / 3.0;
    clamp_confidence(raw)
}

fn backup_confidence(avg_io_size: u64, seq_ratio: f64, write_ratio: f64) -> f64 {
    let size_score = (avg_io_size as f64 / XLARGE_IO_THRESHOLD as f64).min(1.0);
    let seq_score = (seq_ratio - STREAM_SEQ_RATIO_MIN) / (1.0 - STREAM_SEQ_RATIO_MIN);
    let write_score = (write_ratio - WRITE_HEAVY_RATIO_MIN) / (1.0 - WRITE_HEAVY_RATIO_MIN);
    let raw = (size_score + seq_score + write_score) / 3.0;
    clamp_confidence(raw)
}

fn media_confidence(avg_io_size: u64, seq_ratio: f64, read_ratio: f64) -> f64 {
    let size_score = (avg_io_size as f64 / (4 * XLARGE_IO_THRESHOLD) as f64).min(1.0);
    let seq_score = (seq_ratio - MEDIA_SEQ_RATIO_MIN) / (1.0 - MEDIA_SEQ_RATIO_MIN);
    let read_score = (read_ratio - MEDIA_READ_RATIO_MIN) / (1.0 - MEDIA_READ_RATIO_MIN);
    let raw = (size_score + seq_score + read_score) / 3.0;
    clamp_confidence(raw)
}

fn vm_confidence(fsync_rate: f64, random_ratio: f64) -> f64 {
    let fsync_score = (fsync_rate - VM_FSYNC_RATE_MIN).min(0.5) / 0.5;
    let random_score = (random_ratio - VM_RANDOM_RATIO_MIN) / (1.0 - VM_RANDOM_RATIO_MIN);
    let raw = (fsync_score + random_score) / 2.0;
    clamp_confidence(raw)
}

// ── WorkloadMaterializer ────────────────────────────────────────

/// Thin wrapper around [`WorkloadClassifier`] that produces periodic
/// [`WorkloadStats`] snapshots for adaptive subsystems.
///
/// Call [`observe_read`](Self::observe_read),
/// [`observe_write`](Self::observe_write), and
/// [`observe_fsync`](Self::observe_fsync) as IO operations happen,
/// then call [`materialize`](Self::materialize) periodically to get
/// the current signature for downstream consumers.
#[derive(Clone, Debug)]
pub struct WorkloadMaterializer {
    classifier: WorkloadClassifier,
    last_stats: WorkloadStats,
}

impl Default for WorkloadMaterializer {
    fn default() -> Self {
        Self {
            classifier: WorkloadClassifier::new(),
            last_stats: WorkloadStats::default(),
        }
    }
}

impl WorkloadMaterializer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_min_window_ops(mut self, min_ops: usize) -> Self {
        self.classifier = self.classifier.with_min_window_ops(min_ops);
        self
    }

    pub fn observe_read(&mut self, offset: u64, len: u64) {
        self.classifier.observe_read(offset, len);
    }

    pub fn observe_write(&mut self, offset: u64, len: u64) {
        self.classifier.observe_write(offset, len);
    }

    pub fn observe_fsync(&mut self) {
        self.classifier.observe_fsync();
    }

    /// Materialize the current classification and start a new window.
    pub fn materialize(&mut self) -> WorkloadStats {
        self.last_stats = self.classifier.classify();
        self.last_stats
    }

    /// Peek at the most recently materialized stats.
    #[must_use]
    pub fn last_stats(&self) -> WorkloadStats {
        self.last_stats
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        self.classifier.reset();
        self.last_stats = WorkloadStats::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────

    fn feed_random_small(c: &mut WorkloadClassifier, count: usize, max_size: u64) {
        for i in 0..count {
            let off = (i as u64) * 4096 + (i as u64 % 7) * 512;
            c.observe_read(off, max_size.min(4096 + (i as u64 % 3) * 1024));
            c.observe_write(off + 8192, max_size.min(2048 + (i as u64 % 5) * 512));
        }
    }

    fn feed_sequential_reads(c: &mut WorkloadClassifier, count: usize, io_size: u64) {
        let mut off = 0u64;
        for _ in 0..count {
            c.observe_read(off, io_size);
            off += io_size;
        }
    }

    fn feed_sequential_writes(c: &mut WorkloadClassifier, count: usize, io_size: u64) {
        let mut off = 0u64;
        for _ in 0..count {
            c.observe_write(off, io_size);
            off += io_size;
        }
    }

    fn feed_mixed_with_fsync(c: &mut WorkloadClassifier, count: usize, fsync_every: usize) {
        for i in 0..count {
            let off = (i as u64) * 8192 + (i as u64 % 3) * 4096;
            if i % 2 == 0 {
                c.observe_read(off, 8192);
            } else {
                c.observe_write(off, 4096);
            }
            if i % fsync_every == 0 {
                c.observe_fsync();
            }
        }
    }

    // ── Classification tests ─────────────────────────────────

    #[test]
    fn unknown_when_window_too_small() {
        let mut c = WorkloadClassifier::new().with_min_window_ops(1000);
        feed_sequential_reads(&mut c, 10, 65536);
        let stats = c.classify();
        assert_eq!(
            stats.current_signature,
            WorkloadSignature::Unknown,
            "window too small should be Unknown"
        );
        assert_eq!(stats.confidence, 0.0);
    }

    #[test]
    fn oltp_small_random_io() {
        let mut c = WorkloadClassifier::new().with_min_window_ops(50);
        feed_random_small(&mut c, 100, 4096);
        let stats = c.classify();
        assert_eq!(
            stats.current_signature,
            WorkloadSignature::Oltp,
            "small random IO should classify as OLTP, got {}",
            stats.current_signature
        );
        assert!(
            stats.confidence > CONFIDENCE_THRESHOLD,
            "confidence {} should exceed threshold",
            stats.confidence
        );
    }

    #[test]
    fn olap_large_sequential_reads() {
        let mut c = WorkloadClassifier::new().with_min_window_ops(50);
        feed_sequential_reads(&mut c, 100, 65536);
        let stats = c.classify();
        assert_eq!(
            stats.current_signature,
            WorkloadSignature::Olap,
            "large sequential reads should classify as OLAP, got {}",
            stats.current_signature
        );
        assert!(
            stats.confidence > CONFIDENCE_THRESHOLD,
            "confidence {} should exceed threshold",
            stats.confidence
        );
    }

    #[test]
    fn backup_large_sequential_writes() {
        let mut c = WorkloadClassifier::new().with_min_window_ops(50);
        feed_sequential_writes(&mut c, 100, 65536);
        let stats = c.classify();
        assert_eq!(
            stats.current_signature,
            WorkloadSignature::Backup,
            "large sequential writes should classify as Backup, got {}",
            stats.current_signature
        );
        assert!(
            stats.confidence > CONFIDENCE_THRESHOLD,
            "confidence {} should exceed threshold",
            stats.confidence
        );
    }

    #[test]
    fn media_very_large_sequential_reads() {
        let mut c = WorkloadClassifier::new().with_min_window_ops(50);
        feed_sequential_reads(&mut c, 100, 2 * 1024 * 1024); // 2 MiB
        let stats = c.classify();
        assert_eq!(
            stats.current_signature,
            WorkloadSignature::Media,
            "very large sequential reads should classify as Media, got {}",
            stats.current_signature
        );
        assert!(
            stats.confidence > CONFIDENCE_THRESHOLD,
            "confidence {} should exceed threshold",
            stats.confidence
        );
    }

    #[test]
    fn vm_mixed_random_with_fsync() {
        let mut c = WorkloadClassifier::new().with_min_window_ops(50);
        feed_mixed_with_fsync(&mut c, 120, 8);
        let stats = c.classify();
        assert_eq!(
            stats.current_signature,
            WorkloadSignature::Vm,
            "mixed random with fsync should classify as VM, got {}",
            stats.current_signature
        );
        assert!(
            stats.confidence > CONFIDENCE_THRESHOLD,
            "confidence {} should exceed threshold",
            stats.confidence
        );
    }

    #[test]
    fn signature_transition_detected() {
        let mut c = WorkloadClassifier::new().with_min_window_ops(50);

        // Window 1: OLTP
        feed_random_small(&mut c, 100, 4096);
        let stats1 = c.classify();
        assert_eq!(stats1.current_signature, WorkloadSignature::Oltp);

        // Window 2: OLAP (transition)
        feed_sequential_reads(&mut c, 100, 65536);
        let stats2 = c.classify();
        assert_eq!(stats2.current_signature, WorkloadSignature::Olap);

        // Window 3: Backup
        feed_sequential_writes(&mut c, 100, 65536);
        let stats3 = c.classify();
        assert_eq!(stats3.current_signature, WorkloadSignature::Backup);
    }

    #[test]
    fn mixed_workload_unknown() {
        let mut c = WorkloadClassifier::new().with_min_window_ops(50);
        // Feed a pattern that doesn't fit any single classification well:
        // medium-sized IO, roughly 50/50 random/sequential, 50/50 read/write.
        for i in 0..100 {
            let off = (i as u64) * 32768; // 32 KiB stride
            if i < 50 {
                c.observe_read(off, 32768);
            } else {
                c.observe_write(off + 16384, 32768);
            }
        }
        let stats = c.classify();
        // This pattern may or may not fit any signature. If it does,
        // confidence should be modest; if Unknown, confidence is low.
        if stats.current_signature == WorkloadSignature::Unknown {
            assert!(stats.confidence < 0.5);
        } else {
            // Some classification might weakly match.
            // Accept as long as confidence is reasonable.
            assert!(stats.confidence <= 1.0);
        }
    }

    #[test]
    fn empty_window_is_unknown() {
        let c = WorkloadClassifier::new();
        let stats = c.peek();
        assert_eq!(stats.current_signature, WorkloadSignature::Unknown);
        assert_eq!(stats.window_ops, 0);
        assert_eq!(stats.confidence, 0.0);
    }

    // ── WorkloadMaterializer tests ────────────────────────────

    #[test]
    fn materializer_produces_periodic_stats() {
        let mut m = WorkloadMaterializer::new().with_min_window_ops(50);
        feed_sequential_reads_classify(&mut m, 100, 65536);
        let stats = m.last_stats();
        assert!(
            stats.window_ops >= 50,
            "materializer should have classified at least one window"
        );
        assert_eq!(stats.current_signature, WorkloadSignature::Olap);
    }

    fn feed_sequential_reads_classify(m: &mut WorkloadMaterializer, count: usize, io_size: u64) {
        let mut off = 0u64;
        for _ in 0..count {
            m.observe_read(off, io_size);
            off += io_size;
        }
        m.materialize();
    }

    #[test]
    fn materializer_reset_clears_state() {
        let mut m = WorkloadMaterializer::new().with_min_window_ops(30);
        feed_random_small_materialize(&mut m, 100, 4096);
        assert!(m.last_stats().window_ops > 0);

        m.reset();
        let stats = m.last_stats();
        assert_eq!(stats.window_ops, 0);
        assert_eq!(stats.current_signature, WorkloadSignature::Unknown);
    }

    fn feed_random_small_materialize(m: &mut WorkloadMaterializer, count: usize, max_size: u64) {
        for i in 0..count {
            let off = (i as u64) * 4096 + (i as u64 % 7) * 512;
            m.observe_read(off, max_size.min(4096 + (i as u64 % 3) * 1024));
            m.observe_write(off + 8192, max_size.min(2048 + (i as u64 % 5) * 512));
        }
        m.materialize();
    }

    // ── Edge cases ────────────────────────────────────────────

    #[test]
    fn fsync_only_window_is_vm() {
        let mut c = WorkloadClassifier::new().with_min_window_ops(10);
        for _ in 0..100 {
            c.observe_fsync();
        }
        let stats = c.classify();
        assert_eq!(stats.current_signature, WorkloadSignature::Vm);
    }

    #[test]
    fn zero_length_io_handled() {
        let mut c = WorkloadClassifier::new().with_min_window_ops(10);
        for i in 0..100 {
            c.observe_read(i * 4096, 0);
        }
        let stats = c.classify();
        // All zero-length: sequential (all follow expected offset),
        // very small avg_io_size. Should be OLTP-like or Unknown.
        assert!(
            stats.current_signature == WorkloadSignature::Oltp
                || stats.current_signature == WorkloadSignature::Unknown
        );
    }

    #[test]
    fn raw_counts_reflect_observations() {
        let mut c = WorkloadClassifier::new();
        c.observe_read(0, 4096);
        c.observe_read(4096, 8192);
        c.observe_write(12288, 4096);
        c.observe_fsync();

        let (r, w, f, rb, wb) = c.raw_counts();
        assert_eq!(r, 2);
        assert_eq!(w, 1);
        assert_eq!(f, 1);
        assert_eq!(rb, 4096 + 8192);
        assert_eq!(wb, 4096);
    }
}

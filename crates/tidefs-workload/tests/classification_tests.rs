//! Integration tests for workload classification.
//!
//! Exercises the public API across module boundaries: observing IO
//! patterns and verifying the classifier produces the expected
//! signatures and statistics.

use tidefs_workload::{WorkloadClassifier, WorkloadMaterializer, WorkloadSignature};

// ── Helpers ──────────────────────────────────────────────────────

fn produce_oltp_pattern(classifier: &mut WorkloadClassifier, count: usize) {
    for i in 0..count {
        let base = (i as u64) * 8192;
        // Random-like: offsets don't follow sequential pattern.
        let off = base + ((i as u64 % 7) * 512);
        classifier.observe_read(off, 4096 + (i as u64 % 3) * 1024);
        classifier.observe_write(off + 16384, 2048 + (i as u64 % 5) * 512);
    }
}

fn produce_olap_pattern(classifier: &mut WorkloadClassifier, count: usize) {
    let mut off = 0u64;
    let io_size = 65536u64;
    for _ in 0..count {
        classifier.observe_read(off, io_size);
        off += io_size;
    }
}

fn produce_backup_pattern(classifier: &mut WorkloadClassifier, count: usize) {
    let mut off = 0u64;
    let io_size = 65536u64;
    for _ in 0..count {
        classifier.observe_write(off, io_size);
        off += io_size;
    }
}

fn produce_mixed_with_high_fsync(classifier: &mut WorkloadClassifier, count: usize) {
    for i in 0..count {
        let off = (i as u64) * 8192 + ((i % 3) as u64) * 4096;
        if i % 2 == 0 {
            classifier.observe_read(off, 8192);
        } else {
            classifier.observe_write(off, 4096);
        }
        if i % 10 == 0 {
            classifier.observe_fsync();
        }
    }
}

// ── Integration tests ────────────────────────────────────────────

#[test]
fn full_classification_lifecycle() {
    let mut c = WorkloadClassifier::new().with_min_window_ops(50);

    // Phase 1: OLTP
    produce_oltp_pattern(&mut c, 100);
    let stats = c.classify();
    assert_eq!(stats.current_signature, WorkloadSignature::Oltp);
    assert!(stats.confidence > 0.3);
    assert_eq!(stats.window_ops, 200); // 100 reads + 100 writes
    assert!(stats.reads > 0);
    assert!(stats.writes > 0);

    // Phase 2: Transition to OLAP
    produce_olap_pattern(&mut c, 100);
    let stats = c.classify();
    assert_eq!(stats.current_signature, WorkloadSignature::Olap);
    assert!(stats.confidence > 0.3);
    assert_eq!(stats.window_ops, 100);

    // Phase 3: Transition to Backup
    produce_backup_pattern(&mut c, 100);
    let stats = c.classify();
    assert_eq!(stats.current_signature, WorkloadSignature::Backup);
    assert!(stats.confidence > 0.3);
}

#[test]
fn materializer_integration() {
    let mut m = WorkloadMaterializer::new().with_min_window_ops(50);

    // Feed OLTP pattern and materialize.
    for i in 0..100 {
        let off = (i as u64) * 4096 + ((i % 7) as u64) * 512;
        m.observe_read(off, 4096);
        m.observe_write(off + 8192, 2048);
    }
    let stats = m.materialize();
    assert_eq!(stats.current_signature, WorkloadSignature::Oltp);
    assert!(stats.confidence > 0.3);

    // Verify last_stats() returns the same result.
    let cached = m.last_stats();
    assert_eq!(cached.current_signature, stats.current_signature);
    assert_eq!(cached.confidence, stats.confidence);

    // Reset and verify clean state.
    m.reset();
    assert_eq!(m.last_stats().current_signature, WorkloadSignature::Unknown);
    assert_eq!(m.last_stats().window_ops, 0);
}

#[test]
fn sliding_window_produces_fresh_classification_each_call() {
    let mut c = WorkloadClassifier::new().with_min_window_ops(30);

    produce_oltp_pattern(&mut c, 60);
    let s1 = c.classify();
    assert_eq!(s1.current_signature, WorkloadSignature::Oltp);

    produce_olap_pattern(&mut c, 60);
    let s2 = c.classify();
    assert_eq!(s2.current_signature, WorkloadSignature::Olap);

    // Each classification returned correct data for its window.
    assert_eq!(s1.window_ops, 120); // 60 reads + 60 writes
    assert_eq!(s2.window_ops, 60); // 60 reads only
}

#[test]
fn peek_does_not_reset() {
    let mut c = WorkloadClassifier::new().with_min_window_ops(30);

    produce_oltp_pattern(&mut c, 60);
    let peek1 = c.peek();
    let peek2 = c.peek();

    // Two peeks should return identical stats (state unchanged).
    assert_eq!(peek1.current_signature, peek2.current_signature);
    assert_eq!(peek1.confidence, peek2.confidence);
    assert_eq!(peek1.window_ops, peek2.window_ops);

    // classify() consumes the window.
    let _classified = c.classify();
    let peek3 = c.peek();
    assert_eq!(peek3.window_ops, 0); // Window consumed.
}

#[test]
fn vm_high_fsync_detection() {
    let mut c = WorkloadClassifier::new().with_min_window_ops(50);

    produce_mixed_with_high_fsync(&mut c, 120);
    let stats = c.classify();
    assert_eq!(stats.current_signature, WorkloadSignature::Vm);
    assert!(stats.fsyncs > 0);
    assert!(stats.confidence > 0.3);
}

#[test]
fn confidence_increases_with_stronger_signal() {
    let mut c1 = WorkloadClassifier::new().with_min_window_ops(50);

    // Weak OLAP: barely above thresholds.
    for i in 0..100 {
        let off = i as u64 * 65536;
        // 90% sequential, 10% random
        if i % 10 == 0 {
            c1.observe_read(off + 32768, 65536);
        } else {
            c1.observe_read(off, 65536);
        }
    }
    let stats1 = c1.classify();
    assert_eq!(stats1.current_signature, WorkloadSignature::Olap);

    let mut c2 = WorkloadClassifier::new().with_min_window_ops(50);

    // Strong OLAP: 4 MiB IO, fully sequential.
    for i in 0..100 {
        let off = i as u64 * (128 * 1024);
        c2.observe_read(off, 128 * 1024);
    }
    let stats2 = c2.classify();
    assert_eq!(stats2.current_signature, WorkloadSignature::Olap);

    // Stronger signal should have higher confidence.
    assert!(
        stats2.confidence > stats1.confidence,
        "stronger OLAP signal should have higher confidence (weak={:.3}, strong={:.3})",
        stats1.confidence,
        stats2.confidence
    );
}

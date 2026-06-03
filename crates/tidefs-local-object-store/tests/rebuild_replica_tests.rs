//! Rebuild-replica integration tests for `tidefs-local-object-store`.
//!
//! Covers the `rebuild_replica_from_surviving` function that copies all
//! live objects from a surviving store to a replacement store -- the
//! data-copy execution path for mirror-rebuild after device loss.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-rebuild-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn fast_opts() -> StoreOptions {
    StoreOptions::test_fast()
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

#[test]
fn rebuild_copies_all_objects() {
    let surviving_root = temp_root("all-objs-surv");
    let replacement_root = temp_root("all-objs-repl");

    let payloads: Vec<&[u8]> = vec![b"alpha", b"beta-beta-beta", b"gamma"];

    {
        let mut store =
            LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("open");
        for payload in &payloads {
            store.put_content_addressed(payload).expect("put");
        }
        store.sync_all().expect("sync");
    }

    {
        let surviving =
            LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("reopen");
        let replacement = LocalObjectStore::rebuild_replica_from_surviving(
            &surviving,
            &replacement_root,
            fast_opts(),
        )
        .expect("rebuild");

        let sk: Vec<_> = surviving.list_keys();
        let rk: Vec<_> = replacement.list_keys();
        assert_eq!(sk.len(), rk.len(), "key counts match");
        for key in &sk {
            let sp = surviving.get(*key).expect("get").expect("present");
            let rp = replacement.get(*key).expect("get").expect("present");
            assert_eq!(sp, rp, "payload mismatch for {key:?}");
        }
    }

    cleanup(&surviving_root);
    cleanup(&replacement_root);
}

#[test]
fn rebuild_empty_store() {
    let surviving_root = temp_root("empty-surv");
    let replacement_root = temp_root("empty-repl");

    {
        let _store =
            LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("open");
    }

    {
        let surviving =
            LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("reopen");
        let replacement = LocalObjectStore::rebuild_replica_from_surviving(
            &surviving,
            &replacement_root,
            fast_opts(),
        )
        .expect("rebuild");
        assert!(replacement.list_keys().is_empty(), "replacement empty");
    }

    cleanup(&surviving_root);
    cleanup(&replacement_root);
}

#[test]
fn rebuild_excludes_internal_keys() {
    let surviving_root = temp_root("internal-surv");
    let replacement_root = temp_root("internal-repl");

    {
        let mut store =
            LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("open");
        store.put_content_addressed(b"user-data").expect("put");
        store.sync_all().expect("sync");
    }

    {
        let surviving =
            LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("reopen");
        let replacement = LocalObjectStore::rebuild_replica_from_surviving(
            &surviving,
            &replacement_root,
            fast_opts(),
        )
        .expect("rebuild");
        let keys = replacement.list_keys();
        assert_eq!(keys.len(), 1, "only user data, no internal keys");
    }

    cleanup(&surviving_root);
    cleanup(&replacement_root);
}

#[test]
fn rebuild_many_objects() {
    let surviving_root = temp_root("many-surv");
    let replacement_root = temp_root("many-repl");
    let count = 100;

    {
        let mut store =
            LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("open");
        for i in 0..count {
            store
                .put_content_addressed(format!("obj-{i:05}").as_bytes())
                .expect("put");
        }
        store.sync_all().expect("sync");
    }

    {
        let surviving =
            LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("reopen");
        let replacement = LocalObjectStore::rebuild_replica_from_surviving(
            &surviving,
            &replacement_root,
            fast_opts(),
        )
        .expect("rebuild");
        let sk: Vec<_> = surviving.list_keys();
        let rk: Vec<_> = replacement.list_keys();
        assert_eq!(sk.len(), rk.len(), "key equality");
        assert_eq!(rk.len(), count, "all objects rebuilt");
    }

    cleanup(&surviving_root);
    cleanup(&replacement_root);
}

// ---------------------------------------------------------------------------
// Throttled rebuild tests (NEXT-MN-016: background rebuild backpressure)
// ---------------------------------------------------------------------------

#[test]
fn throttled_rebuild_with_no_pressure_proceeds_normally() {
    let surviving_root = temp_root("throt-no-pressure-surv");
    let replacement_root = temp_root("throt-no-pressure-repl");

    {
        let mut store =
            LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("open");
        store.put_content_addressed(b"object-1").expect("put");
        store.put_content_addressed(b"object-2").expect("put");
        store.sync_all().expect("sync");
    }

    let surviving =
        LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("reopen");

    let probe = tidefs_local_object_store::IoPressureProbe::none();
    let throttle = tidefs_local_object_store::RebuildThrottleConfig {
        max_yield_per_object: std::time::Duration::from_millis(10),
        probe_interval_objects: 1,
    };

    let replacement = LocalObjectStore::rebuild_replica_from_surviving_throttled(
        &surviving,
        &replacement_root,
        fast_opts(),
        Some(&probe),
        &throttle,
    )
    .expect("throttled rebuild");

    let keys = replacement.list_keys();
    assert_eq!(keys.len(), 2, "all objects copied under no pressure");

    cleanup(&surviving_root);
    cleanup(&replacement_root);
}

#[test]
fn throttled_rebuild_with_max_pressure_still_completes() {
    let surviving_root = temp_root("throt-max-pressure-surv");
    let replacement_root = temp_root("throt-max-pressure-repl");

    {
        let mut store =
            LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("open");
        for i in 0..20 {
            store
                .put_content_addressed(format!("object-{i}").as_bytes())
                .expect("put");
        }
        store.sync_all().expect("sync");
    }

    let surviving =
        LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("reopen");

    // Max pressure: every probe returns 1.0, so the rebuild yields between
    // every batch. It should still complete (just slower).
    let probe = tidefs_local_object_store::IoPressureProbe::max();
    let throttle = tidefs_local_object_store::RebuildThrottleConfig {
        max_yield_per_object: std::time::Duration::from_millis(1),
        probe_interval_objects: 4,
    };

    let start = std::time::Instant::now();
    let replacement = LocalObjectStore::rebuild_replica_from_surviving_throttled(
        &surviving,
        &replacement_root,
        fast_opts(),
        Some(&probe),
        &throttle,
    )
    .expect("throttled rebuild under max pressure");

    let elapsed = start.elapsed();
    let keys = replacement.list_keys();
    assert_eq!(keys.len(), 20, "all objects copied under max pressure");

    // 20 objects, probed every 4 objects = 5 yields of 1ms each = ~5ms minimum
    assert!(
        elapsed >= std::time::Duration::from_millis(4),
        "expected at least 4ms yield time, got {elapsed:?}"
    );

    cleanup(&surviving_root);
    cleanup(&replacement_root);
}

#[test]
fn throttled_rebuild_yields_proportionally_to_pressure() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    let surviving_root = temp_root("throt-prop-surv");
    let replacement_root = temp_root("throt-prop-repl");

    {
        let mut store =
            LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("open");
        for i in 0..8 {
            store
                .put_content_addressed(format!("obj-{i}").as_bytes())
                .expect("put");
        }
        store.sync_all().expect("sync");
    }

    let surviving =
        LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("reopen");

    // Dynamic probe: starts at 0.0, ramps to 1.0 after first few checks.
    let call_count = Arc::new(AtomicU64::new(0));
    let cc = Arc::clone(&call_count);
    let probe = tidefs_local_object_store::IoPressureProbe::new(move || {
        let n = cc.fetch_add(1, Ordering::SeqCst);
        if n <= 1 {
            0.0
        } else if n <= 3 {
            0.5
        } else {
            1.0
        }
    });

    let throttle = tidefs_local_object_store::RebuildThrottleConfig {
        max_yield_per_object: std::time::Duration::from_millis(5),
        probe_interval_objects: 2,
    };

    let replacement = LocalObjectStore::rebuild_replica_from_surviving_throttled(
        &surviving,
        &replacement_root,
        fast_opts(),
        Some(&probe),
        &throttle,
    )
    .expect("throttled rebuild");

    let keys = replacement.list_keys();
    assert_eq!(keys.len(), 8, "all objects copied");

    // At least 2 probe calls (8 objects / 2 interval = 4, minus first check at i=0 skipped)
    assert!(
        call_count.load(Ordering::SeqCst) >= 2,
        "probe called at least twice"
    );

    cleanup(&surviving_root);
    cleanup(&replacement_root);
}

#[test]
fn throttled_rebuild_disabled_config_is_noop() {
    let surviving_root = temp_root("throt-disabled-surv");
    let replacement_root = temp_root("throt-disabled-repl");

    {
        let mut store =
            LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("open");
        store.put_content_addressed(b"data").expect("put");
        store.sync_all().expect("sync");
    }

    let surviving =
        LocalObjectStore::open_with_options(&surviving_root, fast_opts()).expect("reopen");

    // Even with max pressure, disabled config means no throttling.
    let probe = tidefs_local_object_store::IoPressureProbe::max();
    let throttle = tidefs_local_object_store::RebuildThrottleConfig::disabled();

    let replacement = LocalObjectStore::rebuild_replica_from_surviving_throttled(
        &surviving,
        &replacement_root,
        fast_opts(),
        Some(&probe),
        &throttle,
    )
    .expect("throttled rebuild with disabled config");

    let keys = replacement.list_keys();
    assert_eq!(keys.len(), 1, "object copied with disabled throttle");

    cleanup(&surviving_root);
    cleanup(&replacement_root);
}

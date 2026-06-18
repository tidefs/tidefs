// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Trace regression catalog: generate and replay smoke trace fixtures.
//!
//! ## Generating fixtures
//!
//! Set `TIDEFS_VALIDATION_GENERATE_FIXTURES=1` to regenerate the reference
//! trace fixtures from live smoke runs:
//!
//! ```text
//! TIDEFS_VALIDATION_GENERATE_FIXTURES=1 cargo test -p tidefs-validation \
//!   --features fuse --test fixture_regression -- generate_fixtures --nocapture
//! ```
//!
//! ## Replaying fixtures
//!
//! Without the env var, the test replays every `.json` fixture in
//! `tests/fixtures/` and asserts all recorded assertions pass:
//!
//! ```text
//! cargo test -p tidefs-validation --features fuse \
//!   --test fixture_regression -- replay_fixtures
//! ```

use std::path::PathBuf;
use tidefs_validation::trace::{self, Trace, TraceEvent, ValidationStepStatus};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Generate a reference trace for a basic dir-index-style smoke scenario.
fn generate_harness_smoke_trace() -> Trace {
    vec![
        TraceEvent::ScenarioBegin {
            name: "harness-smoke".into(),
        },
        TraceEvent::DirInsert {
            name: b"entry1".to_vec(),
            inode_id: 100,
            generation: 1,
            kind: 0,
        },
        TraceEvent::DirLookup {
            name: b"entry1".to_vec(),
        },
        TraceEvent::Assert {
            condition: "lookup(entry1) found".into(),
            passed: true,
        },
        TraceEvent::DirRemove {
            name: b"entry1".to_vec(),
        },
        TraceEvent::DirLookup {
            name: b"entry1".to_vec(),
        },
        TraceEvent::Assert {
            condition: "lookup(deleted entry1) is None".into(),
            passed: true,
        },
        TraceEvent::ScenarioEnd {
            name: "harness-smoke".into(),
        },
    ]
}

/// Generate a trace that records a failed validation command in fixture data.
fn generate_harness_failed_step_trace() -> Trace {
    vec![
        TraceEvent::ScenarioBegin {
            name: "harness-failed-step".into(),
        },
        TraceEvent::ValidationStep {
            name: "fixture regression gate".into(),
            command: "cargo test -p tidefs-validation --test fixture_regression".into(),
            status: ValidationStepStatus::Failed,
            exit_code: Some(101),
        },
        TraceEvent::Assert {
            condition: "failed validation step status and exit code recorded".into(),
            passed: true,
        },
        TraceEvent::ScenarioEnd {
            name: "harness-failed-step".into(),
        },
    ]
}

fn generate_all_fixtures() -> Vec<(String, PathBuf)> {
    let dir = fixtures_dir();
    std::fs::create_dir_all(&dir).expect("create fixtures dir");

    let scenarios: Vec<(&str, Trace)> = vec![
        ("harness_smoke", generate_harness_smoke_trace()),
        ("harness_failed_step", generate_harness_failed_step_trace()),
    ];

    let mut written = Vec::new();
    for (name, trace) in &scenarios {
        let path = dir.join(format!("{name}.json"));
        trace::write_trace_to_file(trace, &path)
            .unwrap_or_else(|e| panic!("write fixture {name}: {e}"));
        written.push((name.to_string(), path));
    }
    written
}

fn failed_validation_steps(trace: &Trace) -> Vec<(&str, &str, Option<i32>)> {
    trace
        .iter()
        .filter_map(|event| match event {
            TraceEvent::ValidationStep {
                name,
                command,
                status: ValidationStepStatus::Failed,
                exit_code,
            } => Some((name.as_str(), command.as_str(), *exit_code)),
            _ => None,
        })
        .collect()
}

fn replay_all_fixtures() -> Vec<String> {
    let dir = fixtures_dir();
    let mut errors = Vec::new();

    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => {
            eprintln!("no fixtures directory at {}", dir.display());
            return errors;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }

        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        let trace = match trace::read_trace_from_file(&path) {
            Ok(t) => t,
            Err(e) => {
                errors.push(format!("{name}: read error: {e}"));
                continue;
            }
        };

        let failures = trace::verify_trace_assertions(&trace);
        if !failures.is_empty() {
            errors.push(format!(
                "{name}: assertion failures: {}",
                failures.join(", ")
            ));
            continue;
        }

        let data =
            trace::serialize_trace(&trace).unwrap_or_else(|e| panic!("{name}: serialize: {e}"));
        let back =
            trace::deserialize_trace(&data).unwrap_or_else(|e| panic!("{name}: deserialize: {e}"));
        if trace != back {
            errors.push(format!("{name}: round-trip mismatch"));
        }

        eprintln!("  OK  {name}  ({} events)", trace.len());
    }

    errors
}

// ── tests ──────────────────────────────────────────────────────────────────

#[test]
fn generate_fixtures() {
    if std::env::var("TIDEFS_VALIDATION_GENERATE_FIXTURES").is_err() {
        eprintln!("skipping fixture generation (set TIDEFS_VALIDATION_GENERATE_FIXTURES=1 to run)");
        return;
    }
    let written = generate_all_fixtures();
    eprintln!("generated {} fixture(s):", written.len());
    for (name, path) in &written {
        eprintln!("  {}", path.display());
        let trace =
            trace::read_trace_from_file(path).unwrap_or_else(|e| panic!("read {name}: {e}"));
        let failures = trace::verify_trace_assertions(&trace);
        assert!(
            failures.is_empty(),
            "generated fixture {name} has assertion failures: {failures:?}"
        );
    }
}

#[test]
fn replay_fixtures() {
    let errors = replay_all_fixtures();
    if !errors.is_empty() {
        panic!("fixture replay errors:\n{}", errors.join("\n"));
    }
    let dir = fixtures_dir();
    let has_fixtures = std::fs::read_dir(&dir)
        .map(|mut entries| {
            entries.any(|e| {
                e.ok()
                    .is_some_and(|f| f.path().extension().is_some_and(|ext| ext == "json"))
            })
        })
        .unwrap_or(false);
    if !has_fixtures {
        eprintln!("note: no fixtures found; run with TIDEFS_VALIDATION_GENERATE_FIXTURES=1 to generate them");
    }
}

#[test]
fn failed_step_fixture_retains_status_and_exit_code() {
    let path = fixtures_dir().join("harness_failed_step.json");
    let trace = trace::read_trace_from_file(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    let failed_steps = failed_validation_steps(&trace);
    assert_eq!(
        failed_steps,
        vec![(
            "fixture regression gate",
            "cargo test -p tidefs-validation --test fixture_regression",
            Some(101)
        )]
    );

    let data = trace::serialize_trace(&trace).expect("serialize failed-step fixture");
    let back = trace::deserialize_trace(&data).expect("deserialize failed-step fixture");
    assert_eq!(failed_validation_steps(&back), failed_steps);
}

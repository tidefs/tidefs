// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Tracing subscriber initialization for FUSE daemon observability.
//!
//! Supports two modes:
//! - **File mode** (`init_tracing_json` with `Some(path)`): writes
//!   structured JSON spans to a file via `tracing-subscriber` JSON layer.
//!   Useful for post-hoc latency analysis and flamegraph generation.
//! - **No-op mode** (`init_tracing_json` with `None`): leaves the global
//!   subscriber unset.  All `#[tracing::instrument]` spans and
//!   `tracing::event!` calls compile but produce zero runtime overhead
//!   (a single atomic load-and-branch per span).

use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::sync::Mutex;

use tracing_subscriber::prelude::*;

/// Initialize the global tracing subscriber.
///
/// When `trace_file` is `Some(path)`, a JSON-format tracing subscriber is
/// installed that writes every span open/close/event to the given file.
/// The log level is controlled by the `RUST_LOG` environment variable
/// (defaults to `info` if unset).
///
/// When `trace_file` is `None`, no subscriber is installed.  All tracing
/// instrumentation becomes a no-op, incurring only an atomic `Relaxed`
/// load-and-branch per span/event site.
///
/// # Panics
///
/// Panics if `trace_file` is `Some` and the file cannot be created, or if
/// a global subscriber has already been set.
pub fn init_tracing_json(trace_file: Option<&Path>) {
    let path = match trace_file {
        Some(p) => p,
        None => return,
    };

    let file = File::create(path)
        .unwrap_or_else(|e| panic!("failed to create trace file {}: {e}", path.display()));
    let writer = BufWriter::new(file);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let json_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(Mutex::new(writer))
        .with_target(false)
        .with_span_list(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(json_layer)
        .init();
}

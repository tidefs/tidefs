// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Workload signature materialization for adaptive TideFS tuning.
//!
//! This crate provides a sliding-window IO pattern classifier that
//! observes read, write, and fsync operations and classifies the
//! dominant access pattern into one of six canonical workload
//! signatures: OLTP, OLAP, Backup, Media, VM, or Unknown.
//!
//! Adaptive subsystems (prefetch, recordsize, ARC, scheduler) can
//! consume the materialized [`WorkloadStats`] to tune their behavior.
//!
//! Use [`WorkloadMaterializer`] or [`WorkloadClassifier`] to feed observations
//! and consume the current [`WorkloadStats`] snapshot; [`WorkloadSignature`]
//! provides the stable labels exposed by the crate.
//!
//! # Quick start
//!
//! ```ignore
//! use tidefs_workload::{WorkloadMaterializer, WorkloadSignature};
//!
//! let mut m = WorkloadMaterializer::new().with_min_window_ops(64);
//! // Feed observations as IO happens...
//! m.observe_read(0, 4096);
//! m.observe_write(4096, 2048);
//! // Periodically materialize...
//! let stats = m.materialize();
//! println!("signature={} confidence={:.2}", stats.current_signature, stats.confidence);
//! ```

mod classifier;
mod signature;

pub use classifier::{WorkloadClassifier, WorkloadMaterializer, WorkloadStats};
pub use signature::{InvalidWorkloadSignature, WorkloadSignature};

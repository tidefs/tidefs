//! Range-scan iterator over a B+tree.
//!
//! See [`range_scan`](crate::range_scan) for the iterator implementation.
//! This module provides re-exports for users who expect a module named
//! `iter` following the standard Rust convention.

// Re-export suppressed: RangeScan is already exported from lib.rs via
// `pub use range_scan::RangeScan;`. This module exists for documentation
// discoverability only.

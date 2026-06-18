// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg_attr(all(feature = "kernel", not(feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(dead_code)]
#![deny(unused_imports)]

//! TideFS extent map surfaces.
//!
//! The default build exposes the full userspace extent-map implementation.
//! The `kernel` feature intentionally exposes only the no_std reader surface
//! needed by mounted kernel code so kernel validation does not compile
//! std-bound userspace helpers.

#[cfg(feature = "kernel")]
extern crate alloc;

#[cfg(feature = "kernel")]
pub mod kernel;

#[cfg(feature = "kernel")]
pub use kernel::{ExtentMapKernelReader, ExtentMapping};

#[cfg(feature = "kernel")]
pub use tidefs_types_extent_map_core::{ExtentMapEntryV2, LocatorId};

#[cfg(feature = "std")]
mod userspace;

#[cfg(feature = "std")]
pub use userspace::*;

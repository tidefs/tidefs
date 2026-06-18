// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]
// When built without the std feature (kernel mode), this crate is no_std.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// ── Kernel-mode inode table record reader ─────────────────────────────────

#[cfg(feature = "kernel")]
pub mod kernel_reader;

#[cfg(feature = "kernel")]
pub use kernel_reader::{
    InodeKind as KernelInodeKind, InodeRecord, KernelInodeTableError, KernelInodeTableReader,
};

// ── Std-mode InodeTable implementation (the full crate) ──────────────────

#[cfg(feature = "std")]
#[path = "inode_table_impl.rs"]
mod imp;

#[cfg(feature = "std")]
pub use imp::*;

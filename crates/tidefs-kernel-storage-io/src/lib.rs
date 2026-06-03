#![no_std]
#![forbid(unsafe_code)]

//! Kernel-portable block-I/O storage adapter for TideFS.
//!
//! This crate provides [`KernelStorageIo`], a `no_std` trait that defines
//! sector-aligned read, write, and flush/barrier primitives for kernel-mode
//! storage subsystems. It is the common I/O contract consumed by intent-log
//! append and transaction-group commit-barrier paths, keeping those
//! subsystems portable across block-device backends.
//!
//! # Architecture
//!
//! ```text
//! intent-log append  ──┐
//! txg commit-barrier ──┤
//! pool label scan    ──┤
//!                      ├──► KernelStorageIo (sector-aligned trait)
//!                      │              │
//!                      │     KernelStorageAdapter
//!                      │              │
//!                      │       raw block-device I/O
//!                      │     (byte-offset read/write/flush)
//! ```
//!
//! # Sector alignment
//!
//! All `read` and `write` calls target whole sectors. The sector size is
//! queried via [`sector_size`](KernelStorageIo::sector_size). Callers must
//! supply buffers whose length is a multiple of the sector size.
//!
//! # Pool superblock scan
//!
//! The [`pool_superblock`] module provides [`read_pool_superblock`], which
//! reads and validates the TideFS pool label from a block device through
//! [`KernelStorageIo`]. It returns a [`KernelPoolSuperblock`] with the pool
//! identity, recovery commit_group, and committed-root ledger location —
//! the minimal information needed by the VFS mount path to initialize
//! KernelPoolCore.
//!
//! # no_std
//!
//! This crate is `#![no_std]` and uses only `core` and `alloc` (gated
//! behind the `alloc` feature). It has no file-system, threading, or
//! networking dependencies, making it suitable for Linux kernel modules.

extern crate alloc;

pub mod adapter;
pub mod pool_superblock;
pub mod traits;

// Re-export the public API.
pub use adapter::KernelStorageAdapter;
pub use pool_superblock::{
    read_pool_superblock, read_pool_superblock_at, KernelPoolSuperblock, PoolSuperblockError,
};
pub use traits::{KernelStorageIo, RawBlockIo};

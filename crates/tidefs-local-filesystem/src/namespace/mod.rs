// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Namespace mutation layer for TideFS.
//!
//! This directory holds namespace-level operations that manipulate
//! directory entries, inode metadata, and link counts with transactional
//! persistence. The modules here are consumed by the FUSE dispatch
//! layer and by the POSIX adapter.

pub mod link;
pub mod rename;
pub mod symlink;
pub mod unlink;

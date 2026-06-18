// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! POSIX FUSE request classification dispatch glue.
//!
//! This module provides FUSE request classification and reply-commit dispatch
//! helpers for the POSIX adapter family. It does not carry capacity authority
//! semantics: the production capacity path uses
//! [`tidefs_local_filesystem::capacity_authority::CapacityAuthority`].
//!
//! The retired adapter-local `CapacityFacade`, reservation lifecycle, and
//! tracker are quarantined under `#[cfg(test)]` so release validation cannot
//! import them as the capacity API.
//!
//! # Public modules
//!
//! - [`dispatch`] — FUSE request classification and reply-commit dispatch for
//!   OPENDIR, READDIR, RELEASEDIR, READ, WRITE, RENAME, RENAME2, UNLINK, CREATE,
//!   MKNOD, LINK, and related operations (P5-02 seam).
//! - [`statfs_reply`] — FUSE `statfs_out` reply layout and serialization.

pub mod dispatch;
pub mod statfs_reply;

// ── Test-only legacy capacity fixtures ────────────────────────────────────
// CapacityFacade, admission, and tracker are retired from the production
// capacity path. They remain under cfg(test) so their own unit tests still
// compile and run without exporting a production capacity API.
#[cfg(test)]
pub mod admission;
#[cfg(test)]
pub mod facade;
#[cfg(test)]
pub mod tracker;

// ── Public re-exports ─────────────────────────────────────────────────────

#[allow(unused_imports)]
pub use dispatch::{
    dispatch_create as dispatch_create_classify, dispatch_fallocate, dispatch_flush,
    dispatch_fsync, dispatch_fsyncdir, dispatch_getxattr, dispatch_link as dispatch_link_classify,
    dispatch_listxattr, dispatch_mkdir as dispatch_mkdir_classify,
    dispatch_mknod as dispatch_mknod_classify, dispatch_opendir, dispatch_read, dispatch_readdir,
    dispatch_readdirplus, dispatch_readlink as dispatch_readlink_classify, dispatch_releasedir,
    dispatch_removexattr, dispatch_rename, dispatch_rename2, dispatch_rmdir, dispatch_setxattr,
    dispatch_symlink as dispatch_symlink_classify, dispatch_unlink, dispatch_write, CreateDispatch,
    FallocateDispatch, FlushDispatch, FsyncDispatch, FsyncdirDispatch, GetxattrDispatch,
    LinkDispatch, ListxattrDispatch, MkdirDispatch, MknodDispatch, OpendirDispatch, ReadDispatch,
    ReaddirDispatch, ReaddirplusDispatch, ReadlinkDispatch, ReleasedirDispatch,
    RemovexattrDispatch, RenameDispatch, RmdirDispatch, SetxattrDispatch, SymlinkDispatch,
    UnlinkDispatch, WriteDispatch,
};

#[allow(unused_imports)]
pub use statfs_reply::StatfsReply;

#[cfg(test)]
#[allow(unused_imports)]
pub use dispatch::{dispatch_statfs, StatfsDispatch};
#[cfg(test)]
#[allow(unused_imports)]
pub use facade::CapacityFacade;

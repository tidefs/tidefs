//! FUSE opcode classifier and handler prelude.
//!
//! Every `classify_*_request` function from the ingress classifier, plus the
//! shared handler types (`IngressWriteHandle`, `IngressWriteHandleTable`,
//! `FUSE_WRITE_*` constants), is re-exported from this module so that FUSE
//! dispatch files can `use crate::handler_prelude::*` without repeating the
//! same long import block.
//!
//! When adding a new FUSE opcode handler:
//! 1. Add its `classify_*_request` function below in the appropriate category.
//! 2. Update the opcode reference table in this doc comment.
//! 3. The new function becomes available to every dispatch file automatically.
//!
//! ## Opcode reference
//!
//! | Category | Function | FUSE opcode | Kernel constant |
//! |----------|----------|-------------|-----------------|
//! | Context  | `classify_request_context` | — | general context builder |
//! | File     | `classify_open_request` | 14 | `FUSE_OPEN` |
//! | File     | `classify_release_request` | 18 | `FUSE_RELEASE` |
//! | File     | `classify_fallocate_request` | 43 | `FUSE_FALLOCATE` |
//! | File     | `classify_flush_request` | 25 | `FUSE_FLUSH` |
//! | File     | `classify_fsync_request` | 26 | `FUSE_FSYNC` |
//! | File     | `classify_lseek_request` | 19 | `FUSE_LSEEK` |
//! | File     | `classify_copy_file_range_request` | 47 | `FUSE_COPY_FILE_RANGE` |
//! | Dir      | `classify_lookup_request` | 1 | `FUSE_LOOKUP` |
//! | Dir      | `classify_fsyncdir_request` | 30 | `FUSE_FSYNCDIR` |
//! | Dir      | `classify_rename_request` | 12 | `FUSE_RENAME` |
//! | Dir      | `classify_rename2_request` | 12 | `FUSE_RENAME2` |
//! | Dir      | `classify_unlink_request` | 10 | `FUSE_UNLINK` |
//! | Lock     | `classify_flock_request` | 36 | `FUSE_FLOCK` (BSD) |
//! | Lock     | `classify_getlk_request` | 31 | `FUSE_GETLK` |
//! | Lock     | `classify_setlk_request` | 32 | `FUSE_SETLK` |
//! | Attr     | `classify_setattr_request` | 4 | `FUSE_SETATTR` |
//! | Attr     | `classify_access_request` | 34 | `FUSE_ACCESS` |
//! | Attr     | `classify_statfs_request` | 17 | `FUSE_STATFS` |
//! | Attr     | `classify_statx_request` | 52 | `FUSE_STATX` |
//! | Attr     | `classify_syncfs_request` | 48 | `FUSE_SYNCFS` |
//! | Xattr    | `classify_getxattr_request` | 22 | `FUSE_GETXATTR` |
//! | Xattr    | `classify_setxattr_request` | 6 | `FUSE_SETXATTR` |
//! | Xattr    | `classify_listxattr_request` | 23 | `FUSE_LISTXATTR` |
//! | Xattr    | `classify_removexattr_request` | 24 | `FUSE_REMOVEXATTR` |
//! | Misc     | `classify_ioctl_request` | 39 | `FUSE_IOCTL` |
//! | Misc     | `classify_poll_request` | 40 | `FUSE_POLL` |
//! | Misc     | `classify_bmap_request` | 37 | `FUSE_BMAP` |

// ── Context ────────────────────────────────────────────────────────────

pub use crate::ingress::classify_request_context;

// ── File operations ────────────────────────────────────────────────────

pub use crate::ingress::classify_copy_file_range_request;
pub use crate::ingress::classify_fallocate_request;
pub use crate::ingress::classify_flush_request;
pub use crate::ingress::classify_fsync_request;
pub use crate::ingress::classify_lseek_request;
pub use crate::ingress::classify_open_request;
pub use crate::ingress::classify_release_request;

// ── Directory operations ───────────────────────────────────────────────

pub use crate::ingress::classify_fsyncdir_request;
pub use crate::ingress::classify_lookup_request;
pub use crate::ingress::classify_rename2_request;
pub use crate::ingress::classify_rename_request;
pub use crate::ingress::classify_unlink_request;

// ── Lock operations ────────────────────────────────────────────────────

pub use crate::ingress::classify_flock_request;
pub use crate::ingress::classify_getlk_request;
pub use crate::ingress::classify_setlk_request;

// ── Attribute operations ───────────────────────────────────────────────

pub use crate::ingress::classify_access_request;
pub use crate::ingress::classify_setattr_request;
pub use crate::ingress::classify_statfs_request;
pub use crate::ingress::classify_statx_request;
pub use crate::ingress::classify_syncfs_request;

// ── Extended-attribute operations ──────────────────────────────────────

pub use crate::ingress::classify_getxattr_request;
pub use crate::ingress::classify_listxattr_request;
pub use crate::ingress::classify_removexattr_request;
pub use crate::ingress::classify_setxattr_request;

// ── Miscellaneous ──────────────────────────────────────────────────────

pub use crate::ingress::classify_bmap_request;
pub use crate::ingress::classify_ioctl_request;
pub use crate::ingress::classify_poll_request;

// ── Shared handler types ───────────────────────────────────────────────

pub use crate::ingress::IngressWriteHandle;
pub use crate::ingress::IngressWriteHandleTable;
pub use crate::ingress::FUSE_WRITE_CACHE;
pub use crate::ingress::FUSE_WRITE_KILL_PRIV;
pub use crate::ingress::FUSE_WRITE_LOCKOWNER;

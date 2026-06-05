//! Per-opcode FUSE operation tracing spans and error-rate counters.
//!
//! Gated behind the `fuse-tracing` feature flag. When disabled, all
//! instrumentation compiles to no-ops or minimal static allocations.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::ll::fuse_abi::fuse_opcode;

/// Number of opcode slots (cover all known opcodes + headroom).
const OPCODE_SLOTS: usize = 64;

/// Per-opcode error counters.
///
/// Each slot in the `counters` array corresponds to a FUSE opcode number.
/// The counter is incremented atomically whenever a dispatch error is
/// returned to the kernel with a non-zero errno.
#[derive(Debug)]
pub struct FuseErrorCounters {
    counters: [AtomicU64; OPCODE_SLOTS],
}

impl Default for FuseErrorCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl FuseErrorCounters {
    /// Create a new empty set of error counters.
    pub const fn new() -> Self {
        // Construct an array of zero-initialized AtomicU64 values.
        // SAFETY: AtomicU64::new(0) is used as a const initializer only;
        // the values are never accessed through the const reference.
        #[allow(clippy::declare_interior_mutable_const)]
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            counters: [
                ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
                ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
                ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
                ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
                ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
            ],
        }
    }

    /// Increment the error counter for a given opcode.
    ///
    /// Opcodes outside the valid range are silently ignored.
    pub fn increment(&self, opcode: u32) {
        let idx = opcode as usize;
        if idx < OPCODE_SLOTS {
            self.counters[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Return the current error count for a given opcode.
    pub fn get(&self, opcode: u32) -> u64 {
        let idx = opcode as usize;
        if idx < OPCODE_SLOTS {
            self.counters[idx].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    /// Return a snapshot of all non-zero error counters as (opcode_name, count) pairs.
    pub fn snapshot(&self) -> Vec<(&'static str, u64)> {
        let mut result = Vec::new();
        for (i, ctr) in self.counters.iter().enumerate() {
            let count = ctr.load(Ordering::Relaxed);
            if count > 0 {
                result.push((opcode_name(i as u32), count));
            }
        }
        result
    }
}

/// Global per-opcode FUSE error counters.
pub static ERROR_COUNTERS: FuseErrorCounters = FuseErrorCounters::new();

/// Return a human-readable name for a FUSE opcode number.
///
/// Returns `"UNKNOWN(<opcode>)"` for unrecognized opcodes.
pub fn opcode_name(opcode: u32) -> &'static str {
    use std::convert::TryFrom;
    match fuse_opcode::try_from(opcode) {
        Ok(op) => fuse_opcode_to_name(op),
        Err(_) => "UNKNOWN",
    }
}

/// Compile-time exhaustiveness guard: every `fuse_opcode` variant must map
/// to a non-empty name string.  If a new variant is added to `fuse_opcode`
/// without a corresponding arm here, the match becomes non-exhaustive and
/// compilation fails — preventing silent "UNKNOWN" returns from `opcode_name`.
const fn fuse_opcode_to_name(op: fuse_opcode) -> &'static str {
    match op {
        fuse_opcode::FUSE_LOOKUP => "LOOKUP",
        fuse_opcode::FUSE_FORGET => "FORGET",
        fuse_opcode::FUSE_GETATTR => "GETATTR",
        fuse_opcode::FUSE_SETATTR => "SETATTR",
        fuse_opcode::FUSE_READLINK => "READLINK",
        fuse_opcode::FUSE_SYMLINK => "SYMLINK",
        fuse_opcode::FUSE_MKNOD => "MKNOD",
        fuse_opcode::FUSE_MKDIR => "MKDIR",
        fuse_opcode::FUSE_UNLINK => "UNLINK",
        fuse_opcode::FUSE_RMDIR => "RMDIR",
        fuse_opcode::FUSE_RENAME => "RENAME",
        fuse_opcode::FUSE_LINK => "LINK",
        fuse_opcode::FUSE_OPEN => "OPEN",
        fuse_opcode::FUSE_READ => "READ",
        fuse_opcode::FUSE_WRITE => "WRITE",
        fuse_opcode::FUSE_STATFS => "STATFS",
        fuse_opcode::FUSE_RELEASE => "RELEASE",
        fuse_opcode::FUSE_FSYNC => "FSYNC",
        fuse_opcode::FUSE_SETXATTR => "SETXATTR",
        fuse_opcode::FUSE_GETXATTR => "GETXATTR",
        fuse_opcode::FUSE_LISTXATTR => "LISTXATTR",
        fuse_opcode::FUSE_REMOVEXATTR => "REMOVEXATTR",
        fuse_opcode::FUSE_FLUSH => "FLUSH",
        fuse_opcode::FUSE_INIT => "INIT",
        fuse_opcode::FUSE_OPENDIR => "OPENDIR",
        fuse_opcode::FUSE_READDIR => "READDIR",
        fuse_opcode::FUSE_RELEASEDIR => "RELEASEDIR",
        fuse_opcode::FUSE_FSYNCDIR => "FSYNCDIR",
        fuse_opcode::FUSE_GETLK => "GETLK",
        fuse_opcode::FUSE_SETLK => "SETLK",
        fuse_opcode::FUSE_SETLKW => "SETLKW",
        fuse_opcode::FUSE_ACCESS => "ACCESS",
        fuse_opcode::FUSE_CREATE => "CREATE",
        fuse_opcode::FUSE_INTERRUPT => "INTERRUPT",
        fuse_opcode::FUSE_BMAP => "BMAP",
        fuse_opcode::FUSE_DESTROY => "DESTROY",
        #[cfg(feature = "abi-7-11")]
        fuse_opcode::FUSE_IOCTL => "IOCTL",
        #[cfg(feature = "abi-7-11")]
        fuse_opcode::FUSE_POLL => "POLL",
        #[cfg(feature = "abi-7-16")]
        fuse_opcode::FUSE_BATCH_FORGET => "BATCH_FORGET",
        #[cfg(feature = "abi-7-19")]
        fuse_opcode::FUSE_FALLOCATE => "FALLOCATE",
        #[cfg(feature = "abi-7-21")]
        fuse_opcode::FUSE_READDIRPLUS => "READDIRPLUS",
        #[cfg(feature = "abi-7-23")]
        fuse_opcode::FUSE_RENAME2 => "RENAME2",
        #[cfg(feature = "abi-7-24")]
        fuse_opcode::FUSE_LSEEK => "LSEEK",
        #[cfg(feature = "abi-7-28")]
        fuse_opcode::FUSE_COPY_FILE_RANGE => "COPY_FILE_RANGE",
        #[cfg(feature = "abi-7-30")]
        fuse_opcode::FUSE_STATX => "STATX",
        #[cfg(feature = "abi-7-31")]
        fuse_opcode::FUSE_SYNCFS => "SYNCFS",
        fuse_opcode::FUSE_EXCHANGE => "EXCHANGE",
        #[cfg(target_os = "macos")]
        fuse_opcode::FUSE_SETVOLNAME => "SETVOLNAME",
        #[cfg(target_os = "macos")]
        fuse_opcode::FUSE_GETXTIMES => "GETXTIMES",
    }
}

/// Force the compiler to verify that `fuse_opcode_to_name` is exhaustive.
/// If a new `fuse_opcode` variant is added without a corresponding arm,
/// this will fail to compile with a non-exhaustive match error.
#[allow(dead_code)]
const _FUSE_OPCODE_NAME_EXHAUSTIVE: () = {
    let _ = fuse_opcode_to_name(fuse_opcode::FUSE_LOOKUP);
};

/// Return a human-readable errno name for a libc error code.
///
/// Returns `"ERRNO(<code>")` for unrecognized errno values.
pub fn errno_name(err: libc::c_int) -> &'static str {
    match err {
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ESRCH => "ESRCH",
        libc::EINTR => "EINTR",
        libc::EIO => "EIO",
        libc::ENXIO => "ENXIO",
        libc::E2BIG => "E2BIG",
        libc::ENOEXEC => "ENOEXEC",
        libc::EBADF => "EBADF",
        libc::ECHILD => "ECHILD",
        libc::EAGAIN => "EAGAIN",
        libc::ENOMEM => "ENOMEM",
        libc::EACCES => "EACCES",
        libc::EFAULT => "EFAULT",
        libc::ENOTBLK => "ENOTBLK",
        libc::EBUSY => "EBUSY",
        libc::EEXIST => "EEXIST",
        libc::EXDEV => "EXDEV",
        libc::ENODEV => "ENODEV",
        libc::ENOTDIR => "ENOTDIR",
        libc::EISDIR => "EISDIR",
        libc::EINVAL => "EINVAL",
        libc::ENFILE => "ENFILE",
        libc::EMFILE => "EMFILE",
        libc::ENOTTY => "ENOTTY",
        libc::ETXTBSY => "ETXTBSY",
        libc::EFBIG => "EFBIG",
        libc::ENOSPC => "ENOSPC",
        libc::ESPIPE => "ESPIPE",
        libc::EROFS => "EROFS",
        libc::EMLINK => "EMLINK",
        libc::EPIPE => "EPIPE",
        libc::EDOM => "EDOM",
        libc::ERANGE => "ERANGE",
        libc::EDEADLK => "EDEADLK",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ENOLCK => "ENOLCK",
        libc::ENOSYS => "ENOSYS",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::ELOOP => "ELOOP",
        libc::ENOMSG => "ENOMSG",
        libc::EIDRM => "EIDRM",
        libc::ENOSTR => "ENOSTR",
        libc::ENODATA => "ENODATA",
        libc::ETIME => "ETIME",
        libc::ENOSR => "ENOSR",
        libc::EREMOTE => "EREMOTE",
        libc::ENOLINK => "ENOLINK",
        libc::EPROTO => "EPROTO",
        libc::EMULTIHOP => "EMULTIHOP",
        libc::EBADMSG => "EBADMSG",
        libc::EOVERFLOW => "EOVERFLOW",
        libc::EILSEQ => "EILSEQ",
        libc::ENOTSOCK => "ENOTSOCK",
        libc::EDESTADDRREQ => "EDESTADDRREQ",
        libc::EMSGSIZE => "EMSGSIZE",
        libc::EPROTOTYPE => "EPROTOTYPE",
        libc::ENOPROTOOPT => "ENOPROTOOPT",
        libc::EPROTONOSUPPORT => "EPROTONOSUPPORT",
        libc::ESOCKTNOSUPPORT => "ESOCKTNOSUPPORT",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EPFNOSUPPORT => "EPFNOSUPPORT",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        libc::EADDRINUSE => "EADDRINUSE",
        libc::EADDRNOTAVAIL => "EADDRNOTAVAIL",
        libc::ENETDOWN => "ENETDOWN",
        libc::ENETUNREACH => "ENETUNREACH",
        libc::ENETRESET => "ENETRESET",
        libc::ECONNABORTED => "ECONNABORTED",
        libc::ECONNRESET => "ECONNRESET",
        libc::ENOBUFS => "ENOBUFS",
        libc::EISCONN => "EISCONN",
        libc::ENOTCONN => "ENOTCONN",
        libc::ESHUTDOWN => "ESHUTDOWN",
        libc::ETOOMANYREFS => "ETOOMANYREFS",
        libc::ETIMEDOUT => "ETIMEDOUT",
        libc::ECONNREFUSED => "ECONNREFUSED",
        libc::EHOSTDOWN => "EHOSTDOWN",
        libc::EHOSTUNREACH => "EHOSTUNREACH",
        libc::EALREADY => "EALREADY",
        libc::EINPROGRESS => "EINPROGRESS",
        libc::ESTALE => "ESTALE",
        libc::EDQUOT => "EDQUOT",
        libc::ECANCELED => "ECANCELED",
        libc::EOWNERDEAD => "EOWNERDEAD",
        libc::ENOTRECOVERABLE => "ENOTRECOVERABLE",
        _ => "ERRNO",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_name_known() {
        assert_eq!(opcode_name(1_u32), "LOOKUP");
        assert_eq!(opcode_name(3_u32), "GETATTR");
        assert_eq!(opcode_name(15_u32), "READ");
        assert_eq!(opcode_name(16_u32), "WRITE");
        assert_eq!(opcode_name(9_u32), "MKDIR");
        assert_eq!(opcode_name(12_u32), "RENAME");
        assert_eq!(opcode_name(10_u32), "UNLINK");
        assert_eq!(opcode_name(11_u32), "RMDIR");
        #[cfg(feature = "abi-7-31")]
        assert_eq!(opcode_name(50_u32), "SYNCFS");
    }

    #[test]
    fn test_opcode_name_unknown() {
        assert_eq!(opcode_name(0), "UNKNOWN");
        assert_eq!(opcode_name(255), "UNKNOWN");
    }

    #[test]
    fn test_errno_name_known() {
        assert_eq!(errno_name(libc::ENOENT), "ENOENT");
        assert_eq!(errno_name(libc::EACCES), "EACCES");
        assert_eq!(errno_name(libc::ENOTEMPTY), "ENOTEMPTY");
        assert_eq!(errno_name(libc::ENOSYS), "ENOSYS");
        assert_eq!(errno_name(libc::EIO), "EIO");
        assert_eq!(errno_name(libc::EPERM), "EPERM");
    }

    #[test]
    fn test_errno_name_zero() {
        // 0 is success, not an errno - we still return a label
        assert_eq!(errno_name(0), "ERRNO");
    }

    #[test]
    fn test_error_counters_increment_and_get() {
        let counters = FuseErrorCounters::new();
        assert_eq!(counters.get(1_u32), 0);
        counters.increment(1_u32);
        counters.increment(1_u32);
        assert_eq!(counters.get(1_u32), 2);
        assert_eq!(counters.get(15_u32), 0);
    }

    #[test]
    fn test_error_counters_out_of_range() {
        let counters = FuseErrorCounters::new();
        // Out-of-range should not panic
        counters.increment(64);
        counters.increment(255);
        assert_eq!(counters.get(64), 0);
        assert_eq!(counters.get(255), 0);
    }

    #[test]
    fn test_error_counters_snapshot() {
        let counters = FuseErrorCounters::new();
        counters.increment(1_u32);
        counters.increment(1_u32);
        counters.increment(15_u32);
        let snap = counters.snapshot();
        assert!(snap.contains(&("LOOKUP", 2)));
        assert!(snap.contains(&("READ", 1)));
        // Only non-zero counters appear
        assert!(!snap.iter().any(|(_, c)| *c == 0));
    }
}

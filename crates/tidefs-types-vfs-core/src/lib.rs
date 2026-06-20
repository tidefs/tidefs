// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Portable `no_std` VFS boundary core types.
//!
//! surface into Rust. It intentionally holds only scalar/newtype/fixed-size
//! records so the `environment_boundary` split between `core` and `alloc` stays explicit.
extern crate alloc;

pub mod contract;

pub use contract::*;

use core::convert::TryFrom;
use core::fmt;

/// Nanoseconds per POSIX second.
///
/// This constant belongs to POSIX wall-clock timestamp projection only. It is
/// not a storage generation, transaction group, scrub identity, or format
/// version conversion factor.
pub const POSIX_NANOS_PER_SECOND: i64 = 1_000_000_000;

/// Split POSIX nanoseconds since the UNIX epoch into `(seconds, nanoseconds)`.
///
/// Negative subsecond values are normalized to the POSIX timespec shape where
/// the nanosecond component is always in `0..1_000_000_000`.
#[must_use]
pub const fn split_posix_time_ns(ns: i64) -> (i64, u32) {
    let mut sec = ns / POSIX_NANOS_PER_SECOND;
    let mut nsec = ns % POSIX_NANOS_PER_SECOND;
    if nsec < 0 {
        sec -= 1;
        nsec += POSIX_NANOS_PER_SECOND;
    }
    (sec, nsec as u32)
}

/// Compose POSIX `(seconds, nanoseconds)` into nanoseconds since the UNIX epoch.
///
/// Nanoseconds outside the POSIX timespec range are clamped to
/// `999_999_999`. Arithmetic saturates at the `i64` boundary.
#[must_use]
pub const fn compose_posix_time_ns(sec: i64, nsec: u32) -> i64 {
    let clamped_nsec = if nsec >= POSIX_NANOS_PER_SECOND as u32 {
        POSIX_NANOS_PER_SECOND - 1
    } else {
        nsec as i64
    };
    sec.saturating_mul(POSIX_NANOS_PER_SECOND)
        .saturating_add(clamped_nsec)
}

/// POSIX wall-clock timestamp in nanoseconds since the UNIX epoch.
///
/// This is the named boundary for values projected into POSIX inode timestamp
/// fields such as `atime_ns`, `mtime_ns`, `ctime_ns`, and `btime_ns`. It must
/// not be used as, or derived into, [`Generation`], transaction groups,
/// content object versions, scrub identities, or format-version numbers.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PosixTimestampNs(pub i64);

impl PosixTimestampNs {
    /// POSIX timestamp at the UNIX epoch.
    pub const UNIX_EPOCH: Self = Self(0);
    /// Lowest representable POSIX timestamp boundary.
    pub const MIN: Self = Self(i64::MIN);
    /// Highest representable POSIX timestamp boundary.
    pub const MAX: Self = Self(i64::MAX);

    /// Construct from nanoseconds since the UNIX epoch.
    #[must_use]
    pub const fn from_unix_nanos(value: i64) -> Self {
        Self(value)
    }

    /// Return nanoseconds since the UNIX epoch.
    #[must_use]
    pub const fn as_unix_nanos(self) -> i64 {
        self.0
    }

    /// Split into POSIX `(seconds, nanoseconds)`.
    #[must_use]
    pub const fn split(self) -> (i64, u32) {
        split_posix_time_ns(self.0)
    }

    /// Compose from POSIX `(seconds, nanoseconds)`.
    #[must_use]
    pub const fn from_split(sec: i64, nsec: u32) -> Self {
        Self(compose_posix_time_ns(sec, nsec))
    }
}

impl From<i64> for PosixTimestampNs {
    fn from(value: i64) -> Self {
        Self::from_unix_nanos(value)
    }
}

impl From<PosixTimestampNs> for i64 {
    fn from(value: PosixTimestampNs) -> Self {
        value.as_unix_nanos()
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct InodeId(pub u64);

impl InodeId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Generation(pub u64);

impl Generation {
    /// Zero VFS inode generation.
    pub const ZERO: Self = Self(0);
    /// Highest representable VFS inode generation.
    pub const MAX: Self = Self(u64::MAX);

    /// Construct a VFS inode generation from its raw boundary value.
    ///
    /// A `Generation` is a VFS/file-handle identity token, not POSIX wall-clock
    /// time and not a storage transaction/object/scrub/format authority.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Construct a VFS inode generation from its raw boundary value.
    ///
    /// This synonym exists to make authority conversions explicit at call
    /// sites that would otherwise pass an unlabelled `u64`.
    #[must_use]
    pub const fn from_vfs_generation(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw VFS inode generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Return the raw VFS inode generation value.
    ///
    /// This synonym exists to pair with [`Self::from_vfs_generation`] at
    /// authority boundaries.
    #[must_use]
    pub const fn as_vfs_generation(self) -> u64 {
        self.0
    }

    /// Return the next VFS inode generation, or `None` at the boundary.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        if self.0 == u64::MAX {
            None
        } else {
            Some(Self(self.0 + 1))
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FileHandleId(pub u64);

impl FileHandleId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DirHandleId(pub u64);

impl DirHandleId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

// ── Errno ─────────────────────────────────────────────────────────────────

/// Linux errno value.
///
/// Positive `u16` wrapper per the VFS Engine API contract.
/// Zero means success; all other values are Linux-native positive errno codes
/// (EPERM = 1, ENOENT = 2, …).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Errno(pub u16);

impl Errno {
    /// The success sentinel: `Errno(0)`.
    pub const SUCCESS: Self = Self(0);

    /// Construct from a raw Linux errno value.
    #[must_use]
    pub const fn from_raw(value: u16) -> Self {
        Self(value)
    }

    /// Return the raw Linux errno value.
    #[must_use]
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// True when the value equals SUCCESS (zero).
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 == 0
    }

    /// True when the value is non-zero.
    #[must_use]
    pub const fn is_error(self) -> bool {
        self.0 != 0
    }

    /// Human-readable name (e.g. "ENOENT"), or "UNKNOWN_ERRNO".
    #[must_use]
    pub fn name(self) -> &'static str {
        ERRNO_NAMES
            .get(self.0 as usize)
            .filter(|s| !s.is_empty())
            .copied()
            .unwrap_or("UNKNOWN_ERRNO")
    }

    /// strerror(3)-style message, or "Unknown error".
    #[must_use]
    pub fn message(self) -> &'static str {
        ERRNO_MESSAGES
            .get(self.0 as usize)
            .filter(|s| !s.is_empty())
            .copied()
            .unwrap_or("Unknown error")
    }

    // ── Common Linux errno constants ─────────────────────────────────
    pub const EPERM: Self = Self(1);
    pub const ENOENT: Self = Self(2);
    pub const ESRCH: Self = Self(3);
    pub const EINTR: Self = Self(4);
    pub const EIO: Self = Self(5);
    pub const ENXIO: Self = Self(6);
    pub const E2BIG: Self = Self(7);
    pub const ENOEXEC: Self = Self(8);
    pub const EBADF: Self = Self(9);
    pub const ECHILD: Self = Self(10);
    pub const EAGAIN: Self = Self(11);
    pub const ENOMEM: Self = Self(12);
    pub const EACCES: Self = Self(13);
    pub const EFAULT: Self = Self(14);
    pub const ENOTBLK: Self = Self(15);
    pub const EBUSY: Self = Self(16);
    pub const EEXIST: Self = Self(17);
    pub const EXDEV: Self = Self(18);
    pub const ENODEV: Self = Self(19);
    pub const ENOTDIR: Self = Self(20);
    pub const EISDIR: Self = Self(21);
    pub const EINVAL: Self = Self(22);
    pub const ENFILE: Self = Self(23);
    pub const EMFILE: Self = Self(24);
    pub const ENOTTY: Self = Self(25);
    pub const ETXTBSY: Self = Self(26);
    pub const EFBIG: Self = Self(27);
    pub const ENOSPC: Self = Self(28);
    pub const ESPIPE: Self = Self(29);
    pub const EROFS: Self = Self(30);
    pub const EMLINK: Self = Self(31);
    pub const EPIPE: Self = Self(32);
    pub const EDOM: Self = Self(33);
    pub const ERANGE: Self = Self(34);
    pub const EDEADLK: Self = Self(35);
    pub const ENAMETOOLONG: Self = Self(36);
    pub const ENOLCK: Self = Self(37);
    pub const ENOSYS: Self = Self(38);
    pub const ENOTEMPTY: Self = Self(39);
    pub const ELOOP: Self = Self(40);
    pub const ENOMSG: Self = Self(42);
    pub const EIDRM: Self = Self(43);
    pub const ENOSTR: Self = Self(60);
    pub const ENODATA: Self = Self(61);
    pub const ETIME: Self = Self(62);
    pub const ENOSR: Self = Self(63);
    pub const ENOLINK: Self = Self(67);
    pub const EPROTO: Self = Self(71);
    pub const EMULTIHOP: Self = Self(72);
    pub const EBADMSG: Self = Self(74);
    pub const EOVERFLOW: Self = Self(75);
    pub const EILSEQ: Self = Self(84);
    pub const ENOTSOCK: Self = Self(88);
    pub const EDESTADDRREQ: Self = Self(89);
    pub const EMSGSIZE: Self = Self(90);
    pub const EPROTOTYPE: Self = Self(91);
    pub const ENOPROTOOPT: Self = Self(92);
    pub const EPROTONOSUPPORT: Self = Self(93);
    pub const ESOCKTNOSUPPORT: Self = Self(94);
    pub const EOPNOTSUPP: Self = Self(95);
    pub const EPFNOSUPPORT: Self = Self(96);
    pub const EAFNOSUPPORT: Self = Self(97);
    pub const EADDRINUSE: Self = Self(98);
    pub const EADDRNOTAVAIL: Self = Self(99);
    pub const ENETDOWN: Self = Self(100);
    pub const ENETUNREACH: Self = Self(101);
    pub const ENETRESET: Self = Self(102);
    pub const ECONNABORTED: Self = Self(103);
    pub const ECONNRESET: Self = Self(104);
    pub const ENOBUFS: Self = Self(105);
    pub const EISCONN: Self = Self(106);
    pub const ENOTCONN: Self = Self(107);
    pub const ESHUTDOWN: Self = Self(108);
    pub const ETOOMANYREFS: Self = Self(109);
    pub const ETIMEDOUT: Self = Self(110);
    pub const ECONNREFUSED: Self = Self(111);
    pub const EHOSTDOWN: Self = Self(112);
    pub const EHOSTUNREACH: Self = Self(113);
    pub const EALREADY: Self = Self(114);
    pub const EINPROGRESS: Self = Self(115);
    pub const ESTALE: Self = Self(116);
    pub const EUCLEAN: Self = Self(117);
    pub const EDQUOT: Self = Self(122);
    pub const ECANCELED: Self = Self(125);
    pub const EOWNERDEAD: Self = Self(130);
    pub const ENOTRECOVERABLE: Self = Self(131);
    pub const ERESTARTSYS: Self = Self(512);
    pub const ERESTARTNOINTR: Self = Self(513);
    pub const ERESTARTNOHAND: Self = Self(514);
    pub const ENOIOCTLCMD: Self = Self(515);
    pub const ERESTART_RESTARTBLOCK: Self = Self(516);
    pub const EPROBE_DEFER: Self = Self(517);
}

impl Default for Errno {
    fn default() -> Self {
        Self::SUCCESS
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl From<Errno> for u16 {
    fn from(e: Errno) -> u16 {
        e.0
    }
}

impl From<u16> for Errno {
    fn from(v: u16) -> Self {
        Self(v)
    }
}

// ── Errno lookup tables ─────────────────────────────────────────────────

static ERRNO_NAMES: [&str; 520] = {
    let mut t = [""; 520];
    t[0] = "SUCCESS";
    t[1] = "EPERM";
    t[2] = "ENOENT";
    t[3] = "ESRCH";
    t[4] = "EINTR";
    t[5] = "EIO";
    t[6] = "ENXIO";
    t[7] = "E2BIG";
    t[8] = "ENOEXEC";
    t[9] = "EBADF";
    t[10] = "ECHILD";
    t[11] = "EAGAIN";
    t[12] = "ENOMEM";
    t[13] = "EACCES";
    t[14] = "EFAULT";
    t[15] = "ENOTBLK";
    t[16] = "EBUSY";
    t[17] = "EEXIST";
    t[18] = "EXDEV";
    t[19] = "ENODEV";
    t[20] = "ENOTDIR";
    t[21] = "EISDIR";
    t[22] = "EINVAL";
    t[23] = "ENFILE";
    t[24] = "EMFILE";
    t[25] = "ENOTTY";
    t[26] = "ETXTBSY";
    t[27] = "EFBIG";
    t[28] = "ENOSPC";
    t[29] = "ESPIPE";
    t[30] = "EROFS";
    t[31] = "EMLINK";
    t[32] = "EPIPE";
    t[33] = "EDOM";
    t[34] = "ERANGE";
    t[35] = "EDEADLK";
    t[36] = "ENAMETOOLONG";
    t[37] = "ENOLCK";
    t[38] = "ENOSYS";
    t[39] = "ENOTEMPTY";
    t[40] = "ELOOP";
    t[42] = "ENOMSG";
    t[43] = "EIDRM";
    t[60] = "ENOSTR";
    t[61] = "ENODATA";
    t[62] = "ETIME";
    t[63] = "ENOSR";
    t[67] = "ENOLINK";
    t[71] = "EPROTO";
    t[72] = "EMULTIHOP";
    t[74] = "EBADMSG";
    t[75] = "EOVERFLOW";
    t[84] = "EILSEQ";
    t[88] = "ENOTSOCK";
    t[89] = "EDESTADDRREQ";
    t[90] = "EMSGSIZE";
    t[91] = "EPROTOTYPE";
    t[92] = "ENOPROTOOPT";
    t[93] = "EPROTONOSUPPORT";
    t[94] = "ESOCKTNOSUPPORT";
    t[95] = "EOPNOTSUPP";
    t[96] = "EPFNOSUPPORT";
    t[97] = "EAFNOSUPPORT";
    t[98] = "EADDRINUSE";
    t[99] = "EADDRNOTAVAIL";
    t[100] = "ENETDOWN";
    t[101] = "ENETUNREACH";
    t[102] = "ENETRESET";
    t[103] = "ECONNABORTED";
    t[104] = "ECONNRESET";
    t[105] = "ENOBUFS";
    t[106] = "EISCONN";
    t[107] = "ENOTCONN";
    t[108] = "ESHUTDOWN";
    t[109] = "ETOOMANYREFS";
    t[110] = "ETIMEDOUT";
    t[111] = "ECONNREFUSED";
    t[112] = "EHOSTDOWN";
    t[113] = "EHOSTUNREACH";
    t[114] = "EALREADY";
    t[115] = "EINPROGRESS";
    t[116] = "ESTALE";
    t[117] = "EUCLEAN";
    t[122] = "EDQUOT";
    t[125] = "ECANCELED";
    t[130] = "EOWNERDEAD";
    t[131] = "ENOTRECOVERABLE";
    t[512] = "ERESTARTSYS";
    t[513] = "ERESTARTNOINTR";
    t[514] = "ERESTARTNOHAND";
    t[515] = "ENOIOCTLCMD";
    t[516] = "ERESTART_RESTARTBLOCK";
    t[517] = "EPROBE_DEFER";
    t
};

static ERRNO_MESSAGES: [&str; 520] = {
    let mut t = [""; 520];
    t[0] = "Success";
    t[1] = "Operation not permitted";
    t[2] = "No such file or directory";
    t[3] = "No such process";
    t[4] = "Interrupted system call";
    t[5] = "Input/output error";
    t[6] = "No such device or address";
    t[7] = "Argument list too long";
    t[8] = "Exec format error";
    t[9] = "Bad file descriptor";
    t[10] = "No child processes";
    t[11] = "Resource temporarily unavailable";
    t[12] = "Cannot allocate memory";
    t[13] = "Permission denied";
    t[14] = "Bad address";
    t[15] = "Block device required";
    t[16] = "Device or resource busy";
    t[17] = "File exists";
    t[18] = "Invalid cross-device link";
    t[19] = "No such device";
    t[20] = "Not a directory";
    t[21] = "Is a directory";
    t[22] = "Invalid argument";
    t[23] = "Too many open files in system";
    t[24] = "Too many open files";
    t[25] = "Inappropriate ioctl for device";
    t[26] = "Text file busy";
    t[27] = "File too large";
    t[28] = "No space left on device";
    t[29] = "Illegal seek";
    t[30] = "Read-only file system";
    t[31] = "Too many links";
    t[32] = "Broken pipe";
    t[33] = "Numerical argument out of domain";
    t[34] = "Numerical result out of range";
    t[35] = "Resource deadlock avoided";
    t[36] = "File name too long";
    t[37] = "No locks available";
    t[38] = "Function not implemented";
    t[39] = "Directory not empty";
    t[40] = "Too many levels of symbolic links";
    t[42] = "No message of desired type";
    t[43] = "Identifier removed";
    t[60] = "Device not a stream";
    t[61] = "No data available";
    t[62] = "Timer expired";
    t[63] = "Out of streams resources";
    t[67] = "Link has been severed";
    t[71] = "Protocol error";
    t[72] = "Multihop attempted";
    t[74] = "Bad message";
    t[75] = "Value too large for defined data type";
    t[84] = "Invalid or incomplete multibyte or wide character";
    t[88] = "Socket operation on non-socket";
    t[89] = "Destination address required";
    t[90] = "Message too long";
    t[91] = "Protocol wrong type for socket";
    t[92] = "Protocol not available";
    t[93] = "Protocol not supported";
    t[94] = "Socket type not supported";
    t[95] = "Operation not supported";
    t[96] = "Protocol family not supported";
    t[97] = "Address family not supported by protocol";
    t[98] = "Address already in use";
    t[99] = "Cannot assign requested address";
    t[100] = "Network is down";
    t[101] = "Network is unreachable";
    t[102] = "Network dropped connection on reset";
    t[103] = "Software caused connection abort";
    t[104] = "Connection reset by peer";
    t[105] = "No buffer space available";
    t[106] = "Transport endpoint is already connected";
    t[107] = "Transport endpoint is not connected";
    t[108] = "Cannot send after transport endpoint shutdown";
    t[109] = "Too many references: cannot splice";
    t[110] = "Connection timed out";
    t[111] = "Connection refused";
    t[112] = "Host is down";
    t[113] = "No route to host";
    t[114] = "Operation already in progress";
    t[115] = "Operation now in progress";
    t[116] = "Stale file handle";
    t[117] = "Structure needs cleaning";
    t[122] = "Disk quota exceeded";
    t[125] = "Operation canceled";
    t[130] = "Owner died";
    t[131] = "State not recoverable";
    t[512] = "Interrupted system call should be restarted";
    t[513] = "Interrupted system call should not be restarted";
    t[514] = "Interrupted system call should restart, no handler";
    t[515] = "No IOCTL command";
    t[516] = "Interrupted system call should restart using restart_block";
    t[517] = "Probe deferral";
    t
};

// ── RequestCtx ─────────────────────────────────────────────────────────────

/// Per-request caller context (uid, gid, pid, umask, supplemental groups).
///
/// Mirrors the Linux `struct fuse_ctx` call-chain fields required by the
/// VFS Engine API contract (#1213).  The `groups` vector is gated behind the
/// `alloc` feature because this crate is `no_std` by default.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RequestCtx {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub umask: u32,
    /// Supplemental group IDs; never empty when allocated (contains at least egid).
    pub groups: alloc::vec::Vec<u32>,
}

#[cfg(feature = "alloc")]
impl RequestCtx {
    #[must_use]
    pub fn new(uid: u32, gid: u32, pid: u32, umask: u32, groups: alloc::vec::Vec<u32>) -> Self {
        Self {
            uid,
            gid,
            pid,
            umask,
            groups,
        }
    }
    #[must_use]
    pub fn new_root() -> Self {
        Self {
            uid: 0,
            gid: 0,
            pid: 0,
            umask: 0,
            groups: alloc::vec![0],
        }
    }
}

/// Minimal `no_std` stub when `alloc` is disabled.
#[cfg(not(feature = "alloc"))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestCtx {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub umask: u32,
}

#[cfg(not(feature = "alloc"))]
impl RequestCtx {
    #[must_use]
    pub const fn new(uid: u32, gid: u32, pid: u32, umask: u32) -> Self {
        Self {
            uid,
            gid,
            pid,
            umask,
        }
    }
    #[must_use]
    pub const fn new_root() -> Self {
        Self {
            uid: 0,
            gid: 0,
            pid: 0,
            umask: 0,
        }
    }
}

pub type OpenFlags = u32;
pub type CreateFlags = u32;
pub type RenameFlags = u32;
pub type LseekOffset = i64;

pub const ROOT_INODE_ID: InodeId = InodeId(1);

pub const RENAME_NOREPLACE: u32 = 1;
pub const RENAME_EXCHANGE: u32 = 2;
pub const RENAME_WHITEOUT: u32 = 4;

pub const XATTR_CREATE: u32 = 1;
pub const XATTR_REPLACE: u32 = 2;

/// fallocate(2) mode flags.
pub const FALLOC_FL_KEEP_SIZE: u32 = 1;
pub const FALLOC_FL_PUNCH_HOLE: u32 = 2;
pub const FALLOC_FL_ZERO_RANGE: u32 = 16;
pub const FALLOC_FL_COLLAPSE_RANGE: u32 = 8;
/// Unsupported: insert range (FALLOC_FL_INSERT_RANGE).
pub const FALLOC_FL_INSERT_RANGE: u32 = 32;
pub const FALLOC_FL_UNSHARE_RANGE: u32 = 64;

/// POSIX projection shape over [].
///
/// Design rule Rule 4: , , , and the remaining POSIX
/// inode-type variants are projection shapes — not final ontology.
/// The authoritative graph works in typed facets;  is a
/// convenience label derived from facets.
/// POSIX projection shape over [`NodeFacets`].
///
/// Design rule Rule 4: `File`, `Dir`, `Symlink`, and the remaining POSIX
/// inode-type variants are projection shapes — not final ontology.
/// The authoritative graph works in typed facets; `NodeKind` is a
/// convenience label derived from facets.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum NodeKind {
    Dir = 1,
    File = 2,
    Symlink = 3,
    CharDev = 4,
    BlockDev = 5,
    Fifo = 6,
    Socket = 7,
    Whiteout = 8,
}

impl NodeKind {
    /// Return the  on-disk tag for this projection shape.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Project authoritative [`NodeFacets`] into a POSIX shape.
    ///
    /// Facets are truth; [`NodeKind`] is a derived label for POSIX consumers.
    ///
    /// File and Symlink share the same facet set (`has_byte_space: true`,
    /// `has_child_namespace: false`); metadata-only special nodes share the
    /// no-byte/no-child facet set with whiteout. Callers must consult mode
    /// bits (`S_IFMT`) to recover the original POSIX type.
    #[must_use]
    pub const fn from_facets(f: NodeFacets) -> Self {
        if f.has_child_namespace {
            Self::Dir
        } else {
            Self::File
        }
    }

    /// Decompose this projection shape into authoritative [`NodeFacets`].
    ///
    /// Several POSIX projection types share the same facet output. Use mode
    /// bits or higher-layer helpers that check mode bits to recover the
    /// original shape at the projection boundary.
    #[must_use]
    pub const fn to_facets(self) -> NodeFacets {
        match self {
            Self::Dir => NodeFacets {
                has_byte_space: false,
                has_child_namespace: true,
            },
            Self::File => NodeFacets {
                has_byte_space: true,
                has_child_namespace: false,
            },
            Self::Symlink => NodeFacets {
                has_byte_space: true,
                has_child_namespace: false,
            },
            Self::CharDev | Self::BlockDev | Self::Fifo | Self::Socket => NodeFacets {
                has_byte_space: false,
                has_child_namespace: false,
            },
            Self::Whiteout => NodeFacets {
                has_byte_space: false,
                has_child_namespace: false,
            },
        }
    }

    /// Whether this projection shape admits child namespace bindings.
    ///
    /// Prefer [] when facets are available.
    #[must_use]
    pub const fn has_child_namespace(self) -> bool {
        matches!(self, Self::Dir)
    }
}

impl Default for NodeKind {
    fn default() -> Self {
        Self::File
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeKindDecodeError(pub u32);

impl TryFrom<u32> for NodeKind {
    type Error = NodeKindDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Dir),
            2 => Ok(Self::File),
            3 => Ok(Self::Symlink),
            4 => Ok(Self::CharDev),
            5 => Ok(Self::BlockDev),
            6 => Ok(Self::Fifo),
            7 => Ok(Self::Socket),
            8 => Ok(Self::Whiteout),
            _ => Err(NodeKindDecodeError(value)),
        }
    }
}

// ── Authoritative facet layer ───────────────────────────────────────────
// Design rule Rule 4: facets are ontological truth; NodeKind is a projection
// over them.  For the current local-filesystem scope two discriminators
// derive every supported POSIX shape:
//   - has_byte_space      — inode carries mutable content bytes
//   - has_child_namespace — inode harbours child directory entries
//
// Additional facets (metadata, policy, lineage, placement, witness state)
// are conceptually defined and will be wired when their runtime subsystems
// land.

/// Authoritative typed facets for an inode.
///
/// The graph stores facets as truth; [`NodeKind`] is a derived convenience
/// label.  Consumers that inspect an inode's capabilities should prefer
/// facet predicates over matching on `NodeKind` variants.
///
/// Currently two discriminators derive every supported POSIX shape:
/// - `has_byte_space` — inode carries mutable content bytes
/// - `has_child_namespace` — inode harbours child directory entries
///
/// Additional facets (metadata, policy, lineage, placement, witness state)
/// are conceptually defined and will be wired when their runtime subsystems
/// land.  This struct is the authoritative source of type identity for the
/// local-filesystem storage path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct NodeFacets {
    /// The inode carries mutable content bytes (regular file data or
    /// symlink target).
    pub has_byte_space: bool,
    /// The inode harbours child namespace bindings (directory entries).
    pub has_child_namespace: bool,
}

impl NodeFacets {
    /// Derive the POSIX projection shape.
    ///
    /// File and Symlink share the same facet set; distinguish them via
    /// mode bits or symlink-target attribute.
    #[must_use]
    pub const fn projection_kind(self) -> NodeKind {
        NodeKind::from_facets(self)
    }

    /// True when the inode carries content bytes.
    #[must_use]
    pub const fn carries_byte_space(self) -> bool {
        self.has_byte_space
    }

    /// True when the inode harbours child namespace bindings.
    #[must_use]
    pub const fn carries_child_namespace(self) -> bool {
        self.has_child_namespace
    }
}

impl From<NodeKind> for NodeFacets {
    fn from(k: NodeKind) -> Self {
        k.to_facets()
    }
}

pub const S_IFMT: u32 = 0o170_000;
pub const S_IFSOCK: u32 = 0o140_000;
pub const S_IFLNK: u32 = 0o120_000;
pub const S_IFREG: u32 = 0o100_000;
pub const S_IFBLK: u32 = 0o060_000;
pub const S_IFDIR: u32 = 0o040_000;
pub const S_IFCHR: u32 = 0o020_000;
pub const S_IFIFO: u32 = 0o010_000;

pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;
pub const S_ISVTX: u32 = 0o1000;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EngineFileHandle {
    pub inode_id: InodeId,
    pub open_flags: OpenFlags,
    pub fh_id: FileHandleId,
    pub lock_owner: u64,
}

impl EngineFileHandle {
    #[must_use]
    pub const fn new(
        inode_id: InodeId,
        open_flags: OpenFlags,
        fh_id: FileHandleId,
        lock_owner: u64,
    ) -> Self {
        Self {
            inode_id,
            open_flags,
            fh_id,
            lock_owner,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EngineDirHandle {
    pub inode_id: InodeId,
    pub dh_id: DirHandleId,
}

impl EngineDirHandle {
    #[must_use]
    pub const fn new(inode_id: InodeId, dh_id: DirHandleId) -> Self {
        Self { inode_id, dh_id }
    }
}

pub const FATTR_MODE: u32 = 1 << 0;
pub const FATTR_UID: u32 = 1 << 1;
pub const FATTR_GID: u32 = 1 << 2;
pub const FATTR_SIZE: u32 = 1 << 3;
pub const FATTR_ATIME: u32 = 1 << 4;
pub const FATTR_MTIME: u32 = 1 << 5;
pub const FATTR_FH: u32 = 1 << 6;
pub const FATTR_ATIME_NOW: u32 = 1 << 7;
pub const FATTR_MTIME_NOW: u32 = 1 << 8;
pub const FATTR_LOCKOWNER: u32 = 1 << 9;
pub const FATTR_CTIME: u32 = 1 << 10;

/// Bitwise OR of all known FATTR bits. Bits outside this mask are reserved
/// and must be rejected at the boundary.
pub const FATTR_VALID_MASK: u32 = FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE | FATTR_ATIME | FATTR_MTIME | FATTR_FH | FATTR_ATIME_NOW | FATTR_MTIME_NOW | FATTR_LOCKOWNER | FATTR_CTIME;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SetAttr {
    pub valid: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// POSIX atime projection in nanoseconds since the UNIX epoch.
    ///
    /// Prefer [`SetAttr::set_atime_timestamp`] and
    /// [`SetAttr::atime_timestamp`] at authority boundaries.
    pub atime_ns: i64,
    /// POSIX mtime projection in nanoseconds since the UNIX epoch.
    ///
    /// Prefer [`SetAttr::set_mtime_timestamp`] and
    /// [`SetAttr::mtime_timestamp`] at authority boundaries.
    pub mtime_ns: i64,
    /// POSIX ctime projection in nanoseconds since the UNIX epoch.
    ///
    /// Prefer [`SetAttr::set_ctime_timestamp`] and
    /// [`SetAttr::ctime_timestamp`] at authority boundaries.
    pub ctime_ns: i64,
}

impl SetAttr {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            valid: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            atime_ns: 0,
            mtime_ns: 0,
            ctime_ns: 0,
        }
    }
    #[must_use]
    pub const fn is_valid(&self, bit: u32) -> bool {
        self.valid & bit != 0
    }

    /// Return the atime POSIX timestamp value carried by this request.
    #[must_use]
    pub const fn atime_timestamp(&self) -> PosixTimestampNs {
        PosixTimestampNs::from_unix_nanos(self.atime_ns)
    }

    /// Return the mtime POSIX timestamp value carried by this request.
    #[must_use]
    pub const fn mtime_timestamp(&self) -> PosixTimestampNs {
        PosixTimestampNs::from_unix_nanos(self.mtime_ns)
    }

    /// Return the ctime POSIX timestamp value carried by this request.
    #[must_use]
    pub const fn ctime_timestamp(&self) -> PosixTimestampNs {
        PosixTimestampNs::from_unix_nanos(self.ctime_ns)
    }

    /// Mark this request as an explicit POSIX atime update.
    pub fn set_atime_timestamp(&mut self, timestamp: PosixTimestampNs) {
        self.valid |= FATTR_ATIME;
        self.atime_ns = timestamp.as_unix_nanos();
    }

    /// Mark this request as an explicit POSIX mtime update.
    pub fn set_mtime_timestamp(&mut self, timestamp: PosixTimestampNs) {
        self.valid |= FATTR_MTIME;
        self.mtime_ns = timestamp.as_unix_nanos();
    }

    /// Mark this request as an explicit POSIX ctime update.
    pub fn set_ctime_timestamp(&mut self, timestamp: PosixTimestampNs) {
        self.valid |= FATTR_CTIME;
        self.ctime_ns = timestamp.as_unix_nanos();
    }

    /// Reject `valid` bits outside the known FATTR set.
    ///
    /// Unknown bits in `valid` indicate either a bug or a future-format
    /// record that this version of the crate must not interpret as valid
    /// evidence. Callers at the VFS boundary should validate before using
    /// the request for dispatch or attribute projection.
    #[must_use]
    pub fn validate(&self) -> Result<(), SetAttrValidateError> {
        if self.valid & !FATTR_VALID_MASK != 0 {
            return Err(SetAttrValidateError {
                valid: self.valid,
                unknown_bits: self.valid & !FATTR_VALID_MASK,
            });
        }
        Ok(())
    }
}

/// Error returned when `SetAttr.valid` contains bits outside the known
/// `FATTR_VALID_MASK`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetAttrValidateError {
    /// The full `valid` field value that triggered rejection.
    pub valid: u32,
    /// The subset of bits that are unknown/reserved.
    pub unknown_bits: u32,
}

/// Advisory lock type constants for LockSpec.typ.
pub const F_RDLCK: u32 = 0;
pub const F_WRLCK: u32 = 1;
pub const F_UNLCK: u32 = 2;

/// lseek whence constants for LockSpec.whence.
pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LockSpec {
    pub typ: u32,
    pub whence: u32,
    pub start: u64,
    pub end: u64,
    pub pid: u32,
}

impl LockSpec {
    #[must_use]
    pub const fn new(typ: u32, whence: u32, start: u64, end: u64, pid: u32) -> Self {
        Self {
            typ,
            whence,
            start,
            end,
            pid,
        }
    }

    /// Reject unknown lock type and whence values.
    ///
    /// `typ` must be one of `F_RDLCK` (0), `F_WRLCK` (1), or `F_UNLCK` (2).
    /// `whence` must be one of `SEEK_SET` (0), `SEEK_CUR` (1), or
    /// `SEEK_END` (2).  Future-version records that carry new type or
    /// whence constants must be rejected at the boundary.
    #[must_use]
    pub fn validate(&self) -> Result<(), LockSpecValidateError> {
        let typ_ok = self.typ == F_RDLCK || self.typ == F_WRLCK || self.typ == F_UNLCK;
        let whence_ok = self.whence == SEEK_SET || self.whence == SEEK_CUR || self.whence == SEEK_END;
        if typ_ok && whence_ok {
            Ok(())
        } else {
            Err(LockSpecValidateError {
                typ: self.typ,
                whence: self.whence,
            })
        }
    }
}

/// Error returned when `LockSpec` carries an unknown `typ` or `whence`
/// value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockSpecValidateError {
    /// The raw `typ` value that triggered rejection.
    pub typ: u32,
    /// The raw `whence` value that triggered rejection.
    pub whence: u32,
}

// ── POSIX advisory byte-range lock types ─────────────────────────────────

/// POSIX advisory byte-range lock type values from Linux `fcntl.h`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum LockType {
    /// Shared/read lock (`F_RDLCK`).
    Read = 0,
    /// Exclusive/write lock (`F_WRLCK`).
    Write = 1,
    /// Unlock request (`F_UNLCK`).
    Unlock = 2,
}

impl LockType {
    /// Linux `F_RDLCK` value.
    pub const F_RDLCK: u16 = Self::Read as u16;
    /// Linux `F_WRLCK` value.
    pub const F_WRLCK: u16 = Self::Write as u16;
    /// Linux `F_UNLCK` value.
    pub const F_UNLCK: u16 = Self::Unlock as u16;

    #[must_use]
    pub const fn from_fcntl(value: u16) -> Option<Self> {
        match value {
            Self::F_RDLCK => Some(Self::Read),
            Self::F_WRLCK => Some(Self::Write),
            Self::F_UNLCK => Some(Self::Unlock),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_fcntl(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn conflicts_with(self, other: Self) -> bool {
        !matches!(
            (self, other),
            (Self::Unlock, _) | (_, Self::Unlock) | (Self::Read, Self::Read)
        )
    }
}

/// POSIX advisory byte-range lock for one process.
///
/// `pid` identifies the owning process (used for conflict detection).
/// `owner` identifies the file-description (FUSE `lock_owner`, used for
/// per-fd release on close).
/// `len == 0` means the range extends from `start` to end-of-file.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LockRange {
    pub start: u64,
    pub len: u64,
    pub lock_type: LockType,
    pub owner: u64,
    pub pid: u32,
}

impl LockRange {
    #[must_use]
    pub const fn new(start: u64, len: u64, lock_type: LockType, owner: u64, pid: u32) -> Self {
        Self {
            start,
            len,
            lock_type,
            owner,
            pid,
        }
    }

    #[must_use]
    pub const fn read(start: u64, len: u64, pid: u32) -> Self {
        Self::new(start, len, LockType::Read, 0, pid)
    }

    #[must_use]
    pub const fn write(start: u64, len: u64, pid: u32) -> Self {
        Self::new(start, len, LockType::Write, 0, pid)
    }

    #[must_use]
    pub const fn unlock(start: u64, len: u64, pid: u32) -> Self {
        Self::new(start, len, LockType::Unlock, 0, pid)
    }

    #[must_use]
    pub const fn end_exclusive(self) -> Option<u64> {
        if self.len == 0 {
            None
        } else {
            Some(self.start.saturating_add(self.len))
        }
    }

    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        !range_is_before(self.end_exclusive(), other.start)
            && !range_is_before(other.end_exclusive(), self.start)
    }

    #[must_use]
    pub fn touches_or_overlaps(self, other: Self) -> bool {
        !range_is_strictly_before(self.end_exclusive(), other.start)
            && !range_is_strictly_before(other.end_exclusive(), self.start)
    }

    #[must_use]
    pub fn conflicts_with(self, other: Self) -> bool {
        self.pid != other.pid
            && self.overlaps(other)
            && self.lock_type.conflicts_with(other.lock_type)
    }

    #[must_use]
    fn from_bounds(
        start: u64,
        end_exclusive: Option<u64>,
        lock_type: LockType,
        owner: u64,
        pid: u32,
    ) -> Option<Self> {
        match end_exclusive {
            Some(end) if end <= start => None,
            Some(end) => Some(Self::new(start, end - start, lock_type, owner, pid)),
            None => Some(Self::new(start, 0, lock_type, owner, pid)),
        }
    }
}

/// A concrete lock conflict between a requested range and an existing range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockConflict {
    pub requested: LockRange,
    pub existing: LockRange,
}

impl LockConflict {
    #[must_use]
    pub fn between(existing: LockRange, requested: LockRange) -> Option<Self> {
        existing.conflicts_with(requested).then_some(Self {
            requested,
            existing,
        })
    }
}

/// Ordered lock list for one inode.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LockList {
    locks: alloc::vec::Vec<LockRange>,
}

impl LockList {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            locks: alloc::vec::Vec::new(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.locks.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.locks.len()
    }

    #[must_use]
    pub fn locks(&self) -> &[LockRange] {
        &self.locks
    }

    #[must_use]
    pub fn query_conflict(&self, requested: LockRange) -> Option<LockConflict> {
        self.locks
            .iter()
            .copied()
            .find_map(|existing| LockConflict::between(existing, requested))
    }

    pub fn acquire(&mut self, requested: LockRange) -> Result<(), LockConflict> {
        if requested.lock_type == LockType::Unlock {
            self.release(requested);
            return Ok(());
        }

        if let Some(conflict) = self.query_conflict(requested) {
            return Err(conflict);
        }

        self.remove_pid_range(requested.pid, requested);
        self.locks.push(requested);
        self.normalize();
        Ok(())
    }

    pub fn release(&mut self, requested: LockRange) {
        self.remove_pid_range(requested.pid, requested);
        self.normalize();
    }

    pub fn release_by_pid(&mut self, pid: u32) {
        self.locks.retain(|lock| lock.pid != pid);
    }

    pub fn release_by_owner(&mut self, owner: u64) {
        self.locks.retain(|lock| lock.owner != owner);
    }

    fn remove_pid_range(&mut self, pid: u32, requested: LockRange) {
        let mut replacement = alloc::vec::Vec::with_capacity(self.locks.len() + 1);
        for existing in self.locks.drain(..) {
            if existing.pid != pid || !existing.overlaps(requested) {
                replacement.push(existing);
                continue;
            }
            push_subtracted(existing, requested, &mut replacement);
        }
        self.locks = replacement;
    }

    fn normalize(&mut self) {
        self.locks.sort_by_key(|lock| {
            (
                lock.start,
                lock.end_exclusive().unwrap_or(u64::MAX),
                lock.pid,
                lock.lock_type,
            )
        });

        let mut merged: alloc::vec::Vec<LockRange> =
            alloc::vec::Vec::with_capacity(self.locks.len());
        for lock in self.locks.drain(..) {
            if let Some(last) = merged.last_mut() {
                if can_merge(*last, lock) {
                    *last = merge_ranges(*last, lock);
                    continue;
                }
            }
            merged.push(lock);
        }
        self.locks = merged;
    }
}

/// Dataset-scoped POSIX advisory byte-range lock registry.
/// Keyed by (dataset_mount_id, inode) so locks from different mounts are isolated. now scoped
/// by dataset mount identity so locks from different mounts are isolated.
///
/// Internal key is `(dataset_mount_id, inode)` instead of bare `inode`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LockTracker {
    locks_by_inode: alloc::collections::BTreeMap<(u64, u64), LockList>,
}

impl LockTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            locks_by_inode: alloc::collections::BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.locks_by_inode.is_empty()
    }

    #[must_use]
    pub fn inode_count(&self) -> usize {
        self.locks_by_inode.len()
    }

    #[must_use]
    pub fn locks_for_mount_inode(
        &self,
        dataset_mount_id: u64,
        inode: u64,
    ) -> Option<&LockList> {
        self.locks_by_inode.get(&(dataset_mount_id, inode))
    }

    pub fn acquire(
        &mut self,
        dataset_mount_id: u64,
        inode: u64,
        requested: LockRange,
    ) -> Result<(), LockConflict> {
        if requested.lock_type == LockType::Unlock {
            self.release(dataset_mount_id, inode, requested);
            return Ok(());
        }

        let lock_list = self
            .locks_by_inode
            .entry((dataset_mount_id, inode))
            .or_default();
        lock_list.acquire(requested)?;
        Ok(())
    }

    pub fn release(&mut self, dataset_mount_id: u64, inode: u64, requested: LockRange) {
        if let Some(lock_list) = self.locks_by_inode.get_mut(&(dataset_mount_id, inode)) {
            lock_list.release(requested);
            if lock_list.is_empty() {
                self.locks_by_inode.remove(&(dataset_mount_id, inode));
            }
        }
    }

    #[must_use]
    pub fn query_conflict(
        &self,
        dataset_mount_id: u64,
        inode: u64,
        requested: LockRange,
    ) -> Option<LockConflict> {
        self.locks_by_inode
            .get(&(dataset_mount_id, inode))
            .and_then(|lock_list| lock_list.query_conflict(requested))
    }

    pub fn release_by_pid(&mut self, dataset_mount_id: u64, pid: u32) {
        let mut empty_keys = alloc::vec::Vec::new();
        for (&(mid, ino), lock_list) in &mut self.locks_by_inode {
            if mid != dataset_mount_id {
                continue;
            }
            lock_list.release_by_pid(pid);
            if lock_list.is_empty() {
                empty_keys.push((mid, ino));
            }
        }
        for key in empty_keys {
            self.locks_by_inode.remove(&key);
        }
    }

    /// Release all locks held by `pid` on a single inode within a mount.
    pub fn release_by_pid_mount_inode(
        &mut self,
        dataset_mount_id: u64,
        inode: u64,
        pid: u32,
    ) {
        let key = (dataset_mount_id, inode);
        let mut remove = false;
        if let Some(lock_list) = self.locks_by_inode.get_mut(&key) {
            lock_list.release_by_pid(pid);
            if lock_list.is_empty() {
                remove = true;
            }
        }
        if remove {
            self.locks_by_inode.remove(&key);
        }
    }

    /// Release all locks held through file-description `owner` on a
    /// single inode within a mount.
    pub fn release_by_owner_mount_inode(
        &mut self,
        dataset_mount_id: u64,
        inode: u64,
        owner: u64,
    ) {
        let key = (dataset_mount_id, inode);
        let mut remove = false;
        if let Some(lock_list) = self.locks_by_inode.get_mut(&key) {
            lock_list.release_by_owner(owner);
            if lock_list.is_empty() {
                remove = true;
            }
        }
        if remove {
            self.locks_by_inode.remove(&key);
        }
    }

    /// Release every lock belonging to a dataset mount identity.
    /// Returns the number of distinct (mount, inode) entries cleared.
    pub fn release_all_for_mount(&mut self, dataset_mount_id: u64) -> usize {
        let keys: alloc::vec::Vec<_> = self
            .locks_by_inode
            .keys()
            .filter(|(mid, _)| *mid == dataset_mount_id)
            .copied()
            .collect();
        let count = keys.len();
        for key in keys {
            self.locks_by_inode.remove(&key);
        }
        count
    }
}

// ── Internal lock helpers ─────────────────────────────────────────────

fn range_is_before(end_exclusive: Option<u64>, start: u64) -> bool {
    end_exclusive.is_some_and(|end| end <= start)
}

fn range_is_strictly_before(end_exclusive: Option<u64>, start: u64) -> bool {
    end_exclusive.is_some_and(|end| end < start)
}

fn max_end(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (None, _) | (_, None) => None,
        (Some(left), Some(right)) => Some(core::cmp::max(left, right)),
    }
}

fn can_merge(left: LockRange, right: LockRange) -> bool {
    left.pid == right.pid
        && left.owner == right.owner
        && left.lock_type == right.lock_type
        && left.touches_or_overlaps(right)
}

fn merge_ranges(left: LockRange, right: LockRange) -> LockRange {
    let start = core::cmp::min(left.start, right.start);
    let end = max_end(left.end_exclusive(), right.end_exclusive());
    LockRange::from_bounds(start, end, left.lock_type, left.owner, left.pid)
        .expect("merged range is non-empty")
}

fn push_subtracted(existing: LockRange, cut: LockRange, out: &mut alloc::vec::Vec<LockRange>) {
    if !existing.overlaps(cut) {
        out.push(existing);
        return;
    }

    if existing.start < cut.start {
        if let Some(left) = LockRange::from_bounds(
            existing.start,
            Some(cut.start),
            existing.lock_type,
            existing.owner,
            existing.pid,
        ) {
            out.push(left);
        }
    }

    let Some(cut_end) = cut.end_exclusive() else {
        return;
    };

    match existing.end_exclusive() {
        Some(existing_end) if existing_end > cut_end => {
            if let Some(right) = LockRange::from_bounds(
                cut_end,
                Some(existing_end),
                existing.lock_type,
                existing.owner,
                existing.pid,
            ) {
                out.push(right);
            }
        }
        None => {
            if let Some(right) = LockRange::from_bounds(
                cut_end,
                None,
                existing.lock_type,
                existing.owner,
                existing.pid,
            ) {
                out.push(right);
            }
        }
        _ => {}
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixAttrs {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub rdev: u32,
    /// POSIX atime projection in nanoseconds since the UNIX epoch.
    ///
    /// Prefer [`Self::atime_timestamp`] at authority boundaries.
    pub atime_ns: i64,
    /// POSIX mtime projection in nanoseconds since the UNIX epoch.
    ///
    /// Prefer [`Self::mtime_timestamp`] at authority boundaries.
    pub mtime_ns: i64,
    /// POSIX ctime projection in nanoseconds since the UNIX epoch.
    ///
    /// Prefer [`Self::ctime_timestamp`] at authority boundaries.
    pub ctime_ns: i64,
    /// POSIX btime projection in nanoseconds since the UNIX epoch.
    ///
    /// Prefer [`Self::btime_timestamp`] at authority boundaries.
    pub btime_ns: i64,
    pub size: u64,
    pub blocks_512: u64,
    pub blksize: u32,
}

impl PosixAttrs {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        mode: u32,
        uid: u32,
        gid: u32,
        nlink: u32,
        rdev: u32,
        atime_ns: i64,
        mtime_ns: i64,
        ctime_ns: i64,
        btime_ns: i64,
        size: u64,
        blocks_512: u64,
        blksize: u32,
    ) -> Self {
        Self {
            mode,
            uid,
            gid,
            nlink,
            rdev,
            atime_ns,
            mtime_ns,
            ctime_ns,
            btime_ns,
            size,
            blocks_512,
            blksize,
        }
    }
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
    #[must_use]
    pub const fn is_file(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
    #[must_use]
    pub const fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }
    #[must_use]
    pub const fn mode_type(&self) -> u32 {
        self.mode & S_IFMT
    }
    #[must_use]
    pub const fn mode_perms(&self) -> u32 {
        self.mode & !S_IFMT
    }
    #[must_use]
    pub const fn atime_timestamp(&self) -> PosixTimestampNs {
        PosixTimestampNs::from_unix_nanos(self.atime_ns)
    }
    #[must_use]
    pub const fn mtime_timestamp(&self) -> PosixTimestampNs {
        PosixTimestampNs::from_unix_nanos(self.mtime_ns)
    }
    #[must_use]
    pub const fn ctime_timestamp(&self) -> PosixTimestampNs {
        PosixTimestampNs::from_unix_nanos(self.ctime_ns)
    }
    #[must_use]
    pub const fn btime_timestamp(&self) -> PosixTimestampNs {
        PosixTimestampNs::from_unix_nanos(self.btime_ns)
    }

    /// Reject unknown POSIX inode type in the `mode` field.
    ///
    /// `mode & S_IFMT` must be one of `S_IFREG`, `S_IFDIR`, `S_IFLNK`,
    /// `S_IFBLK`, `S_IFCHR`, `S_IFIFO`, or `S_IFSOCK`.  Any other value
    /// is reserved and must be rejected at the boundary.
    #[must_use]
    pub fn validate(&self) -> Result<(), PosixAttrsValidateError> {
        let mode_type = self.mode & S_IFMT;
        match mode_type {
            S_IFREG | S_IFDIR | S_IFLNK | S_IFBLK | S_IFCHR | S_IFIFO | S_IFSOCK => Ok(()),
            _ => Err(PosixAttrsValidateError { mode }),
        }
    }
}

/// Error returned when `PosixAttrs.mode` carries an unknown `S_IFMT` type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PosixAttrsValidateError {
    /// The full `mode` field value that triggered rejection.
    pub mode: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InodeFlags {
    pub immutable: bool,
    pub append_only: bool,
    pub noatime: bool,
    pub nodump: bool,
}

impl InodeFlags {
    #[must_use]
    pub const fn new(immutable: bool, append_only: bool, noatime: bool, nodump: bool) -> Self {
        Self {
            immutable,
            append_only,
            noatime,
            nodump,
        }
    }
    #[must_use]
    pub const fn none() -> Self {
        Self {
            immutable: false,
            append_only: false,
            noatime: false,
            nodump: false,
        }
    }

    /// POSIX inode flag bit constants matching Linux FS_IOC_GETFLAGS/FS_IOC_SETFLAGS.
    pub const FLAG_IMMUTABLE: u32 = 0x00000010;
    pub const FLAG_APPEND_ONLY: u32 = 0x00000020;
    pub const FLAG_NODUMP: u32 = 0x00000040;
    pub const FLAG_NOATIME: u32 = 0x00000080;

    /// Bitwise OR of all known inode flag bits. Bits outside this mask
    /// are reserved and must be rejected.
    pub const FLAG_VALID_MASK: u32 = Self::FLAG_IMMUTABLE
        | Self::FLAG_APPEND_ONLY
        | Self::FLAG_NODUMP
        | Self::FLAG_NOATIME;

    /// Encode the flag fields into a raw `u32` suitable for
    /// `tidefs_posix_semantics` enforcement predicates.
    #[must_use]
    pub const fn to_raw_flags(self) -> u32 {
        let mut raw: u32 = 0;
        if self.immutable {
            raw |= Self::FLAG_IMMUTABLE;
        }
        if self.append_only {
            raw |= Self::FLAG_APPEND_ONLY;
        }
        if self.nodump {
            raw |= Self::FLAG_NODUMP;
        }
        if self.noatime {
            raw |= Self::FLAG_NOATIME;
        }
        raw
    }

    /// Decode raw `u32` flags from `FS_IOC_GETFLAGS` into `InodeFlags`,
    /// rejecting bits outside the known mask.
    #[must_use]
    pub const fn from_raw_flags(raw: u32) -> Result<Self, InodeFlagsValidateError> {
        if raw & !Self::FLAG_VALID_MASK != 0 {
            return Err(InodeFlagsValidateError {
                raw,
                unknown_bits: raw & !Self::FLAG_VALID_MASK,
            });
        }
        Ok(Self {
            immutable: raw & Self::FLAG_IMMUTABLE != 0,
            append_only: raw & Self::FLAG_APPEND_ONLY != 0,
            nodump: raw & Self::FLAG_NODUMP != 0,
            noatime: raw & Self::FLAG_NOATIME != 0,
        })
    }

    /// Reject unknown flag bits; convenience alias for
    /// [`Self::from_raw_flags`].
    #[must_use]
    pub fn validate_raw_flags(raw: u32) -> Result<(), InodeFlagsValidateError> {
        Self::from_raw_flags(raw).map(|_| ())
    }
}

/// Error returned when `InodeFlags` raw bits contain unknown/reserved
/// flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InodeFlagsValidateError {
    /// The full raw flags value that triggered rejection.
    pub raw: u32,
    /// The subset of bits that are unknown/reserved.
    pub unknown_bits: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InodeAttr {
    pub inode_id: InodeId,
    /// VFS inode generation token.
    ///
    /// This is not POSIX wall-clock time, storage object version,
    /// transaction/replay generation, scrub identity, or a format version.
    pub generation: Generation,
    pub kind: NodeKind,
    pub posix: PosixAttrs,
    pub flags: InodeFlags,
    pub subtree_rev: u64,
    pub dir_rev: u64,
}

impl InodeAttr {
    #[must_use]
    pub const fn new(
        inode_id: InodeId,
        generation: Generation,
        kind: NodeKind,
        posix: PosixAttrs,
        flags: InodeFlags,
        subtree_rev: u64,
        dir_rev: u64,
    ) -> Self {
        Self {
            inode_id,
            generation,
            kind,
            posix,
            flags,
            subtree_rev,
            dir_rev,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatFs {
    pub block_size: u32,
    pub fragment_size: u32,
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub avail_blocks: u64,
    pub files: u64,
    pub files_free: u64,
    pub name_max: u32,
    pub fsid_hi: u32,
    pub fsid_lo: u32,
}

impl StatFs {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        block_size: u32,
        fragment_size: u32,
        total_blocks: u64,
        free_blocks: u64,
        avail_blocks: u64,
        files: u64,
        files_free: u64,
        name_max: u32,
        fsid_hi: u32,
        fsid_lo: u32,
    ) -> Self {
        Self {
            block_size,
            fragment_size,
            total_blocks,
            free_blocks,
            avail_blocks,
            files,
            files_free,
            name_max,
            fsid_hi,
            fsid_lo,
        }
    }
}

// ── DirEntry ────────────────────────────────────────────────────────────────

/// A single directory entry returned by `readdir`.
///
/// `name` holds raw bytes (not assumed UTF-8) for xfstests compatibility.
/// The `name` field is gated behind the `alloc` feature because this crate
/// is `no_std` by default.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DirEntry {
    pub name: alloc::vec::Vec<u8>,
    pub inode_id: InodeId,
    pub kind: NodeKind,
    pub generation: Generation,
    pub cookie: u64,
}

#[cfg(feature = "alloc")]
impl DirEntry {
    #[must_use]
    pub fn new(
        name: alloc::vec::Vec<u8>,
        inode_id: InodeId,
        kind: NodeKind,
        generation: Generation,
        cookie: u64,
    ) -> Self {
        Self {
            name,
            inode_id,
            kind,
            generation,
            cookie,
        }
    }
}

/// Minimal `no_std` stub when `alloc` is disabled — uses a fixed-capacity
/// bounded name so the type remains usable in embedded contexts.
#[cfg(not(feature = "alloc"))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirEntry {
    pub name: DirEntryName,
    pub inode_id: InodeId,
    pub kind: NodeKind,
    pub generation: Generation,
    pub cookie: u64,
}

#[cfg(not(feature = "alloc"))]
impl DirEntry {
    #[must_use]
    pub const fn new(
        name: DirEntryName,
        inode_id: InodeId,
        kind: NodeKind,
        generation: Generation,
        cookie: u64,
    ) -> Self {
        Self {
            name,
            inode_id,
            kind,
            generation,
            cookie,
        }
    }
}

/// Fixed-capacity directory entry name for `no_std` contexts (max 255 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirEntryName {
    pub data: [u8; 256],
    pub len: u8,
}

impl DirEntryName {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            data: [0; 256],
            len: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

impl Default for DirEntryName {
    fn default() -> Self {
        Self::empty()
    }
}

// ── Control Plane types (from tidefs-types-control-plane-core) ──

/// Control plane component classes per P9-01 g0-g10 taxonomy.
/// Each component class represents a distinct architectural responsibility within
/// the control plane's internal processing graph.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneComponentClass {
    PolicyAdmission = 0,
    TruthView = 1,
    ExplanationQuery = 2,
    SecretLeaseBroker = 3,
    PublicationGateway = 4,
    PlacementController = 5,
    MembershipController = 6,
    TransportController = 7,
    HealthMonitor = 8,
    RecallArchive = 9,
    CutoverCoordinator = 10,
}

impl ControlPlaneComponentClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyAdmission => "component.control_plane.policy_admission.g0",
            Self::TruthView => "component.control_plane.truth_view.g1",
            Self::ExplanationQuery => "component.control_plane.explanation_query.g2",
            Self::SecretLeaseBroker => "component.control_plane.secret_lease_broker.g3",
            Self::PublicationGateway => "component.control_plane.publication_gateway.g4",
            Self::PlacementController => "component.control_plane.placement_controller.g5",
            Self::MembershipController => "component.control_plane.membership_controller.g6",
            Self::TransportController => "component.control_plane.transport_controller.g7",
            Self::HealthMonitor => "component.control_plane.health_monitor.g8",
            Self::RecallArchive => "component.control_plane.recall_archive.g9",
            Self::CutoverCoordinator => "component.control_plane.cutover_coordinator.g10",
        }
    }
}

impl Default for ControlPlaneComponentClass {
    fn default() -> Self {
        Self::PolicyAdmission
    }
}

impl TryFrom<u32> for ControlPlaneComponentClass {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PolicyAdmission),
            1 => Ok(Self::TruthView),
            2 => Ok(Self::ExplanationQuery),
            3 => Ok(Self::SecretLeaseBroker),
            4 => Ok(Self::PublicationGateway),
            5 => Ok(Self::PlacementController),
            6 => Ok(Self::MembershipController),
            7 => Ok(Self::TransportController),
            8 => Ok(Self::HealthMonitor),
            9 => Ok(Self::RecallArchive),
            10 => Ok(Self::CutoverCoordinator),
            _ => Err(ControlPlaneRecordDecodeError::InvalidComponentClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneCarrierClass {
    LocalKernelUapi = 0,
    RemoteMtlsGateway = 1,
    InternalKernelStub = 2,
}

impl ControlPlaneCarrierClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalKernelUapi => "carrier.control_plane.local.kernel_uapi.c0",
            Self::RemoteMtlsGateway => "carrier.control_plane.remote.mtls_gateway.c1",
            Self::InternalKernelStub => "carrier.control_plane.internal.kernel_stub.c2",
        }
    }
}

impl Default for ControlPlaneCarrierClass {
    fn default() -> Self {
        Self::LocalKernelUapi
    }
}

impl TryFrom<u32> for ControlPlaneCarrierClass {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::LocalKernelUapi),
            1 => Ok(Self::RemoteMtlsGateway),
            2 => Ok(Self::InternalKernelStub),
            _ => Err(ControlPlaneRecordDecodeError::InvalidCarrierClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneRouteClass {
    Session = 0,
    Write = 1,
    Runbook = 2,
    SecretControl = 3,
    TruthSurface = 4,
    Recall = 5,
    /// r6 — Admin membership: manage cluster members, join, depart, epoch transitions
    AdminMembership = 6,
    /// r7 — Admin transport: manage transport configuration, gateway connectivity, RDMA setup
    AdminTransport = 7,
}

impl ControlPlaneRouteClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "route.control_plane.session.r0",
            Self::Write => "route.control_plane.write.r1",
            Self::Runbook => "route.control_plane.runbook.r2",
            Self::SecretControl => "route.control_plane.secret_control.r3",
            Self::TruthSurface => "route.control_plane.truth_surface.r4",
            Self::Recall => "route.control_plane.recall.r5",
            Self::AdminMembership => "route.control_plane.admin_membership.r6",
            Self::AdminTransport => "route.control_plane.admin_transport.r7",
        }
    }

    /// Map route class to its primary P9-01 component class
    pub const fn primary_component_class(
        self,
    ) -> Result<ControlPlaneComponentClass, ControlPlaneRecordDecodeError> {
        match self {
            Self::Session => Ok(ControlPlaneComponentClass::HealthMonitor),
            Self::Write => Ok(ControlPlaneComponentClass::PolicyAdmission),
            Self::Runbook => Ok(ControlPlaneComponentClass::CutoverCoordinator),
            Self::SecretControl => Ok(ControlPlaneComponentClass::SecretLeaseBroker),
            Self::TruthSurface => Ok(ControlPlaneComponentClass::TruthView),
            Self::Recall => Ok(ControlPlaneComponentClass::RecallArchive),
            Self::AdminMembership => Ok(ControlPlaneComponentClass::MembershipController),
            Self::AdminTransport => Ok(ControlPlaneComponentClass::TransportController),
        }
    }
}

impl Default for ControlPlaneRouteClass {
    fn default() -> Self {
        Self::Session
    }
}

impl TryFrom<u32> for ControlPlaneRouteClass {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Session),
            1 => Ok(Self::Write),
            2 => Ok(Self::Runbook),
            3 => Ok(Self::SecretControl),
            4 => Ok(Self::TruthSurface),
            5 => Ok(Self::Recall),
            6 => Ok(Self::AdminMembership),
            7 => Ok(Self::AdminTransport),
            _ => Err(ControlPlaneRecordDecodeError::InvalidRouteClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneRenderClass {
    Machine = 0,
    OperatorText = 1,
    OperatorRedacted = 2,
}

impl ControlPlaneRenderClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Machine => "render.control_plane.machine.r0",
            Self::OperatorText => "render.control_plane.operator_text.r1",
            Self::OperatorRedacted => "render.control_plane.operator_redacted.r2",
        }
    }
}

impl Default for ControlPlaneRenderClass {
    fn default() -> Self {
        Self::Machine
    }
}

impl TryFrom<u32> for ControlPlaneRenderClass {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Machine),
            1 => Ok(Self::OperatorText),
            2 => Ok(Self::OperatorRedacted),
            _ => Err(ControlPlaneRecordDecodeError::InvalidRenderClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneVisibilityClass {
    PublicRedacted = 0,
    OperatorScoped = 1,
    InternalKernel = 2,
}

impl ControlPlaneVisibilityClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicRedacted => "visibility.control_plane.public_redacted.v0",
            Self::OperatorScoped => "visibility.control_plane.operator_scoped.v1",
            Self::InternalKernel => "visibility.control_plane.internal_kernel.v2",
        }
    }
}

impl Default for ControlPlaneVisibilityClass {
    fn default() -> Self {
        Self::PublicRedacted
    }
}

impl TryFrom<u32> for ControlPlaneVisibilityClass {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PublicRedacted),
            1 => Ok(Self::OperatorScoped),
            2 => Ok(Self::InternalKernel),
            _ => Err(ControlPlaneRecordDecodeError::InvalidVisibilityClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneResponseKind {
    Bundle = 0,
    Refusal = 1,
}

impl ControlPlaneResponseKind {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bundle => "response.control_plane.bundle.k0",
            Self::Refusal => "response.control_plane.refusal.k1",
        }
    }
}

impl Default for ControlPlaneResponseKind {
    fn default() -> Self {
        Self::Bundle
    }
}

impl TryFrom<u32> for ControlPlaneResponseKind {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Bundle),
            1 => Ok(Self::Refusal),
            _ => Err(ControlPlaneRecordDecodeError::InvalidResponseKind(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneWriteRequestKind {
    ProductAdmissionManual = 0,
}

impl ControlPlaneWriteRequestKind {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProductAdmissionManual => "req.product_admission.manual.r0",
        }
    }
}

impl Default for ControlPlaneWriteRequestKind {
    fn default() -> Self {
        Self::ProductAdmissionManual
    }
}

impl TryFrom<u32> for ControlPlaneWriteRequestKind {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ProductAdmissionManual),
            _ => Err(ControlPlaneRecordDecodeError::InvalidWriteRequestKind(
                value,
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneRecordDecodeError {
    InvalidCarrierClass(u32),
    InvalidRouteClass(u32),
    InvalidRenderClass(u32),
    InvalidVisibilityClass(u32),
    InvalidResponseKind(u32),
    InvalidWriteRequestKind(u32),
    InvalidComponentClass(u32),
}

fn decode_carrier_class(
    value: u32,
) -> Result<ControlPlaneCarrierClass, ControlPlaneRecordDecodeError> {
    ControlPlaneCarrierClass::try_from(value)
}

fn decode_route_class(value: u32) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
    ControlPlaneRouteClass::try_from(value)
}

fn decode_render_class(
    value: u32,
) -> Result<ControlPlaneRenderClass, ControlPlaneRecordDecodeError> {
    ControlPlaneRenderClass::try_from(value)
}

fn decode_visibility_class(
    value: u32,
) -> Result<ControlPlaneVisibilityClass, ControlPlaneRecordDecodeError> {
    ControlPlaneVisibilityClass::try_from(value)
}

fn decode_response_kind(
    value: u32,
) -> Result<ControlPlaneResponseKind, ControlPlaneRecordDecodeError> {
    ControlPlaneResponseKind::try_from(value)
}

fn decode_write_request_kind(
    value: u32,
) -> Result<ControlPlaneWriteRequestKind, ControlPlaneRecordDecodeError> {
    ControlPlaneWriteRequestKind::try_from(value)
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ControlPlaneId128(pub [u8; 16]);

impl ControlPlaneId128 {
    pub const ZERO: Self = Self([0_u8; 16]);

    #[must_use]
    pub const fn from_u128_le(value: u128) -> Self {
        Self(value.to_le_bytes())
    }

    #[must_use]
    pub const fn as_u128_le(self) -> u128 {
        u128::from_le_bytes(self.0)
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}

pub type ControlPlaneRequestId = ControlPlaneId128;
pub type ControlPlaneSessionId = ControlPlaneId128;
pub type ControlPlaneJournalId = ControlPlaneId128;
pub type ControlPlaneReceiptId = ControlPlaneId128;
pub type ControlPlaneIdempotencyKey = ControlPlaneId128;
pub type ControlPlaneDigest32 = [u8; 32];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlanePolicyBudgetRecipeWitnessRefs {
    pub witness_join_id: ControlPlaneId128,
    pub policy_witness_id: ControlPlaneId128,
    pub budget_witness_id: ControlPlaneId128,
    pub recipe_witness_id: ControlPlaneId128,
    pub witness_join_digest: ControlPlaneDigest32,
}

impl ControlPlanePolicyBudgetRecipeWitnessRefs {
    pub const ZERO: Self = Self {
        witness_join_id: ControlPlaneId128::ZERO,
        policy_witness_id: ControlPlaneId128::ZERO,
        budget_witness_id: ControlPlaneId128::ZERO,
        recipe_witness_id: ControlPlaneId128::ZERO,
        witness_join_digest: [0_u8; 32],
    };

    #[must_use]
    pub const fn new(
        witness_join_id: ControlPlaneId128,
        policy_witness_id: ControlPlaneId128,
        budget_witness_id: ControlPlaneId128,
        recipe_witness_id: ControlPlaneId128,
        witness_join_digest: ControlPlaneDigest32,
    ) -> Self {
        Self {
            witness_join_id,
            policy_witness_id,
            budget_witness_id,
            recipe_witness_id,
            witness_join_digest,
        }
    }

    #[must_use]
    pub const fn has_join(&self) -> bool {
        !self.witness_join_id.is_zero()
    }
}

pub const CONTROL_PLANE_CANON_VERSION_1: u32 = 1;
pub const CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT: u32 = 1 << 0;
pub const CONTROL_PLANE_REQUEST_FLAG_PUBLIC_CARRIER: u32 = 1 << 1;
pub const CONTROL_PLANE_REQUEST_FLAG_JOURNAL_REQUIRED: u32 = 1 << 2;
pub const CONTROL_PLANE_REQUEST_FLAG_PAYLOAD_REDACTED: u32 = 1 << 3;
pub const CONTROL_PLANE_TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY: u32 = u32::MAX;
pub const CONTROL_PLANE_TRUTH_RECALL_LOOKUP_ANSWER_KIND_FILTER_ANY: u32 = u32::MAX;
pub const CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_REQUIRE_TERMINAL_RECEIPT: u32 = 1 << 0;
pub const CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_ALLOW_SUPERSEDED: u32 = 1 << 1;
pub const CONTROL_PLANE_TRUTH_RECALL_LOOKUP_HIT_FLAG_TERMINAL_RECEIPT: u32 = 1 << 0;
pub const CONTROL_PLANE_TRUTH_RECALL_LOOKUP_BATCH_RECEIPT_FLAG_ALL_TERMINAL_RECEIPTS: u32 = 1 << 0;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneTruthRecallLookupRequestRecord {
    pub route_class: u32,
    pub index_class: u32,
    pub retention_class: u32,
    pub disclosure_filter_or_any: u32,
    pub answer_kind_filter_or_any: u32,
    pub flags: u32,
    pub _reserved0: u32,
    pub _reserved1: u32,
    pub index_key_digest: ControlPlaneDigest32,
}

impl Default for ControlPlaneTruthRecallLookupRequestRecord {
    fn default() -> Self {
        Self {
            route_class: 0,
            index_class: 0,
            retention_class: 0,
            disclosure_filter_or_any: CONTROL_PLANE_TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY,
            answer_kind_filter_or_any: CONTROL_PLANE_TRUTH_RECALL_LOOKUP_ANSWER_KIND_FILTER_ANY,
            flags: 0,
            _reserved0: 0,
            _reserved1: 0,
            index_key_digest: [0_u8; 32],
        }
    }
}

impl ControlPlaneTruthRecallLookupRequestRecord {
    #[must_use]
    pub const fn new(
        route_class: ControlPlaneRouteClass,
        index_class: u32,
        retention_class: u32,
        disclosure_filter_or_any: u32,
        answer_kind_filter_or_any: u32,
        flags: u32,
        index_key_digest: ControlPlaneDigest32,
    ) -> Self {
        Self {
            route_class: route_class.as_u32(),
            index_class,
            retention_class,
            disclosure_filter_or_any,
            answer_kind_filter_or_any,
            flags,
            _reserved0: 0,
            _reserved1: 0,
            index_key_digest,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    #[must_use]
    pub const fn has_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }

    #[must_use]
    pub const fn requires_terminal_receipt(&self) -> bool {
        self.has_flag(CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_REQUIRE_TERMINAL_RECEIPT)
    }

    #[must_use]
    pub const fn allows_superseded(&self) -> bool {
        self.has_flag(CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_ALLOW_SUPERSEDED)
    }

    #[must_use]
    pub const fn has_disclosure_filter(&self) -> bool {
        self.disclosure_filter_or_any != CONTROL_PLANE_TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY
    }

    #[must_use]
    pub const fn has_answer_kind_filter(&self) -> bool {
        self.answer_kind_filter_or_any != CONTROL_PLANE_TRUTH_RECALL_LOOKUP_ANSWER_KIND_FILTER_ANY
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneTruthRecallLookupHitRecord {
    pub route_class: u32,
    pub index_class: u32,
    pub retention_class: u32,
    pub disclosure_class: u32,
    pub answer_kind: u32,
    pub flags: u32,
    pub _reserved0: u32,
    pub _reserved1: u32,
    pub index_entry_id: ControlPlaneReceiptId,
    pub response_receipt_id: ControlPlaneReceiptId,
    pub bundle_receipt_id: ControlPlaneReceiptId,
    pub terminal_receipt_id_or_zero: ControlPlaneReceiptId,
    pub binding_id: ControlPlaneReceiptId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneTruthRecallLookupHitRecordInput {
    pub route_class: ControlPlaneRouteClass,
    pub index_class: u32,
    pub retention_class: u32,
    pub disclosure_class: u32,
    pub answer_kind: u32,
    pub index_entry_id: ControlPlaneReceiptId,
    pub response_receipt_id: ControlPlaneReceiptId,
    pub bundle_receipt_id: ControlPlaneReceiptId,
    pub terminal_receipt_id_or_zero: ControlPlaneReceiptId,
    pub binding_id: ControlPlaneReceiptId,
}

impl ControlPlaneTruthRecallLookupHitRecord {
    #[must_use]
    pub const fn new(input: ControlPlaneTruthRecallLookupHitRecordInput) -> Self {
        Self {
            route_class: input.route_class.as_u32(),
            index_class: input.index_class,
            retention_class: input.retention_class,
            disclosure_class: input.disclosure_class,
            answer_kind: input.answer_kind,
            flags: if input.terminal_receipt_id_or_zero.is_zero() {
                0
            } else {
                CONTROL_PLANE_TRUTH_RECALL_LOOKUP_HIT_FLAG_TERMINAL_RECEIPT
            },
            _reserved0: 0,
            _reserved1: 0,
            index_entry_id: input.index_entry_id,
            response_receipt_id: input.response_receipt_id,
            bundle_receipt_id: input.bundle_receipt_id,
            terminal_receipt_id_or_zero: input.terminal_receipt_id_or_zero,
            binding_id: input.binding_id,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    #[must_use]
    pub const fn has_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }

    #[must_use]
    pub const fn has_terminal_receipt(&self) -> bool {
        !self.terminal_receipt_id_or_zero.is_zero()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneTruthRecallLookupBatchReceiptRecord {
    pub receipt_id: ControlPlaneReceiptId,
    pub journal_id: ControlPlaneJournalId,
    pub route_class: u32,
    pub carrier_class: u32,
    pub render_class: u32,
    pub visibility_class: u32,
    pub query_count: u32,
    pub hit_count: u32,
    pub flags: u32,
    pub _reserved0: u32,
    pub query_stream_digest: ControlPlaneDigest32,
    pub hit_stream_digest: ControlPlaneDigest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneTruthRecallLookupBatchReceiptRecordInput {
    pub receipt_id: ControlPlaneReceiptId,
    pub journal_id: ControlPlaneJournalId,
    pub route_class: ControlPlaneRouteClass,
    pub carrier_class: ControlPlaneCarrierClass,
    pub render_class: ControlPlaneRenderClass,
    pub visibility_class: ControlPlaneVisibilityClass,
    pub query_count: u32,
    pub hit_count: u32,
    pub all_hits_have_terminal_receipt: bool,
    pub query_stream_digest: ControlPlaneDigest32,
    pub hit_stream_digest: ControlPlaneDigest32,
}

impl ControlPlaneTruthRecallLookupBatchReceiptRecord {
    #[must_use]
    pub const fn new(input: ControlPlaneTruthRecallLookupBatchReceiptRecordInput) -> Self {
        Self {
            receipt_id: input.receipt_id,
            journal_id: input.journal_id,
            route_class: input.route_class.as_u32(),
            carrier_class: input.carrier_class.as_u32(),
            render_class: input.render_class.as_u32(),
            visibility_class: input.visibility_class.as_u32(),
            query_count: input.query_count,
            hit_count: input.hit_count,
            flags: if input.all_hits_have_terminal_receipt {
                CONTROL_PLANE_TRUTH_RECALL_LOOKUP_BATCH_RECEIPT_FLAG_ALL_TERMINAL_RECEIPTS
            } else {
                0
            },
            _reserved0: 0,
            query_stream_digest: input.query_stream_digest,
            hit_stream_digest: input.hit_stream_digest,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidCarrierClass`] if the stored
    /// raw tag does not correspond to a valid carrier.
    pub fn carrier(self) -> Result<ControlPlaneCarrierClass, ControlPlaneRecordDecodeError> {
        decode_carrier_class(self.carrier_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRenderClass`] if the stored
    /// raw tag does not correspond to a valid render.
    pub fn render(self) -> Result<ControlPlaneRenderClass, ControlPlaneRecordDecodeError> {
        decode_render_class(self.render_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidVisibilityClass`] if the stored
    /// raw tag does not correspond to a valid visibility.
    pub fn visibility(self) -> Result<ControlPlaneVisibilityClass, ControlPlaneRecordDecodeError> {
        decode_visibility_class(self.visibility_class)
    }

    #[must_use]
    pub const fn has_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }

    #[must_use]
    pub const fn all_hits_have_terminal_receipt(&self) -> bool {
        self.has_flag(CONTROL_PLANE_TRUTH_RECALL_LOOKUP_BATCH_RECEIPT_FLAG_ALL_TERMINAL_RECEIPTS)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneRequestEnvelopeHead {
    pub version: u32,
    pub carrier_class: u32,
    pub route_class: u32,
    pub render_class: u32,
    pub visibility_class: u32,
    pub flags: u32,
    pub payload_len: u32,
    pub _reserved0: u32,
    pub request_id: ControlPlaneRequestId,
    pub session_id: ControlPlaneSessionId,
    pub idempotency_key: ControlPlaneIdempotencyKey,
    pub normalized_request_digest: ControlPlaneDigest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneRequestEnvelopeHeadInput {
    pub carrier_class: ControlPlaneCarrierClass,
    pub route_class: ControlPlaneRouteClass,
    pub render_class: ControlPlaneRenderClass,
    pub visibility_class: ControlPlaneVisibilityClass,
    pub flags: u32,
    pub payload_len: u32,
    pub request_id: ControlPlaneRequestId,
    pub session_id: ControlPlaneSessionId,
    pub idempotency_key: ControlPlaneIdempotencyKey,
    pub normalized_request_digest: ControlPlaneDigest32,
}

impl ControlPlaneRequestEnvelopeHead {
    #[must_use]
    pub const fn new(input: ControlPlaneRequestEnvelopeHeadInput) -> Self {
        Self {
            version: CONTROL_PLANE_CANON_VERSION_1,
            carrier_class: input.carrier_class.as_u32(),
            route_class: input.route_class.as_u32(),
            render_class: input.render_class.as_u32(),
            visibility_class: input.visibility_class.as_u32(),
            flags: input.flags,
            payload_len: input.payload_len,
            _reserved0: 0,
            request_id: input.request_id,
            session_id: input.session_id,
            idempotency_key: input.idempotency_key,
            normalized_request_digest: input.normalized_request_digest,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidCarrierClass`] if the stored
    /// raw tag does not correspond to a valid carrier.
    pub fn carrier(self) -> Result<ControlPlaneCarrierClass, ControlPlaneRecordDecodeError> {
        decode_carrier_class(self.carrier_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRenderClass`] if the stored
    /// raw tag does not correspond to a valid render.
    pub fn render(self) -> Result<ControlPlaneRenderClass, ControlPlaneRecordDecodeError> {
        decode_render_class(self.render_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidVisibilityClass`] if the stored
    /// raw tag does not correspond to a valid visibility.
    pub fn visibility(self) -> Result<ControlPlaneVisibilityClass, ControlPlaneRecordDecodeError> {
        decode_visibility_class(self.visibility_class)
    }

    #[must_use]
    pub const fn has_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }

    #[must_use]
    pub const fn project_journal_record(
        self,
        journal_id: ControlPlaneJournalId,
    ) -> ControlPlaneRequestJournalRecord {
        ControlPlaneRequestJournalRecord {
            journal_id,
            request_id: self.request_id,
            session_id: self.session_id,
            carrier_class: self.carrier_class,
            route_class: self.route_class,
            normalized_request_digest: self.normalized_request_digest,
            idempotency_key: self.idempotency_key,
            upstream_receipt_count: 0,
            _reserved0: 0,
            terminal_render_receipt_id: ControlPlaneReceiptId::ZERO,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneRequestJournalRecord {
    pub journal_id: ControlPlaneJournalId,
    pub request_id: ControlPlaneRequestId,
    pub session_id: ControlPlaneSessionId,
    pub carrier_class: u32,
    pub route_class: u32,
    pub normalized_request_digest: ControlPlaneDigest32,
    pub idempotency_key: ControlPlaneIdempotencyKey,
    pub upstream_receipt_count: u32,
    pub _reserved0: u32,
    pub terminal_render_receipt_id: ControlPlaneReceiptId,
}

impl ControlPlaneRequestJournalRecord {
    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidCarrierClass`] if the stored
    /// raw tag does not correspond to a valid carrier.
    pub fn carrier(self) -> Result<ControlPlaneCarrierClass, ControlPlaneRecordDecodeError> {
        decode_carrier_class(self.carrier_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    #[must_use]
    pub const fn with_terminal_render_receipt(
        mut self,
        receipt_id: ControlPlaneReceiptId,
        upstream_receipt_count: u32,
    ) -> Self {
        self.terminal_render_receipt_id = receipt_id;
        self.upstream_receipt_count = upstream_receipt_count;
        self
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneResponseRenderReceipt {
    pub receipt_id: ControlPlaneReceiptId,
    pub journal_id: ControlPlaneJournalId,
    pub route_class: u32,
    pub render_class: u32,
    pub visibility_class: u32,
    pub carrier_class: u32,
    pub response_kind: u32,
    pub _reserved0: u32,
    pub bundle_or_refusal_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneResponseRenderReceiptInput {
    pub receipt_id: ControlPlaneReceiptId,
    pub journal_id: ControlPlaneJournalId,
    pub route_class: ControlPlaneRouteClass,
    pub render_class: ControlPlaneRenderClass,
    pub visibility_class: ControlPlaneVisibilityClass,
    pub carrier_class: ControlPlaneCarrierClass,
    pub response_kind: ControlPlaneResponseKind,
    pub bundle_or_refusal_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
}

impl ControlPlaneResponseRenderReceipt {
    #[must_use]
    pub const fn new(input: ControlPlaneResponseRenderReceiptInput) -> Self {
        Self {
            receipt_id: input.receipt_id,
            journal_id: input.journal_id,
            route_class: input.route_class.as_u32(),
            render_class: input.render_class.as_u32(),
            visibility_class: input.visibility_class.as_u32(),
            carrier_class: input.carrier_class.as_u32(),
            response_kind: input.response_kind.as_u32(),
            _reserved0: 0,
            bundle_or_refusal_digest: input.bundle_or_refusal_digest,
            artifact_locator_digest: input.artifact_locator_digest,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRenderClass`] if the stored
    /// raw tag does not correspond to a valid render.
    pub fn render(self) -> Result<ControlPlaneRenderClass, ControlPlaneRecordDecodeError> {
        decode_render_class(self.render_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidVisibilityClass`] if the stored
    /// raw tag does not correspond to a valid visibility.
    pub fn visibility(self) -> Result<ControlPlaneVisibilityClass, ControlPlaneRecordDecodeError> {
        decode_visibility_class(self.visibility_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidCarrierClass`] if the stored
    /// raw tag does not correspond to a valid carrier.
    pub fn carrier(self) -> Result<ControlPlaneCarrierClass, ControlPlaneRecordDecodeError> {
        decode_carrier_class(self.carrier_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidResponseKind`] if the stored
    /// raw tag does not correspond to a valid response_kind.
    pub fn response_kind(self) -> Result<ControlPlaneResponseKind, ControlPlaneRecordDecodeError> {
        decode_response_kind(self.response_kind)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneRouteTerminalReceiptRecord {
    pub terminal_receipt_id: ControlPlaneReceiptId,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub response_registry_receipt_id: ControlPlaneReceiptId,
    pub render_receipt_id: ControlPlaneReceiptId,
    pub route_class: u32,
    pub response_kind: u32,
    pub render_class: u32,
    pub visibility_class: u32,
    pub carrier_class: u32,
    pub _reserved0: u32,
    pub answer_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
    pub witness_refs: ControlPlanePolicyBudgetRecipeWitnessRefs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneRouteTerminalReceiptRecordInput {
    pub terminal_receipt_id: ControlPlaneReceiptId,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub response_registry_receipt_id: ControlPlaneReceiptId,
    pub render_receipt_id: ControlPlaneReceiptId,
    pub route_class: ControlPlaneRouteClass,
    pub response_kind: ControlPlaneResponseKind,
    pub render_class: ControlPlaneRenderClass,
    pub visibility_class: ControlPlaneVisibilityClass,
    pub carrier_class: ControlPlaneCarrierClass,
    pub answer_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
    pub witness_refs: ControlPlanePolicyBudgetRecipeWitnessRefs,
}

impl ControlPlaneRouteTerminalReceiptRecord {
    #[must_use]
    pub const fn new(input: ControlPlaneRouteTerminalReceiptRecordInput) -> Self {
        Self {
            terminal_receipt_id: input.terminal_receipt_id,
            request_id: input.request_id,
            journal_id: input.journal_id,
            response_registry_receipt_id: input.response_registry_receipt_id,
            render_receipt_id: input.render_receipt_id,
            route_class: input.route_class.as_u32(),
            response_kind: input.response_kind.as_u32(),
            render_class: input.render_class.as_u32(),
            visibility_class: input.visibility_class.as_u32(),
            carrier_class: input.carrier_class.as_u32(),
            _reserved0: 0,
            answer_digest: input.answer_digest,
            artifact_locator_digest: input.artifact_locator_digest,
            witness_refs: input.witness_refs,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidResponseKind`] if the stored
    /// raw tag does not correspond to a valid response_kind.
    pub fn response_kind(self) -> Result<ControlPlaneResponseKind, ControlPlaneRecordDecodeError> {
        decode_response_kind(self.response_kind)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRenderClass`] if the stored
    /// raw tag does not correspond to a valid render.
    pub fn render(self) -> Result<ControlPlaneRenderClass, ControlPlaneRecordDecodeError> {
        decode_render_class(self.render_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidVisibilityClass`] if the stored
    /// raw tag does not correspond to a valid visibility.
    pub fn visibility(self) -> Result<ControlPlaneVisibilityClass, ControlPlaneRecordDecodeError> {
        decode_visibility_class(self.visibility_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidCarrierClass`] if the stored
    /// raw tag does not correspond to a valid carrier.
    pub fn carrier(self) -> Result<ControlPlaneCarrierClass, ControlPlaneRecordDecodeError> {
        decode_carrier_class(self.carrier_class)
    }

    #[must_use]
    pub const fn has_witness_join(&self) -> bool {
        self.witness_refs.has_join()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneWriteManualProductAdmissionPayload {
    pub write_request_kind: u32,
    pub flags: u32,
    pub _reserved0: u64,
    pub product_recipe_digest: ControlPlaneDigest32,
    pub subject_scope_digest: ControlPlaneDigest32,
    pub required_anchor_set_id: ControlPlaneId128,
    pub budget_domain_id: ControlPlaneId128,
}

impl ControlPlaneWriteManualProductAdmissionPayload {
    #[must_use]
    pub const fn new(
        flags: u32,
        product_recipe_digest: ControlPlaneDigest32,
        subject_scope_digest: ControlPlaneDigest32,
        required_anchor_set_id: ControlPlaneId128,
        budget_domain_id: ControlPlaneId128,
    ) -> Self {
        Self {
            write_request_kind: ControlPlaneWriteRequestKind::ProductAdmissionManual.as_u32(),
            flags,
            _reserved0: 0,
            product_recipe_digest,
            subject_scope_digest,
            required_anchor_set_id,
            budget_domain_id,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidWriteRequestKind`] if the stored
    /// raw tag does not correspond to a valid kind.
    pub fn kind(self) -> Result<ControlPlaneWriteRequestKind, ControlPlaneRecordDecodeError> {
        decode_write_request_kind(self.write_request_kind)
    }
}

const _: [(); 16] = [(); core::mem::size_of::<ControlPlaneId128>()];
const _: [(); 96] = [(); core::mem::size_of::<ControlPlanePolicyBudgetRecipeWitnessRefs>()];
const _: [(); 64] = [(); core::mem::size_of::<ControlPlaneTruthRecallLookupRequestRecord>()];
const _: [(); 112] = [(); core::mem::size_of::<ControlPlaneTruthRecallLookupHitRecord>()];
const _: [(); 128] = [(); core::mem::size_of::<ControlPlaneTruthRecallLookupBatchReceiptRecord>()];
const _: [(); 112] = [(); core::mem::size_of::<ControlPlaneRequestEnvelopeHead>()];
const _: [(); 128] = [(); core::mem::size_of::<ControlPlaneRequestJournalRecord>()];
const _: [(); 120] = [(); core::mem::size_of::<ControlPlaneResponseRenderReceipt>()];
const _: [(); 264] = [(); core::mem::size_of::<ControlPlaneRouteTerminalReceiptRecord>()];
const _: [(); 112] = [(); core::mem::size_of::<ControlPlaneWriteManualProductAdmissionPayload>()];
// Policy authority record surface.
pub const POLICY_AUTHORITY_REQUEST_FAMILY_REQUEST_QUEUE: &str =
    "family.request.policy_authority.request_queue_0";
pub const POLICY_AUTHORITY_REQUEST_PACKET_REQUEST_QUEUE_P0: &str = "request_queue_0.p0";

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PolicyAuthorityIngressSurfaceClass {
    ControlPlaneLocal = 0,
    PosixFilesystemAdapterClient = 1,
    ExplanationQueryClient = 2,
    BlockVolumeAdapterClient = 3,
    ClusterRuntime = 4,
    ShadowReplay = 5,
}

impl PolicyAuthorityIngressSurfaceClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ControlPlaneLocal => "surface.policy_authority.control_plane_local.s0",
            Self::PosixFilesystemAdapterClient => {
                "surface.policy_authority.client_posix_filesystem_adapter.s1"
            }
            Self::ExplanationQueryClient => "surface.policy_authority.client_explanation_query.s2",
            Self::BlockVolumeAdapterClient => {
                "surface.policy_authority.client_block_volume_adapter.s3"
            }
            Self::ClusterRuntime => "surface.policy_authority.cluster_runtime.s4",
            Self::ShadowReplay => "surface.policy_authority.shadow_replay.s5",
        }
    }
}

impl Default for PolicyAuthorityIngressSurfaceClass {
    fn default() -> Self {
        Self::ControlPlaneLocal
    }
}

impl TryFrom<u32> for PolicyAuthorityIngressSurfaceClass {
    type Error = PolicyAuthorityRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ControlPlaneLocal),
            1 => Ok(Self::PosixFilesystemAdapterClient),
            2 => Ok(Self::ExplanationQueryClient),
            3 => Ok(Self::BlockVolumeAdapterClient),
            4 => Ok(Self::ClusterRuntime),
            5 => Ok(Self::ShadowReplay),
            _ => Err(PolicyAuthorityRecordDecodeError::InvalidIngressSurfaceClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PolicyAuthorityShardClass {
    Policy = 0,
    Override = 1,
    Budget = 2,
    Recipe = 3,
    ProductAdmission = 4,
    ProductReclaim = 5,
}

impl PolicyAuthorityShardClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "shard.policy_authority.policy.d0",
            Self::Override => "shard.policy_authority.override.d1",
            Self::Budget => "shard.policy_authority.budget.d2",
            Self::Recipe => "shard.policy_authority.recipe.d3",
            Self::ProductAdmission => "shard.policy_authority.product_admission.d4",
            Self::ProductReclaim => "shard.policy_authority.product_reclaim.d5",
        }
    }
}

impl Default for PolicyAuthorityShardClass {
    fn default() -> Self {
        Self::Policy
    }
}

impl TryFrom<u32> for PolicyAuthorityShardClass {
    type Error = PolicyAuthorityRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Policy),
            1 => Ok(Self::Override),
            2 => Ok(Self::Budget),
            3 => Ok(Self::Recipe),
            4 => Ok(Self::ProductAdmission),
            5 => Ok(Self::ProductReclaim),
            _ => Err(PolicyAuthorityRecordDecodeError::InvalidShardClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PolicyAuthorityCapsuleClass {
    PolicyWrite = 0,
    PolicyRead = 1,
    OverrideWrite = 2,
    OverrideRead = 3,
    BudgetWrite = 4,
    BudgetRead = 5,
    RecipeWrite = 6,
    ProductAdmission = 7,
    ProductReclaim = 8,
}

impl PolicyAuthorityCapsuleClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyWrite => "capsule.policy_authority.policy.write.k0",
            Self::PolicyRead => "capsule.policy_authority.policy.read.k1",
            Self::OverrideWrite => "capsule.policy_authority.override.write.k2",
            Self::OverrideRead => "capsule.policy_authority.override.read.k3",
            Self::BudgetWrite => "capsule.policy_authority.budget.write.k4",
            Self::BudgetRead => "capsule.policy_authority.budget.read.k5",
            Self::RecipeWrite => "capsule.policy_authority.recipe.write.k6",
            Self::ProductAdmission => "capsule.policy_authority.product_admission.k7",
            Self::ProductReclaim => "capsule.policy_authority.product_reclaim.k8",
        }
    }
}

impl Default for PolicyAuthorityCapsuleClass {
    fn default() -> Self {
        Self::PolicyWrite
    }
}

impl TryFrom<u32> for PolicyAuthorityCapsuleClass {
    type Error = PolicyAuthorityRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PolicyWrite),
            1 => Ok(Self::PolicyRead),
            2 => Ok(Self::OverrideWrite),
            3 => Ok(Self::OverrideRead),
            4 => Ok(Self::BudgetWrite),
            5 => Ok(Self::BudgetRead),
            6 => Ok(Self::RecipeWrite),
            7 => Ok(Self::ProductAdmission),
            8 => Ok(Self::ProductReclaim),
            _ => Err(PolicyAuthorityRecordDecodeError::InvalidCapsuleClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PolicyAuthorityRequestName {
    PolicyPublish = 0,
    PolicyLookup = 1,
    OverrideIssue = 2,
    OverrideValidate = 3,
    OverrideRevoke = 4,
    BudgetDomainPublish = 5,
    BudgetDomainQuote = 6,
    BudgetDomainAdjust = 7,
    ProductRecipePublish = 8,
    ProductAdmissionManual = 9,
    ProductReclaimManual = 10,
}

impl PolicyAuthorityRequestName {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyPublish => "req.policy.publish.r0",
            Self::PolicyLookup => "req.policy.lookup.r0",
            Self::OverrideIssue => "req.override.issue.r0",
            Self::OverrideValidate => "req.override.validate.r0",
            Self::OverrideRevoke => "req.override.revoke.r0",
            Self::BudgetDomainPublish => "req.budget_domain.publish.r0",
            Self::BudgetDomainQuote => "req.budget_domain.quote.r0",
            Self::BudgetDomainAdjust => "req.budget_domain.adjust.r0",
            Self::ProductRecipePublish => "req.product_recipe.publish.r0",
            Self::ProductAdmissionManual => "req.product_admission.manual.r0",
            Self::ProductReclaimManual => "req.product_reclaim.manual.r0",
        }
    }

    #[must_use]
    pub const fn packet_scope(self) -> &'static str {
        POLICY_AUTHORITY_REQUEST_PACKET_REQUEST_QUEUE_P0
    }

    #[must_use]
    pub const fn primary_shard(self) -> PolicyAuthorityShardClass {
        match self {
            Self::PolicyPublish | Self::PolicyLookup => PolicyAuthorityShardClass::Policy,
            Self::OverrideIssue | Self::OverrideValidate | Self::OverrideRevoke => {
                PolicyAuthorityShardClass::Override
            }
            Self::BudgetDomainPublish | Self::BudgetDomainQuote | Self::BudgetDomainAdjust => {
                PolicyAuthorityShardClass::Budget
            }
            Self::ProductRecipePublish => PolicyAuthorityShardClass::Recipe,
            Self::ProductAdmissionManual => PolicyAuthorityShardClass::ProductAdmission,
            Self::ProductReclaimManual => PolicyAuthorityShardClass::ProductReclaim,
        }
    }

    #[must_use]
    pub const fn primary_capsule(self) -> PolicyAuthorityCapsuleClass {
        match self {
            Self::PolicyPublish => PolicyAuthorityCapsuleClass::PolicyWrite,
            Self::PolicyLookup => PolicyAuthorityCapsuleClass::PolicyRead,
            Self::OverrideIssue | Self::OverrideRevoke => {
                PolicyAuthorityCapsuleClass::OverrideWrite
            }
            Self::OverrideValidate => PolicyAuthorityCapsuleClass::OverrideRead,
            Self::BudgetDomainPublish | Self::BudgetDomainAdjust => {
                PolicyAuthorityCapsuleClass::BudgetWrite
            }
            Self::BudgetDomainQuote => PolicyAuthorityCapsuleClass::BudgetRead,
            Self::ProductRecipePublish => PolicyAuthorityCapsuleClass::RecipeWrite,
            Self::ProductAdmissionManual => PolicyAuthorityCapsuleClass::ProductAdmission,
            Self::ProductReclaimManual => PolicyAuthorityCapsuleClass::ProductReclaim,
        }
    }

    #[must_use]
    pub const fn is_mutating(self) -> bool {
        !matches!(
            self,
            Self::PolicyLookup | Self::OverrideValidate | Self::BudgetDomainQuote
        )
    }
}

impl Default for PolicyAuthorityRequestName {
    fn default() -> Self {
        Self::PolicyPublish
    }
}

impl TryFrom<u32> for PolicyAuthorityRequestName {
    type Error = PolicyAuthorityRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PolicyPublish),
            1 => Ok(Self::PolicyLookup),
            2 => Ok(Self::OverrideIssue),
            3 => Ok(Self::OverrideValidate),
            4 => Ok(Self::OverrideRevoke),
            5 => Ok(Self::BudgetDomainPublish),
            6 => Ok(Self::BudgetDomainQuote),
            7 => Ok(Self::BudgetDomainAdjust),
            8 => Ok(Self::ProductRecipePublish),
            9 => Ok(Self::ProductAdmissionManual),
            10 => Ok(Self::ProductReclaimManual),
            _ => Err(PolicyAuthorityRecordDecodeError::InvalidRequestName(value)),
        }
    }
}

pub const POLICY_AUTHORITY_FIRST_MANUAL_ADMISSION_STAGE_CHAIN: &[PolicyAuthorityStageClass] = &[
    PolicyAuthorityStageClass::CanonicalizeRequest,
    PolicyAuthorityStageClass::FreezeAnchorSet,
    PolicyAuthorityStageClass::BindDomainShard,
    PolicyAuthorityStageClass::ResolvePolicyOverrideBudget,
    PolicyAuthorityStageClass::EvaluateProductDecision,
    PolicyAuthorityStageClass::IssueSuccessorOrAnswerPlan,
];

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PolicyAuthorityStageClass {
    IngressBind = 0,
    CanonicalizeRequest = 1,
    FreezeAnchorSet = 2,
    BindDomainShard = 3,
    ResolvePolicyOverrideBudget = 4,
    EvaluateProductDecision = 5,
    IssueSuccessorOrAnswerPlan = 6,
    BridgePublicationPipelineSchemaCodecResponseRegistry = 7,
}

impl PolicyAuthorityStageClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IngressBind => "stage.policy_authority.ingress_bind.h0",
            Self::CanonicalizeRequest => "stage.policy_authority.canonicalize_request.h1",
            Self::FreezeAnchorSet => "stage.policy_authority.freeze_anchor_set.h2",
            Self::BindDomainShard => "stage.policy_authority.bind_domain_shard.h3",
            Self::ResolvePolicyOverrideBudget => "stage.policy_authority.resolve_policy_override_budget.h4",
            Self::EvaluateProductDecision => "stage.policy_authority.evaluate_product_decision.h5",
            Self::IssueSuccessorOrAnswerPlan => "stage.policy_authority.issue_successor_or_answer_plan.h6",
            Self::BridgePublicationPipelineSchemaCodecResponseRegistry => "stage.policy_authority.bridge_publication_pipeline_schema_codec_response_registry.h7",
        }
    }
}

impl Default for PolicyAuthorityStageClass {
    fn default() -> Self {
        Self::IngressBind
    }
}

impl TryFrom<u32> for PolicyAuthorityStageClass {
    type Error = PolicyAuthorityRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::IngressBind),
            1 => Ok(Self::CanonicalizeRequest),
            2 => Ok(Self::FreezeAnchorSet),
            3 => Ok(Self::BindDomainShard),
            4 => Ok(Self::ResolvePolicyOverrideBudget),
            5 => Ok(Self::EvaluateProductDecision),
            6 => Ok(Self::IssueSuccessorOrAnswerPlan),
            7 => Ok(Self::BridgePublicationPipelineSchemaCodecResponseRegistry),
            _ => Err(PolicyAuthorityRecordDecodeError::InvalidStageClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PolicyAuthorityRefusalClass {
    AuthzOrSession = 0,
    AnchorStale = 1,
    IdempotencyConflict = 2,
    PolicyOrSecretMissing = 3,
    OverrideInvalid = 4,
    BudgetOrProductDenied = 5,
    StopOrQuarantine = 6,
}

impl PolicyAuthorityRefusalClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthzOrSession => "refusal.policy_authority.authz_or_session.r0",
            Self::AnchorStale => "refusal.policy_authority.anchor_stale.r1",
            Self::IdempotencyConflict => "refusal.policy_authority.idempotency_conflict.r2",
            Self::PolicyOrSecretMissing => "refusal.policy_authority.policy_or_secret_missing.r3",
            Self::OverrideInvalid => "refusal.policy_authority.override_invalid.r4",
            Self::BudgetOrProductDenied => "refusal.policy_authority.budget_or_product_denied.r5",
            Self::StopOrQuarantine => "refusal.policy_authority.stop_or_quarantine.r6",
        }
    }
}

impl Default for PolicyAuthorityRefusalClass {
    fn default() -> Self {
        Self::AuthzOrSession
    }
}

impl TryFrom<u32> for PolicyAuthorityRefusalClass {
    type Error = PolicyAuthorityRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::AuthzOrSession),
            1 => Ok(Self::AnchorStale),
            2 => Ok(Self::IdempotencyConflict),
            3 => Ok(Self::PolicyOrSecretMissing),
            4 => Ok(Self::OverrideInvalid),
            5 => Ok(Self::BudgetOrProductDenied),
            6 => Ok(Self::StopOrQuarantine),
            _ => Err(PolicyAuthorityRecordDecodeError::InvalidRefusalClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PolicyAuthorityDecisionClass {
    Admit = 0,
    Refuse = 1,
}

impl PolicyAuthorityDecisionClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "decision.policy_authority.admit.k0",
            Self::Refuse => "decision.policy_authority.refuse.k1",
        }
    }
}

impl Default for PolicyAuthorityDecisionClass {
    fn default() -> Self {
        Self::Admit
    }
}

impl TryFrom<u32> for PolicyAuthorityDecisionClass {
    type Error = PolicyAuthorityRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Admit),
            1 => Ok(Self::Refuse),
            _ => Err(PolicyAuthorityRecordDecodeError::InvalidDecisionClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PolicyAuthorityAnswerPlanKind {
    PublishMutation = 0,
    RefusalAnswer = 1,
}

impl PolicyAuthorityAnswerPlanKind {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublishMutation => "plan.policy_authority.publish_mutation.k0",
            Self::RefusalAnswer => "plan.policy_authority.refusal_answer.k1",
        }
    }
}

impl Default for PolicyAuthorityAnswerPlanKind {
    fn default() -> Self {
        Self::PublishMutation
    }
}

impl TryFrom<u32> for PolicyAuthorityAnswerPlanKind {
    type Error = PolicyAuthorityRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PublishMutation),
            1 => Ok(Self::RefusalAnswer),
            _ => Err(PolicyAuthorityRecordDecodeError::InvalidAnswerPlanKind(
                value,
            )),
        }
    }
}

pub const POLICY_AUTHORITY_REFUSAL_CLASS_NONE: u32 = u32::MAX;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PolicyAuthorityWitnessJoinClass {
    PolicyBudgetRecipe = 0,
}

impl PolicyAuthorityWitnessJoinClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyBudgetRecipe => "join.policy_authority.policy_budget_recipe.w0",
        }
    }
}

impl Default for PolicyAuthorityWitnessJoinClass {
    fn default() -> Self {
        Self::PolicyBudgetRecipe
    }
}

impl TryFrom<u32> for PolicyAuthorityWitnessJoinClass {
    type Error = PolicyAuthorityRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PolicyBudgetRecipe),
            _ => Err(PolicyAuthorityRecordDecodeError::InvalidWitnessJoinClass(
                value,
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PolicyAuthorityRecordDecodeError {
    InvalidRequestName(u32),
    InvalidIngressSurfaceClass(u32),
    InvalidShardClass(u32),
    InvalidCapsuleClass(u32),
    InvalidStageClass(u32),
    InvalidRefusalClass(u32),
    InvalidDecisionClass(u32),
    InvalidAnswerPlanKind(u32),
    InvalidWitnessJoinClass(u32),
}

fn decode_request_name(
    value: u32,
) -> Result<PolicyAuthorityRequestName, PolicyAuthorityRecordDecodeError> {
    PolicyAuthorityRequestName::try_from(value)
        .map_err(|_| PolicyAuthorityRecordDecodeError::InvalidRequestName(value))
}

fn decode_ingress_surface_class(
    value: u32,
) -> Result<PolicyAuthorityIngressSurfaceClass, PolicyAuthorityRecordDecodeError> {
    PolicyAuthorityIngressSurfaceClass::try_from(value)
        .map_err(|_| PolicyAuthorityRecordDecodeError::InvalidIngressSurfaceClass(value))
}

fn decode_shard_class(
    value: u32,
) -> Result<PolicyAuthorityShardClass, PolicyAuthorityRecordDecodeError> {
    PolicyAuthorityShardClass::try_from(value)
        .map_err(|_| PolicyAuthorityRecordDecodeError::InvalidShardClass(value))
}

fn decode_capsule_class(
    value: u32,
) -> Result<PolicyAuthorityCapsuleClass, PolicyAuthorityRecordDecodeError> {
    PolicyAuthorityCapsuleClass::try_from(value)
        .map_err(|_| PolicyAuthorityRecordDecodeError::InvalidCapsuleClass(value))
}

fn decode_stage_class(
    value: u32,
) -> Result<PolicyAuthorityStageClass, PolicyAuthorityRecordDecodeError> {
    PolicyAuthorityStageClass::try_from(value)
        .map_err(|_| PolicyAuthorityRecordDecodeError::InvalidStageClass(value))
}

fn decode_refusal_class(
    value: u32,
) -> Result<PolicyAuthorityRefusalClass, PolicyAuthorityRecordDecodeError> {
    PolicyAuthorityRefusalClass::try_from(value)
        .map_err(|_| PolicyAuthorityRecordDecodeError::InvalidRefusalClass(value))
}

fn decode_optional_refusal_class(
    value: u32,
) -> Result<Option<PolicyAuthorityRefusalClass>, PolicyAuthorityRecordDecodeError> {
    if value == POLICY_AUTHORITY_REFUSAL_CLASS_NONE {
        Ok(None)
    } else {
        decode_refusal_class(value).map(Some)
    }
}

fn decode_decision_class(
    value: u32,
) -> Result<PolicyAuthorityDecisionClass, PolicyAuthorityRecordDecodeError> {
    PolicyAuthorityDecisionClass::try_from(value)
        .map_err(|_| PolicyAuthorityRecordDecodeError::InvalidDecisionClass(value))
}

fn decode_answer_plan_kind(
    value: u32,
) -> Result<PolicyAuthorityAnswerPlanKind, PolicyAuthorityRecordDecodeError> {
    PolicyAuthorityAnswerPlanKind::try_from(value)
        .map_err(|_| PolicyAuthorityRecordDecodeError::InvalidAnswerPlanKind(value))
}

fn decode_witness_join_class(
    value: u32,
) -> Result<PolicyAuthorityWitnessJoinClass, PolicyAuthorityRecordDecodeError> {
    PolicyAuthorityWitnessJoinClass::try_from(value)
        .map_err(|_| PolicyAuthorityRecordDecodeError::InvalidWitnessJoinClass(value))
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyAuthorityRequestCapsuleRecord {
    pub capsule_id: ControlPlaneId128,
    pub request_id: ControlPlaneRequestId,
    pub source_journal_id: ControlPlaneJournalId,
    pub request_name: u32,
    pub ingress_surface_class: u32,
    pub primary_shard_class: u32,
    pub capsule_class: u32,
    pub _reserved0: u32,
    pub idempotency_key: ControlPlaneIdempotencyKey,
    pub product_recipe_digest: ControlPlaneDigest32,
    pub subject_scope_digest: ControlPlaneDigest32,
    pub required_anchor_set_id: ControlPlaneId128,
    pub budget_domain_id: ControlPlaneId128,
}

impl PolicyAuthorityRequestCapsuleRecord {
    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn request_name(
        self,
    ) -> Result<PolicyAuthorityRequestName, PolicyAuthorityRecordDecodeError> {
        decode_request_name(self.request_name)
    }

    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn ingress_surface(
        self,
    ) -> Result<PolicyAuthorityIngressSurfaceClass, PolicyAuthorityRecordDecodeError> {
        decode_ingress_surface_class(self.ingress_surface_class)
    }

    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn primary_shard(
        self,
    ) -> Result<PolicyAuthorityShardClass, PolicyAuthorityRecordDecodeError> {
        decode_shard_class(self.primary_shard_class)
    }

    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn capsule_class(
        self,
    ) -> Result<PolicyAuthorityCapsuleClass, PolicyAuthorityRecordDecodeError> {
        decode_capsule_class(self.capsule_class)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyAuthorityAnchorFreezeRecord {
    pub freeze_id: ControlPlaneId128,
    pub request_id: ControlPlaneRequestId,
    pub source_journal_id: ControlPlaneJournalId,
    pub stage_class: u32,
    pub refusal_class_or_none: u32,
    pub primary_shard_class: u32,
    pub _reserved0: u32,
    pub required_anchor_set_id: ControlPlaneId128,
    pub frozen_anchor_set_id: ControlPlaneId128,
    pub budget_domain_id: ControlPlaneId128,
    pub subject_scope_digest: ControlPlaneDigest32,
}

impl PolicyAuthorityAnchorFreezeRecord {
    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn stage(self) -> Result<PolicyAuthorityStageClass, PolicyAuthorityRecordDecodeError> {
        decode_stage_class(self.stage_class)
    }

    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn refusal_class(
        self,
    ) -> Result<Option<PolicyAuthorityRefusalClass>, PolicyAuthorityRecordDecodeError> {
        decode_optional_refusal_class(self.refusal_class_or_none)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyAuthorityEvaluationPlanRecord {
    pub plan_id: ControlPlaneId128,
    pub request_id: ControlPlaneRequestId,
    pub source_journal_id: ControlPlaneJournalId,
    pub freeze_id: ControlPlaneId128,
    pub stage_class: u32,
    pub decision_class: u32,
    pub refusal_class_or_none: u32,
    pub primary_shard_class: u32,
    pub product_recipe_digest: ControlPlaneDigest32,
    pub subject_scope_digest: ControlPlaneDigest32,
    pub budget_domain_id: ControlPlaneId128,
}

impl PolicyAuthorityEvaluationPlanRecord {
    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn stage(self) -> Result<PolicyAuthorityStageClass, PolicyAuthorityRecordDecodeError> {
        decode_stage_class(self.stage_class)
    }

    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn decision(
        self,
    ) -> Result<PolicyAuthorityDecisionClass, PolicyAuthorityRecordDecodeError> {
        decode_decision_class(self.decision_class)
    }
    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn refusal_class(
        self,
    ) -> Result<Option<PolicyAuthorityRefusalClass>, PolicyAuthorityRecordDecodeError> {
        decode_optional_refusal_class(self.refusal_class_or_none)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyAuthoritySuccessorOrAnswerPlanRecord {
    pub answer_plan_id: ControlPlaneId128,
    pub request_id: ControlPlaneRequestId,
    pub source_journal_id: ControlPlaneJournalId,
    pub stage_class: u32,
    pub answer_plan_kind: u32,
    pub refusal_class_or_none: u32,
    pub primary_shard_class: u32,
    pub _reserved0: u32,
    pub outcome_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
}

impl PolicyAuthoritySuccessorOrAnswerPlanRecord {
    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn stage(self) -> Result<PolicyAuthorityStageClass, PolicyAuthorityRecordDecodeError> {
        decode_stage_class(self.stage_class)
    }

    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn answer_plan_kind(
        self,
    ) -> Result<PolicyAuthorityAnswerPlanKind, PolicyAuthorityRecordDecodeError> {
        decode_answer_plan_kind(self.answer_plan_kind)
    }

    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn refusal_class(
        self,
    ) -> Result<Option<PolicyAuthorityRefusalClass>, PolicyAuthorityRecordDecodeError> {
        decode_optional_refusal_class(self.refusal_class_or_none)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyAuthorityPolicyBudgetRecipeWitnessJoinRecord {
    pub witness_join_id: ControlPlaneId128,
    pub request_id: ControlPlaneRequestId,
    pub source_journal_id: ControlPlaneJournalId,
    pub freeze_id: ControlPlaneId128,
    pub answer_plan_id: ControlPlaneId128,
    pub primary_shard_class: u32,
    pub witness_join_class: u32,
    pub _reserved0: u32,
    pub _reserved1: u32,
    pub policy_witness_id: ControlPlaneId128,
    pub budget_witness_id: ControlPlaneId128,
    pub recipe_witness_id: ControlPlaneId128,
    pub policy_digest: ControlPlaneDigest32,
    pub budget_digest: ControlPlaneDigest32,
    pub recipe_digest: ControlPlaneDigest32,
    pub witness_join_digest: ControlPlaneDigest32,
}

impl PolicyAuthorityPolicyBudgetRecipeWitnessJoinRecord {
    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn primary_shard(
        self,
    ) -> Result<PolicyAuthorityShardClass, PolicyAuthorityRecordDecodeError> {
        decode_shard_class(self.primary_shard_class)
    }

    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn witness_join_class(
        self,
    ) -> Result<PolicyAuthorityWitnessJoinClass, PolicyAuthorityRecordDecodeError> {
        decode_witness_join_class(self.witness_join_class)
    }

    #[must_use]
    pub const fn receipt_refs(&self) -> ControlPlanePolicyBudgetRecipeWitnessRefs {
        ControlPlanePolicyBudgetRecipeWitnessRefs::new(
            self.witness_join_id,
            self.policy_witness_id,
            self.budget_witness_id,
            self.recipe_witness_id,
            self.witness_join_digest,
        )
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyAuthorityStopOrRefusalRecord {
    pub refusal_id: ControlPlaneId128,
    pub request_id: ControlPlaneRequestId,
    pub source_journal_id: ControlPlaneJournalId,
    pub stage_class: u32,
    pub refusal_class: u32,
    pub _reserved0: u64,
    pub outcome_digest: ControlPlaneDigest32,
}

impl PolicyAuthorityStopOrRefusalRecord {
    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn stage(self) -> Result<PolicyAuthorityStageClass, PolicyAuthorityRecordDecodeError> {
        decode_stage_class(self.stage_class)
    }

    /// # Errors
    ///
    /// Returns [`PolicyAuthorityRecordDecodeError`] on failure.
    pub fn refusal_class(
        self,
    ) -> Result<PolicyAuthorityRefusalClass, PolicyAuthorityRecordDecodeError> {
        decode_refusal_class(self.refusal_class)
    }
}

const _: [(); 180] = [(); core::mem::size_of::<PolicyAuthorityRequestCapsuleRecord>()];
const _: [(); 144] = [(); core::mem::size_of::<PolicyAuthorityAnchorFreezeRecord>()];
const _: [(); 160] = [(); core::mem::size_of::<PolicyAuthorityEvaluationPlanRecord>()];
const _: [(); 132] = [(); core::mem::size_of::<PolicyAuthoritySuccessorOrAnswerPlanRecord>()];
const _: [(); 272] =
    [(); core::mem::size_of::<PolicyAuthorityPolicyBudgetRecipeWitnessJoinRecord>()];
const _: [(); 96] = [(); core::mem::size_of::<PolicyAuthorityStopOrRefusalRecord>()];
// ── Publication Pipeline types (from tidefs-types-publication-pipeline-core) ──

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineDecodeError {
    UnknownQueueClass(u32),
    UnknownBatchClass(u32),
    UnknownEmissionTicketKind(u32),
    UnknownSealTriggerClass(u32),
    UnknownPersistenceTaskClass(u32),
    UnknownStopTriggerClass(u32),
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineQueueClass {
    Ingress = 0,
    Prepare = 1,
    Batch = 2,
    Commit = 3,
    Progress = 4,
    ProductWake = 5,
    EmitTicket = 6,
    Recovery = 7,
}

impl PublicationPipelineQueueClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "queue.publication_pipeline.ingress.q0",
            Self::Prepare => "queue.publication_pipeline.prepare.q1",
            Self::Batch => "queue.publication_pipeline.batch.q2",
            Self::Commit => "queue.publication_pipeline.commit.q3",
            Self::Progress => "queue.publication_pipeline.progress.q4",
            Self::ProductWake => "queue.publication_pipeline.product_wake.q5",
            Self::EmitTicket => "queue.publication_pipeline.emit_ticket.q6",
            Self::Recovery => "queue.publication_pipeline.recovery.q7",
        }
    }
}

impl Default for PublicationPipelineQueueClass {
    fn default() -> Self {
        Self::Ingress
    }
}

impl TryFrom<u32> for PublicationPipelineQueueClass {
    type Error = PublicationPipelineDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ingress),
            1 => Ok(Self::Prepare),
            2 => Ok(Self::Batch),
            3 => Ok(Self::Commit),
            4 => Ok(Self::Progress),
            5 => Ok(Self::ProductWake),
            6 => Ok(Self::EmitTicket),
            7 => Ok(Self::Recovery),
            _ => Err(PublicationPipelineDecodeError::UnknownQueueClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineBatchClass {
    SingleDomain = 0,
    SyncForced = 1,
    ClusterCommitGroup = 2,
    PolicyOrGovernance = 3,
    FailoverOrStage = 4,
    MultiDomainExpensive = 5,
}

impl PublicationPipelineBatchClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleDomain => "batch.publication_pipeline.single_domain.b0",
            Self::SyncForced => "batch.publication_pipeline.sync_forced.b1",
            Self::ClusterCommitGroup => "batch.publication_pipeline.cluster_commit_group.b2",
            Self::PolicyOrGovernance => "batch.publication_pipeline.policy_or_governance.b3",
            Self::FailoverOrStage => "batch.publication_pipeline.failover_or_stage.b4",
            Self::MultiDomainExpensive => "batch.publication_pipeline.multi_domain_expensive.b5",
        }
    }
}

impl Default for PublicationPipelineBatchClass {
    fn default() -> Self {
        Self::SingleDomain
    }
}

impl TryFrom<u32> for PublicationPipelineBatchClass {
    type Error = PublicationPipelineDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SingleDomain),
            1 => Ok(Self::SyncForced),
            2 => Ok(Self::ClusterCommitGroup),
            3 => Ok(Self::PolicyOrGovernance),
            4 => Ok(Self::FailoverOrStage),
            5 => Ok(Self::MultiDomainExpensive),
            _ => Err(PublicationPipelineDecodeError::UnknownBatchClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineEmissionTicketKind {
    ControlWriteMutation = 0,
}

impl PublicationPipelineEmissionTicketKind {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ControlWriteMutation => "ticket.publication_pipeline.control_write_mutation.t0",
        }
    }
}

impl Default for PublicationPipelineEmissionTicketKind {
    fn default() -> Self {
        Self::ControlWriteMutation
    }
}

impl TryFrom<u32> for PublicationPipelineEmissionTicketKind {
    type Error = PublicationPipelineDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ControlWriteMutation),
            _ => Err(PublicationPipelineDecodeError::UnknownEmissionTicketKind(
                value,
            )),
        }
    }
}

// ── Seal-trigger classes (P3-02 §3, s0-s6) ──────────────────────────

/// P3-02 §3 seal-trigger taxonomy: the seven conditions that force a batch
/// to seal and proceed to commit cut.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineSealTriggerClass {
    /// s0 — op-count threshold (default: 256 ops)
    TargetOps = 0,
    /// s1 — time threshold (default: 10 ms)
    TargetSeconds = 1,
    /// s2 — dirty-bytes threshold (default: 256 KiB)
    TargetBytes = 2,
    /// s3 — hard dirty cap (default: 1 GiB)
    DirtyMaxBytes = 3,
    /// s4 — caller barrier: fsync / fdatasync / fsyncdata
    CallerBarrier = 4,
    /// s5 — runbook stage fence or failover cut
    RunbookOrFailover = 5,
    /// s6 — checkpoint or snapshot boundary
    CheckpointOrCursor = 6,
}

impl PublicationPipelineSealTriggerClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetOps => "seal.publication_pipeline.target_ops.s0",
            Self::TargetSeconds => "seal.publication_pipeline.target_seconds.s1",
            Self::TargetBytes => "seal.publication_pipeline.target_bytes.s2",
            Self::DirtyMaxBytes => "seal.publication_pipeline.dirty_max_bytes.s3",
            Self::CallerBarrier => "seal.publication_pipeline.caller_barrier.s4",
            Self::RunbookOrFailover => "seal.publication_pipeline.runbook_or_failover.s5",
            Self::CheckpointOrCursor => "seal.publication_pipeline.checkpoint_or_cursor.s6",
        }
    }
}

impl Default for PublicationPipelineSealTriggerClass {
    fn default() -> Self {
        Self::TargetOps
    }
}

impl From<PublicationPipelineSealTriggerClass> for u32 {
    fn from(v: PublicationPipelineSealTriggerClass) -> Self {
        v.as_u32()
    }
}

impl TryFrom<u32> for PublicationPipelineSealTriggerClass {
    type Error = PublicationPipelineDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::TargetOps),
            1 => Ok(Self::TargetSeconds),
            2 => Ok(Self::TargetBytes),
            3 => Ok(Self::DirtyMaxBytes),
            4 => Ok(Self::CallerBarrier),
            5 => Ok(Self::RunbookOrFailover),
            6 => Ok(Self::CheckpointOrCursor),
            _ => Err(PublicationPipelineDecodeError::UnknownSealTriggerClass(
                value,
            )),
        }
    }
}

// ── Persistence-task classes (P3-02 §5, t0-t9) ───────────────────────

/// P3-02 §5 persistence-task taxonomy: the ten durable-task classes that
/// must survive restart or failover.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelinePersistenceTaskClass {
    /// t0 — commit-cut persistence
    CommitCut = 0,
    /// t1 — replica cursor advance
    ReplicaCursor = 1,
    /// t2 — product cache invalidation
    ProductCache = 2,
    /// t3 — view / truth-surface invalidation
    ViewInvalidation = 3,
    /// t4 — fence / barrier release
    FenceRelease = 4,
    /// t5 — transport-session progress cursor (consumes transport_session_0)
    TransportProgressCursor = 5,
    /// t6 — checkpoint / snapshot cursor write
    CheckpointCursor = 6,
    /// t7 — emission ticket persistence
    EmissionTicket = 7,
    /// t8 — recovery marker write
    RecoveryMarker = 8,
    /// t9 — archive / validation hold
    ArchiveHold = 9,
}

impl PublicationPipelinePersistenceTaskClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommitCut => "task.publication_pipeline.commit_cut.t0",
            Self::ReplicaCursor => "task.publication_pipeline.replica_cursor.t1",
            Self::ProductCache => "task.publication_pipeline.product_cache.t2",
            Self::ViewInvalidation => "task.publication_pipeline.view_invalidation.t3",
            Self::FenceRelease => "task.publication_pipeline.fence_release.t4",
            Self::TransportProgressCursor => {
                "task.publication_pipeline.transport_progress_cursor.t5"
            }
            Self::CheckpointCursor => "task.publication_pipeline.checkpoint_cursor.t6",
            Self::EmissionTicket => "task.publication_pipeline.emission_ticket.t7",
            Self::RecoveryMarker => "task.publication_pipeline.recovery_marker.t8",
            Self::ArchiveHold => "task.publication_pipeline.archive_hold.t9",
        }
    }
}

impl Default for PublicationPipelinePersistenceTaskClass {
    fn default() -> Self {
        Self::CommitCut
    }
}

impl From<PublicationPipelinePersistenceTaskClass> for u32 {
    fn from(v: PublicationPipelinePersistenceTaskClass) -> Self {
        v.as_u32()
    }
}

impl TryFrom<u32> for PublicationPipelinePersistenceTaskClass {
    type Error = PublicationPipelineDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CommitCut),
            1 => Ok(Self::ReplicaCursor),
            2 => Ok(Self::ProductCache),
            3 => Ok(Self::ViewInvalidation),
            4 => Ok(Self::FenceRelease),
            5 => Ok(Self::TransportProgressCursor),
            6 => Ok(Self::CheckpointCursor),
            7 => Ok(Self::EmissionTicket),
            8 => Ok(Self::RecoveryMarker),
            9 => Ok(Self::ArchiveHold),
            _ => Err(PublicationPipelineDecodeError::UnknownPersistenceTaskClass(
                value,
            )),
        }
    }
}

// ── Stop-trigger classes (P3-02 §8) ───────────────────────────────────

/// P3-02 §8: typed refusal/hold/rollback conditions.
/// When one fires, the result is not a warning — it is a typed stop.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineStopTrigger {
    /// batch reached hard capacity without a legal seal
    BatchCapacityExceeded = 0,
    /// membership anchor, epoch, or cut precondition changed before h5
    MembershipAnchorChanged = 1,
    /// commit cut happened but progress state is ambiguous
    ProgressUncertain = 2,
    /// committed cut lacks required emission ticket
    EmissionTicketGap = 3,
    /// restart/failover cannot classify in-flight work
    RecoveryUnknown = 4,
}

impl PublicationPipelineStopTrigger {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BatchCapacityExceeded => "stop.publication_pipeline.batch_capacity_exceeded",
            Self::MembershipAnchorChanged => "stop.publication_pipeline.membership_anchor_changed",
            Self::ProgressUncertain => "stop.publication_pipeline.progress_uncertain",
            Self::EmissionTicketGap => "stop.publication_pipeline.emission_ticket_gap",
            Self::RecoveryUnknown => "stop.publication_pipeline.recovery_unknown",
        }
    }
}

impl Default for PublicationPipelineStopTrigger {
    fn default() -> Self {
        Self::BatchCapacityExceeded
    }
}

impl From<PublicationPipelineStopTrigger> for u32 {
    fn from(v: PublicationPipelineStopTrigger) -> Self {
        v.as_u32()
    }
}

impl TryFrom<u32> for PublicationPipelineStopTrigger {
    type Error = PublicationPipelineDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::BatchCapacityExceeded),
            1 => Ok(Self::MembershipAnchorChanged),
            2 => Ok(Self::ProgressUncertain),
            3 => Ok(Self::EmissionTicketGap),
            4 => Ok(Self::RecoveryUnknown),
            _ => Err(PublicationPipelineDecodeError::UnknownStopTriggerClass(
                value,
            )),
        }
    }
}

// ── Publication stage marker (P3-02 §4, h0-h9) ───────────────────────

/// P3-02 canonical 10-stage publication chain.
/// h0 normalizes intent, h9 recovers or retires.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineStage {
    /// h0 — normalize intent
    NormalizeIntent = 0,
    /// h1 — freeze anchor set
    FreezeAnchorSet = 1,
    /// h2 — prepare work item
    PrepareWorkItem = 2,
    /// h3 — join batch
    JoinBatch = 3,
    /// h4 — seal batch
    SealBatch = 4,
    /// h5 — commit cut
    CommitCut = 5,
    /// h6 — persist progress cursor
    PersistProgressCursor = 6,
    /// h7 — emit wake tasks
    EmitWakeTasks = 7,
    /// h8 — issue emission ticket
    IssueEmissionTicket = 8,
    /// h9 — recover or retire
    RecoverOrRetire = 9,
}

impl PublicationPipelineStage {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NormalizeIntent => "stage.publication_pipeline.normalize_intent.h0",
            Self::FreezeAnchorSet => "stage.publication_pipeline.freeze_anchor_set.h1",
            Self::PrepareWorkItem => "stage.publication_pipeline.prepare_work_item.h2",
            Self::JoinBatch => "stage.publication_pipeline.join_batch.h3",
            Self::SealBatch => "stage.publication_pipeline.seal_batch.h4",
            Self::CommitCut => "stage.publication_pipeline.commit_cut.h5",
            Self::PersistProgressCursor => "stage.publication_pipeline.persist_progress_cursor.h6",
            Self::EmitWakeTasks => "stage.publication_pipeline.emit_wake_tasks.h7",
            Self::IssueEmissionTicket => "stage.publication_pipeline.issue_emission_ticket.h8",
            Self::RecoverOrRetire => "stage.publication_pipeline.recover_or_retire.h9",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationPipelineEmissionTicketInput {
    pub ticket_id: ControlPlaneId128,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub primary_shard_class: u32,
    pub queue_class: PublicationPipelineQueueClass,
    pub batch_class: PublicationPipelineBatchClass,
    pub ticket_kind: PublicationPipelineEmissionTicketKind,
    pub freeze_id: ControlPlaneId128,
    pub answer_plan_id: ControlPlaneId128,
    pub render_receipt_seed: ControlPlaneReceiptId,
    pub outcome_digest: ControlPlaneDigest32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PublicationPipelineEmissionTicketRecord {
    pub ticket_id: ControlPlaneId128,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub primary_shard_class: u32,
    pub queue_class: u32,
    pub batch_class: u32,
    pub ticket_kind: u32,
    pub _reserved0: u32,
    pub freeze_id: ControlPlaneId128,
    pub answer_plan_id: ControlPlaneId128,
    pub render_receipt_seed: ControlPlaneReceiptId,
    pub outcome_digest: ControlPlaneDigest32,
}

impl PublicationPipelineEmissionTicketRecord {
    #[must_use]
    pub const fn new(input: PublicationPipelineEmissionTicketInput) -> Self {
        Self {
            ticket_id: input.ticket_id,
            request_id: input.request_id,
            journal_id: input.journal_id,
            primary_shard_class: input.primary_shard_class,
            queue_class: input.queue_class.as_u32(),
            batch_class: input.batch_class.as_u32(),
            ticket_kind: input.ticket_kind.as_u32(),
            _reserved0: 0,
            freeze_id: input.freeze_id,
            answer_plan_id: input.answer_plan_id,
            render_receipt_seed: input.render_receipt_seed,
            outcome_digest: input.outcome_digest,
        }
    }

    /// # Errors
    ///
    /// Returns [`PublicationPipelineDecodeError::UnknownQueueClass`] if the stored
    /// raw tag does not correspond to a valid publication pipeline queue class.
    pub fn queue(self) -> Result<PublicationPipelineQueueClass, PublicationPipelineDecodeError> {
        PublicationPipelineQueueClass::try_from(self.queue_class)
    }

    /// # Errors
    ///
    /// Returns [`PublicationPipelineDecodeError::UnknownBatchClass`] if the stored
    /// raw tag does not correspond to a valid publication pipeline batch class.
    pub fn batch(self) -> Result<PublicationPipelineBatchClass, PublicationPipelineDecodeError> {
        PublicationPipelineBatchClass::try_from(self.batch_class)
    }

    /// # Errors
    ///
    /// Returns [`PublicationPipelineDecodeError::UnknownEmissionTicketKind`] if the stored
    /// raw tag does not correspond to a valid emission ticket kind.
    pub fn ticket_kind(
        self,
    ) -> Result<PublicationPipelineEmissionTicketKind, PublicationPipelineDecodeError> {
        PublicationPipelineEmissionTicketKind::try_from(self.ticket_kind)
    }
}

const _: [(); 148] = [(); core::mem::size_of::<PublicationPipelineEmissionTicketRecord>()];
// ── Response Registry types (from tidefs-types-response-registry-core) ──

pub const RESPONSE_REGISTRY_REFUSAL_CLASS_NONE: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseRegistryRecordDecodeError {
    InvalidRouteClass(u32),
    InvalidIndexClass(u32),
    InvalidRetentionClass(u32),
    InvalidDisclosureClass(u32),
    InvalidAnswerKind(u32),
    InvalidRefusalClass(u32),
    InvalidScopeClass(u32),
    InvalidCutClass(u32),
    InvalidRenderClass(u32),
}

fn decode_rr_route_class(
    value: u32,
) -> Result<ControlPlaneRouteClass, ResponseRegistryRecordDecodeError> {
    ControlPlaneRouteClass::try_from(value)
        .map_err(|_| ResponseRegistryRecordDecodeError::InvalidRouteClass(value))
}

fn decode_rr_index_class(
    value: u32,
) -> Result<ResponseRegistryIndexClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryIndexClass::try_from(value)
}

fn decode_rr_retention_class(
    value: u32,
) -> Result<ResponseRegistryRetentionClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryRetentionClass::try_from(value)
}

fn decode_rr_disclosure_class(
    value: u32,
) -> Result<ResponseRegistryDisclosureClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryDisclosureClass::try_from(value)
}

fn decode_rr_answer_kind(
    value: u32,
) -> Result<ResponseRegistryAnswerKind, ResponseRegistryRecordDecodeError> {
    ResponseRegistryAnswerKind::try_from(value)
}

fn decode_rr_refusal_class(
    value: u32,
) -> Result<ResponseRegistryRefusalClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryRefusalClass::try_from(value)
}

fn decode_rr_scope_class(
    value: u32,
) -> Result<ResponseRegistryScopeClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryScopeClass::try_from(value)
}

fn decode_rr_cut_class(
    value: u32,
) -> Result<ResponseRegistryCutClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryCutClass::try_from(value)
}

fn decode_rr_render_class(
    value: u32,
) -> Result<ResponseRegistryRenderClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryRenderClass::try_from(value)
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryScopeClass {
    CharterRead = 0,
    CharterMutation = 1,
    ControlWrite = 2,
    ControlRead = 3,
    RunbookStage = 4,
    TruthOrRecall = 5,
    ShadowOrGate = 6,
    TestOrCampaign = 7,
}

impl ResponseRegistryScopeClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CharterRead => "scope.response_registry.charter.read.s0",
            Self::CharterMutation => "scope.response_registry.charter.mutation.s1",
            Self::ControlWrite => "scope.response_registry.control.write.s2",
            Self::ControlRead => "scope.response_registry.control.read.s3",
            Self::RunbookStage => "scope.response_registry.runbook.stage.s4",
            Self::TruthOrRecall => "scope.response_registry.truth_or_recall.s5",
            Self::ShadowOrGate => "scope.response_registry.shadow_or_gate.s6",
            Self::TestOrCampaign => "scope.response_registry.test_or_campaign.s7",
        }
    }
}

impl Default for ResponseRegistryScopeClass {
    fn default() -> Self {
        Self::CharterRead
    }
}

impl TryFrom<u32> for ResponseRegistryScopeClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CharterRead),
            1 => Ok(Self::CharterMutation),
            2 => Ok(Self::ControlWrite),
            3 => Ok(Self::ControlRead),
            4 => Ok(Self::RunbookStage),
            5 => Ok(Self::TruthOrRecall),
            6 => Ok(Self::ShadowOrGate),
            7 => Ok(Self::TestOrCampaign),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidScopeClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryCutClass {
    CommittedAuthority = 0,
    ReadAnchorExact = 1,
    ReadAnchorDegraded = 2,
    StopOrRefusal = 3,
    RecallArchive = 4,
}

impl ResponseRegistryCutClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommittedAuthority => "cut.response_registry.committed_authority.c0",
            Self::ReadAnchorExact => "cut.response_registry.read_anchor_exact.c1",
            Self::ReadAnchorDegraded => "cut.response_registry.read_anchor_degraded.c2",
            Self::StopOrRefusal => "cut.response_registry.stop_or_refusal.c3",
            Self::RecallArchive => "cut.response_registry.recall_archive.c4",
        }
    }
}

impl Default for ResponseRegistryCutClass {
    fn default() -> Self {
        Self::CommittedAuthority
    }
}

impl TryFrom<u32> for ResponseRegistryCutClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CommittedAuthority),
            1 => Ok(Self::ReadAnchorExact),
            2 => Ok(Self::ReadAnchorDegraded),
            3 => Ok(Self::StopOrRefusal),
            4 => Ok(Self::RecallArchive),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidCutClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryRenderClass {
    PosixFilesystemAdapterWire = 0,
    BlockVolumeAdapterCompletion = 1,
    ControlPlaneJsonRpc = 2,
    ExplanationQueryFieldset = 3,
    TruthViewBundle = 4,
    ValidationPreservationRecall = 5,
    TestCampaignReport = 6,
    RefusalOnly = 7,
}

impl ResponseRegistryRenderClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PosixFilesystemAdapterWire => {
                "render.response_registry.posix_filesystem_adapter_wire.r0"
            }
            Self::BlockVolumeAdapterCompletion => {
                "render.response_registry.block_volume_adapter_completion.r1"
            }
            Self::ControlPlaneJsonRpc => "render.response_registry.control_plane_json_rpc.r2",
            Self::ExplanationQueryFieldset => {
                "render.response_registry.explanation_query_fieldset.r3"
            }
            Self::TruthViewBundle => "render.response_registry.truth_view_bundle.r4",
            Self::ValidationPreservationRecall => {
                "render.response_registry.validation_output_recall.r5"
            }
            Self::TestCampaignReport => "render.response_registry.test_campaign_report.r6",
            Self::RefusalOnly => "render.response_registry.refusal_only.r7",
        }
    }
}

impl Default for ResponseRegistryRenderClass {
    fn default() -> Self {
        Self::ControlPlaneJsonRpc
    }
}

impl TryFrom<u32> for ResponseRegistryRenderClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PosixFilesystemAdapterWire),
            1 => Ok(Self::BlockVolumeAdapterCompletion),
            2 => Ok(Self::ControlPlaneJsonRpc),
            3 => Ok(Self::ExplanationQueryFieldset),
            4 => Ok(Self::TruthViewBundle),
            5 => Ok(Self::ValidationPreservationRecall),
            6 => Ok(Self::TestCampaignReport),
            7 => Ok(Self::RefusalOnly),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidRenderClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryAnswerKind {
    Bundle = 0,
    Refusal = 1,
}

impl ResponseRegistryAnswerKind {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bundle => "answer.response_registry.bundle.k0",
            Self::Refusal => "answer.response_registry.refusal.k1",
        }
    }
}

impl Default for ResponseRegistryAnswerKind {
    fn default() -> Self {
        Self::Bundle
    }
}

impl TryFrom<u32> for ResponseRegistryAnswerKind {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Bundle),
            1 => Ok(Self::Refusal),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidAnswerKind(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryRefusalClass {
    AuthOrPolicy = 0,
    ReserveOrBudget = 1,
    PreparedNotPublished = 2,
    StaleOrDegradedNotAdmitted = 3,
    UnsupportedCutOrSurface = 4,
    StopTicketOrHazard = 5,
    DeliveryOrRecallBlocked = 6,
}

impl ResponseRegistryRefusalClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthOrPolicy => "refusal.response_registry.auth_or_policy.f0",
            Self::ReserveOrBudget => "refusal.response_registry.reserve_or_budget.f1",
            Self::PreparedNotPublished => "refusal.response_registry.prepared_not_published.f2",
            Self::StaleOrDegradedNotAdmitted => {
                "refusal.response_registry.stale_or_degraded_not_admitted.f3"
            }
            Self::UnsupportedCutOrSurface => {
                "refusal.response_registry.unsupported_cut_or_surface.f4"
            }
            Self::StopTicketOrHazard => "refusal.response_registry.stop_ticket_or_hazard.f5",
            Self::DeliveryOrRecallBlocked => {
                "refusal.response_registry.delivery_or_recall_blocked.f6"
            }
        }
    }
}

impl Default for ResponseRegistryRefusalClass {
    fn default() -> Self {
        Self::AuthOrPolicy
    }
}

impl TryFrom<u32> for ResponseRegistryRefusalClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::AuthOrPolicy),
            1 => Ok(Self::ReserveOrBudget),
            2 => Ok(Self::PreparedNotPublished),
            3 => Ok(Self::StaleOrDegradedNotAdmitted),
            4 => Ok(Self::UnsupportedCutOrSurface),
            5 => Ok(Self::StopTicketOrHazard),
            6 => Ok(Self::DeliveryOrRecallBlocked),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidRefusalClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryRetentionClass {
    Ephemeral = 0,
    IndexedHot = 1,
    RecallableArchive = 2,
    StopHold = 3,
}

impl ResponseRegistryRetentionClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ephemeral => "retain.response_registry.ephemeral.r0",
            Self::IndexedHot => "retain.response_registry.indexed_hot.r1",
            Self::RecallableArchive => "retain.response_registry.recallable_archive.r2",
            Self::StopHold => "retain.response_registry.stop_hold.r3",
        }
    }
}

impl Default for ResponseRegistryRetentionClass {
    fn default() -> Self {
        Self::Ephemeral
    }
}

impl TryFrom<u32> for ResponseRegistryRetentionClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ephemeral),
            1 => Ok(Self::IndexedHot),
            2 => Ok(Self::RecallableArchive),
            3 => Ok(Self::StopHold),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidRetentionClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryIndexClass {
    RequestOrIdempotency = 0,
    SubjectAnchor = 1,
    ResponseReceipt = 2,
    RouteStage = 3,
    ArtifactLocator = 4,
}

impl ResponseRegistryIndexClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestOrIdempotency => "index.response_registry.request_or_idempotency.i0",
            Self::SubjectAnchor => "index.response_registry.subject_anchor.i1",
            Self::ResponseReceipt => "index.response_registry.response_receipt.i2",
            Self::RouteStage => "index.response_registry.route_stage.i3",
            Self::ArtifactLocator => "index.response_registry.artifact_locator.i4",
        }
    }
}

impl Default for ResponseRegistryIndexClass {
    fn default() -> Self {
        Self::RequestOrIdempotency
    }
}

impl TryFrom<u32> for ResponseRegistryIndexClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::RequestOrIdempotency),
            1 => Ok(Self::SubjectAnchor),
            2 => Ok(Self::ResponseReceipt),
            3 => Ok(Self::RouteStage),
            4 => Ok(Self::ArtifactLocator),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidIndexClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryDisclosureClass {
    MachineCanonical = 0,
    OperatorSummary = 1,
    ArchiveReader = 2,
}

impl ResponseRegistryDisclosureClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MachineCanonical => "disclosure.response_registry.machine_canonical.d0",
            Self::OperatorSummary => "disclosure.response_registry.operator_summary.d1",
            Self::ArchiveReader => "disclosure.response_registry.archive_reader.d2",
        }
    }
}

impl Default for ResponseRegistryDisclosureClass {
    fn default() -> Self {
        Self::OperatorSummary
    }
}

impl TryFrom<u32> for ResponseRegistryDisclosureClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::MachineCanonical),
            1 => Ok(Self::OperatorSummary),
            2 => Ok(Self::ArchiveReader),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidDisclosureClass(
                value,
            )),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResponseRegistryResponseIndexEntryRecord {
    pub index_entry_id: ControlPlaneReceiptId,
    pub response_receipt_id: ControlPlaneReceiptId,
    pub bundle_receipt_id_or_zero: ControlPlaneReceiptId,
    pub terminal_receipt_id_or_zero: ControlPlaneReceiptId,
    pub journal_id: ControlPlaneJournalId,
    pub route_class: u32,
    pub index_class: u32,
    pub retention_class: u32,
    pub _reserved0: u32,
    pub index_key_digest: ControlPlaneDigest32,
    pub lineage_digest: ControlPlaneDigest32,
    pub superseded_by_id_or_zero: ControlPlaneReceiptId,
}

impl ResponseRegistryResponseIndexEntryRecord {
    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ResponseRegistryRecordDecodeError> {
        decode_rr_route_class(self.route_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn index_class(
        self,
    ) -> Result<ResponseRegistryIndexClass, ResponseRegistryRecordDecodeError> {
        decode_rr_index_class(self.index_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn retention(
        self,
    ) -> Result<ResponseRegistryRetentionClass, ResponseRegistryRecordDecodeError> {
        decode_rr_retention_class(self.retention_class)
    }

    #[must_use]
    pub const fn has_bundle_receipt(&self) -> bool {
        !self.bundle_receipt_id_or_zero.is_zero()
    }

    #[must_use]
    pub const fn has_terminal_receipt(&self) -> bool {
        !self.terminal_receipt_id_or_zero.is_zero()
    }

    #[must_use]
    pub const fn has_supersession(&self) -> bool {
        !self.superseded_by_id_or_zero.is_zero()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResponseRegistryResponseRecallBindingRecord {
    pub binding_id: ControlPlaneReceiptId,
    pub response_receipt_id: ControlPlaneReceiptId,
    pub bundle_receipt_id: ControlPlaneReceiptId,
    pub terminal_receipt_id_or_zero: ControlPlaneReceiptId,
    pub hold_receipt_id: ControlPlaneReceiptId,
    pub recall_receipt_id: ControlPlaneReceiptId,
    pub disposition_receipt_id: ControlPlaneReceiptId,
    pub route_class: u32,
    pub truth_view_surface_class: u32,
    pub disclosure_class: u32,
    pub answer_kind: u32,
    pub refusal_class_or_none: u32,
    pub _reserved0: u32,
    pub archive_locator_digest: ControlPlaneDigest32,
    pub binding_digest: ControlPlaneDigest32,
}

impl ResponseRegistryResponseRecallBindingRecord {
    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ResponseRegistryRecordDecodeError> {
        decode_rr_route_class(self.route_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn disclosure(
        self,
    ) -> Result<ResponseRegistryDisclosureClass, ResponseRegistryRecordDecodeError> {
        decode_rr_disclosure_class(self.disclosure_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn answer_kind(
        self,
    ) -> Result<ResponseRegistryAnswerKind, ResponseRegistryRecordDecodeError> {
        decode_rr_answer_kind(self.answer_kind)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn refusal_class(
        self,
    ) -> Result<Option<ResponseRegistryRefusalClass>, ResponseRegistryRecordDecodeError> {
        if self.refusal_class_or_none == RESPONSE_REGISTRY_REFUSAL_CLASS_NONE {
            Ok(None)
        } else {
            decode_rr_refusal_class(self.refusal_class_or_none).map(Some)
        }
    }

    #[must_use]
    pub const fn has_terminal_receipt(&self) -> bool {
        !self.terminal_receipt_id_or_zero.is_zero()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseRegistryVisibleAnswerRecord {
    pub receipt_id: ControlPlaneReceiptId,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub scope_class: u32,
    pub cut_class: u32,
    pub render_class: u32,
    pub answer_kind: u32,
    pub retention_class: u32,
    pub refusal_class_or_none: u32,
    pub _reserved0: u32,
    pub answer_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
}

impl Default for ResponseRegistryVisibleAnswerRecord {
    fn default() -> Self {
        Self {
            receipt_id: ControlPlaneReceiptId::ZERO,
            request_id: ControlPlaneRequestId::ZERO,
            journal_id: ControlPlaneJournalId::ZERO,
            scope_class: ResponseRegistryScopeClass::ControlWrite.as_u32(),
            cut_class: ResponseRegistryCutClass::CommittedAuthority.as_u32(),
            render_class: ResponseRegistryRenderClass::ControlPlaneJsonRpc.as_u32(),
            answer_kind: ResponseRegistryAnswerKind::Bundle.as_u32(),
            retention_class: ResponseRegistryRetentionClass::IndexedHot.as_u32(),
            refusal_class_or_none: RESPONSE_REGISTRY_REFUSAL_CLASS_NONE,
            _reserved0: 0,
            answer_digest: [0_u8; 32],
            artifact_locator_digest: [0_u8; 32],
        }
    }
}

/// Parameter shape for `ResponseRegistryVisibleAnswerRecord::bundle`.
pub struct VisibleAnswerBundleParams {
    pub receipt_id: ControlPlaneReceiptId,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub scope_class: ResponseRegistryScopeClass,
    pub cut_class: ResponseRegistryCutClass,
    pub render_class: ResponseRegistryRenderClass,
    pub retention_class: ResponseRegistryRetentionClass,
    pub answer_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
}

/// Parameter shape for `ResponseRegistryVisibleAnswerRecord::refusal`.
pub struct VisibleAnswerRefusalParams {
    pub receipt_id: ControlPlaneReceiptId,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub scope_class: ResponseRegistryScopeClass,
    pub cut_class: ResponseRegistryCutClass,
    pub render_class: ResponseRegistryRenderClass,
    pub retention_class: ResponseRegistryRetentionClass,
    pub refusal_class: ResponseRegistryRefusalClass,
    pub answer_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
}

impl ResponseRegistryVisibleAnswerRecord {
    #[must_use]
    pub const fn bundle(params: VisibleAnswerBundleParams) -> Self {
        Self {
            receipt_id: params.receipt_id,
            request_id: params.request_id,
            journal_id: params.journal_id,
            scope_class: params.scope_class.as_u32(),
            cut_class: params.cut_class.as_u32(),
            render_class: params.render_class.as_u32(),
            answer_kind: ResponseRegistryAnswerKind::Bundle.as_u32(),
            retention_class: params.retention_class.as_u32(),
            refusal_class_or_none: RESPONSE_REGISTRY_REFUSAL_CLASS_NONE,
            _reserved0: 0,
            answer_digest: params.answer_digest,
            artifact_locator_digest: params.artifact_locator_digest,
        }
    }

    #[must_use]
    pub const fn refusal(params: VisibleAnswerRefusalParams) -> Self {
        Self {
            receipt_id: params.receipt_id,
            request_id: params.request_id,
            journal_id: params.journal_id,
            scope_class: params.scope_class.as_u32(),
            cut_class: params.cut_class.as_u32(),
            render_class: params.render_class.as_u32(),
            answer_kind: ResponseRegistryAnswerKind::Refusal.as_u32(),
            retention_class: params.retention_class.as_u32(),
            refusal_class_or_none: params.refusal_class.as_u32(),
            _reserved0: 0,
            answer_digest: params.answer_digest,
            artifact_locator_digest: params.artifact_locator_digest,
        }
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn scope(self) -> Result<ResponseRegistryScopeClass, ResponseRegistryRecordDecodeError> {
        decode_rr_scope_class(self.scope_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn cut(self) -> Result<ResponseRegistryCutClass, ResponseRegistryRecordDecodeError> {
        decode_rr_cut_class(self.cut_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn render(self) -> Result<ResponseRegistryRenderClass, ResponseRegistryRecordDecodeError> {
        decode_rr_render_class(self.render_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn answer_kind(
        self,
    ) -> Result<ResponseRegistryAnswerKind, ResponseRegistryRecordDecodeError> {
        decode_rr_answer_kind(self.answer_kind)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn retention(
        self,
    ) -> Result<ResponseRegistryRetentionClass, ResponseRegistryRecordDecodeError> {
        decode_rr_retention_class(self.retention_class)
    }
    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn refusal_class(
        self,
    ) -> Result<Option<ResponseRegistryRefusalClass>, ResponseRegistryRecordDecodeError> {
        if self.refusal_class_or_none == RESPONSE_REGISTRY_REFUSAL_CLASS_NONE {
            Ok(None)
        } else {
            decode_rr_refusal_class(self.refusal_class_or_none).map(Some)
        }
    }
}

const _: [(); 176] = [(); core::mem::size_of::<ResponseRegistryResponseIndexEntryRecord>()];
const _: [(); 200] = [(); core::mem::size_of::<ResponseRegistryResponseRecallBindingRecord>()];
const _: [(); 140] = [(); core::mem::size_of::<ResponseRegistryVisibleAnswerRecord>()];
// ── Observe record surface ──

pub const OBSERVE_HOST_PROBE_FLAG_PARSED_RELEASE: u32 = 1 << 0;
pub const OBSERVE_HOST_PROBE_FLAG_BASELINE_SATISFIED: u32 = 1 << 1;
pub const OBSERVE_HOST_PROBE_FLAG_ASSUME_LINUX_RELEASE: u32 = 1 << 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserveRecordDecodeError {
    InvalidHostKernelClass(u32),
    InvalidActivationFamilyClass(u32),
    InvalidActivationProfileClass(u32),
    InvalidActivationBundleClass(u32),
    InvalidValidationClass(u32),
    InvalidValidationStatusClass(u32),
    InvalidPersistenceClass(u32),
    InvalidAdaptiveGovernorProfileClass(u32),
    InvalidAdaptiveGovernorScopeClass(u32),
    InvalidWorkloadSignalWindowClass(u32),
    InvalidWorkloadSignatureClass(u32),
    InvalidTopologyObservationClass(u32),
    InvalidPathClassScoreClass(u32),
    InvalidAdaptiveDecisionClass(u32),
    InvalidAdaptiveActuationClass(u32),
    InvalidAdaptiveActuationStatusClass(u32),
}

fn decode_host_kernel_class(
    value: u32,
) -> Result<ObserveHostKernelClass, ObserveRecordDecodeError> {
    ObserveHostKernelClass::try_from(value)
}

fn decode_activation_family_class(
    value: u32,
) -> Result<ObserveActivationFamilyClass, ObserveRecordDecodeError> {
    ObserveActivationFamilyClass::try_from(value)
}

fn decode_activation_profile_class(
    value: u32,
) -> Result<ObserveActivationProfileClass, ObserveRecordDecodeError> {
    ObserveActivationProfileClass::try_from(value)
}

fn decode_activation_bundle_class(
    value: u32,
) -> Result<ObserveActivationBundleClass, ObserveRecordDecodeError> {
    ObserveActivationBundleClass::try_from(value)
}

fn decode_validation_class(value: u32) -> Result<ObserveValidationClass, ObserveRecordDecodeError> {
    ObserveValidationClass::try_from(value)
}

fn decode_validation_status_class(
    value: u32,
) -> Result<ObserveValidationStatusClass, ObserveRecordDecodeError> {
    ObserveValidationStatusClass::try_from(value)
}

fn decode_persistence_class(
    value: u32,
) -> Result<ObservePersistenceClass, ObserveRecordDecodeError> {
    ObservePersistenceClass::try_from(value)
}

fn decode_adaptive_governor_profile_class(
    value: u32,
) -> Result<ObserveAdaptiveGovernorProfileClass, ObserveRecordDecodeError> {
    ObserveAdaptiveGovernorProfileClass::try_from(value)
}

fn decode_adaptive_governor_scope_class(
    value: u32,
) -> Result<ObserveAdaptiveGovernorScopeClass, ObserveRecordDecodeError> {
    ObserveAdaptiveGovernorScopeClass::try_from(value)
}

fn decode_workload_signal_window_class(
    value: u32,
) -> Result<ObserveWorkloadSignalWindowClass, ObserveRecordDecodeError> {
    ObserveWorkloadSignalWindowClass::try_from(value)
}

fn decode_workload_signature_class(
    value: u32,
) -> Result<ObserveWorkloadSignatureClass, ObserveRecordDecodeError> {
    ObserveWorkloadSignatureClass::try_from(value)
}

fn decode_topology_observation_class(
    value: u32,
) -> Result<ObserveTopologyObservationClass, ObserveRecordDecodeError> {
    ObserveTopologyObservationClass::try_from(value)
}

fn decode_path_class_score_class(
    value: u32,
) -> Result<ObservePathClassScoreClass, ObserveRecordDecodeError> {
    ObservePathClassScoreClass::try_from(value)
}

fn decode_adaptive_decision_class(
    value: u32,
) -> Result<ObserveAdaptiveDecisionClass, ObserveRecordDecodeError> {
    ObserveAdaptiveDecisionClass::try_from(value)
}

fn decode_adaptive_actuation_class(
    value: u32,
) -> Result<ObserveAdaptiveActuationClass, ObserveRecordDecodeError> {
    ObserveAdaptiveActuationClass::try_from(value)
}

fn decode_adaptive_actuation_status_class(
    value: u32,
) -> Result<ObserveAdaptiveActuationStatusClass, ObserveRecordDecodeError> {
    ObserveAdaptiveActuationStatusClass::try_from(value)
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveHostKernelClass {
    Linux700OrNewer = 0,
    LinuxTooPrevious = 1,
    UnknownOrNonLinux = 2,
}

impl ObserveHostKernelClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux700OrNewer => "receipt.observe.host.kernel_linux_7_0_plus.k0",
            Self::LinuxTooPrevious => "receipt.observe.host.kernel_linux_too_old.k1",
            Self::UnknownOrNonLinux => "receipt.observe.host.kernel_unknown_or_nonlinux.k2",
        }
    }
}

impl Default for ObserveHostKernelClass {
    fn default() -> Self {
        Self::UnknownOrNonLinux
    }
}

impl TryFrom<u32> for ObserveHostKernelClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Linux700OrNewer),
            1 => Ok(Self::LinuxTooPrevious),
            2 => Ok(Self::UnknownOrNonLinux),
            _ => Err(ObserveRecordDecodeError::InvalidHostKernelClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveActivationFamilyClass {
    PolicyAuthority = 0,
    PosixFilesystemAdapter = 1,
    ControlPlane = 2,
    Xtask = 3,
    BlockVolumeAdapter = 4,
}

impl ObserveActivationFamilyClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyAuthority => "receipt.observe.activation.family_policy_authority.f0",
            Self::PosixFilesystemAdapter => {
                "receipt.observe.activation.family_posix_filesystem_adapter.f1"
            }
            Self::ControlPlane => "receipt.observe.activation.family_control_plane.f2",
            Self::Xtask => "receipt.observe.activation.family_xtask.f3",
            Self::BlockVolumeAdapter => "receipt.observe.activation.family_block_volume_adapter.f4",
        }
    }

    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        self.as_str()
    }

    #[must_use]
    pub const fn stable_locator(self) -> &'static str {
        match self {
            Self::PolicyAuthority => "policy_authority",
            Self::PosixFilesystemAdapter => "posix_filesystem_adapter",
            Self::ControlPlane => "control_plane",
            Self::Xtask => "xtask",
            Self::BlockVolumeAdapter => "block_volume_adapter",
        }
    }

    #[must_use]
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::PolicyAuthority => "Policy Authority",
            Self::PosixFilesystemAdapter => "POSIX Filesystem Adapter",
            Self::ControlPlane => "Control Plane",
            Self::Xtask => "Workspace Tooling",
            Self::BlockVolumeAdapter => "Block Volume Adapter",
        }
    }

    #[must_use]
    pub const fn rust_hint(self) -> &'static str {
        match self {
            Self::PolicyAuthority => "policy_authority",
            Self::PosixFilesystemAdapter => "posix_filesystem_adapter",
            Self::ControlPlane => "control_plane",
            Self::Xtask => "workspace_tooling",
            Self::BlockVolumeAdapter => "block_volume_adapter",
        }
    }
}

impl Default for ObserveActivationFamilyClass {
    fn default() -> Self {
        Self::PolicyAuthority
    }
}

impl TryFrom<u32> for ObserveActivationFamilyClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PolicyAuthority),
            1 => Ok(Self::PosixFilesystemAdapter),
            2 => Ok(Self::ControlPlane),
            3 => Ok(Self::Xtask),
            4 => Ok(Self::BlockVolumeAdapter),
            _ => Err(ObserveRecordDecodeError::InvalidActivationFamilyClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveActivationProfileClass {
    CorePortable = 0,
    AllocPortable = 1,
    UserspaceLibrary = 2,
    UserspaceApp = 3,
    TestXtaskStd = 4,
}

impl ObserveActivationProfileClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CorePortable => "receipt.observe.activation.profile_core_portable.p0",
            Self::AllocPortable => "receipt.observe.activation.profile_alloc_portable.p1",
            Self::UserspaceLibrary => "receipt.observe.activation.profile_userspace_library.p2",
            Self::UserspaceApp => "receipt.observe.activation.profile_userspace_app.p3",
            Self::TestXtaskStd => "receipt.observe.activation.profile_test_xtask.p4",
        }
    }

    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        self.as_str()
    }

    #[must_use]
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::CorePortable => "Core portable",
            Self::AllocPortable => "Alloc portable",
            Self::UserspaceLibrary => "Userspace library",
            Self::UserspaceApp => "Userspace application",
            Self::TestXtaskStd => "Workspace test/xtask",
        }
    }
}

impl Default for ObserveActivationProfileClass {
    fn default() -> Self {
        Self::UserspaceApp
    }
}

impl TryFrom<u32> for ObserveActivationProfileClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CorePortable),
            1 => Ok(Self::AllocPortable),
            2 => Ok(Self::UserspaceLibrary),
            3 => Ok(Self::UserspaceApp),
            4 => Ok(Self::TestXtaskStd),
            _ => Err(ObserveRecordDecodeError::InvalidActivationProfileClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveActivationBundleClass {
    DevWorkspace = 0,
    RuntimeAuthorityUserspace = 1,
    RuntimePosixUserspace = 2,
    RuntimeControlQuery = 3,
    ObserveTestGate = 4,
    RuntimeBlockVolumeUserspace = 5,
}

impl ObserveActivationBundleClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DevWorkspace => "receipt.observe.activation.bundle_dev_workspace.b0",
            Self::RuntimeAuthorityUserspace => {
                "receipt.observe.activation.bundle_runtime_authority_userspace.b1"
            }
            Self::RuntimePosixUserspace => {
                "receipt.observe.activation.bundle_runtime_posix_userspace.b2"
            }
            Self::RuntimeControlQuery => {
                "receipt.observe.activation.bundle_runtime_control_query.b3"
            }
            Self::ObserveTestGate => "receipt.observe.activation.bundle_observe_test_gate.b4",
            Self::RuntimeBlockVolumeUserspace => {
                "receipt.observe.activation.bundle_runtime_block_volume_userspace.b5"
            }
        }
    }

    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        self.as_str()
    }

    #[must_use]
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::DevWorkspace => "Development workspace",
            Self::RuntimeAuthorityUserspace => "Runtime policy-authority userspace",
            Self::RuntimePosixUserspace => "Runtime POSIX-adapter userspace",
            Self::RuntimeControlQuery => "Runtime control/query service",
            Self::ObserveTestGate => "Observation test gate",
            Self::RuntimeBlockVolumeUserspace => "Runtime block-volume-adapter userspace",
        }
    }
}

impl Default for ObserveActivationBundleClass {
    fn default() -> Self {
        Self::RuntimeAuthorityUserspace
    }
}

impl TryFrom<u32> for ObserveActivationBundleClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::DevWorkspace),
            1 => Ok(Self::RuntimeAuthorityUserspace),
            2 => Ok(Self::RuntimePosixUserspace),
            3 => Ok(Self::RuntimeControlQuery),
            4 => Ok(Self::ObserveTestGate),
            5 => Ok(Self::RuntimeBlockVolumeUserspace),
            _ => Err(ObserveRecordDecodeError::InvalidActivationBundleClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveValidationClass {
    HostProbe = 0,
    BundleActivation = 1,
    ControlWriteAdmitted = 2,
    ControlWriteRefused = 3,
    ControlWriteBlocked = 4,
}

impl ObserveValidationClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostProbe => "validation.observe.host_probe.e0",
            Self::BundleActivation => "validation.observe.bundle_activation.e1",
            Self::ControlWriteAdmitted => "validation.observe.control_write_admitted.e2",
            Self::ControlWriteRefused => "validation.observe.control_write_refused.e3",
            Self::ControlWriteBlocked => "validation.observe.control_write_blocked.e4",
        }
    }
}

impl Default for ObserveValidationClass {
    fn default() -> Self {
        Self::ControlWriteBlocked
    }
}

impl TryFrom<u32> for ObserveValidationClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::HostProbe),
            1 => Ok(Self::BundleActivation),
            2 => Ok(Self::ControlWriteAdmitted),
            3 => Ok(Self::ControlWriteRefused),
            4 => Ok(Self::ControlWriteBlocked),
            _ => Err(ObserveRecordDecodeError::InvalidValidationClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveValidationStatusClass {
    Produced = 0,
    RefusedNoMutation = 1,
    Blocked = 2,
}

impl ObserveValidationStatusClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Produced => "status.observe.validation_produced.s0",
            Self::RefusedNoMutation => "status.observe.validation_refused_no_mutation.s1",
            Self::Blocked => "status.observe.validation_blocked.s2",
        }
    }
}

impl Default for ObserveValidationStatusClass {
    fn default() -> Self {
        Self::Blocked
    }
}

impl TryFrom<u32> for ObserveValidationStatusClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Produced),
            1 => Ok(Self::RefusedNoMutation),
            2 => Ok(Self::Blocked),
            _ => Err(ObserveRecordDecodeError::InvalidValidationStatusClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObservePersistenceClass {
    HostActivationSnapshot = 0,
    ValidationAppend = 1,
    WitnessBoundValidationAppend = 2,
}

impl ObservePersistenceClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostActivationSnapshot => "receipt.observe.persist.host_activation_snapshot.p0",
            Self::ValidationAppend => "receipt.observe.persist.validation_append.p1",
            Self::WitnessBoundValidationAppend => {
                "receipt.observe.persist.witness_bound_validation_append.p2"
            }
        }
    }
}

impl Default for ObservePersistenceClass {
    fn default() -> Self {
        Self::ValidationAppend
    }
}

impl TryFrom<u32> for ObservePersistenceClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::HostActivationSnapshot),
            1 => Ok(Self::ValidationAppend),
            2 => Ok(Self::WitnessBoundValidationAppend),
            _ => Err(ObserveRecordDecodeError::InvalidPersistenceClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveAdaptiveGovernorProfileClass {
    LatencyBiased = 0,
    Balanced = 1,
    EfficiencyBiased = 2,
    RecoveryBiased = 3,
}

impl ObserveAdaptiveGovernorProfileClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LatencyBiased => "profile.adaptive_governor_0.latency_biased.p0",
            Self::Balanced => "profile.adaptive_governor_0.balanced.p1",
            Self::EfficiencyBiased => "profile.adaptive_governor_0.efficiency_biased.p2",
            Self::RecoveryBiased => "profile.adaptive_governor_0.recovery_biased.p3",
        }
    }
}

impl Default for ObserveAdaptiveGovernorProfileClass {
    fn default() -> Self {
        Self::Balanced
    }
}

impl TryFrom<u32> for ObserveAdaptiveGovernorProfileClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::LatencyBiased),
            1 => Ok(Self::Balanced),
            2 => Ok(Self::EfficiencyBiased),
            3 => Ok(Self::RecoveryBiased),
            _ => Err(ObserveRecordDecodeError::InvalidAdaptiveGovernorProfileClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveAdaptiveGovernorScopeClass {
    PoolCluster = 0,
    PosixFilesystemAdapter = 1,
    BlockVolumeAdapter = 2,
    Placement = 3,
    WorkloadModel = 4,
}

impl ObserveAdaptiveGovernorScopeClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PoolCluster => "scope.adaptive_governor_0.pool_cluster.s0",
            Self::PosixFilesystemAdapter => "scope.adaptive_governor_0.posix_filesystem_adapter.s1",
            Self::BlockVolumeAdapter => "scope.adaptive_governor_0.block_volume_adapter.s2",
            Self::Placement => "scope.adaptive_governor_0.placement.s3",
            Self::WorkloadModel => "scope.adaptive_governor_0.workload_model_0.s4",
        }
    }
}

impl Default for ObserveAdaptiveGovernorScopeClass {
    fn default() -> Self {
        Self::PoolCluster
    }
}

impl TryFrom<u32> for ObserveAdaptiveGovernorScopeClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PoolCluster),
            1 => Ok(Self::PosixFilesystemAdapter),
            2 => Ok(Self::BlockVolumeAdapter),
            3 => Ok(Self::Placement),
            4 => Ok(Self::WorkloadModel),
            _ => Err(ObserveRecordDecodeError::InvalidAdaptiveGovernorScopeClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveWorkloadSignalWindowClass {
    Fast = 0,
    Steady = 1,
    Slow = 2,
}

impl ObserveWorkloadSignalWindowClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "window.adaptive_governor_0.workload_signal.fast.w0",
            Self::Steady => "window.adaptive_governor_0.workload_signal.steady.w1",
            Self::Slow => "window.adaptive_governor_0.workload_signal.slow.w2",
        }
    }
}

impl Default for ObserveWorkloadSignalWindowClass {
    fn default() -> Self {
        Self::Steady
    }
}

impl TryFrom<u32> for ObserveWorkloadSignalWindowClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Fast),
            1 => Ok(Self::Steady),
            2 => Ok(Self::Slow),
            _ => Err(ObserveRecordDecodeError::InvalidWorkloadSignalWindowClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveWorkloadSignatureClass {
    MetadataHotset = 0,
    StreamSequential = 1,
    RandomLowLatency = 2,
    SyncDurableWrite = 3,
    QueryLineage = 4,
    RebuildRepair = 5,
    ShadowCompare = 6,
    MixedUnknown = 7,
}

impl ObserveWorkloadSignatureClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataHotset => "signature.workload_model_0.metadata_hotset.s0",
            Self::StreamSequential => "signature.workload_model_0.stream_seq.s1",
            Self::RandomLowLatency => "signature.workload_model_0.random_lowlat.s2",
            Self::SyncDurableWrite => "signature.workload_model_0.sync_durable_write.s3",
            Self::QueryLineage => "signature.workload_model_0.query_lineage.s4",
            Self::RebuildRepair => "signature.workload_model_0.rebuild_repair.s5",
            Self::ShadowCompare => "signature.workload_model_0.shadow_compare.s6",
            Self::MixedUnknown => "signature.workload_model_0.mixed_unknown.s7",
        }
    }
}

impl Default for ObserveWorkloadSignatureClass {
    fn default() -> Self {
        Self::MixedUnknown
    }
}

impl TryFrom<u32> for ObserveWorkloadSignatureClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::MetadataHotset),
            1 => Ok(Self::StreamSequential),
            2 => Ok(Self::RandomLowLatency),
            3 => Ok(Self::SyncDurableWrite),
            4 => Ok(Self::QueryLineage),
            5 => Ok(Self::RebuildRepair),
            6 => Ok(Self::ShadowCompare),
            7 => Ok(Self::MixedUnknown),
            _ => Err(ObserveRecordDecodeError::InvalidWorkloadSignatureClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveTopologyObservationClass {
    InferredPathLatency = 0,
    FailureDomainSpread = 1,
    LocalityHeat = 2,
    CapacityPressure = 3,
}

impl ObserveTopologyObservationClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InferredPathLatency => "observation.adaptive_governor_0.path_latency.o0",
            Self::FailureDomainSpread => "observation.adaptive_governor_0.failure_spread.o1",
            Self::LocalityHeat => "observation.adaptive_governor_0.locality_heat.o2",
            Self::CapacityPressure => "observation.adaptive_governor_0.capacity_pressure.o3",
        }
    }
}

impl Default for ObserveTopologyObservationClass {
    fn default() -> Self {
        Self::InferredPathLatency
    }
}

impl TryFrom<u32> for ObserveTopologyObservationClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::InferredPathLatency),
            1 => Ok(Self::FailureDomainSpread),
            2 => Ok(Self::LocalityHeat),
            3 => Ok(Self::CapacityPressure),
            _ => Err(ObserveRecordDecodeError::InvalidTopologyObservationClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObservePathClassScoreClass {
    LocalFast = 0,
    PeerSameFailureDomain = 1,
    PeerCrossFailureDomain = 2,
    Degraded = 3,
    Unknown = 4,
}

impl ObservePathClassScoreClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalFast => "score.adaptive_governor_0.path.local_fast.p0",
            Self::PeerSameFailureDomain => {
                "score.adaptive_governor_0.path.peer_same_failure_domain.p1"
            }
            Self::PeerCrossFailureDomain => {
                "score.adaptive_governor_0.path.peer_cross_failure_domain.p2"
            }
            Self::Degraded => "score.adaptive_governor_0.path.degraded.p3",
            Self::Unknown => "score.adaptive_governor_0.path.unknown.p4",
        }
    }
}

impl Default for ObservePathClassScoreClass {
    fn default() -> Self {
        Self::Unknown
    }
}

impl TryFrom<u32> for ObservePathClassScoreClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::LocalFast),
            1 => Ok(Self::PeerSameFailureDomain),
            2 => Ok(Self::PeerCrossFailureDomain),
            3 => Ok(Self::Degraded),
            4 => Ok(Self::Unknown),
            _ => Err(ObserveRecordDecodeError::InvalidPathClassScoreClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveAdaptiveDecisionClass {
    Hold = 0,
    BiasReadHotset = 1,
    BuildOrRefresh = 2,
    ReclaimOrDemote = 3,
    ThrottleBackground = 4,
}

impl ObserveAdaptiveDecisionClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "decision.adaptive_governor_0.hold.d0",
            Self::BiasReadHotset => "decision.adaptive_governor_0.bias_read_hotset.d1",
            Self::BuildOrRefresh => "decision.adaptive_governor_0.build_or_refresh.d2",
            Self::ReclaimOrDemote => "decision.adaptive_governor_0.reclaim_or_demote.d3",
            Self::ThrottleBackground => "decision.adaptive_governor_0.throttle_background.d4",
        }
    }
}

impl Default for ObserveAdaptiveDecisionClass {
    fn default() -> Self {
        Self::Hold
    }
}

impl TryFrom<u32> for ObserveAdaptiveDecisionClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Hold),
            1 => Ok(Self::BiasReadHotset),
            2 => Ok(Self::BuildOrRefresh),
            3 => Ok(Self::ReclaimOrDemote),
            4 => Ok(Self::ThrottleBackground),
            _ => Err(ObserveRecordDecodeError::InvalidAdaptiveDecisionClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveAdaptiveActuationClass {
    Noop = 0,
    CacheBias = 1,
    MaterializationBuild = 2,
    MaterializationReclaim = 3,
    PlacementBias = 4,
    BackgroundThrottle = 5,
}

impl ObserveAdaptiveActuationClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Noop => "actuation.adaptive_governor_0.noop.a0",
            Self::CacheBias => "actuation.adaptive_governor_0.cache_bias.a1",
            Self::MaterializationBuild => "actuation.adaptive_governor_0.materialization_build.a2",
            Self::MaterializationReclaim => {
                "actuation.adaptive_governor_0.materialization_reclaim.a3"
            }
            Self::PlacementBias => "actuation.adaptive_governor_0.placement_bias.a4",
            Self::BackgroundThrottle => "actuation.adaptive_governor_0.background_throttle.a5",
        }
    }
}

impl Default for ObserveAdaptiveActuationClass {
    fn default() -> Self {
        Self::Noop
    }
}

impl TryFrom<u32> for ObserveAdaptiveActuationClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Noop),
            1 => Ok(Self::CacheBias),
            2 => Ok(Self::MaterializationBuild),
            3 => Ok(Self::MaterializationReclaim),
            4 => Ok(Self::PlacementBias),
            5 => Ok(Self::BackgroundThrottle),
            _ => Err(ObserveRecordDecodeError::InvalidAdaptiveActuationClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObserveAdaptiveActuationStatusClass {
    Emitted = 0,
    Deferred = 1,
    Refused = 2,
}

impl ObserveAdaptiveActuationStatusClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emitted => "status.adaptive_governor_0.actuation_emitted.s0",
            Self::Deferred => "status.adaptive_governor_0.actuation_deferred.s1",
            Self::Refused => "status.adaptive_governor_0.actuation_refused.s2",
        }
    }
}

impl Default for ObserveAdaptiveActuationStatusClass {
    fn default() -> Self {
        Self::Deferred
    }
}

impl TryFrom<u32> for ObserveAdaptiveActuationStatusClass {
    type Error = ObserveRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Emitted),
            1 => Ok(Self::Deferred),
            2 => Ok(Self::Refused),
            _ => Err(ObserveRecordDecodeError::InvalidAdaptiveActuationStatusClass(value)),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserveHostProbeReceiptRecord {
    pub host_probe_receipt_id: ControlPlaneReceiptId,
    pub kernel_class: u32,
    pub flags: u32,
    pub release_major: u32,
    pub release_minor: u32,
    pub release_patch: u32,
    pub _reserved0: u32,
    pub release_digest: ControlPlaneDigest32,
}

impl ObserveHostProbeReceiptRecord {
    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn kernel_class(self) -> Result<ObserveHostKernelClass, ObserveRecordDecodeError> {
        decode_host_kernel_class(self.kernel_class)
    }

    #[must_use]
    pub const fn has_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }

    #[must_use]
    pub const fn baseline_satisfied(&self) -> bool {
        self.has_flag(OBSERVE_HOST_PROBE_FLAG_BASELINE_SATISFIED)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserveBundleActivationReceiptRecord {
    pub activation_receipt_id: ControlPlaneReceiptId,
    pub host_probe_receipt_id: ControlPlaneReceiptId,
    pub family_class: u32,
    pub profile_class: u32,
    pub bundle_class: u32,
    pub capability_mask: u32,
    pub stage_digest: ControlPlaneDigest32,
    pub surface_digest: ControlPlaneDigest32,
}

impl ObserveBundleActivationReceiptRecord {
    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn family(self) -> Result<ObserveActivationFamilyClass, ObserveRecordDecodeError> {
        decode_activation_family_class(self.family_class)
    }

    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn profile(self) -> Result<ObserveActivationProfileClass, ObserveRecordDecodeError> {
        decode_activation_profile_class(self.profile_class)
    }

    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn bundle(self) -> Result<ObserveActivationBundleClass, ObserveRecordDecodeError> {
        decode_activation_bundle_class(self.bundle_class)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserveValidationRowRecord {
    pub row_id: ControlPlaneReceiptId,
    pub activation_receipt_id: ControlPlaneReceiptId,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub response_registry_receipt_id: ControlPlaneReceiptId,
    pub publication_pipeline_ticket_id_or_zero: ControlPlaneId128,
    pub policy_authority_plan_id: ControlPlaneId128,
    pub validation_class: u32,
    pub validation_status_class: u32,
    pub _reserved0: u64,
    pub answer_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
}

impl ObserveValidationRowRecord {
    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn validation_class(self) -> Result<ObserveValidationClass, ObserveRecordDecodeError> {
        decode_validation_class(self.validation_class)
    }

    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn validation_status(
        self,
    ) -> Result<ObserveValidationStatusClass, ObserveRecordDecodeError> {
        decode_validation_status_class(self.validation_status_class)
    }

    #[must_use]
    pub const fn has_publication_pipeline_ticket(&self) -> bool {
        !self.publication_pipeline_ticket_id_or_zero.is_zero()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserveHostActivationSnapshotRecord {
    pub snapshot_receipt_id: ControlPlaneReceiptId,
    pub host_probe_receipt_id: ControlPlaneReceiptId,
    pub activation_receipt_id: ControlPlaneReceiptId,
    pub persistence_class: u32,
    pub family_class: u32,
    pub profile_class: u32,
    pub bundle_class: u32,
    pub capability_mask: u32,
    pub flags: u32,
    pub _reserved0: u64,
    pub release_digest: ControlPlaneDigest32,
    pub stage_digest: ControlPlaneDigest32,
    pub surface_digest: ControlPlaneDigest32,
    pub persistence_digest: ControlPlaneDigest32,
}

impl ObserveHostActivationSnapshotRecord {
    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn persistence_class(self) -> Result<ObservePersistenceClass, ObserveRecordDecodeError> {
        decode_persistence_class(self.persistence_class)
    }

    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn family(self) -> Result<ObserveActivationFamilyClass, ObserveRecordDecodeError> {
        decode_activation_family_class(self.family_class)
    }

    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn profile(self) -> Result<ObserveActivationProfileClass, ObserveRecordDecodeError> {
        decode_activation_profile_class(self.profile_class)
    }

    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn bundle(self) -> Result<ObserveActivationBundleClass, ObserveRecordDecodeError> {
        decode_activation_bundle_class(self.bundle_class)
    }

    #[must_use]
    pub const fn has_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }

    #[must_use]
    pub const fn baseline_satisfied(&self) -> bool {
        self.has_flag(OBSERVE_HOST_PROBE_FLAG_BASELINE_SATISFIED)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserveValidationPersistenceRecord {
    pub persistence_receipt_id: ControlPlaneReceiptId,
    pub snapshot_receipt_id: ControlPlaneReceiptId,
    pub row_id: ControlPlaneReceiptId,
    pub activation_receipt_id: ControlPlaneReceiptId,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub response_registry_receipt_id: ControlPlaneReceiptId,
    pub publication_pipeline_ticket_id_or_zero: ControlPlaneId128,
    pub policy_authority_plan_id: ControlPlaneId128,
    pub persistence_class: u32,
    pub validation_class: u32,
    pub validation_status_class: u32,
    pub _reserved0: u32,
    pub answer_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
    pub witness_refs: ControlPlanePolicyBudgetRecipeWitnessRefs,
}

impl ObserveValidationPersistenceRecord {
    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn persistence_class(self) -> Result<ObservePersistenceClass, ObserveRecordDecodeError> {
        decode_persistence_class(self.persistence_class)
    }

    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn validation_class(self) -> Result<ObserveValidationClass, ObserveRecordDecodeError> {
        decode_validation_class(self.validation_class)
    }

    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn validation_status(
        self,
    ) -> Result<ObserveValidationStatusClass, ObserveRecordDecodeError> {
        decode_validation_status_class(self.validation_status_class)
    }

    #[must_use]
    pub const fn has_publication_pipeline_ticket(&self) -> bool {
        !self.publication_pipeline_ticket_id_or_zero.is_zero()
    }

    #[must_use]
    pub const fn has_witness_join(&self) -> bool {
        self.witness_refs.has_join()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserveAdaptiveGovernorProfileBindingRecord {
    pub binding_receipt_id: ControlPlaneReceiptId,
    pub scope_id: ControlPlaneId128,
    pub profile_class: u32,
    pub scope_class: u32,
    pub performance_bias_ppm: u32,
    pub reserve_bias_ppm: u32,
    pub flags: u32,
    pub _reserved0: u32,
    pub profile_digest: ControlPlaneDigest32,
}

impl ObserveAdaptiveGovernorProfileBindingRecord {
    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn profile(self) -> Result<ObserveAdaptiveGovernorProfileClass, ObserveRecordDecodeError> {
        decode_adaptive_governor_profile_class(self.profile_class)
    }

    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn scope(self) -> Result<ObserveAdaptiveGovernorScopeClass, ObserveRecordDecodeError> {
        decode_adaptive_governor_scope_class(self.scope_class)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserveWorkloadSignalWindowRecord {
    pub window_receipt_id: ControlPlaneReceiptId,
    pub activation_receipt_id: ControlPlaneReceiptId,
    pub window_class: u32,
    pub signature_class: u32,
    pub flags: u32,
    pub sample_count: u32,
    pub read_ops: u64,
    pub write_ops: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub latency_p99_micros: u64,
    pub pressure_ppm: u32,
    pub debt_units: u32,
    pub confidence_ppm: u32,
    pub _reserved0: u32,
    pub signal_digest: ControlPlaneDigest32,
}

impl ObserveWorkloadSignalWindowRecord {
    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn window(self) -> Result<ObserveWorkloadSignalWindowClass, ObserveRecordDecodeError> {
        decode_workload_signal_window_class(self.window_class)
    }

    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn signature(self) -> Result<ObserveWorkloadSignatureClass, ObserveRecordDecodeError> {
        decode_workload_signature_class(self.signature_class)
    }

    #[must_use]
    pub const fn pressure_or_debt_present(&self) -> bool {
        self.pressure_ppm != 0 || self.debt_units != 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserveTopologyObservationRecord {
    pub observation_receipt_id: ControlPlaneReceiptId,
    pub activation_receipt_id: ControlPlaneReceiptId,
    pub observation_class: u32,
    pub flags: u32,
    pub node_count: u32,
    pub failure_domain_count: u32,
    pub inferred_path_count: u32,
    pub confidence_ppm: u32,
    pub observation_digest: ControlPlaneDigest32,
}

impl ObserveTopologyObservationRecord {
    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn observation(self) -> Result<ObserveTopologyObservationClass, ObserveRecordDecodeError> {
        decode_topology_observation_class(self.observation_class)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObservePathClassScoreRecord {
    pub score_receipt_id: ControlPlaneReceiptId,
    pub observation_receipt_id: ControlPlaneReceiptId,
    pub path_class: u32,
    pub score_ppm: u32,
    pub latency_cost_ppm: u32,
    pub locality_score_ppm: u32,
    pub pressure_cost_ppm: u32,
    pub failure_domain_risk_ppm: u32,
    pub score_digest: ControlPlaneDigest32,
}

impl ObservePathClassScoreRecord {
    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn path_class(self) -> Result<ObservePathClassScoreClass, ObserveRecordDecodeError> {
        decode_path_class_score_class(self.path_class)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserveAdaptiveDecisionReceiptRecord {
    pub decision_receipt_id: ControlPlaneReceiptId,
    pub binding_receipt_id: ControlPlaneReceiptId,
    pub window_receipt_id: ControlPlaneReceiptId,
    pub observation_receipt_id: ControlPlaneReceiptId,
    pub selected_path_score_receipt_id_or_zero: ControlPlaneReceiptId,
    pub decision_class: u32,
    pub profile_class: u32,
    pub confidence_ppm: u32,
    pub pressure_debt_ppm: u32,
    pub budget_ppm: u32,
    pub flags: u32,
    pub decision_digest: ControlPlaneDigest32,
}

impl ObserveAdaptiveDecisionReceiptRecord {
    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn decision(self) -> Result<ObserveAdaptiveDecisionClass, ObserveRecordDecodeError> {
        decode_adaptive_decision_class(self.decision_class)
    }

    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn profile(self) -> Result<ObserveAdaptiveGovernorProfileClass, ObserveRecordDecodeError> {
        decode_adaptive_governor_profile_class(self.profile_class)
    }

    #[must_use]
    pub const fn has_selected_path_score(&self) -> bool {
        !self.selected_path_score_receipt_id_or_zero.is_zero()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserveAdaptiveActuationReceiptRecord {
    pub actuation_receipt_id: ControlPlaneReceiptId,
    pub decision_receipt_id: ControlPlaneReceiptId,
    pub actuation_class: u32,
    pub status_class: u32,
    pub target_scope_class: u32,
    pub applied_budget_ppm: u32,
    pub ttl_seconds: u32,
    pub flags: u32,
    pub actuation_digest: ControlPlaneDigest32,
}

impl ObserveAdaptiveActuationReceiptRecord {
    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn actuation(self) -> Result<ObserveAdaptiveActuationClass, ObserveRecordDecodeError> {
        decode_adaptive_actuation_class(self.actuation_class)
    }

    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn status(self) -> Result<ObserveAdaptiveActuationStatusClass, ObserveRecordDecodeError> {
        decode_adaptive_actuation_status_class(self.status_class)
    }

    /// # Errors
    ///
    /// Returns [`ObserveRecordDecodeError`] on failure.
    pub fn target_scope(
        self,
    ) -> Result<ObserveAdaptiveGovernorScopeClass, ObserveRecordDecodeError> {
        decode_adaptive_governor_scope_class(self.target_scope_class)
    }
}

const _: [(); 72] = [(); core::mem::size_of::<ObserveHostProbeReceiptRecord>()];
const _: [(); 112] = [(); core::mem::size_of::<ObserveBundleActivationReceiptRecord>()];
const _: [(); 192] = [(); core::mem::size_of::<ObserveValidationRowRecord>()];
const _: [(); 208] = [(); core::mem::size_of::<ObserveHostActivationSnapshotRecord>()];
const _: [(); 320] = [(); core::mem::size_of::<ObserveValidationPersistenceRecord>()];
const _: [(); 88] = [(); core::mem::size_of::<ObserveAdaptiveGovernorProfileBindingRecord>()];
const _: [(); 136] = [(); core::mem::size_of::<ObserveWorkloadSignalWindowRecord>()];
const _: [(); 88] = [(); core::mem::size_of::<ObserveTopologyObservationRecord>()];
const _: [(); 88] = [(); core::mem::size_of::<ObservePathClassScoreRecord>()];
const _: [(); 136] = [(); core::mem::size_of::<ObserveAdaptiveDecisionReceiptRecord>()];
const _: [(); 88] = [(); core::mem::size_of::<ObserveAdaptiveActuationReceiptRecord>()];
// ── Truth view record surface ──

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TruthViewDecodeError {
    UnknownSurfaceRecordLiveViewClass(u32),
    UnknownSurfaceRecordSignalClass(u32),
    UnknownSurfaceRecordStatusClass(u32),
    UnknownSurfaceRecordSourceClass(u32),
    UnknownSurfaceRecordCutClass(u32),
    UnknownSurfaceRecordProvenanceClass(u32),
    UnknownSurfaceRecordExactnessClass(u32),
    UnknownSurfaceRecordFreshnessClass(u32),
    UnknownTruthBundleRouteClass(u32),
    UnknownTruthBundleSurfaceClass(u32),
    UnknownTruthBundleCutClass(u32),
    UnknownTruthBundleSourceClass(u32),
    UnknownTruthBundleProvenanceClass(u32),
    UnknownTruthBundleAudienceClass(u32),
    UnknownTruthBundleAnswerKind(u32),
    UnknownMetricClass(u32),
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TruthViewSurfaceClass {
    SystemOverview = 0,
    RunbookTransition = 1,
    PerformancePb0 = 2,
    ChaosCc0 = 3,
    ValidationPreservation = 4,
    SecuritySk0 = 5,
    CharterAdapter = 6,
    MigrationKernel = 7,
}

impl TruthViewSurfaceClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemOverview => "surface.truth_view.system.overview.s0",
            Self::RunbookTransition => "surface.truth_view.runbook.transition.s1",
            Self::PerformancePb0 => "surface.truth_view.performance.performance_budget_0.s2",
            Self::ChaosCc0 => "surface.truth_view.chaos.cutover_control_0.s3",
            Self::ValidationPreservation => "surface.truth_view.validation.validation_output.s4",
            Self::SecuritySk0 => "surface.truth_view.security.secret_key_policy_0.s5",
            Self::CharterAdapter => "surface.truth_view.charter.adapter.s6",
            Self::MigrationKernel => "surface.truth_view.migration.kernel.s7",
        }
    }
}

impl Default for TruthViewSurfaceClass {
    fn default() -> Self {
        Self::ValidationPreservation
    }
}

impl TryFrom<u32> for TruthViewSurfaceClass {
    type Error = TruthViewDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SystemOverview),
            1 => Ok(Self::RunbookTransition),
            2 => Ok(Self::PerformancePb0),
            3 => Ok(Self::ChaosCc0),
            4 => Ok(Self::ValidationPreservation),
            5 => Ok(Self::SecuritySk0),
            6 => Ok(Self::CharterAdapter),
            7 => Ok(Self::MigrationKernel),
            _ => Err(TruthViewDecodeError::UnknownTruthBundleSurfaceClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TruthViewCutClass {
    LiveWindow = 0,
    ReceiptAnchor = 1,
    CampaignWindow = 2,
    TraceReplay = 3,
    ArchiveRecall = 4,
}

impl TruthViewCutClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LiveWindow => "cut.truth_view.live_window.c0",
            Self::ReceiptAnchor => "cut.truth_view.receipt_anchor.c1",
            Self::CampaignWindow => "cut.truth_view.campaign_window.c2",
            Self::TraceReplay => "cut.truth_view.trace_replay.c3",
            Self::ArchiveRecall => "cut.truth_view.archive_recall.c4",
        }
    }
}

impl Default for TruthViewCutClass {
    fn default() -> Self {
        Self::ArchiveRecall
    }
}

impl TryFrom<u32> for TruthViewCutClass {
    type Error = TruthViewDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::LiveWindow),
            1 => Ok(Self::ReceiptAnchor),
            2 => Ok(Self::CampaignWindow),
            3 => Ok(Self::TraceReplay),
            4 => Ok(Self::ArchiveRecall),
            _ => Err(TruthViewDecodeError::UnknownTruthBundleCutClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TruthViewProvenanceClass {
    ReceiptGate = 0,
    ManifestRecall = 1,
    NormalizedReport = 2,
    SemanticTrace = 3,
    LiveMirror = 4,
    RawArtifact = 5,
}

impl TruthViewProvenanceClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptGate => "prov.truth_view.receipt_gate.p0",
            Self::ManifestRecall => "prov.truth_view.manifest_recall.p1",
            Self::NormalizedReport => "prov.truth_view.normalized_report.p2",
            Self::SemanticTrace => "prov.truth_view.semantic_trace.p3",
            Self::LiveMirror => "prov.truth_view.live_mirror.p4",
            Self::RawArtifact => "prov.truth_view.raw_artifact.p5",
        }
    }
}

impl Default for TruthViewProvenanceClass {
    fn default() -> Self {
        Self::ManifestRecall
    }
}

impl TryFrom<u32> for TruthViewProvenanceClass {
    type Error = TruthViewDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ReceiptGate),
            1 => Ok(Self::ManifestRecall),
            2 => Ok(Self::NormalizedReport),
            3 => Ok(Self::SemanticTrace),
            4 => Ok(Self::LiveMirror),
            5 => Ok(Self::RawArtifact),
            _ => Err(TruthViewDecodeError::UnknownTruthBundleProvenanceClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TruthViewExactnessClass {
    ReceiptExact = 0,
    SourceBoundProjection = 1,
    AggregatedSummary = 2,
    DegradedOrPartial = 3,
}

impl TruthViewExactnessClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptExact => "exact.truth_view.receipt_exact.e0",
            Self::SourceBoundProjection => "exact.truth_view.source_bound_projection.e1",
            Self::AggregatedSummary => "exact.truth_view.aggregated_summary.e2",
            Self::DegradedOrPartial => "exact.truth_view.degraded_or_partial.e3",
        }
    }
}

impl Default for TruthViewExactnessClass {
    fn default() -> Self {
        Self::SourceBoundProjection
    }
}

impl TryFrom<u32> for TruthViewExactnessClass {
    type Error = TruthViewDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ReceiptExact),
            1 => Ok(Self::SourceBoundProjection),
            2 => Ok(Self::AggregatedSummary),
            3 => Ok(Self::DegradedOrPartial),
            _ => Err(TruthViewDecodeError::UnknownSurfaceRecordExactnessClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TruthViewFreshnessClass {
    LiveWithinBudget = 0,
    ArchivedSnapshot = 1,
    DeterministicNonLive = 2,
    Stale = 3,
    Refused = 4,
}

impl TruthViewFreshnessClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LiveWithinBudget => "fresh.truth_view.live_within_budget.f0",
            Self::ArchivedSnapshot => "fresh.truth_view.archived_snapshot.f1",
            Self::DeterministicNonLive => "fresh.truth_view.deterministic_non_live.f2",
            Self::Stale => "fresh.truth_view.stale.f3",
            Self::Refused => "fresh.truth_view.refused.f4",
        }
    }
}

impl Default for TruthViewFreshnessClass {
    fn default() -> Self {
        Self::DeterministicNonLive
    }
}

impl TryFrom<u32> for TruthViewFreshnessClass {
    type Error = TruthViewDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::LiveWithinBudget),
            1 => Ok(Self::ArchivedSnapshot),
            2 => Ok(Self::DeterministicNonLive),
            3 => Ok(Self::Stale),
            4 => Ok(Self::Refused),
            _ => Err(TruthViewDecodeError::UnknownSurfaceRecordFreshnessClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TruthViewSourceClass {
    ReceiptGate = 0,
    RunbookState = 1,
    RuntimeMirror = 2,
    SemanticTrace = 3,
    XfstestsScoreboard = 4,
    ScenarioSuite = 5,
    PerformanceEval = 6,
    ChaosCampaign = 7,
    SecretPolicy = 8,
    ValidationArchiveStage = 9,
}

impl TruthViewSourceClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptGate => "source.truth_view.receipt_gate.a0",
            Self::RunbookState => "source.truth_view.runbook_state.a1",
            Self::RuntimeMirror => "source.truth_view.runtime_mirror.a2",
            Self::SemanticTrace => "source.truth_view.semantic_trace.a3",
            Self::XfstestsScoreboard => "source.truth_view.xfstests_scoreboard.a4",
            Self::ScenarioSuite => "source.truth_view.scenario_suite.a5",
            Self::PerformanceEval => "source.truth_view.performance_eval.a6",
            Self::ChaosCampaign => "source.truth_view.chaos_campaign.a7",
            Self::SecretPolicy => "source.truth_view.secret_policy.a8",
            Self::ValidationArchiveStage => "source.truth_view.validation_archive_stage.a9",
        }
    }
}

impl Default for TruthViewSourceClass {
    fn default() -> Self {
        Self::ValidationArchiveStage
    }
}

impl TryFrom<u32> for TruthViewSourceClass {
    type Error = TruthViewDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ReceiptGate),
            1 => Ok(Self::RunbookState),
            2 => Ok(Self::RuntimeMirror),
            3 => Ok(Self::SemanticTrace),
            4 => Ok(Self::XfstestsScoreboard),
            5 => Ok(Self::ScenarioSuite),
            6 => Ok(Self::PerformanceEval),
            7 => Ok(Self::ChaosCampaign),
            8 => Ok(Self::SecretPolicy),
            9 => Ok(Self::ValidationArchiveStage),
            _ => Err(TruthViewDecodeError::UnknownTruthBundleSourceClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TruthViewAudienceClass {
    MachineCanonical = 0,
    OperatorSummary = 1,
    ArchiveReader = 2,
}

impl TruthViewAudienceClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MachineCanonical => "audience.truth_view.machine_canonical.v0",
            Self::OperatorSummary => "audience.truth_view.operator_summary.v1",
            Self::ArchiveReader => "audience.truth_view.archive_reader.v2",
        }
    }
}

impl Default for TruthViewAudienceClass {
    fn default() -> Self {
        Self::OperatorSummary
    }
}

impl TryFrom<u32> for TruthViewAudienceClass {
    type Error = TruthViewDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::MachineCanonical),
            1 => Ok(Self::OperatorSummary),
            2 => Ok(Self::ArchiveReader),
            _ => Err(TruthViewDecodeError::UnknownTruthBundleAudienceClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TruthViewLiveViewClass {
    ClusterTopology = 0,
    PathHeatmap = 1,
    FailureDomainSpread = 2,
    GovernorTimeline = 3,
    WorkloadClassifier = 4,
    CapacityPressure = 5,
    MaterializationUtility = 6,
    ForeignMaterialization = 7,
    ClusterHealth = 8,
    RebuildProgress = 9,
    RiskRegister = 10,
}

impl TruthViewLiveViewClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClusterTopology => "view.truth_view.cluster_topology.v0",
            Self::PathHeatmap => "view.truth_view.path_heatmap.v1",
            Self::FailureDomainSpread => "view.truth_view.failure_domain_spread.v2",
            Self::GovernorTimeline => "view.truth_view.governor_timeline.v3",
            Self::WorkloadClassifier => "view.truth_view.workload_classifier.v4",
            Self::CapacityPressure => "view.truth_view.capacity_pressure.v5",
            Self::MaterializationUtility => "view.truth_view.materialization_utility.v6",
            Self::ForeignMaterialization => "view.truth_view.foreign_materialization.v7",
            Self::ClusterHealth => "view.truth_view.cluster_health.v8",
            Self::RebuildProgress => "view.truth_view.rebuild_progress.v9",
            Self::RiskRegister => "view.truth_view.risk_register.v10",
        }
    }

    #[must_use]
    pub const fn exposes_adaptive_governor_substrate(self) -> bool {
        matches!(
            self,
            Self::ClusterTopology
                | Self::PathHeatmap
                | Self::FailureDomainSpread
                | Self::GovernorTimeline
                | Self::WorkloadClassifier
                | Self::CapacityPressure
        )
    }

    #[must_use]
    pub const fn exposes_distributed_operator_truth(self) -> bool {
        matches!(
            self,
            Self::ClusterTopology
                | Self::FailureDomainSpread
                | Self::ClusterHealth
                | Self::RebuildProgress
                | Self::RiskRegister
        )
    }
}

impl Default for TruthViewLiveViewClass {
    fn default() -> Self {
        Self::GovernorTimeline
    }
}

impl TryFrom<u32> for TruthViewLiveViewClass {
    type Error = TruthViewDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ClusterTopology),
            1 => Ok(Self::PathHeatmap),
            2 => Ok(Self::FailureDomainSpread),
            3 => Ok(Self::GovernorTimeline),
            4 => Ok(Self::WorkloadClassifier),
            5 => Ok(Self::CapacityPressure),
            6 => Ok(Self::MaterializationUtility),
            7 => Ok(Self::ForeignMaterialization),
            8 => Ok(Self::ClusterHealth),
            9 => Ok(Self::RebuildProgress),
            10 => Ok(Self::RiskRegister),
            _ => Err(TruthViewDecodeError::UnknownSurfaceRecordLiveViewClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TruthViewMetricClass {
    EffectiveGovernorProfile = 0,
    InferredTopologyConfidence = 1,
    RecentActuationStatus = 2,
    PressureDebt = 3,
    WorkloadSignalConfidence = 4,
    PlacementSpreadRisk = 5,
    RebuildImpact = 6,
}

impl TruthViewMetricClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EffectiveGovernorProfile => "metric.truth_view.effective_governor_profile.m0",
            Self::InferredTopologyConfidence => "metric.truth_view.inferred_topology_confidence.m1",
            Self::RecentActuationStatus => "metric.truth_view.recent_actuation_status.m2",
            Self::PressureDebt => "metric.truth_view.pressure_debt.m3",
            Self::WorkloadSignalConfidence => "metric.truth_view.workload_signal_confidence.m4",
            Self::PlacementSpreadRisk => "metric.truth_view.placement_spread_risk.m5",
            Self::RebuildImpact => "metric.truth_view.rebuild_impact.m6",
        }
    }
}

impl Default for TruthViewMetricClass {
    fn default() -> Self {
        Self::EffectiveGovernorProfile
    }
}

impl TryFrom<u32> for TruthViewMetricClass {
    type Error = TruthViewDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::EffectiveGovernorProfile),
            1 => Ok(Self::InferredTopologyConfidence),
            2 => Ok(Self::RecentActuationStatus),
            3 => Ok(Self::PressureDebt),
            4 => Ok(Self::WorkloadSignalConfidence),
            5 => Ok(Self::PlacementSpreadRisk),
            6 => Ok(Self::RebuildImpact),
            _ => Err(TruthViewDecodeError::UnknownMetricClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TruthViewDistributedOperatorSignalClass {
    Placement = 0,
    Health = 1,
    Rebuild = 2,
    Risk = 3,
}

impl TruthViewDistributedOperatorSignalClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Placement => "operator.truth_view.distributed.placement.o0",
            Self::Health => "operator.truth_view.distributed.health.o1",
            Self::Rebuild => "operator.truth_view.distributed.rebuild.o2",
            Self::Risk => "operator.truth_view.distributed.risk.o3",
        }
    }

    #[must_use]
    pub const fn required_live_view(self) -> TruthViewLiveViewClass {
        match self {
            Self::Placement => TruthViewLiveViewClass::FailureDomainSpread,
            Self::Health => TruthViewLiveViewClass::ClusterHealth,
            Self::Rebuild => TruthViewLiveViewClass::RebuildProgress,
            Self::Risk => TruthViewLiveViewClass::RiskRegister,
        }
    }
}

impl Default for TruthViewDistributedOperatorSignalClass {
    fn default() -> Self {
        Self::Placement
    }
}

impl TryFrom<u32> for TruthViewDistributedOperatorSignalClass {
    type Error = TruthViewDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Placement),
            1 => Ok(Self::Health),
            2 => Ok(Self::Rebuild),
            3 => Ok(Self::Risk),
            _ => Err(TruthViewDecodeError::UnknownSurfaceRecordSignalClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TruthViewDistributedOperatorStatusClass {
    Nominal = 0,
    Degraded = 1,
    Rebuilding = 2,
    AtRisk = 3,
    Blocked = 4,
}

impl TruthViewDistributedOperatorStatusClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nominal => "status.truth_view.operator.nominal.s0",
            Self::Degraded => "status.truth_view.operator.degraded.s1",
            Self::Rebuilding => "status.truth_view.operator.rebuilding.s2",
            Self::AtRisk => "status.truth_view.operator.at_risk.s3",
            Self::Blocked => "status.truth_view.operator.blocked.s4",
        }
    }

    #[must_use]
    pub const fn requires_operator_attention(self) -> bool {
        matches!(
            self,
            Self::Degraded | Self::Rebuilding | Self::AtRisk | Self::Blocked
        )
    }
}

impl Default for TruthViewDistributedOperatorStatusClass {
    fn default() -> Self {
        Self::Nominal
    }
}

impl TryFrom<u32> for TruthViewDistributedOperatorStatusClass {
    type Error = TruthViewDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Nominal),
            1 => Ok(Self::Degraded),
            2 => Ok(Self::Rebuilding),
            3 => Ok(Self::AtRisk),
            4 => Ok(Self::Blocked),
            _ => Err(TruthViewDecodeError::UnknownSurfaceRecordStatusClass(value)),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TruthViewDistributedOperatorSurfaceRecord {
    pub surface_receipt_id: ControlPlaneReceiptId,
    pub source_bundle_receipt_id: ControlPlaneReceiptId,
    pub live_view_class: u32,
    pub signal_class: u32,
    pub status_class: u32,
    pub risk_ppm: u32,
    pub debt_units: u32,
    pub source_class: u32,
    pub cut_class: u32,
    pub provenance_class: u32,
    pub exactness_class: u32,
    pub freshness_class: u32,
    pub subject_digest: ControlPlaneDigest32,
    pub validation_digest: ControlPlaneDigest32,
    pub blocker_digest: ControlPlaneDigest32,
}

impl TruthViewDistributedOperatorSurfaceRecord {
    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn live_view(self) -> Result<TruthViewLiveViewClass, TruthViewDecodeError> {
        TruthViewLiveViewClass::try_from(self.live_view_class).map_err(|_| {
            TruthViewDecodeError::UnknownSurfaceRecordLiveViewClass(self.live_view_class)
        })
    }

    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn signal(self) -> Result<TruthViewDistributedOperatorSignalClass, TruthViewDecodeError> {
        TruthViewDistributedOperatorSignalClass::try_from(self.signal_class)
            .map_err(|_| TruthViewDecodeError::UnknownSurfaceRecordSignalClass(self.signal_class))
    }

    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn status(self) -> Result<TruthViewDistributedOperatorStatusClass, TruthViewDecodeError> {
        TruthViewDistributedOperatorStatusClass::try_from(self.status_class)
            .map_err(|_| TruthViewDecodeError::UnknownSurfaceRecordStatusClass(self.status_class))
    }

    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn source(self) -> Result<TruthViewSourceClass, TruthViewDecodeError> {
        TruthViewSourceClass::try_from(self.source_class)
            .map_err(|_| TruthViewDecodeError::UnknownSurfaceRecordSourceClass(self.source_class))
    }

    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn cut(self) -> Result<TruthViewCutClass, TruthViewDecodeError> {
        TruthViewCutClass::try_from(self.cut_class)
            .map_err(|_| TruthViewDecodeError::UnknownSurfaceRecordCutClass(self.cut_class))
    }

    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn provenance(self) -> Result<TruthViewProvenanceClass, TruthViewDecodeError> {
        TruthViewProvenanceClass::try_from(self.provenance_class).map_err(|_| {
            TruthViewDecodeError::UnknownSurfaceRecordProvenanceClass(self.provenance_class)
        })
    }

    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn exactness(self) -> Result<TruthViewExactnessClass, TruthViewDecodeError> {
        TruthViewExactnessClass::try_from(self.exactness_class).map_err(|_| {
            TruthViewDecodeError::UnknownSurfaceRecordExactnessClass(self.exactness_class)
        })
    }

    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn freshness(self) -> Result<TruthViewFreshnessClass, TruthViewDecodeError> {
        TruthViewFreshnessClass::try_from(self.freshness_class).map_err(|_| {
            TruthViewDecodeError::UnknownSurfaceRecordFreshnessClass(self.freshness_class)
        })
    }

    #[must_use]
    pub fn has_blocker(self) -> bool {
        self.blocker_digest != [0_u8; 32]
    }

    pub fn requires_operator_attention(self) -> bool {
        self.status()
            .map(TruthViewDistributedOperatorStatusClass::requires_operator_attention)
            .unwrap_or(true)
            || self.risk_ppm >= 500_000
            || self.has_blocker()
    }
}

const _: [(); 168] = [(); core::mem::size_of::<TruthViewDistributedOperatorSurfaceRecord>()];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TruthViewTruthBundleRecord {
    pub bundle_receipt_id: ControlPlaneReceiptId,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub response_registry_receipt_id: ControlPlaneReceiptId,
    pub control_plane_render_receipt_id_or_zero: ControlPlaneReceiptId,
    pub snapshot_receipt_id: ControlPlaneReceiptId,
    pub persistence_receipt_id: ControlPlaneReceiptId,
    pub hold_receipt_id: ControlPlaneReceiptId,
    pub recall_receipt_id: ControlPlaneReceiptId,
    pub disposition_receipt_id: ControlPlaneReceiptId,
    pub route_class: u32,
    pub surface_class: u32,
    pub cut_class: u32,
    pub source_class: u32,
    pub provenance_class: u32,
    pub audience_class: u32,
    pub answer_kind: u32,
    pub _reserved0: u32,
    pub answer_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
    pub bundle_digest: ControlPlaneDigest32,
    pub witness_refs: ControlPlanePolicyBudgetRecipeWitnessRefs,
}

impl TruthViewTruthBundleRecord {
    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn route(self) -> Result<ControlPlaneRouteClass, TruthViewDecodeError> {
        ControlPlaneRouteClass::try_from(self.route_class)
            .map_err(|_| TruthViewDecodeError::UnknownTruthBundleRouteClass(self.route_class))
    }

    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn surface(self) -> Result<TruthViewSurfaceClass, TruthViewDecodeError> {
        TruthViewSurfaceClass::try_from(self.surface_class)
            .map_err(|_| TruthViewDecodeError::UnknownTruthBundleSurfaceClass(self.surface_class))
    }

    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn cut(self) -> Result<TruthViewCutClass, TruthViewDecodeError> {
        TruthViewCutClass::try_from(self.cut_class)
            .map_err(|_| TruthViewDecodeError::UnknownTruthBundleCutClass(self.cut_class))
    }

    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn source(self) -> Result<TruthViewSourceClass, TruthViewDecodeError> {
        TruthViewSourceClass::try_from(self.source_class)
            .map_err(|_| TruthViewDecodeError::UnknownTruthBundleSourceClass(self.source_class))
    }

    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn provenance(self) -> Result<TruthViewProvenanceClass, TruthViewDecodeError> {
        TruthViewProvenanceClass::try_from(self.provenance_class).map_err(|_| {
            TruthViewDecodeError::UnknownTruthBundleProvenanceClass(self.provenance_class)
        })
    }

    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn audience(self) -> Result<TruthViewAudienceClass, TruthViewDecodeError> {
        TruthViewAudienceClass::try_from(self.audience_class)
            .map_err(|_| TruthViewDecodeError::UnknownTruthBundleAudienceClass(self.audience_class))
    }

    /// # Errors
    ///
    /// Returns [`TruthViewDecodeError`] on failure.
    pub fn answer_kind(self) -> Result<ResponseRegistryAnswerKind, TruthViewDecodeError> {
        ResponseRegistryAnswerKind::try_from(self.answer_kind)
            .map_err(|_| TruthViewDecodeError::UnknownTruthBundleAnswerKind(self.answer_kind))
    }

    #[must_use]
    pub const fn has_control_plane_render_receipt(&self) -> bool {
        !self.control_plane_render_receipt_id_or_zero.is_zero()
    }

    #[must_use]
    pub const fn has_witness_join(&self) -> bool {
        self.witness_refs.has_join()
    }
}

const _: [(); 384] = [(); core::mem::size_of::<TruthViewTruthBundleRecord>()];

// ── Convenience re-export modules ──────────────────────────────────────────

pub mod control_plane {
    pub const FAMILY_NAME: &str = "Control Plane";
    pub const ROLE: &str = "operator/control API, request envelopes, carrier frames, and receipts";

    pub use super::{
        ControlPlaneCarrierClass as CarrierClass, ControlPlaneDigest32 as Digest32,
        ControlPlaneId128 as Id128, ControlPlaneIdempotencyKey as IdempotencyKey,
        ControlPlaneJournalId as JournalId,
        ControlPlanePolicyBudgetRecipeWitnessRefs as PolicyBudgetRecipeWitnessRefs,
        ControlPlaneReceiptId as ReceiptId, ControlPlaneRenderClass as RenderClass,
        ControlPlaneRequestEnvelopeHead as RequestEnvelopeHead,
        ControlPlaneRequestEnvelopeHeadInput as RequestEnvelopeHeadInput,
        ControlPlaneRequestId as RequestId,
        ControlPlaneRequestJournalRecord as RequestJournalRecord,
        ControlPlaneResponseKind as ResponseKind,
        ControlPlaneResponseRenderReceipt as ResponseRenderReceipt,
        ControlPlaneResponseRenderReceiptInput as ResponseRenderReceiptInput,
        ControlPlaneRouteClass as RouteClass,
        ControlPlaneRouteTerminalReceiptRecord as RouteTerminalReceiptRecord,
        ControlPlaneRouteTerminalReceiptRecordInput as RouteTerminalReceiptRecordInput,
        ControlPlaneSessionId as SessionId,
        ControlPlaneTruthRecallLookupBatchReceiptRecord as TruthRecallLookupBatchReceiptRecord,
        ControlPlaneTruthRecallLookupBatchReceiptRecordInput as TruthRecallLookupBatchReceiptRecordInput,
        ControlPlaneTruthRecallLookupHitRecord as TruthRecallLookupHitRecord,
        ControlPlaneTruthRecallLookupHitRecordInput as TruthRecallLookupHitRecordInput,
        ControlPlaneTruthRecallLookupRequestRecord as TruthRecallLookupRequestRecord,
        ControlPlaneVisibilityClass as VisibilityClass,
        ControlPlaneWriteManualProductAdmissionPayload as ManualProductAdmissionPayload,
        ControlPlaneWriteRequestKind as WriteRequestKind,
    };

    pub const CANON_VERSION_1: u32 = super::CONTROL_PLANE_CANON_VERSION_1;
    pub const REQUEST_FLAG_IDEMPOTENT: u32 = super::CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT;
    pub const REQUEST_FLAG_PUBLIC_CARRIER: u32 = super::CONTROL_PLANE_REQUEST_FLAG_PUBLIC_CARRIER;
    pub const REQUEST_FLAG_JOURNAL_REQUIRED: u32 =
        super::CONTROL_PLANE_REQUEST_FLAG_JOURNAL_REQUIRED;
    pub const REQUEST_FLAG_PAYLOAD_REDACTED: u32 =
        super::CONTROL_PLANE_REQUEST_FLAG_PAYLOAD_REDACTED;
    pub const TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY: u32 =
        super::CONTROL_PLANE_TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY;
    pub const TRUTH_RECALL_LOOKUP_ANSWER_KIND_FILTER_ANY: u32 =
        super::CONTROL_PLANE_TRUTH_RECALL_LOOKUP_ANSWER_KIND_FILTER_ANY;
    pub const TRUTH_RECALL_LOOKUP_REQUEST_FLAG_REQUIRE_TERMINAL_RECEIPT: u32 =
        super::CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_REQUIRE_TERMINAL_RECEIPT;
    pub const TRUTH_RECALL_LOOKUP_REQUEST_FLAG_ALLOW_SUPERSEDED: u32 =
        super::CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_ALLOW_SUPERSEDED;
    pub const TRUTH_RECALL_LOOKUP_HIT_FLAG_TERMINAL_RECEIPT: u32 =
        super::CONTROL_PLANE_TRUTH_RECALL_LOOKUP_HIT_FLAG_TERMINAL_RECEIPT;
    pub const TRUTH_RECALL_LOOKUP_BATCH_RECEIPT_FLAG_ALL_TERMINAL_RECEIPTS: u32 =
        super::CONTROL_PLANE_TRUTH_RECALL_LOOKUP_BATCH_RECEIPT_FLAG_ALL_TERMINAL_RECEIPTS;
}

pub mod policy_authority {
    pub const FAMILY_NAME: &str = "Policy Authority";
    pub const ROLE: &str = "policy authority types";

    pub use super::{
        PolicyAuthorityCapsuleClass as CapsuleClass,
        PolicyAuthorityIngressSurfaceClass as IngressSurfaceClass,
        PolicyAuthorityRefusalClass as RefusalClass, PolicyAuthorityShardClass as ShardClass,
        PolicyAuthorityStageClass as StageClass,
    };
}

pub mod publication_pipeline {
    pub use super::PublicationPipelineEmissionTicketRecord as EmissionTicketRecord;
}

pub mod response_registry {
    pub use super::ResponseRegistryRenderClass as RenderClass;
}

pub mod truth_view {
    // TruthView types are available directly via crate root;
}

// TURN3_HUMAN_VFS_ENGINE_ALIASES
/// Human-named module for the VFS engine boundary types.
pub mod vfs_engine {
    pub const FAMILY_NAME: &str = "VFS Engine Boundary";
    pub const ROLE: &str = "portable POSIX/VFS scalar and fixed-size record types";

    pub use super::{
        CreateFlags, DirEntry, DirEntryName, DirHandleId, EngineDirHandle, EngineFileHandle, Errno,
        FileHandleId, Generation, InodeAttr, InodeFlags, InodeId, LockSpec, LseekOffset,
        NodeFacets, NodeKind, OpenFlags, PosixAttrs, PosixTimestampNs, RenameFlags, RequestCtx,
        SetAttr, StatFs, FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_UNSHARE_RANGE,
        FALLOC_FL_ZERO_RANGE, FATTR_ATIME, FATTR_ATIME_NOW, FATTR_CTIME, FATTR_FH, FATTR_GID,
        FATTR_LOCKOWNER, FATTR_MODE, FATTR_MTIME, FATTR_MTIME_NOW, FATTR_SIZE, FATTR_UID, F_RDLCK,
        F_UNLCK, F_WRLCK, RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT, ROOT_INODE_ID,
        SEEK_CUR, SEEK_END, SEEK_SET, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG,
        S_IFSOCK, S_ISGID, S_ISUID, S_ISVTX, XATTR_CREATE, XATTR_REPLACE,
    };
}

/// Human alias namespace. Prefer `human::vfs_engine::*` in new examples.
pub mod human {
    pub mod vfs_engine {
        pub use crate::vfs_engine::*;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_posix_time_ns_normalizes_negative_subsecond() {
        assert_eq!(split_posix_time_ns(-1), (-1, 999_999_999));
        assert_eq!(
            split_posix_time_ns(-315_619_198_876_543_211),
            (-315_619_199, 123_456_789)
        );
    }

    #[test]
    fn compose_posix_time_ns_preserves_negative_subsecond() {
        assert_eq!(compose_posix_time_ns(-1, 999_999_999), -1);
        assert_eq!(
            compose_posix_time_ns(-315_619_199, 123_456_789),
            -315_619_198_876_543_211
        );
    }

    #[test]
    fn posix_timestamp_ns_wraps_split_compose_boundary() {
        let ts = PosixTimestampNs::from_unix_nanos(-315_619_198_876_543_211);
        let (sec, nsec) = ts.split();
        assert_eq!((sec, nsec), (-315_619_199, 123_456_789));
        assert_eq!(
            PosixTimestampNs::from_split(sec, nsec),
            PosixTimestampNs::from_unix_nanos(-315_619_198_876_543_211)
        );
        assert_eq!(i64::from(ts), -315_619_198_876_543_211);
    }

    #[test]
    fn node_kind_round_trips_through_u32() {
        let kind = NodeKind::Socket;
        let roundtrip = NodeKind::try_from(kind.as_u32()).expect("kind");
        assert_eq!(roundtrip, kind);
    }

    #[test]
    fn inode_id_round_trips_through_u64() {
        let id = InodeId::new(0xCAFE_BABE_DEAD_BEEF);
        assert_eq!(id.get(), 0xCAFE_BABE_DEAD_BEEF);
    }

    #[test]
    fn generation_round_trips_through_u64() {
        let gen = Generation::new(42);
        assert_eq!(gen.get(), 42);
        assert_eq!(Generation::from_vfs_generation(42).as_vfs_generation(), 42);
    }

    #[test]
    fn generation_boundary_values_stay_vfs_identity() {
        assert_eq!(Generation::ZERO.as_vfs_generation(), 0);
        assert_eq!(Generation::MAX.as_vfs_generation(), u64::MAX);
        assert_eq!(
            Generation::from_vfs_generation(u64::MAX - 1).checked_next(),
            Some(Generation::MAX)
        );
        assert_eq!(Generation::MAX.checked_next(), None);
    }

    #[test]
    fn setattr_timestamp_helpers_mark_explicit_posix_updates() {
        let mut set = SetAttr::new();
        set.set_atime_timestamp(PosixTimestampNs::from_unix_nanos(-1));
        set.set_mtime_timestamp(PosixTimestampNs::from_split(2, 3));
        set.set_ctime_timestamp(PosixTimestampNs::UNIX_EPOCH);

        assert!(set.is_valid(FATTR_ATIME));
        assert!(set.is_valid(FATTR_MTIME));
        assert!(set.is_valid(FATTR_CTIME));
        assert_eq!(set.atime_timestamp(), PosixTimestampNs::from_unix_nanos(-1));
        assert_eq!(
            set.mtime_timestamp(),
            PosixTimestampNs::from_unix_nanos(2_000_000_003)
        );
        assert_eq!(set.ctime_timestamp(), PosixTimestampNs::UNIX_EPOCH);
    }

    #[test]
    fn file_and_dir_handle_ids_round_trip() {
        let fh = FileHandleId::new(100);
        let dh = DirHandleId::new(200);
        assert_eq!(fh.get(), 100);
        assert_eq!(dh.get(), 200);
    }

    #[test]
    fn node_kind_all_variants_round_trip_through_u32() {
        let kinds = [
            NodeKind::Dir,
            NodeKind::File,
            NodeKind::Symlink,
            NodeKind::CharDev,
            NodeKind::BlockDev,
            NodeKind::Fifo,
            NodeKind::Socket,
            NodeKind::Whiteout,
        ];
        for &k in &kinds {
            let roundtrip = NodeKind::try_from(k.as_u32()).expect("valid kind");
            assert_eq!(roundtrip, k);
        }
    }

    #[test]
    fn engine_file_handle_round_trips_fields() {
        let fh = EngineFileHandle {
            inode_id: InodeId::new(3),
            open_flags: 0x42,
            fh_id: FileHandleId::new(5),
            lock_owner: 7,
        };
        assert_eq!(fh.inode_id, InodeId::new(3));
        assert_eq!(fh.open_flags, 0x42);
        assert_eq!(fh.fh_id, FileHandleId::new(5));
        assert_eq!(fh.lock_owner, 7);
    }

    #[test]
    fn engine_dir_handle_round_trips_fields() {
        let dh = EngineDirHandle {
            inode_id: InodeId::new(4),
            dh_id: DirHandleId::new(6),
        };
        assert_eq!(dh.inode_id, InodeId::new(4));
        assert_eq!(dh.dh_id, DirHandleId::new(6));
    }

    #[test]
    fn set_attr_preserves_all_fields() {
        let sa = SetAttr {
            valid: FATTR_MODE | FATTR_SIZE,
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            size: 4096,
            atime_ns: 1,
            mtime_ns: 2,
            ctime_ns: 3,
        };
        assert_eq!(sa.valid, FATTR_MODE | FATTR_SIZE);
        assert_eq!(sa.mode, 0o755);
        assert_eq!(sa.size, 4096);
    }

    #[test]
    fn lock_spec_preserves_all_fields() {
        let ls = LockSpec {
            typ: 1,
            whence: 0,
            start: 0,
            end: 4095,
            pid: 42,
        };
        assert_eq!(ls.typ, 1);
        assert_eq!(ls.pid, 42);
    }

    #[test]
    fn posix_attrs_inode_attr_and_flags_construction() {
        let flags = InodeFlags {
            immutable: true,
            append_only: false,
            noatime: true,
            nodump: false,
        };
        assert!(flags.immutable);
        assert!(flags.noatime);
        assert!(!flags.append_only);

        let posix = PosixAttrs {
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            nlink: 1,
            rdev: 0,
            atime_ns: 100,
            mtime_ns: 200,
            ctime_ns: 300,
            btime_ns: 50,
            size: 1024,
            blocks_512: 2,
            blksize: 4096,
        };
        assert_eq!(posix.mode, 0o644);

        let attr = InodeAttr {
            inode_id: InodeId::new(10),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix,
            flags,
            subtree_rev: 0,
            dir_rev: 0,
        };
        assert_eq!(attr.inode_id, InodeId::new(10));
        assert_eq!(attr.kind, NodeKind::File);
        assert_eq!(attr.posix.size, 1024);
    }

    #[test]
    fn statfs_construction_preserves_fields() {
        let sf = StatFs {
            block_size: 4096,
            fragment_size: 4096,
            total_blocks: 1_000_000,
            free_blocks: 500_000,
            avail_blocks: 400_000,
            files: 200_000,
            files_free: 100_000,
            name_max: 255,
            fsid_hi: 1,
            fsid_lo: 2,
        };
        assert_eq!(sf.block_size, 4096);
        assert_eq!(sf.total_blocks, 1_000_000);
        assert_eq!(sf.name_max, 255);
    }

    #[test]
    fn root_inode_id_is_one() {
        assert_eq!(ROOT_INODE_ID, InodeId::new(1));
    }

    // ── NodeKind boundary tests ────────────────────────────────────────

    #[test]
    fn node_kind_default_is_file() {
        assert_eq!(NodeKind::default(), NodeKind::File);
        assert_eq!(NodeKind::default().as_u32(), 2);
    }

    #[test]
    fn node_kind_all_variants_have_distinct_u32() {
        let kinds = [
            NodeKind::Dir,
            NodeKind::File,
            NodeKind::Symlink,
            NodeKind::CharDev,
            NodeKind::BlockDev,
            NodeKind::Fifo,
            NodeKind::Socket,
            NodeKind::Whiteout,
        ];
        // All values are in 1..=8
        for k in &kinds {
            let v = k.as_u32();
            assert!((1..=8).contains(&v));
        }
        // All distinct
        for i in 0..kinds.len() {
            for j in (i + 1)..kinds.len() {
                assert_ne!(kinds[i].as_u32(), kinds[j].as_u32());
            }
        }
    }

    #[test]
    fn node_kind_try_from_rejects_invalid() {
        let err = NodeKind::try_from(0_u32).expect_err("0 is invalid");
        assert_eq!(err.0, 0);
        let err = NodeKind::try_from(9_u32).expect_err("9 is invalid");
        assert_eq!(err.0, 9);
        let err = NodeKind::try_from(255_u32).expect_err("255 is invalid");
        assert_eq!(err.0, 255);
    }

    #[test]
    fn node_kind_decode_error_holds_value() {
        let e = NodeKindDecodeError(42);
        assert_eq!(e.0, 42);
    }

    // ── Scalar newtype boundary ────────────────────────────────────────

    #[test]
    fn inode_id_default_is_zero() {
        assert_eq!(InodeId::default().get(), 0);
    }

    #[test]
    fn generation_max_value_roundtrip() {
        let g = Generation::new(u64::MAX);
        assert_eq!(g.get(), u64::MAX);
    }

    #[test]
    fn file_handle_id_boundary_values() {
        assert_eq!(FileHandleId::default().get(), 0);
        let fh = FileHandleId::new(u64::MAX);
        assert_eq!(fh.get(), u64::MAX);
    }

    #[test]
    fn dir_handle_id_boundary_values() {
        assert_eq!(DirHandleId::default().get(), 0);
        let dh = DirHandleId::new(u64::MAX);
        assert_eq!(dh.get(), u64::MAX);
    }

    // ── Engine struct exhaustive roundtrip ─────────────────────────────

    #[test]
    fn engine_file_handle_default_all_zeros() {
        let fh = EngineFileHandle::default();
        assert_eq!(fh.inode_id.get(), 0);
        assert_eq!(fh.open_flags, 0);
        assert_eq!(fh.fh_id.get(), 0);
        assert_eq!(fh.lock_owner, 0);
    }

    #[test]
    fn engine_dir_handle_default_all_zeros() {
        let dh = EngineDirHandle::default();
        assert_eq!(dh.inode_id.get(), 0);
        assert_eq!(dh.dh_id.get(), 0);
    }

    // ── SetAttr full coverage ──────────────────────────────────────────

    #[test]
    fn set_attr_all_fields_roundtrip() {
        let sa = SetAttr {
            valid: FATTR_MODE
                | FATTR_UID
                | FATTR_GID
                | FATTR_SIZE
                | FATTR_ATIME
                | FATTR_MTIME
                | FATTR_CTIME,
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            size: 8192,
            atime_ns: 100,
            mtime_ns: 200,
            ctime_ns: 300,
        };
        assert_eq!(
            sa.valid,
            FATTR_MODE
                | FATTR_UID
                | FATTR_GID
                | FATTR_SIZE
                | FATTR_ATIME
                | FATTR_MTIME
                | FATTR_CTIME
        );
        assert_eq!(sa.mode, 0o755);
        assert_eq!(sa.uid, 1000);
        assert_eq!(sa.gid, 1000);
        assert_eq!(sa.size, 8192);
        assert_eq!(sa.atime_ns, 100);
        assert_eq!(sa.mtime_ns, 200);
        assert_eq!(sa.ctime_ns, 300);
    }

    #[test]
    fn set_attr_flag_bits_are_distinct_powers_of_two() {
        let flags = [
            FATTR_MODE,
            FATTR_UID,
            FATTR_GID,
            FATTR_SIZE,
            FATTR_ATIME,
            FATTR_MTIME,
            FATTR_FH,
            FATTR_ATIME_NOW,
            FATTR_MTIME_NOW,
            FATTR_LOCKOWNER,
            FATTR_CTIME,
        ];
        for f in &flags {
            assert!(f.count_ones() == 1);
        }
    }

    // ── LockSpec full coverage ─────────────────────────────────────────

    #[test]
    fn lock_spec_all_fields_roundtrip() {
        let ls = LockSpec {
            typ: 2,
            whence: 1,
            start: 1024,
            end: 2048,
            pid: 99,
        };
        assert_eq!(ls.typ, 2);
        assert_eq!(ls.whence, 1);
        assert_eq!(ls.start, 1024);
        assert_eq!(ls.end, 2048);
        assert_eq!(ls.pid, 99);
    }

    // ── PosixAttrs full coverage ───────────────────────────────────────

    #[test]
    fn posix_attrs_all_fields_roundtrip() {
        let pa = PosixAttrs {
            mode: 0o644,
            uid: 1001,
            gid: 1002,
            nlink: 3,
            rdev: 0xABCD,
            atime_ns: 111,
            mtime_ns: 222,
            ctime_ns: 333,
            btime_ns: 44,
            size: 2048,
            blocks_512: 4,
            blksize: 4096,
        };
        assert_eq!(pa.mode, 0o644);
        assert_eq!(pa.uid, 1001);
        assert_eq!(pa.gid, 1002);
        assert_eq!(pa.nlink, 3);
        assert_eq!(pa.rdev, 0xABCD);
        assert_eq!(pa.atime_ns, 111);
        assert_eq!(pa.mtime_ns, 222);
        assert_eq!(pa.ctime_ns, 333);
        assert_eq!(pa.btime_ns, 44);
        assert_eq!(pa.size, 2048);
        assert_eq!(pa.blocks_512, 4);
        assert_eq!(pa.blksize, 4096);
    }

    // ── InodeFlags full coverage ──────────────────────────────────────

    #[test]
    fn inode_flags_all_combinations() {
        let f1 = InodeFlags {
            immutable: true,
            append_only: false,
            noatime: false,
            nodump: false,
        };
        assert!(f1.immutable);
        assert!(!f1.append_only);

        let f2 = InodeFlags {
            immutable: false,
            append_only: true,
            noatime: false,
            nodump: false,
        };
        assert!(f2.append_only);

        let f3 = InodeFlags {
            immutable: false,
            append_only: false,
            noatime: true,
            nodump: false,
        };
        assert!(f3.noatime);

        let f4 = InodeFlags {
            immutable: false,
            append_only: false,
            noatime: false,
            nodump: true,
        };
        assert!(f4.nodump);

        let all = InodeFlags {
            immutable: true,
            append_only: true,
            noatime: true,
            nodump: true,
        };
        assert!(all.immutable && all.append_only && all.noatime && all.nodump);

        let none = InodeFlags::default();
        assert!(!none.immutable && !none.append_only && !none.noatime && !none.nodump);
    }

    // ── InodeAttr full coverage ────────────────────────────────────────

    #[test]
    fn inode_attr_all_fields_roundtrip() {
        let attr = InodeAttr {
            inode_id: InodeId::new(42),
            generation: Generation::new(7),
            kind: NodeKind::Dir,
            posix: PosixAttrs {
                mode: 0o755,
                ..PosixAttrs::default()
            },
            flags: InodeFlags {
                noatime: true,
                ..InodeFlags::default()
            },
            subtree_rev: 5,
            dir_rev: 10,
        };
        assert_eq!(attr.inode_id, InodeId::new(42));
        assert_eq!(attr.generation, Generation::new(7));
        assert_eq!(attr.kind, NodeKind::Dir);
        assert_eq!(attr.posix.mode, 0o755);
        assert!(attr.flags.noatime);
        assert_eq!(attr.subtree_rev, 5);
        assert_eq!(attr.dir_rev, 10);
    }

    // ── StatFs full coverage ───────────────────────────────────────────

    #[test]
    fn statfs_all_fields_roundtrip() {
        let sf = StatFs {
            block_size: 512,
            fragment_size: 512,
            total_blocks: 2_000_000,
            free_blocks: 1_500_000,
            avail_blocks: 1_400_000,
            files: 500_000,
            files_free: 300_000,
            name_max: 255,
            fsid_hi: 0xDEAD,
            fsid_lo: 0xBEEF,
        };
        assert_eq!(sf.block_size, 512);
        assert_eq!(sf.fragment_size, 512);
        assert_eq!(sf.total_blocks, 2_000_000);
        assert_eq!(sf.free_blocks, 1_500_000);
        assert_eq!(sf.avail_blocks, 1_400_000);
        assert_eq!(sf.files, 500_000);
        assert_eq!(sf.files_free, 300_000);
        assert_eq!(sf.name_max, 255);
        assert_eq!(sf.fsid_hi, 0xDEAD);
        assert_eq!(sf.fsid_lo, 0xBEEF);
    }

    // ── Constants ──────────────────────────────────────────────────────

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn rename_flag_bits_are_distinct() {
        assert!(RENAME_NOREPLACE != RENAME_EXCHANGE);
        assert!(RENAME_EXCHANGE != RENAME_WHITEOUT);
        assert!(RENAME_NOREPLACE != RENAME_WHITEOUT);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn xattr_flags_are_distinct() {
        assert!(XATTR_CREATE != XATTR_REPLACE);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn inode_mode_constants_are_non_zero() {
        assert!(S_IFMT != 0);
        assert!(S_IFREG != 0);
        assert!(S_IFDIR != 0);
        assert!(S_IFLNK != 0);
    }

    #[test]
    fn root_inode_id_has_value_one() {
        assert_eq!(ROOT_INODE_ID.get(), 1);
    }

    // ── Facet layer tests (Design rule Rule 4) ────────────────────────────

    #[test]
    fn facets_dir_has_child_namespace_no_byte_space() {
        let f = NodeKind::Dir.to_facets();
        assert!(!f.has_byte_space);
        assert!(f.has_child_namespace);
        assert!(f.carries_child_namespace());
        assert!(!f.carries_byte_space());
    }

    #[test]
    fn facets_file_has_byte_space_no_child_namespace() {
        let f = NodeKind::File.to_facets();
        assert!(f.has_byte_space);
        assert!(!f.has_child_namespace);
        assert!(f.carries_byte_space());
        assert!(!f.carries_child_namespace());
    }

    #[test]
    fn facets_symlink_has_byte_space_no_child_namespace() {
        let f = NodeKind::Symlink.to_facets();
        assert!(f.has_byte_space);
        assert!(!f.has_child_namespace);
    }

    #[test]
    fn facets_special_nodes_are_metadata_only() {
        for kind in [
            NodeKind::CharDev,
            NodeKind::BlockDev,
            NodeKind::Fifo,
            NodeKind::Socket,
        ] {
            let f = kind.to_facets();
            assert!(!f.has_byte_space, "{kind:?} must not carry content bytes");
            assert!(!f.has_child_namespace, "{kind:?} must not carry children");
        }
    }

    #[test]
    fn nodekind_from_facets_roundtrips_dir() {
        let facets = NodeKind::Dir.to_facets();
        assert_eq!(NodeKind::from_facets(facets), NodeKind::Dir);
    }

    #[test]
    fn nodekind_from_facets_roundtrips_file() {
        let facets = NodeKind::File.to_facets();
        assert_eq!(NodeKind::from_facets(facets), NodeKind::File);
    }

    #[test]
    fn nodekind_from_facets_roundtrips_symlink() {
        let facets = NodeKind::Symlink.to_facets();
        // Symlink and File share facets; from_facets produces File.
        // Distinguishing them requires mode bits.
        assert_eq!(NodeKind::from_facets(facets), NodeKind::File);
    }

    #[test]
    fn facets_default_is_no_caps() {
        let f = NodeFacets::default();
        assert!(!f.has_byte_space);
        assert!(!f.has_child_namespace);
    }

    #[test]
    fn nodekind_has_child_namespace_only_for_dir() {
        assert!(NodeKind::Dir.has_child_namespace());
        assert!(!NodeKind::File.has_child_namespace());
        assert!(!NodeKind::Symlink.has_child_namespace());
        assert!(!NodeKind::CharDev.has_child_namespace());
        assert!(!NodeKind::BlockDev.has_child_namespace());
    }

    #[test]
    fn to_facets_from_nodekind_via_into() {
        let f: NodeFacets = NodeKind::Dir.into();
        assert!(f.has_child_namespace);
        assert!(!f.has_byte_space);
    }

    #[test]
    fn projection_kind_is_from_facets() {
        let facets = NodeFacets {
            has_byte_space: true,
            has_child_namespace: false,
        };
        assert_eq!(facets.projection_kind(), NodeKind::from_facets(facets));
    }

    #[test]
    fn whiteout_has_no_caps() {
        let f = NodeKind::Whiteout.to_facets();
        assert!(!f.has_byte_space);
        assert!(!f.has_child_namespace);
    }
}

#[cfg(test)]
mod errno_tests {
    use super::*;

    #[test]
    fn errno_success_is_zero() {
        assert_eq!(Errno::SUCCESS.raw(), 0);
        assert!(Errno::SUCCESS.is_success());
        assert!(!Errno::SUCCESS.is_error());
    }

    #[test]
    fn errno_eperm_is_one() {
        assert_eq!(Errno::EPERM.raw(), 1);
        assert!(!Errno::EPERM.is_success());
        assert!(Errno::EPERM.is_error());
    }

    #[test]
    fn errno_name_returns_constant_string() {
        assert_eq!(Errno::SUCCESS.name(), "SUCCESS");
        assert_eq!(Errno::ENOENT.name(), "ENOENT");
        assert_eq!(Errno::EACCES.name(), "EACCES");
        assert_eq!(Errno::ENOSPC.name(), "ENOSPC");
        assert_eq!(Errno::ESTALE.name(), "ESTALE");
        assert_eq!(Errno::EOPNOTSUPP.name(), "EOPNOTSUPP");
    }

    #[test]
    fn errno_message_returns_strerror_string() {
        assert_eq!(Errno::SUCCESS.message(), "Success");
        assert_eq!(Errno::ENOENT.message(), "No such file or directory");
        assert_eq!(Errno::EACCES.message(), "Permission denied");
        assert_eq!(Errno::ENOSPC.message(), "No space left on device");
        assert_eq!(Errno::ESTALE.message(), "Stale file handle");
    }

    #[test]
    fn errno_display_uses_name() {
        assert_eq!(alloc::format!("{}", Errno::ENOENT), "ENOENT");
        assert_eq!(alloc::format!("{}", Errno::EIO), "EIO");
        assert_eq!(alloc::format!("{}", Errno::SUCCESS), "SUCCESS");
    }

    #[test]
    fn errno_default_is_success() {
        assert_eq!(Errno::default(), Errno::SUCCESS);
    }

    #[test]
    fn errno_from_u16_and_back() {
        let e: Errno = 2u16.into();
        assert_eq!(e, Errno::ENOENT);
        let raw: u16 = e.into();
        assert_eq!(raw, 2);
    }

    #[test]
    fn errno_from_raw_roundtrip() {
        for val in [0u16, 1, 2, 13, 17, 22, 28, 39, 95, 116] {
            let e = Errno::from_raw(val);
            assert_eq!(e.raw(), val);
        }
    }

    #[test]
    fn unknown_errno_has_fallback_name() {
        let e = Errno::from_raw(255);
        assert_eq!(e.name(), "UNKNOWN_ERRNO");
        assert_eq!(e.message(), "Unknown error");
    }

    #[test]
    fn unknown_errno_out_of_bounds_safe() {
        let e = Errno::from_raw(600);
        assert_eq!(e.name(), "UNKNOWN_ERRNO");
        assert_eq!(e.message(), "Unknown error");
    }

    #[test]
    fn all_defined_constants_have_non_empty_name() {
        let constants: &[(Errno, &str)] = &[
            (Errno::EPERM, "EPERM"),
            (Errno::ENOENT, "ENOENT"),
            (Errno::EACCES, "EACCES"),
            (Errno::ENOSPC, "ENOSPC"),
            (Errno::ENOTDIR, "ENOTDIR"),
            (Errno::EISDIR, "EISDIR"),
            (Errno::EINVAL, "EINVAL"),
            (Errno::EBUSY, "EBUSY"),
            (Errno::EEXIST, "EEXIST"),
            (Errno::EXDEV, "EXDEV"),
            (Errno::ENOTEMPTY, "ENOTEMPTY"),
            (Errno::ENAMETOOLONG, "ENAMETOOLONG"),
            (Errno::EMLINK, "EMLINK"),
            (Errno::ENOSYS, "ENOSYS"),
            (Errno::EOPNOTSUPP, "EOPNOTSUPP"),
            (Errno::ESTALE, "ESTALE"),
            (Errno::EROFS, "EROFS"),
            (Errno::EFBIG, "EFBIG"),
        ];
        for (c, name) in constants {
            assert_eq!(c.name(), *name, "constant {name} has wrong name");
            assert!(!c.message().is_empty(), "constant {name} has empty message");
        }
    }

    #[test]
    fn errno_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Errno>();
    }

    #[test]
    fn errno_size_is_two_bytes() {
        assert_eq!(core::mem::size_of::<Errno>(), 2);
    }

    #[test]
    fn errno_ordering_follows_numeric_value() {
        assert!(Errno::SUCCESS < Errno::EPERM);
        assert!(Errno::ENOENT < Errno::EACCES);
        assert!(Errno::EACCES < Errno::ESTALE);
    }

    #[test]
    fn errno_noncontiguous_entries_have_correct_names() {
        assert_eq!(Errno::ENOMSG.name(), "ENOMSG");
        assert_eq!(Errno::EIDRM.name(), "EIDRM");
        assert_eq!(Errno::ENOSTR.name(), "ENOSTR");
        assert_eq!(Errno::ENODATA.name(), "ENODATA");
        assert_eq!(Errno::ETIME.name(), "ETIME");
        assert_eq!(Errno::EBADMSG.name(), "EBADMSG");
        assert_eq!(Errno::EOVERFLOW.name(), "EOVERFLOW");
        assert_eq!(Errno::EILSEQ.name(), "EILSEQ");
    }

    #[test]
    fn from_u16_to_errno_constructs_correct_value() {
        let e: Errno = 13u16.into();
        assert_eq!(e, Errno::EACCES);
    }
}

#[cfg(test)]
mod request_ctx_tests {
    use super::*;

    #[test]
    fn request_ctx_default_is_zeroed() {
        let ctx = RequestCtx::default();
        assert_eq!(ctx.uid, 0);
        assert_eq!(ctx.gid, 0);
        assert_eq!(ctx.pid, 0);
        assert_eq!(ctx.umask, 0);
    }

    #[test]
    fn request_ctx_construction_preserves_fields() {
        let ctx = RequestCtx {
            uid: 1000,
            gid: 100,
            pid: 42,
            umask: 0o022,
            #[cfg(feature = "alloc")]
            groups: alloc::vec![100, 200],
        };
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 100);
        assert_eq!(ctx.pid, 42);
        assert_eq!(ctx.umask, 0o022);
        #[cfg(feature = "alloc")]
        assert_eq!(ctx.groups, alloc::vec![100, 200]);
    }

    #[test]
    fn request_ctx_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RequestCtx>();
    }
}

#[cfg(test)]
mod dir_entry_tests {
    use super::*;

    #[test]
    fn dir_entry_default_values() {
        let de = DirEntry::default();
        assert_eq!(de.inode_id, InodeId::default());
        assert_eq!(de.kind, NodeKind::default());
        assert_eq!(de.generation, Generation::default());
        assert_eq!(de.cookie, 0);
    }

    #[test]
    fn dir_entry_construction_preserves_fields() {
        let de = DirEntry {
            #[cfg(feature = "alloc")]
            name: alloc::vec![b'h', b'e', b'l', b'l', b'o'],
            #[cfg(not(feature = "alloc"))]
            name: {
                let mut n = DirEntryName::empty();
                n.data[..5].copy_from_slice(b"hello");
                n.len = 5;
                n
            },
            inode_id: InodeId::new(42),
            kind: NodeKind::File,
            generation: Generation::new(3),
            cookie: 7,
        };
        assert_eq!(de.inode_id, InodeId::new(42));
        assert_eq!(de.kind, NodeKind::File);
        assert_eq!(de.generation, Generation::new(3));
        assert_eq!(de.cookie, 7);
    }

    #[test]
    fn dir_entry_name_empty_default() {
        let n = DirEntryName::default();
        assert_eq!(n.len, 0);
        assert!(n.as_bytes().is_empty());
    }

    #[test]
    fn dir_entry_name_stores_and_retrieves_bytes() {
        let mut n = DirEntryName::empty();
        n.data[..3].copy_from_slice(b"foo");
        n.len = 3;
        assert_eq!(n.as_bytes(), b"foo");
    }

    #[test]
    fn dir_entry_name_max_capacity() {
        let mut n = DirEntryName::empty();
        let full = [b'x'; 255];
        n.data[..255].copy_from_slice(&full);
        n.len = 255;
        assert_eq!(n.as_bytes().len(), 255);
    }

    #[test]
    fn dir_entry_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DirEntry>();

    }
}

#[cfg(test)]
mod setattr_validate_tests {
    use super::*;

    #[test]
    fn valid_with_all_known_bits_passes() {
        let sa = SetAttr {
            valid: FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE
                | FATTR_ATIME | FATTR_MTIME | FATTR_FH
                | FATTR_ATIME_NOW | FATTR_MTIME_NOW
                | FATTR_LOCKOWNER | FATTR_CTIME,
            ..SetAttr::default()
        };
        assert!(sa.validate().is_ok());
    }

    #[test]
    fn valid_with_no_bits_passes() {
        let sa = SetAttr::default();
        assert!(sa.validate().is_ok());
    }

    #[test]
    fn valid_rejects_unknown_bit() {
        let sa = SetAttr {
            valid: FATTR_VALID_MASK | (1 << 15),
            ..SetAttr::default()
        };
        let err = sa.validate().expect_err("unknown bit should reject");
        assert_eq!(err.unknown_bits, 1 << 15);
        assert_eq!(err.valid, FATTR_VALID_MASK | (1 << 15));
    }

    #[test]
    fn valid_rejects_all_unknown() {
        let sa = SetAttr {
            valid: 0xFFFF_0000,
            ..SetAttr::default()
        };
        let err = sa.validate().expect_err("all-unknown should reject");
        assert_eq!(err.unknown_bits, 0xFFFF_0000 & !FATTR_VALID_MASK);
    }

    #[test]
    fn fattr_valid_mask_covers_every_known_bit() {
        assert_eq!(FATTR_VALID_MASK, (1 << 11) - 1); // bits 0-10
    }
}

#[cfg(test)]
mod posix_attrs_validate_tests {
    use super::*;

    #[test]
    fn valid_mode_types_pass() {
        for mt in [S_IFREG, S_IFDIR, S_IFLNK, S_IFBLK, S_IFCHR, S_IFIFO, S_IFSOCK] {
            let pa = PosixAttrs {
                mode: mt | 0o755,
                ..PosixAttrs::default()
            };
            assert!(pa.validate().is_ok(), "mode type {mt:#o} should pass");
        }
    }

    #[test]
    fn zero_mode_type_rejects() {
        let pa = PosixAttrs {
            mode: 0o755, // no S_IFMT bits set
            ..PosixAttrs::default()
        };
        let err = pa.validate().expect_err("zero mode type should reject");
        assert_eq!(err.mode, 0o755);
    }

    #[test]
    fn unknown_mode_type_rejects() {
        let pa = PosixAttrs {
            mode: 0o030_000 | 0o644, // reserved S_IFMT bits
            ..PosixAttrs::default()
        };
        let err = pa.validate().expect_err("unknown mode type should reject");
        assert_eq!(err.mode, 0o030_000 | 0o644);
    }

    #[test]
    fn default_posix_attrs_rejects() {
        let pa = PosixAttrs::default();
        let err = pa.validate().expect_err("default has no mode type");
        assert_eq!(err.mode, 0);
    }
}

#[cfg(test)]
mod inode_flags_validate_tests {
    use super::*;

    #[test]
    fn from_raw_flags_roundtrips_immutable() {
        let raw = InodeFlags::FLAG_IMMUTABLE;
        let flags = InodeFlags::from_raw_flags(raw).expect("valid");
        assert!(flags.immutable);
        assert!(!flags.append_only);
        assert!(!flags.nodump);
        assert!(!flags.noatime);
    }

    #[test]
    fn from_raw_flags_roundtrips_all_known() {
        let raw = InodeFlags::FLAG_IMMUTABLE
            | InodeFlags::FLAG_APPEND_ONLY
            | InodeFlags::FLAG_NODUMP
            | InodeFlags::FLAG_NOATIME;
        let flags = InodeFlags::from_raw_flags(raw).expect("all known");
        assert_eq!(flags.to_raw_flags(), raw);
        assert!(flags.immutable);
        assert!(flags.append_only);
        assert!(flags.nodump);
        assert!(flags.noatime);
    }

    #[test]
    fn from_raw_flags_zero_roundtrips() {
        let flags = InodeFlags::from_raw_flags(0).expect("zero");
        assert_eq!(flags.to_raw_flags(), 0);
        assert!(!flags.immutable);
        assert!(!flags.append_only);
        assert!(!flags.nodump);
        assert!(!flags.noatime);
    }

    #[test]
    fn from_raw_flags_rejects_unknown_bits() {
        let err = InodeFlags::from_raw_flags(0x1).expect_err("bit 0 unknown");
        assert_eq!(err.unknown_bits, 0x1);

        let err = InodeFlags::from_raw_flags(InodeFlags::FLAG_VALID_MASK | 0x100).expect_err("bit 8 unknown");
        assert_eq!(err.unknown_bits, 0x100);
    }

    #[test]
    fn raw_flags_include_nodump() {
        let f = InodeFlags {
            nodump: true,
            ..InodeFlags::default()
        };
        assert_eq!(f.to_raw_flags(), InodeFlags::FLAG_NODUMP);
    }
}

#[cfg(test)]
mod lock_spec_validate_tests {
    use super::*;

    #[test]
    fn valid_typ_whence_combinations_pass() {
        for typ in [F_RDLCK, F_WRLCK, F_UNLCK] {
            for whence in [SEEK_SET, SEEK_CUR, SEEK_END] {
                let ls = LockSpec {
                    typ,
                    whence,
                    ..LockSpec::default()
                };
                assert!(ls.validate().is_ok(), "typ={typ} whence={whence}");
            }
        }
    }

    #[test]
    fn unknown_typ_rejects() {
        let ls = LockSpec {
            typ: 99,
            whence: SEEK_SET,
            ..LockSpec::default()
        };
        let err = ls.validate().expect_err("unknown typ");
        assert_eq!(err.typ, 99);
        assert_eq!(err.whence, SEEK_SET);
    }

    #[test]
    fn unknown_whence_rejects() {
        let ls = LockSpec {
            typ: F_WRLCK,
            whence: 99,
            ..LockSpec::default()
        };
        let err = ls.validate().expect_err("unknown whence");
        assert_eq!(err.typ, F_WRLCK);
        assert_eq!(err.whence, 99);
    }

    #[test]
    fn both_unknown_rejects() {
        let ls = LockSpec {
            typ: 99,
            whence: 99,
            ..LockSpec::default()
        };
        let err = ls.validate().expect_err("both unknown");
        assert_eq!(err.typ, 99);
        assert_eq!(err.whence, 99);
    }

    #[test]
    fn default_lock_spec_passes() {
        let ls = LockSpec::default();
        assert!(ls.validate().is_ok());
    }
}

#[cfg(test)]
mod contract_version_validate_tests {
    use crate::contract::*;

    #[test]
    fn v1_passes_validation() {
        assert!(TIDE_CONTRACT_VERSION_V1.validate().is_ok());
        assert!(ContractVersion::new(1).validate().is_ok());
    }

    #[test]
    fn version_zero_rejects() {
        let err = ContractVersion::new(0).validate().expect_err("zero");
        assert_eq!(err.version, 0);
    }

    #[test]
    fn version_above_max_rejects() {
        let err = ContractVersion::new(2).validate().expect_err("above max");
        assert_eq!(err.version, 2);

        let err = ContractVersion::new(255).validate().expect_err("far above");
        assert_eq!(err.version, 255);
    }
}

#[cfg(test)]
mod request_envelope_validate_tests {
    use crate::contract::*;

    #[test]
    fn zero_payload_flags_passes() {
        let envelope = RequestEnvelope::new(
            RequestMetadata::new(RequestId::ZERO, ContractEpoch::new(1), TraceId::ZERO),
            TideRequest::default(),
        );
        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn non_zero_payload_flags_rejects() {
        let mut envelope = RequestEnvelope::new(
            RequestMetadata::new(RequestId::ZERO, ContractEpoch::new(1), TraceId::ZERO),
            TideRequest::default(),
        );
        envelope.payload_flags = 1;
        let err = envelope.validate().expect_err("non-zero flags");
        assert_eq!(err.payload_flags, 1);
    }
}

#[cfg(test)]
mod tide_completion_validate_tests {
    use crate::contract::*;

    #[test]
    fn zero_result_flags_passes() {
        let tc = TideCompletion::success(
            RequestId::ZERO,
            TraceId::ZERO,
            ContractEpoch::new(1),
        );
        assert!(tc.validate().is_ok());
    }

    #[test]
    fn non_zero_result_flags_rejects() {
        let mut tc = TideCompletion::success(
            RequestId::ZERO,
            TraceId::ZERO,
            ContractEpoch::new(1),
        );
        tc.result_flags = 0xDEAD;
        let err = tc.validate().expect_err("non-zero flags");
        assert_eq!(err.result_flags, 0xDEAD);
    }
}

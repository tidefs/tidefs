//! Kernel-compatible no_std type definitions for the TideFS VFS boundary.
//!
//! These types MUST match the userspace types in tidefs-types-vfs-core and
//! tidefs-vfs-engine exactly in field names, method signatures, and trait
//! contracts so that the consuming source files compile without change in
//! either environment.
//!
//! Under cargo (non-Kbuild), this module re-exports the authoritative
//! userspace crate types so that the kernel leaf modules see exactly the
//! same API surface that tidefs-types-vfs-core and tidefs-vfs-engine
//! provide — zero divergence, zero surprise.
//!
//! Under Kbuild (Linux 7.0 kernel build environment), where userspace
//! crates are not available, this module defines self-contained
//! kernel-compatible equivalents.

mod kbuild_impl {
    use core::fmt;

    pub const POSIX_NANOS_PER_SECOND: i64 = 1_000_000_000;

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

    // ── InodeId ────────────────────────────────────────────────────────

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

    impl fmt::Display for InodeId {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    // ── Generation ─────────────────────────────────────────────────────

    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
    pub struct Generation(pub u64);

    impl Generation {
        #[must_use]
        pub const fn new(value: u64) -> Self {
            Self(value)
        }
        #[must_use]
        pub const fn get(self) -> u64 {
            self.0
        }
    }

    // ── FileHandleId / DirHandleId ─────────────────────────────────────

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

    // ── Errno ──────────────────────────────────────────────────────────

    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
    pub struct Errno(pub u16);

    impl Errno {
        pub const SUCCESS: Self = Self(0);
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
        pub const EOVERFLOW: Self = Self(75);
        pub const EOPNOTSUPP: Self = Self(95);
        pub const ESTALE: Self = Self(116);
        pub const ENODATA: Self = Self(61);
        pub const EUCLEAN: Self = Self(117);
        pub const ENOTSUP: Self = Self(95);

        #[must_use]
        pub const fn from_raw(value: u16) -> Self {
            Self(value)
        }
        #[must_use]
        pub const fn raw(self) -> u16 {
            self.0
        }
        #[must_use]
        pub const fn is_success(self) -> bool {
            self.0 == 0
        }
        #[must_use]
        pub const fn is_error(self) -> bool {
            self.0 != 0
        }
        #[must_use]
        pub fn name(self) -> &'static str {
            "EUNKNOWN"
        }
        #[must_use]
        pub fn message(self) -> &'static str {
            "unknown error"
        }
    }

    impl fmt::Display for Errno {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "errno={}", self.0)
        }
    }

    // ── RequestCtx ─────────────────────────────────────────────────────

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RequestCtx {
        pub uid: u32,
        pub gid: u32,
        pub pid: u32,
        pub umask: u32,
        pub groups: KmodVec<u32>,
    }

    impl RequestCtx {
        #[must_use]
        pub fn new(uid: u32, gid: u32, pid: u32, umask: u32, groups: KmodVec<u32>) -> Self {
            Self {
                uid,
                gid,
                pid,
                umask,
                groups,
            }
        }
    }

    impl Default for RequestCtx {
        fn default() -> Self {
            Self {
                uid: 0,
                gid: 0,
                pid: 0,
                umask: 0o022,
                groups: KmodVec::<u32>::new(),
            }
        }
    }

    // ── EngineFileHandle / EngineDirHandle ─────────────────────────────

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EngineFileHandle {
        pub inode_id: InodeId,
        pub open_flags: u32,
        pub fh_id: FileHandleId,
        pub lock_owner: u64,
    }

    impl EngineFileHandle {
        #[must_use]
        pub fn placeholder() -> Self {
            Self {
                inode_id: InodeId::new(0),
                open_flags: 0,
                fh_id: FileHandleId::new(0),
                lock_owner: 0,
            }
        }
        #[must_use]
        pub fn new(
            inode_id: InodeId,
            open_flags: u32,
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

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EngineDirHandle {
        pub inode_id: InodeId,
        pub dh_id: DirHandleId,
    }

    impl EngineDirHandle {
        #[must_use]
        pub fn new(inode_id: InodeId, dh_id: DirHandleId) -> Self {
            Self { inode_id, dh_id }
        }
    }

    // ── NodeKind ───────────────────────────────────────────────────────
    // Must match tidefs-types-vfs-core exactly.

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
        #[must_use]
        pub const fn has_child_namespace(self) -> bool {
            matches!(self, Self::Dir)
        }
    }

    // ── PosixAttrs ─────────────────────────────────────────────────────

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct PosixAttrs {
        pub mode: u32,
        pub uid: u32,
        pub gid: u32,
        pub nlink: u32,
        pub rdev: u32,
        pub atime_ns: i64,
        pub mtime_ns: i64,
        pub ctime_ns: i64,
        pub btime_ns: i64,
        pub size: u64,
        pub blocks_512: u64,
        pub blksize: u32,
    }

    // ── InodeFlags ─────────────────────────────────────────────────────

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct InodeFlags(pub u32);

    // ── InodeAttr ──────────────────────────────────────────────────────
    // Must match tidefs-types-vfs-core exactly (including Eq).

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct InodeAttr {
        pub inode_id: InodeId,
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

    // ── DirEntry ───────────────────────────────────────────────────────

    pub struct DirEntry {
        pub name: kernel::alloc::KVec<u8>,
        pub inode_id: InodeId,
        pub kind: NodeKind,
        pub generation: Generation,
        pub cookie: u64,
    }

    // KVec does not implement Clone; implement manually.
    impl Clone for DirEntry {
        fn clone(&self) -> Self {
            let mut name = kernel::alloc::KVec::<u8>::with_capacity(
                self.name.len(),
                kernel::alloc::flags::GFP_KERNEL,
            )
            .unwrap_or_else(|_| kernel::alloc::KVec::<u8>::new());
            let _ = name.extend_from_slice(&self.name, kernel::alloc::flags::GFP_KERNEL);
            Self {
                name,
                inode_id: self.inode_id,
                kind: self.kind,
                generation: self.generation,
                cookie: self.cookie,
            }
        }
    }

    impl PartialEq for DirEntry {
        fn eq(&self, other: &Self) -> bool {
            self.name == other.name
                && self.inode_id == other.inode_id
                && self.kind == other.kind
                && self.generation == other.generation
                && self.cookie == other.cookie
        }
    }

    impl fmt::Debug for DirEntry {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("DirEntry")
                .field("name", &"<<KVec>>")
                .field("inode_id", &self.inode_id)
                .field("kind", &self.kind)
                .field("generation", &self.generation)
                .field("cookie", &self.cookie)
                .finish()
        }
    }

    // ── LockSpec ───────────────────────────────────────────────────────
    // Must match tidefs-types-vfs-core exactly.

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    }

    // ── SetAttr ────────────────────────────────────────────────────────
    // Must match tidefs-types-vfs-core exactly.

    #[derive(Clone, Debug, PartialEq)]
    pub struct SetAttr {
        pub valid: u32,
        pub mode: u32,
        pub uid: u32,
        pub gid: u32,
        pub size: u64,
        pub atime_ns: i64,
        pub mtime_ns: i64,
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
    }

    impl Default for SetAttr {
        fn default() -> Self {
            Self::new()
        }
    }

    // ── StatFs ─────────────────────────────────────────────────────────

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct StatFs {
        pub blocks: u64,
        pub bfree: u64,
        pub bavail: u64,
        pub files: u64,
        pub ffree: u64,
        pub bsize: u32,
        pub namelen: u32,
        pub frsize: u32,
        pub block_size: u32,
        pub fsid_hi: u64,
        pub fsid_lo: u64,
    }

    // ── FATTR_* / S_IF* / F_*LCK / O_* constants ───────────────────────

    pub const FATTR_MODE: u32 = 1 << 0;
    pub const FATTR_UID: u32 = 1 << 1;
    pub const FATTR_GID: u32 = 1 << 2;
    pub const FATTR_SIZE: u32 = 1 << 3;
    pub const FATTR_ATIME: u32 = 1 << 4;
    pub const FATTR_MTIME: u32 = 1 << 5;
    pub const FATTR_CTIME: u32 = 1 << 7;
    pub const FATTR_ATIME_NOW: u32 = 1 << 8;
    pub const FATTR_MTIME_NOW: u32 = 1 << 9;

    pub const S_IFMT: u32 = 0o170000;
    pub const S_IFDIR: u32 = 0o040000;
    pub const S_IFREG: u32 = 0o100000;
    pub const S_IFCHR: u32 = 0o020000;
    pub const S_IFBLK: u32 = 0o060000;
    pub const S_IFIFO: u32 = 0o010000;
    pub const S_IFSOCK: u32 = 0o140000;
    pub const S_IFLNK: u32 = 0o120000;

    pub const F_RDLCK: u32 = 0;
    pub const F_WRLCK: u32 = 1;
    pub const F_UNLCK: u32 = 2;

    pub const O_RDONLY: u32 = 0;
    pub const O_WRONLY: u32 = 1;
    pub const O_RDWR: u32 = 2;
    pub const O_ACCMODE: u32 = 3;
    pub const O_CREAT: u32 = 0o100;
    pub const O_EXCL: u32 = 0o200;
    pub const O_TRUNC: u32 = 0o1000;
    pub const O_APPEND: u32 = 0o2000;
    pub const O_DIRECTORY: u32 = 0o200000;

    // ── Writeback / extent / lseek / setattr outcome types ─────────────

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct WritebackRange {
        pub offset: u64,
        pub length: u64,
    }

    impl WritebackRange {
        #[must_use]
        pub const fn new(offset: u64, length: u64) -> Self {
            Self { offset, length }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct WritebackOutcome {
        pub bytes_written: u64,
        pub complete: bool,
    }

    impl WritebackOutcome {
        #[must_use]
        pub const fn new(bytes_written: u64, complete: bool) -> Self {
            Self {
                bytes_written,
                complete,
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct AllocateExtentsOutcome {
        pub bytes_allocated: u64,
        pub complete: bool,
    }

    impl AllocateExtentsOutcome {
        #[must_use]
        pub const fn new(bytes_allocated: u64, complete: bool) -> Self {
            Self {
                bytes_allocated,
                complete,
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct LseekDataRange {
        pub start: u64,
        pub end: u64,
    }

    impl LseekDataRange {
        #[must_use]
        pub const fn new(start: u64, end: u64) -> Self {
            Self { start, end }
        }
    }
    // ── FiemapExtent / FiemapExtentVec ──────────────────────────────────

    /// A single FIEMAP extent matching Linux `struct fiemap_extent` layout.
    ///
    /// Fields match `tidefs_types_extent_map_core::FiemapExtent` exactly:
    /// `fe_logical`, `fe_physical`, `fe_length`, `fe_flags`.
    /// The two reserved u64 fields (`fe_reserved64`) are omitted.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct FiemapExtent {
        /// Logical byte offset within the file where this extent begins.
        pub fe_logical: u64,
        /// Physical byte offset on the underlying device.
        pub fe_physical: u64,
        /// Length of the extent in bytes.
        pub fe_length: u64,
        /// FIEMAP_EXTENT_* flags.
        pub fe_flags: u32,
    }

    impl FiemapExtent {
        pub const FLAG_LAST: u32 = 0x0000_0001;
        pub const FLAG_UNKNOWN: u32 = 0x0000_0002;
        pub const FLAG_DELALLOC: u32 = 0x0000_0004;
        pub const FLAG_ENCODED: u32 = 0x0000_0008;
        pub const FLAG_DATA_ENCRYPTED: u32 = 0x0000_0080;
        pub const FLAG_NOT_ALIGNED: u32 = 0x0000_0100;
        pub const FLAG_DATA_INLINE: u32 = 0x0000_0200;
        pub const FLAG_DATA_TAIL: u32 = 0x0000_0400;
        pub const FLAG_UNWRITTEN: u32 = 0x0000_0800;
        pub const FLAG_MERGED: u32 = 0x0000_1000;
        pub const FLAG_SHARED: u32 = 0x0000_2000;

        #[must_use]
        pub const fn new(fe_logical: u64, fe_physical: u64, fe_length: u64, fe_flags: u32) -> Self {
            Self {
                fe_logical,
                fe_physical,
                fe_length,
                fe_flags,
            }
        }
    }

    /// A collection of [`FiemapExtent`] entries returned by [`VfsEngine::fiemap`].
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct FiemapExtentVec {
        pub extents: KmodVec<FiemapExtent>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SetattrOutcome {
        pub attr: InodeAttr,
        pub truncate_block_change: bool,
    }

    impl SetattrOutcome {
        #[must_use]
        pub fn new(attr: InodeAttr, truncate_block_change: bool) -> Self {
            Self {
                attr,
                truncate_block_change,
            }
        }
    }

    /// Access mode for the page-ownership protocol.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PageOwnershipMode {
        Read,
        Write,
    }

    // ── VfsEngine trait ────────────────────────────────────────────────
    // Must match tidefs-vfs-engine exactly.

    #[allow(unused_variables)]
    pub struct KmodVec<T> {
        inner: kernel::alloc::KVec<T>,
    }

    impl<T> KmodVec<T> {
        #[must_use]
        pub const fn new() -> Self {
            Self {
                inner: kernel::alloc::KVec::new(),
            }
        }

        #[must_use]
        pub fn with_capacity(capacity: usize) -> Self {
            Self {
                inner: kernel::alloc::KVec::with_capacity(
                    capacity,
                    kernel::alloc::flags::GFP_KERNEL,
                )
                .unwrap_or_else(|_| kernel::alloc::KVec::new()),
            }
        }

        pub fn push(&mut self, value: T) {
            let _ = self.inner.push(value, kernel::alloc::flags::GFP_KERNEL);
        }

        #[must_use]
        pub fn from_elem(value: T, n: usize) -> Self
        where
            T: Clone,
        {
            Self {
                inner: kernel::alloc::KVec::from_elem(value, n, kernel::alloc::flags::GFP_KERNEL)
                    .unwrap_or_else(|_| kernel::alloc::KVec::new()),
            }
        }

        pub fn resize(&mut self, new_len: usize, value: T)
        where
            T: Clone,
        {
            let _ = self
                .inner
                .resize(new_len, value, kernel::alloc::flags::GFP_KERNEL);
        }

        pub fn extend_from_slice(&mut self, other: &[T])
        where
            T: Clone,
        {
            let _ = self
                .inner
                .extend_from_slice(other, kernel::alloc::flags::GFP_KERNEL);
        }

        #[must_use]
        pub fn len(&self) -> usize {
            self.inner.len()
        }

        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }

        #[must_use]
        pub fn capacity(&self) -> usize {
            self.inner.capacity()
        }

        pub fn clear(&mut self) {
            self.inner.clear();
        }

        pub fn pop(&mut self) -> Option<T> {
            self.inner.pop()
        }

        pub fn reserve(&mut self, additional: usize) {
            let _ = self
                .inner
                .reserve(additional, kernel::alloc::flags::GFP_KERNEL);
        }

        pub fn truncate(&mut self, len: usize) {
            self.inner.truncate(len);
        }

        pub fn remove(&mut self, index: usize) -> T {
            self.inner
                .remove(index)
                .unwrap_or_else(|_| panic!("index out of bounds"))
        }

        pub fn insert(&mut self, index: usize, element: T) {
            let _ = self.inner.insert_within_capacity(index, element);
        }

        pub fn retain(&mut self, f: impl FnMut(&mut T) -> bool) {
            self.inner.retain(f);
        }
    }

    impl<T> From<&[T]> for KmodVec<T>
    where
        T: Clone,
    {
        fn from(slice: &[T]) -> Self {
            let mut v = Self::with_capacity(slice.len());
            v.extend_from_slice(slice);
            v
        }
    }

    impl<T> core::ops::Deref for KmodVec<T> {
        type Target = [T];

        fn deref(&self) -> &[T] {
            self.inner.as_slice()
        }
    }

    impl<T> core::ops::DerefMut for KmodVec<T> {
        fn deref_mut(&mut self) -> &mut [T] {
            self.inner.as_mut_slice()
        }
    }

    impl<T: Clone> Clone for KmodVec<T> {
        fn clone(&self) -> Self {
            let mut v = Self::with_capacity(self.len());
            v.extend_from_slice(self);
            v
        }
    }

    impl<T: core::fmt::Debug> core::fmt::Debug for KmodVec<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Debug::fmt(&**self, f)
        }
    }

    impl<T: PartialEq> PartialEq for KmodVec<T> {
        fn eq(&self, other: &Self) -> bool {
            self.as_ref() == other.as_ref()
        }
    }

    impl<T: PartialEq, const N: usize> PartialEq<[T; N]> for KmodVec<T> {
        fn eq(&self, other: &[T; N]) -> bool {
            self.as_ref() == other.as_slice()
        }
    }

    impl<T: Clone, const N: usize> From<[T; N]> for KmodVec<T> {
        fn from(arr: [T; N]) -> Self {
            let mut v = Self::with_capacity(N);
            v.extend_from_slice(&arr);
            v
        }
    }

    impl<T: Eq> Eq for KmodVec<T> {}

    impl<T> Default for KmodVec<T> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<'a, T: Clone> Extend<&'a T> for KmodVec<T> {
        fn extend<I: IntoIterator<Item = &'a T>>(&mut self, iter: I) {
            for item in iter {
                self.push(item.clone());
            }
        }
    }

    impl<T> Extend<T> for KmodVec<T> {
        fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
            for item in iter {
                self.push(item);
            }
        }
    }

    // ── IntoIterator implementations ──────────────────────────────────

    impl<T> IntoIterator for KmodVec<T> {
        type Item = T;
        type IntoIter = kernel::alloc::IntoIter<T, kernel::alloc::allocator::Kmalloc>;

        fn into_iter(self) -> Self::IntoIter {
            self.inner.into_iter()
        }
    }

    impl<'a, T> IntoIterator for &'a KmodVec<T> {
        type Item = &'a T;
        type IntoIter = core::slice::Iter<'a, T>;

        fn into_iter(self) -> Self::IntoIter {
            self.inner.as_slice().iter()
        }
    }

    impl<'a, T> IntoIterator for &'a mut KmodVec<T> {
        type Item = &'a mut T;
        type IntoIter = core::slice::IterMut<'a, T>;

        fn into_iter(self) -> Self::IntoIter {
            self.inner.as_mut_slice().iter_mut()
        }
    }

    // -- Memory-mapped I/O types -----------------------------------------

    /// Engine policy for memory-mapped file access.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum MmapPolicy {
        PopulateOnFault,
        PreFaultPages,
        Denied,
    }

    /// Outcome of a page-fault resolution by the engine.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct VmFaultOutcome {
        pub page: KmodVec<u8>,
        pub vm_fault_code: u32,
    }

    pub const VM_FAULT_MINOR: u32 = 0;
    pub const VM_FAULT_MAJOR: u32 = 1;
    pub const VM_FAULT_LOCKED: u32 = 2;
    pub const VM_FAULT_OOM: u32 = 3;
    pub const VM_FAULT_SIGBUS: u32 = 4;
    pub const VM_FAULT_NOPAGE: u32 = 5;
    pub const VM_FAULT_HWPOISON: u32 = 6;
    pub const VM_FAULT_RETRY: u32 = 7;

    // ── KmodBox — kernel-compatible Box alias ────────────────────────────
    /// Kernel-compatible `Box`.
    ///
    /// Under Kbuild this is `kernel::alloc::KBox`; under cargo it is
    /// `alloc::boxed::Box` (see `kmod/src/lib.rs`).
    pub type KmodBox<T> = kernel::alloc::KBox<T>;

    // ── KmodString — kernel-compatible String wrapper ──────────────────────
    /// Kernel-compatible `String` wrapping `KVec<u8>`.
    ///
    /// Provides the minimal `alloc::string::String`-compatible API so
    /// kernel leaf modules can compile the same `format!(…)` and push_str
    /// code paths used under cargo.  Under cargo this is a plain
    /// `alloc::string::String` type alias (see `kmod/src/lib.rs`).
    pub struct KmodString {
        inner: kernel::alloc::KVec<u8>,
    }

    impl KmodString {
        #[must_use]
        pub fn new() -> Self {
            Self {
                inner: kernel::alloc::KVec::new(),
            }
        }

        #[must_use]
        pub fn with_capacity(capacity: usize) -> Self {
            Self {
                inner: kernel::alloc::KVec::with_capacity(
                    capacity,
                    kernel::alloc::flags::GFP_KERNEL,
                )
                .unwrap_or_else(|_| kernel::alloc::KVec::new()),
            }
        }

        pub fn push_str(&mut self, s: &str) {
            let _ = self
                .inner
                .extend_from_slice(s.as_bytes(), kernel::alloc::flags::GFP_KERNEL);
        }

        pub fn push(&mut self, ch: char) {
            let mut buf = [0u8; 4];
            let s = ch.encode_utf8(&mut buf);
            let _ = self
                .inner
                .extend_from_slice(s.as_bytes(), kernel::alloc::flags::GFP_KERNEL);
        }

        #[must_use]
        pub fn as_str(&self) -> Result<&str, core::str::Utf8Error> {
            core::str::from_utf8(self.inner.as_slice())
        }

        #[must_use]
        pub fn len(&self) -> usize {
            self.inner.len()
        }

        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }

        pub fn clear(&mut self) {
            self.inner.clear();
        }

        #[must_use]
        pub fn as_bytes(&self) -> &[u8] {
            self.inner.as_slice()
        }
    }

    impl core::fmt::Write for KmodString {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            self.push_str(s);
            Ok(())
        }
    }

    impl core::fmt::Display for KmodString {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self.as_str() {
                Ok(s) => core::fmt::Display::fmt(s, f),
                Err(_) => core::fmt::Debug::fmt(self.inner.as_slice(), f),
            }
        }
    }

    impl core::fmt::Debug for KmodString {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self.as_str() {
                Ok(s) => core::fmt::Debug::fmt(s, f),
                Err(_) => core::fmt::Debug::fmt(self.inner.as_slice(), f),
            }
        }
    }

    impl From<&str> for KmodString {
        fn from(s: &str) -> Self {
            let mut v = Self::with_capacity(s.len());
            v.push_str(s);
            v
        }
    }

    impl Clone for KmodString {
        fn clone(&self) -> Self {
            let mut v = Self::with_capacity(self.len());
            let _ = v
                .inner
                .extend_from_slice(self.inner.as_slice(), kernel::alloc::flags::GFP_KERNEL);
            v
        }
    }

    impl PartialEq for KmodString {
        fn eq(&self, other: &Self) -> bool {
            self.inner.as_slice() == other.inner.as_slice()
        }
    }

    impl PartialEq<str> for KmodString {
        fn eq(&self, other: &str) -> bool {
            self.inner.as_slice() == other.as_bytes()
        }
    }

    impl Eq for KmodString {}

    impl Default for KmodString {
        fn default() -> Self {
            Self::new()
        }
    }

    impl core::ops::Deref for KmodString {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            self.inner.as_slice()
        }
    }

    pub const VFS_COPY_FILE_RANGE_MAX_CHUNK: u64 = 4096;

    // ── kformat! — format-like macro for KmodString ──────────────────────
    /// Format arguments into a [`KmodString`].
    ///
    /// This is the kernel-compatible equivalent of `alloc::format!`.
    /// Under cargo, `alloc::format!` is used directly.
    #[macro_export]
    macro_rules! kformat {
        ($($arg:tt)*) => {{
            use core::fmt::Write;
            let mut s = $crate::kernel_types_impl::KmodString::new();
            let _ = write!(s, $($arg)*);
            s
        }};
    }

    pub trait VfsEngine {
        fn get_root_inode(&self, ctx: &RequestCtx) -> Result<InodeId, Errno>;
        fn lookup(
            &self,
            parent: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno>;
        fn getattr(
            &self,
            inode: InodeId,
            handle: Option<&EngineFileHandle>,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno>;
        fn setattr(
            &self,
            inode: InodeId,
            attr: &SetAttr,
            handle: Option<&EngineFileHandle>,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno>;
        fn mkdir(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno>;
        fn create(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno>;
        fn create_excl(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }
        fn tmpfile(
            &self,
            parent: InodeId,
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno>;
        fn unlink(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno>;
        fn rmdir(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno>;
        fn rename(
            &self,
            old_parent: InodeId,
            old_name: &[u8],
            new_parent: InodeId,
            new_name: &[u8],
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(), Errno>;
        fn link(
            &self,
            target: InodeId,
            new_parent: InodeId,
            new_name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno>;
        fn symlink(
            &self,
            parent: InodeId,
            name: &[u8],
            target: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno>;
        fn readlink(&self, inode: InodeId, ctx: &RequestCtx) -> Result<KmodVec<u8>, Errno>;
        fn mknod(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            rdev: u32,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno>;
        fn open(
            &self,
            inode: InodeId,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<EngineFileHandle, Errno>;
        fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno>;
        fn read(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            size: u32,
            ctx: &RequestCtx,
        ) -> Result<KmodVec<u8>, Errno>;
        fn write(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            data: &[u8],
            ctx: &RequestCtx,
        ) -> Result<u32, Errno>;
        fn flush(&self, fh: &EngineFileHandle, ctx: &RequestCtx) -> Result<(), Errno>;
        fn fsync(
            &self,
            fh: &EngineFileHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno>;
        fn fallocate(
            &self,
            fh: &EngineFileHandle,
            mode: u32,
            offset: u64,
            length: u64,
            ctx: &RequestCtx,
        ) -> Result<(), Errno>;
        /// Advisory readahead hint. The engine may prefetch data for the given
        /// range. Errors are non-fatal; the caller should tolerate them.
        fn readahead(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            length: u32,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Ok(())
        }
        fn opendir(&self, inode: InodeId, ctx: &RequestCtx) -> Result<EngineDirHandle, Errno>;
        fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno>;
        fn readdir(
            &self,
            dh: &EngineDirHandle,
            offset: u64,
            ctx: &RequestCtx,
        ) -> Result<(KmodVec<DirEntry>, bool), Errno>;
        fn fsyncdir(
            &self,
            dh: &EngineDirHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno>;
        fn getxattr(
            &self,
            inode: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<KmodVec<u8>, Errno>;
        fn setxattr(
            &self,
            inode: InodeId,
            name: &[u8],
            value: &[u8],
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(), Errno>;
        fn listxattr(&self, inode: InodeId, ctx: &RequestCtx) -> Result<KmodVec<u8>, Errno>;
        fn removexattr(&self, inode: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno>;
        fn getlk(
            &self,
            inode: InodeId,
            lock: &LockSpec,
            ctx: &RequestCtx,
        ) -> Result<Option<LockSpec>, Errno>;
        fn setlk(&self, inode: InodeId, lock: &LockSpec, ctx: &RequestCtx) -> Result<(), Errno>;
        fn writeback_folios(
            &self,
            inode: InodeId,
            fh: &EngineFileHandle,
            range: WritebackRange,
            ctx: &RequestCtx,
        ) -> Result<WritebackOutcome, Errno>;
        fn allocate_extents(
            &self,
            inode: InodeId,
            offset: u64,
            length: u64,
            ctx: &RequestCtx,
        ) -> Result<AllocateExtentsOutcome, Errno>;
        fn data_ranges(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            length: u64,
            ctx: &RequestCtx,
        ) -> Result<KmodVec<LseekDataRange>, Errno> {
            Err(Errno::ENOSYS)
        }
        /// Query file extent mapping information (FIEMAP / FS_IOC_FIEMAP).
        ///
        /// Returns committed extent-map data for the open file handle.
        /// Each [`FiemapExtent`] records a logical offset, physical offset,
        /// length, and FIEMAP_EXTENT_* flags. An empty extent vector means
        /// either a sparse (unwritten) file or an engine that does not yet
        /// expose extent metadata.
        ///
        /// The default implementation returns an empty [`FiemapExtentVec`].
        /// Engines that maintain physical extent layout (e.g., via
        /// `tidefs-extent-map`) should override this to return real
        /// extent information, enabling tools like `filefrag` and
        /// `hdparm --fibmap` on kernel-mounted TideFS instances.
        ///
        /// # No-daemon boundary
        ///
        /// Fiemap resolution resolves locally within kernel authority
        /// through the engine. No userspace daemon is required.
        fn fiemap(
            &self,
            _fh: &EngineFileHandle,
            _ctx: &RequestCtx,
        ) -> Result<FiemapExtentVec, Errno> {
            Ok(FiemapExtentVec {
                extents: KmodVec::new(),
            })
        }

        /// Return the mmap policy for a file mapping.
        fn mmap(
            &self,
            _inode: InodeId,
            _offset: u64,
            _length: u64,
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<MmapPolicy, Errno> {
            Ok(MmapPolicy::PopulateOnFault)
        }

        /// Resolve a memory-mapped page fault through the engine read path.
        fn fault(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            size: u32,
            ctx: &RequestCtx,
        ) -> Result<VmFaultOutcome, Errno> {
            let data = self.read(fh, offset, size, ctx)?;
            let vm_fault_code = if data.is_empty() {
                VM_FAULT_NOPAGE
            } else {
                VM_FAULT_MAJOR
            };
            Ok(VmFaultOutcome {
                page: data,
                vm_fault_code,
            })
        }

        fn syncfs(&self, ctx: &RequestCtx) -> Result<(), Errno>;

        // ── Methods with default impls ─────────────────────────────────

        /// Record an opaque intent-log entry before applying a mutation.
        ///
        /// The product VFS adapter calls this before namespace and data
        /// mutations so crash-recovery engines can persist replay records.
        /// The default no-op matches the userspace VfsEngine contract.
        fn record_intent_entry(&self, _entry: &[u8]) -> Result<(), Errno> {
            Ok(())
        }

        /// Advisory byte-range lock, blocking variant.
        fn setlkw(&self, inode: InodeId, lock: &LockSpec, ctx: &RequestCtx) -> Result<(), Errno> {
            self.setlk(inode, lock, ctx)
        }

        /// Copy a byte range between two file handles.
        fn copy_file_range(
            &self,
            source_fh: &EngineFileHandle,
            offset_in: u64,
            dest_fh: &EngineFileHandle,
            offset_out: u64,
            length: u64,
            ctx: &RequestCtx,
        ) -> Result<u32, Errno> {
            if length == 0 {
                return Ok(0);
            }

            let requested = length.min(u64::from(u32::MAX));
            let source_end = offset_in.checked_add(requested).ok_or(Errno::EINVAL)?;
            let dest_end = offset_out.checked_add(requested).ok_or(Errno::EINVAL)?;
            if source_fh.inode_id == dest_fh.inode_id
                && offset_in < dest_end
                && offset_out < source_end
            {
                return Err(Errno::EINVAL);
            }

            let mut copied = 0_u64;
            while copied < requested {
                let remaining = requested - copied;
                let chunk_len = remaining.min(VFS_COPY_FILE_RANGE_MAX_CHUNK);
                let chunk_size = u32::try_from(chunk_len).map_err(|_| Errno::EFBIG)?;
                let read_offset = offset_in.checked_add(copied).ok_or(Errno::EINVAL)?;
                let chunk = self.read(source_fh, read_offset, chunk_size, ctx)?;
                if chunk.is_empty() {
                    break;
                }

                let write_offset = offset_out.checked_add(copied).ok_or(Errno::EINVAL)?;
                let written = self.write(dest_fh, write_offset, &chunk, ctx)?;
                if u64::from(written) > chunk.len() as u64 {
                    return Err(Errno::EIO);
                }
                copied = copied.checked_add(u64::from(written)).ok_or(Errno::EFBIG)?;
                if written == 0 || u64::from(written) < chunk.len() as u64 {
                    break;
                }
            }

            u32::try_from(copied).map_err(|_| Errno::EFBIG)
        }

        /// Invalidate cached data for a byte range.
        fn invalidate_cache_range(
            &self,
            _inode: InodeId,
            _offset: u64,
            _len: u64,
        ) -> Result<(), Errno> {
            Ok(())
        }

        /// Called when the kernel acquires page ownership from the engine.
        fn page_ownership_acquired(
            &self,
            _inode: InodeId,
            _page_idx: u64,
            _mode: PageOwnershipMode,
        ) {
        }

        /// Called when the kernel transfers page ownership back to the engine.
        fn page_ownership_transferred(&self, _inode: InodeId, _page_idx: u64) {}

        /// Called when the engine must invalidate its cached copy of a page.
        fn page_invalidation_needed(&self, _inode: InodeId, _page_idx: u64) {}

        // ── Block device operations (kmod-block-kmod) ──────────────

        /// Return the total block device capacity in sectors.
        fn block_capacity_sectors(&self) -> u64 {
            0
        }

        /// Return the logical sector size in bytes.
        fn block_sector_size(&self) -> u32 {
            512
        }

        /// Read sectors from the block device.
        fn block_read(
            &self,
            _start_sector: u64,
            _sector_count: u32,
            _buf: &mut [u8],
        ) -> Result<u32, Errno> {
            Err(Errno::ENOSYS)
        }

        /// Write sectors to the block device.
        fn block_write(&self, _start_sector: u64, _data: &[u8]) -> Result<u32, Errno> {
            Err(Errno::ENOSYS)
        }

        /// Flush the block device write cache.
        fn block_flush(&self) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }

        /// Discard (trim/unmap) sectors on the block device.
        fn block_discard(&self, _start_sector: u64, _sector_count: u32) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }

        /// Write zeroes to a range of sectors.
        ///
        /// Unlike discard, subsequent reads MUST return zeroes.  The backend
        /// MAY allocate backing storage as needed.  Maps to Linux
        /// REQ_OP_WRITE_ZEROES.
        fn block_write_zeroes(&self, _start_sector: u64, _sector_count: u32) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }

        /// Zero a range of sectors through the allocation layer.
        ///
        /// Stronger than both discard and write-zeroes: the range MUST be
        /// readable (no fault on access) and MUST return zeroes.  Maps to
        /// Linux FALLOC_FL_ZERO_RANGE / REQ_OP_WRITE_ZEROES with no-unmap.
        fn block_zero_range(&self, _start_sector: u64, _sector_count: u32) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        // ── Committed-root writeback (kernel-mode) ────────────

        /// Write the committed root to the pool-label superblock.
        ///
        /// Bridges txg commit to durable on-disk persistence.
        /// The default is a no-op; engines that back real block
        /// devices must override this to write the label.
        fn write_committed_root(
            &self,
            _committed_root: &CommittedRoot,
            _device_index: u32,
        ) -> Result<(), Errno> {
            Ok(())
        }

        /// Finalize a transaction group commit.
        ///
        /// Calls write_committed_root to persist the committed root
        /// to the pool label.
        fn txg_commit_finish(&self, committed_root: CommittedRoot) -> Result<(), Errno> {
            self.write_committed_root(&committed_root, 0)
        }

        /// Store the latest committed root for use by [].
        ///
        /// Called by mount and txg-commit paths so the engine can later publish
        /// the root during fsync/syncfs/unmount without an explicit handle.
        /// The default is a no-op; engines that support kernel-mode txg
        /// barriers must override this.
        fn set_committed_root(&self, _root: CommittedRoot) {}

        /// Commit the current transaction group without an explicit root hash.
        ///
        /// Engines that track the committed-root hash internally must override
        /// this to publish the latest root.  The default no-op is compatible
        /// with engines that use [`txg_commit_finish`] directly or do not
        /// support kernel-mode txg barriers yet.
        ///
        /// The mounted POSIX kmod adapter calls this from
        /// `KmodPosixVfs::commit_fs_barrier` after fsync, syncfs,
        /// and clean unmount to establish a txg commit point without knowing
        /// the root hash.
        fn txg_commit_barrier(&self) -> Result<(), Errno> {
            Ok(())
        }
    }

    // ── VfsEngineStatFs trait ──────────────────────────────────────────

    pub trait VfsEngineStatFs: VfsEngine {
        fn statfs(&self, ctx: &RequestCtx) -> Result<StatFs, Errno>;
    }

    // ── to_vec helper for &[u8] under Kbuild ───────────────────────────
    // Under Kbuild, the kernel's alloc crate does not provide ToOwned/to_vec
    // on slices.  This extension trait bridges that gap.

    pub trait ByteSliceExt {
        fn to_vec(&self) -> KmodVec<u8>;
    }

    impl ByteSliceExt for [u8] {
        fn to_vec(&self) -> KmodVec<u8> {
            let mut v = KmodVec::<u8>::with_capacity(self.len());
            v.extend_from_slice(self);
            v
        }
    }

    // ── CommittedRoot (kernel-compatible stub) ────────────────────
    // Mirrors tidefs_vfs_engine::CommittedRoot for kernel-mode usage.

    /// Durable committed-root identifier (32-byte content hash).
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CommittedRoot(pub [u8; 32]);

    impl CommittedRoot {
        #[must_use]
        pub const fn new(bytes: [u8; 32]) -> Self {
            Self(bytes)
        }

        #[must_use]
        pub const fn as_bytes(&self) -> &[u8; 32] {
            &self.0
        }

        #[must_use]
        pub fn is_zero(&self) -> bool {
            self.0 == [0u8; 32]
        }
    }

    impl Default for CommittedRoot {
        fn default() -> Self {
            Self([0u8; 32])
        }
    }

    impl core::fmt::Debug for CommittedRoot {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "CommittedRoot({:02x}{:02x}{:02x}{:02x}...)",
                self.0[0], self.0[1], self.0[2], self.0[3]
            )
        }
    }

    // ── Pool label types (kernel-compatible types, product-format) ──
    // Under cargo these come from tidefs_types_pool_label_core.
    // Under Kbuild we provide self-contained no_std equivalents that
    // mirror the canonical crate exactly: wire sizes 411/436/440, enum
    // variants, feature bits, checksum offsets, and fail-closed
    // decode_label.

    // ------------------------------------------------------------------
    // Feature flag bit masks
    // ------------------------------------------------------------------

    /// Feature bit constants for features_incompat / features_ro_compat /
    /// features_compat in PoolLabelV1.
    pub mod features {
        /// Pool label format V1 (always set; incompat bit 0).
        pub const POOL_LABEL_V1: u64 = 1 << 0;
        /// Pool uses DeviceClass for allocation policy (compat bit 0).
        pub const DEVICE_CLASS_AWARE: u64 = 1 << 0;
        /// Pool supports hot-spare auto-replace (compat bit 1).
        pub const SPARE_POLICY_SUPPORTED: u64 = 1 << 1;
        /// Per-device health state (ONLINE/DEGRADED/FAULTED) and error
        /// counters are persisted in the label extension area.
        pub const DEVICE_HEALTH_STATE: u64 = 1 << 7;
        /// Pool-wide redundancy policy extension fields are persisted in
        /// the label extension area.
        pub const POOL_REDUNDANCY_POLICY: u64 = 1 << 9;
    }

    // Re-export feature bits at module level for compatibility.
    pub use features::{DEVICE_HEALTH_STATE, POOL_REDUNDANCY_POLICY};

    // ------------------------------------------------------------------
    // PoolRedundancyPolicy
    // ------------------------------------------------------------------

    /// Pool-wide allocation policy recorded in every pool member label.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    pub enum PoolRedundancyPolicy {
        /// Store `copies` full replicas on distinct eligible devices.
        Replicated { copies: u8 },
        /// Store one erasure stripe over `data_shards + parity_shards` targets.
        Erasure { data_shards: u8, parity_shards: u8 },
    }

    impl Default for PoolRedundancyPolicy {
        fn default() -> Self {
            Self::Replicated { copies: 1 }
        }
    }

    impl PoolRedundancyPolicy {
        /// Decode from the compact on-label policy extension fields.
        #[must_use]
        pub const fn from_wire(kind: u8, first: u8, second: u8) -> Option<Self> {
            match kind {
                0 if first > 0 && second == 0 => Some(Self::Replicated { copies: first }),
                1 if first > 0 && second > 0 => Some(Self::Erasure {
                    data_shards: first,
                    parity_shards: second,
                }),
                _ => None,
            }
        }
    }

    // ------------------------------------------------------------------
    // DeviceClass
    // ------------------------------------------------------------------

    /// Device class for pool-level allocation routing (on-disk label variant).
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    #[repr(u8)]
    pub enum DeviceClass {
        /// General-purpose HDD storage.
        Hdd = 0,
        /// Solid-state drive storage.
        Ssd = 1,
        /// NVMe flash storage.
        Nvme = 2,
        /// Separate fast intent-log device (LOG_DEVICE).
        LogDevice = 3,
        /// Read cache device (FlashTier).
        Cache = 4,
        /// Special allocation class (small files, dedup tables).
        Special = 5,
        /// Hot spare device — does not participate in normal I/O routing.
        Spare = 6,
    }

    impl DeviceClass {
        /// Decode from a u8 wire value.
        #[must_use]
        pub const fn from_u8(v: u8) -> Option<Self> {
            match v {
                0 => Some(Self::Hdd),
                1 => Some(Self::Ssd),
                2 => Some(Self::Nvme),
                3 => Some(Self::LogDevice),
                4 => Some(Self::Cache),
                5 => Some(Self::Special),
                6 => Some(Self::Spare),
                _ => None,
            }
        }

        /// Encode to a u8 wire value.
        #[must_use]
        pub const fn to_u8(self) -> u8 {
            self as u8
        }

        /// Returns true if this is a data-bearing device class.
        #[must_use]
        pub const fn is_data_bearing(self) -> bool {
            matches!(self, Self::Hdd | Self::Ssd | Self::Nvme | Self::Special)
        }
    }

    impl core::fmt::Display for DeviceClass {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Hdd => f.write_str("HDD"),
                Self::Ssd => f.write_str("SSD"),
                Self::Nvme => f.write_str("NVME"),
                Self::LogDevice => f.write_str("LOG_DEVICE"),
                Self::Cache => f.write_str("CACHE"),
                Self::Special => f.write_str("SPECIAL"),
                Self::Spare => f.write_str("SPARE"),
            }
        }
    }

    // ------------------------------------------------------------------
    // PoolState
    // ------------------------------------------------------------------

    /// Operational state of the pool recorded in each device label.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    #[repr(u8)]
    pub enum PoolState {
        /// Pool is live and writable.
        Active = 0,
        /// Pool was cleanly exported; ready for import.
        Exported = 1,
        /// Pool has been administratively destroyed (terminal).
        Destroyed = 2,
    }

    impl PoolState {
        /// Decode from a u8 wire value.
        #[must_use]
        pub const fn from_u8(v: u8) -> Option<Self> {
            match v {
                0 => Some(Self::Active),
                1 => Some(Self::Exported),
                2 => Some(Self::Destroyed),
                _ => None,
            }
        }

        /// Encode to a u8 wire value.
        #[must_use]
        pub const fn to_u8(self) -> u8 {
            self as u8
        }

        /// Returns true if the pool can be imported in this state.
        #[must_use]
        pub const fn is_importable(self) -> bool {
            matches!(self, Self::Active | Self::Exported)
        }
    }

    impl core::fmt::Display for PoolState {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Active => f.write_str("ACTIVE"),
                Self::Exported => f.write_str("EXPORTED"),
                Self::Destroyed => f.write_str("DESTROYED"),
            }
        }
    }

    // ------------------------------------------------------------------
    // Pool name / label constants
    // ------------------------------------------------------------------

    /// Maximum pool name length in bytes (UTF-8).
    pub const POOL_NAME_MAX: usize = 255;

    /// Magic bytes identifying a TideFS pool label.
    pub const POOL_LABEL_MAGIC: [u8; 4] = *b"VBFS";

    /// Size of each label copy on disk (256 KiB).
    pub const POOL_LABEL_SIZE: usize = 262_144;

    /// Total wire size of a PoolLabelV1 base label in bytes.
    pub const POOL_LABEL_V1_WIRE_SIZE: usize = 411;

    /// Extended wire size including device health fields, before pool-wide
    /// redundancy policy was added.
    pub const POOL_LABEL_V1_HEALTH_WIRE_SIZE: usize = 436;

    /// Extended wire size including device health and pool-wide redundancy policy.
    pub const POOL_LABEL_V1_EXT_WIRE_SIZE: usize = 440;

    /// Offset of the checksum field for base labels (no health extension).
    pub const POOL_LABEL_V1_CHECKSUM_BASE_OFFSET: usize = 379;

    /// Offset of the checksum field for health-only extended labels.
    pub const POOL_LABEL_V1_CHECKSUM_HEALTH_OFFSET: usize = 404;

    /// Offset of the checksum field for current extended labels.
    pub const POOL_LABEL_V1_CHECKSUM_OFFSET: usize = 408;

    // ------------------------------------------------------------------
    // PoolLabelV1
    // ------------------------------------------------------------------

    /// On-device self-describing pool label (version 1).
    ///
    /// Field order and wire layout match the canonical
    /// `tidefs_types_pool_label_core::PoolLabelV1` exactly.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PoolLabelV1 {
        pub magic: [u8; 4],
        pub version: u32,
        pub pool_guid: [u8; 16],
        pub device_guid: [u8; 16],
        pub pool_name: [u8; POOL_NAME_MAX],
        pub pool_name_len: u16,
        pub pool_state: PoolState,
        pub commit_group: u64,
        pub label_commit_group: u64,
        pub device_index: u32,
        pub topology_generation: u64,
        pub device_count: u32,
        pub device_class: DeviceClass,
        pub device_capacity_bytes: u64,
        pub system_area_pointer: u64,
        pub system_area_size: u64,
        pub features_incompat: u64,
        pub features_ro_compat: u64,
        pub features_compat: u64,
        pub device_health: u8,
        pub device_read_errors: u64,
        pub device_write_errors: u64,
        pub device_checksum_errors: u64,
        pub redundancy_policy: PoolRedundancyPolicy,
        pub checksum: [u8; 32],
    }

    impl PoolLabelV1 {
        /// Create a new label with default fields (zero checksum).
        /// Callers should set appropriate fields and then compute a
        /// real checksum via the canonical `seal_label` or `encode_label`.
        #[must_use]
        pub fn new(pool_guid: [u8; 16], device_guid: [u8; 16], pool_name: &str) -> Self {
            let name_bytes = pool_name.as_bytes();
            let name_len = name_bytes.len().min(POOL_NAME_MAX);
            let mut name_buf = [0u8; POOL_NAME_MAX];
            name_buf[..name_len].copy_from_slice(&name_bytes[..name_len]);
            Self {
                magic: *b"VBFS",
                version: 1,
                pool_guid,
                device_guid,
                pool_name: name_buf,
                pool_name_len: name_len as u16,
                pool_state: PoolState::Active,
                commit_group: 0,
                label_commit_group: 0,
                device_index: 0,
                topology_generation: 0,
                device_count: 1,
                device_class: DeviceClass::Hdd,
                device_capacity_bytes: 0,
                system_area_pointer: 0,
                system_area_size: 0,
                features_incompat: 0,
                features_ro_compat: 0,
                features_compat: 0,
                device_health: 0,
                device_read_errors: 0,
                device_write_errors: 0,
                device_checksum_errors: 0,
                redundancy_policy: PoolRedundancyPolicy::default(),
                checksum: [0u8; 32],
            }
        }

        /// Returns the pool name as a UTF-8 `&str`, truncating at
        /// `pool_name_len`. Returns an empty string for zero-length
        /// names or invalid UTF-8.
        #[must_use]
        pub fn pool_name_str(&self) -> &str {
            let len = self.pool_name_len as usize;
            let slice = &self.pool_name[..len.min(POOL_NAME_MAX)];
            core::str::from_utf8(slice).unwrap_or("")
        }
    }

    // ------------------------------------------------------------------
    // Label errors
    // ------------------------------------------------------------------

    /// Possible errors when decoding or validating a pool label.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum LabelError {
        /// Input buffer is too small to contain a complete label.
        BufferTooSmall,
        /// Magic bytes do not match `b"VBFS"`.
        BadMagic,
        /// Unrecognized label format version.
        UnsupportedVersion(u32),
        /// `PoolState` value out of range.
        BadPoolState(u8),
        /// `DeviceClass` value out of range.
        BadDeviceClass(u8),
        /// Pool-wide redundancy policy extension fields are invalid.
        BadRedundancyPolicy { kind: u8, first: u8, second: u8 },
        /// `pool_name_len` exceeds `POOL_NAME_MAX`.
        NameTooLong,
        /// BLAKE3-256 checksum mismatch (label is corrupt).
        ChecksumMismatch,
        /// Cannot remove the last remaining device from a pool.
        LastDevice,
        /// BLAKE3-256 checksum verification is unavailable in this build.
        ChecksumUnavailable,
    }

    impl core::fmt::Display for LabelError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::BufferTooSmall => f.write_str("buffer too small for label"),
                Self::BadMagic => f.write_str("bad magic bytes"),
                Self::UnsupportedVersion(v) => write!(f, "unsupported label version {v}"),
                Self::BadPoolState(v) => write!(f, "bad pool state {v}"),
                Self::BadDeviceClass(v) => write!(f, "bad device class {v}"),
                Self::BadRedundancyPolicy {
                    kind,
                    first,
                    second,
                } => write!(
                    f,
                    "bad redundancy policy kind={kind} first={first} second={second}"
                ),
                Self::NameTooLong => f.write_str("pool name too long"),
                Self::ChecksumMismatch => f.write_str("checksum mismatch"),
                Self::LastDevice => f.write_str("cannot remove last device from pool"),
                Self::ChecksumUnavailable => f.write_str("BLAKE3 checksum unavailable"),
            }
        }
    }

    // ------------------------------------------------------------------
    // blake3 availability signal
    // ------------------------------------------------------------------

    /// Returns `true` when a real BLAKE3-256 implementation is available.
    #[must_use]
    pub const fn blake3_available() -> bool {
        true
    }

    // ------------------------------------------------------------------
    // decode_label
    // ------------------------------------------------------------------

    /// Decode a `PoolLabelV1` from a raw byte buffer.
    ///
    /// Performs full structural parsing: magic, version, field ranges,
    /// enum validation, and name length — matching the canonical
    /// `tidefs_types_pool_label_core::decode_label`.
    ///
    /// Kbuild now carries the same BLAKE3-256 hash semantics needed for
    /// label checksum verification. If a future build disables hashing,
    /// non-zero checksums fail closed with [`LabelError::ChecksumUnavailable`].
    pub fn decode_label(buf: &[u8]) -> Result<PoolLabelV1, LabelError> {
        if buf.len() < POOL_LABEL_V1_WIRE_SIZE {
            return Err(LabelError::BufferTooSmall);
        }

        // Verify magic.
        let magic: [u8; 4] = buf[0..4].try_into().unwrap();
        if magic != *b"VBFS" {
            return Err(LabelError::BadMagic);
        }

        let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        if version != 1 {
            return Err(LabelError::UnsupportedVersion(version));
        }

        let pool_guid: [u8; 16] = buf[8..24].try_into().unwrap();
        let device_guid: [u8; 16] = buf[24..40].try_into().unwrap();

        let pool_name_len = u16::from_le_bytes(buf[40..42].try_into().unwrap());
        if pool_name_len as usize > POOL_NAME_MAX {
            return Err(LabelError::NameTooLong);
        }

        let mut pool_name = [0u8; POOL_NAME_MAX];
        pool_name.copy_from_slice(&buf[42..297]);

        let pool_state = PoolState::from_u8(buf[297]).ok_or(LabelError::BadPoolState(buf[297]))?;
        let commit_group = u64::from_le_bytes(buf[298..306].try_into().unwrap());
        let label_commit_group = u64::from_le_bytes(buf[306..314].try_into().unwrap());
        let device_index = u32::from_le_bytes(buf[314..318].try_into().unwrap());
        let topology_generation = u64::from_le_bytes(buf[318..326].try_into().unwrap());
        let device_count = u32::from_le_bytes(buf[326..330].try_into().unwrap());
        let device_class =
            DeviceClass::from_u8(buf[330]).ok_or(LabelError::BadDeviceClass(buf[330]))?;
        let device_capacity_bytes = u64::from_le_bytes(buf[331..339].try_into().unwrap());
        let system_area_pointer = u64::from_le_bytes(buf[339..347].try_into().unwrap());
        let system_area_size = u64::from_le_bytes(buf[347..355].try_into().unwrap());
        let features_incompat = u64::from_le_bytes(buf[355..363].try_into().unwrap());
        let features_ro_compat = u64::from_le_bytes(buf[363..371].try_into().unwrap());
        let features_compat = u64::from_le_bytes(buf[371..379].try_into().unwrap());

        let has_health = features_compat & features::DEVICE_HEALTH_STATE != 0;
        let has_policy = features_compat & features::POOL_REDUNDANCY_POLICY != 0;
        if has_health && buf.len() < POOL_LABEL_V1_HEALTH_WIRE_SIZE {
            return Err(LabelError::BufferTooSmall);
        }
        if has_policy && !has_health {
            return Err(LabelError::BadRedundancyPolicy {
                kind: buf.get(404).copied().unwrap_or(0),
                first: buf.get(405).copied().unwrap_or(0),
                second: buf.get(406).copied().unwrap_or(0),
            });
        }
        if has_policy && buf.len() < POOL_LABEL_V1_EXT_WIRE_SIZE {
            return Err(LabelError::BufferTooSmall);
        }

        let (device_health, device_read_errors, device_write_errors, device_checksum_errors) =
            if has_health {
                (
                    buf[379],
                    u64::from_le_bytes(buf[380..388].try_into().unwrap()),
                    u64::from_le_bytes(buf[388..396].try_into().unwrap()),
                    u64::from_le_bytes(buf[396..404].try_into().unwrap()),
                )
            } else {
                (0, 0, 0, 0)
            };

        let redundancy_policy = if has_policy {
            PoolRedundancyPolicy::from_wire(buf[404], buf[405], buf[406]).ok_or(
                LabelError::BadRedundancyPolicy {
                    kind: buf[404],
                    first: buf[405],
                    second: buf[406],
                },
            )?
        } else {
            PoolRedundancyPolicy::default()
        };

        let checksum_offset = if has_policy {
            POOL_LABEL_V1_CHECKSUM_OFFSET
        } else if has_health {
            POOL_LABEL_V1_CHECKSUM_HEALTH_OFFSET
        } else {
            POOL_LABEL_V1_CHECKSUM_BASE_OFFSET
        };
        let checksum_end = if has_policy {
            POOL_LABEL_V1_EXT_WIRE_SIZE
        } else if has_health {
            POOL_LABEL_V1_HEALTH_WIRE_SIZE
        } else {
            POOL_LABEL_V1_WIRE_SIZE
        };
        let checksum: [u8; 32] = buf[checksum_offset..checksum_end].try_into().unwrap();

        // Refuse non-zero checksums if a future build disables real hashing.
        if !blake3_available() {
            // Zero checksum = bootstrap/unsigned; accept structurally.
            // Non-zero checksum = needs real verification; reject.
            if checksum != [0u8; 32] {
                return Err(LabelError::ChecksumUnavailable);
            }
        } else {
            // Verify checksum: hash everything before the checksum field.
            let mut hasher = super::blake3::Hasher::new();
            hasher.update(&buf[0..checksum_offset]);
            let computed = hasher.finalize();
            if computed.as_bytes() != &checksum {
                return Err(LabelError::ChecksumMismatch);
            }
        }

        Ok(PoolLabelV1 {
            magic,
            version,
            pool_guid,
            device_guid,
            pool_name,
            pool_name_len,
            pool_state,
            commit_group,
            label_commit_group,
            device_index,
            topology_generation,
            device_count,
            device_class,
            device_capacity_bytes,
            system_area_pointer,
            system_area_size,
            features_incompat,
            features_ro_compat,
            features_compat,
            device_health,
            device_read_errors,
            device_write_errors,
            device_checksum_errors,
            redundancy_policy,
            checksum,
        })
    }

    // ── KernelStorageIo facade (Kbuild mirror of tidefs-kernel-storage-io) ──

    /// Portable sector-aligned block-I/O trait for kernel-mode storage.
    ///
    /// This mirrors `tidefs_kernel_storage_io::KernelStorageIo` so Kbuild
    /// users of `tidefs-kmod-posix-vfs` see the same trait surface as Cargo
    /// builds without linking Cargo crates from the Linux build system.
    pub trait KernelStorageIo: Send + Sync {
        fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno>;
        fn write_sectors(&self, start_sector: u64, data: &[u8]) -> Result<u32, Errno>;
        fn flush(&self) -> Result<(), Errno>;
        fn sector_size(&self) -> u32;
        fn capacity_sectors(&self) -> u64;

        #[inline]
        fn capacity_bytes(&self) -> u64 {
            self.capacity_sectors()
                .saturating_mul(u64::from(self.sector_size()))
        }

        #[inline]
        fn validate_range(&self, start_sector: u64, sector_count: u64) -> Result<(), Errno> {
            let end = start_sector
                .checked_add(sector_count)
                .ok_or(Errno::EINVAL)?;
            if end > self.capacity_sectors() {
                return Err(Errno::EINVAL);
            }
            Ok(())
        }
    }

    /// Low-level byte-offset block I/O trait used by [`KernelStorageAdapter`].
    pub trait RawBlockIo: Send + Sync {
        fn read_bytes(&self, offset_bytes: u64, buf: &mut [u8]) -> Result<u32, Errno>;
        fn write_bytes(&self, offset_bytes: u64, data: &[u8]) -> Result<u32, Errno>;
        fn flush_bytes(&self) -> Result<(), Errno>;
        fn block_size(&self) -> u32;
        fn total_capacity_bytes(&self) -> u64;
    }

    /// Generic adapter from byte-offset block I/O to sector-aligned I/O.
    pub struct KernelStorageAdapter<B: RawBlockIo> {
        backend: B,
    }

    impl<B: RawBlockIo> KernelStorageAdapter<B> {
        #[inline]
        pub fn new(backend: B) -> Self {
            Self { backend }
        }

        #[inline]
        pub fn backend(&self) -> &B {
            &self.backend
        }

        #[inline]
        pub fn backend_mut(&mut self) -> &mut B {
            &mut self.backend
        }
    }

    impl<B: RawBlockIo> KernelStorageIo for KernelStorageAdapter<B> {
        #[inline]
        fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno> {
            let ss = u64::from(self.sector_size());
            if ss == 0 {
                return Err(Errno::EINVAL);
            }
            let offset = start_sector.checked_mul(ss).ok_or(Errno::EINVAL)?;
            let len = buf.len() as u64;
            if len % ss != 0 {
                return Err(Errno::EINVAL);
            }
            let byte_count = self.backend.read_bytes(offset, buf)?;
            Ok(byte_count / self.sector_size())
        }

        #[inline]
        fn write_sectors(&self, start_sector: u64, data: &[u8]) -> Result<u32, Errno> {
            let ss = u64::from(self.sector_size());
            if ss == 0 {
                return Err(Errno::EINVAL);
            }
            let offset = start_sector.checked_mul(ss).ok_or(Errno::EINVAL)?;
            let len = data.len() as u64;
            if len % ss != 0 {
                return Err(Errno::EINVAL);
            }
            let byte_count = self.backend.write_bytes(offset, data)?;
            Ok(byte_count / self.sector_size())
        }

        #[inline]
        fn flush(&self) -> Result<(), Errno> {
            self.backend.flush_bytes()
        }

        #[inline]
        fn sector_size(&self) -> u32 {
            self.backend.block_size()
        }

        #[inline]
        fn capacity_sectors(&self) -> u64 {
            let bs = u64::from(self.backend.block_size());
            if bs == 0 {
                return 0;
            }
            self.backend.total_capacity_bytes() / bs
        }
    }

    /// Mount-relevant pool identity parsed from [`PoolLabelV1`].
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct KernelPoolSuperblock {
        pub magic: [u8; 4],
        pub pool_guid: [u8; 16],
        pub device_guid: [u8; 16],
        pub pool_name: [u8; 255],
        pub pool_name_len: u16,
        pub pool_state: u8,
        pub commit_group: u64,
        pub device_index: u32,
        pub topology_generation: u64,
        pub device_count: u32,
        pub device_class: u8,
        pub device_capacity_bytes: u64,
        pub system_area_pointer: u64,
        pub system_area_size: u64,
        pub features_incompat: u64,
        pub features_ro_compat: u64,
        pub features_compat: u64,
        pub redundancy_policy: PoolRedundancyPolicy,
        pub checksum: [u8; 32],
    }

    impl KernelPoolSuperblock {
        #[must_use]
        pub fn from_label(label: &PoolLabelV1) -> Self {
            Self {
                magic: label.magic,
                pool_guid: label.pool_guid,
                device_guid: label.device_guid,
                pool_name: label.pool_name,
                pool_name_len: label.pool_name_len,
                pool_state: label.pool_state.to_u8(),
                commit_group: label.commit_group,
                device_index: label.device_index,
                topology_generation: label.topology_generation,
                device_count: label.device_count,
                device_class: label.device_class.to_u8(),
                device_capacity_bytes: label.device_capacity_bytes,
                system_area_pointer: label.system_area_pointer,
                system_area_size: label.system_area_size,
                features_incompat: label.features_incompat,
                features_ro_compat: label.features_ro_compat,
                features_compat: label.features_compat,
                redundancy_policy: label.redundancy_policy,
                checksum: label.checksum,
            }
        }

        #[must_use]
        pub fn pool_name_str(&self) -> &str {
            let len = (self.pool_name_len as usize).min(POOL_NAME_MAX);
            core::str::from_utf8(&self.pool_name[..len]).unwrap_or("")
        }

        #[must_use]
        pub const fn is_importable(&self) -> bool {
            self.pool_state == 0 || self.pool_state == 1
        }
    }

    impl core::fmt::Display for KernelPoolSuperblock {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "KernelPoolSuperblock(pool={}, device_index={}, txg={}, system_area=0x{:x})",
                self.pool_name_str(),
                self.device_index,
                self.commit_group,
                self.system_area_pointer,
            )
        }
    }

    /// Errors returned by [`read_pool_superblock`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PoolSuperblockError {
        Io(Errno),
        DeviceTooSmall,
        BadMagic,
        UnsupportedVersion(u32),
        Corrupt,
        InvalidPoolName,
    }

    impl core::fmt::Display for PoolSuperblockError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Io(e) => write!(f, "I/O error reading pool superblock: {e:?}"),
                Self::DeviceTooSmall => f.write_str("device too small for pool superblock"),
                Self::BadMagic => f.write_str("bad magic bytes"),
                Self::UnsupportedVersion(v) => write!(f, "unsupported label version {v}"),
                Self::Corrupt => f.write_str("pool label is corrupt"),
                Self::InvalidPoolName => f.write_str("pool name contains invalid UTF-8"),
            }
        }
    }

    impl From<LabelError> for PoolSuperblockError {
        fn from(e: LabelError) -> Self {
            match e {
                LabelError::BufferTooSmall => Self::DeviceTooSmall,
                LabelError::BadMagic => Self::BadMagic,
                LabelError::UnsupportedVersion(v) => Self::UnsupportedVersion(v),
                LabelError::ChecksumMismatch | LabelError::ChecksumUnavailable => Self::Corrupt,
                LabelError::BadPoolState(_)
                | LabelError::BadDeviceClass(_)
                | LabelError::BadRedundancyPolicy { .. }
                | LabelError::NameTooLong
                | LabelError::LastDevice => Self::Corrupt,
            }
        }
    }

    /// Read and validate the TideFS pool label from sector 0.
    pub fn read_pool_superblock(
        io: &dyn KernelStorageIo,
    ) -> Result<KernelPoolSuperblock, PoolSuperblockError> {
        read_pool_superblock_at(io, 0)
    }

    /// Read and validate the TideFS pool label from a specific sector.
    pub fn read_pool_superblock_at(
        io: &dyn KernelStorageIo,
        start_sector: u64,
    ) -> Result<KernelPoolSuperblock, PoolSuperblockError> {
        let ss = io.sector_size() as usize;
        if ss == 0 {
            return Err(PoolSuperblockError::DeviceTooSmall);
        }

        let sectors_needed = (POOL_LABEL_V1_EXT_WIRE_SIZE + ss - 1) / ss;
        if sectors_needed == 0 {
            return Err(PoolSuperblockError::DeviceTooSmall);
        }

        let end = start_sector
            .checked_add(sectors_needed as u64)
            .ok_or(PoolSuperblockError::DeviceTooSmall)?;
        if end > io.capacity_sectors() {
            return Err(PoolSuperblockError::DeviceTooSmall);
        }

        let mut buf = KmodVec::<u8>::from_elem(0, sectors_needed * ss);
        let read_sectors = io
            .read_sectors(start_sector, &mut buf)
            .map_err(PoolSuperblockError::Io)?;

        if read_sectors < sectors_needed as u32 {
            return Err(PoolSuperblockError::Io(Errno::EIO));
        }
        if buf.len() < 4 || buf[0..4] != POOL_LABEL_MAGIC {
            return Err(PoolSuperblockError::BadMagic);
        }

        let label = decode_label(&buf)?;
        Ok(KernelPoolSuperblock::from_label(&label))
    }

    // ── Xattr storage types (kernel-compatible stubs for CONFIG_RUST builds) ──

    /// Xattr store error kind — must match tidefs_xattr_storage::XattrStoreError.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum XattrStoreError {
        /// The requested xattr name does not exist.
        EntryNotFound,
    }

    /// Dataset xattr policy stub — must match tidefs_xattr_storage::DatasetXattrPolicy.
    #[derive(Debug, Clone, Copy)]
    pub struct DatasetXattrPolicy {
        max_entries: u32,
        max_value_bytes: u32,
        _reserved1: u32,
        _reserved2: u32,
    }

    impl DatasetXattrPolicy {
        #[must_use]
        pub const fn new(max_entries: u32, max_value_bytes: u32, _r1: u32, _r2: u32) -> Self {
            Self {
                max_entries,
                max_value_bytes,
                _reserved1: _r1,
                _reserved2: _r2,
            }
        }
    }

    /// Error returned by pack_posix_xattr_name_list.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum XattrNameListError {
        NameTooLong,
    }

    /// Pack a list of xattr name byte slices into a POSIX listxattr buffer.
    pub fn pack_posix_xattr_name_list(
        _names: &[KmodVec<u8>],
    ) -> Result<KmodVec<u8>, XattrNameListError> {
        Ok(KmodVec::new())
    }

    /// Kernel-compatible xattr store stub.
    #[derive(Debug)]
    pub struct XattrStore {
        _policy: DatasetXattrPolicy,
        version_counter: u64,
    }

    impl XattrStore {
        #[must_use]
        pub fn new(policy: DatasetXattrPolicy) -> Self {
            Self {
                _policy: policy,
                version_counter: 0,
            }
        }

        #[must_use]
        pub fn get(&self, _name: &[u8]) -> Option<KmodVec<u8>> {
            None
        }

        pub fn set(&mut self, _name: &[u8], _value: &[u8], _flags: u8) {
            self.version_counter += 1;
        }

        #[must_use]
        pub fn contains(&self, _name: &[u8]) -> bool {
            false
        }

        pub fn remove(&mut self, _name: &[u8]) -> Result<(), XattrStoreError> {
            Err(XattrStoreError::EntryNotFound)
        }

        #[must_use]
        pub fn list_names(&self) -> KmodVec<KmodVec<u8>> {
            KmodVec::new()
        }

        #[must_use]
        pub fn len(&self) -> u64 {
            0
        }

        #[must_use]
        pub fn is_empty(&self) -> bool {
            true
        }

        #[must_use]
        pub fn version(&self) -> u64 {
            self.version_counter
        }

        #[must_use]
        pub fn policy(&self) -> DatasetXattrPolicy {
            self._policy
        }
    }

    // ── KernelPoolCore authority types (Kbuild mirror of tidefs-vfs-engine::pool_core) ──

    use core::sync::atomic::{AtomicU64, Ordering};

    /// Describes a single lower block device bound to a pool.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct LowerDeviceDesc {
        pub major: u32,
        pub minor: u32,
        pub sector_count: u64,
        pub logical_block_size: u32,
    }

    impl LowerDeviceDesc {
        #[must_use]
        pub const fn new(
            major: u32,
            minor: u32,
            sector_count: u64,
            logical_block_size: u32,
        ) -> Self {
            Self {
                major,
                minor,
                sector_count,
                logical_block_size,
            }
        }

        #[must_use]
        pub fn capacity_bytes(&self) -> u64 {
            self.sector_count
                .saturating_mul(self.logical_block_size as u64)
        }
    }

    /// Lifecycle state of a kernel-resident pool.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u64)]
    pub enum KernelPoolState {
        Configured = 0,
        Importing = 1,
        Mounted = 2,
        Teardown = 3,
    }

    impl KernelPoolState {
        #[must_use]
        pub fn from_u64(v: u64) -> Option<Self> {
            match v {
                0 => Some(Self::Configured),
                1 => Some(Self::Importing),
                2 => Some(Self::Mounted),
                3 => Some(Self::Teardown),
                _ => None,
            }
        }

        #[must_use]
        pub const fn to_u64(self) -> u64 {
            self as u64
        }

        #[must_use]
        pub fn can_transition_to(self, target: Self) -> bool {
            matches!(
                (self, target),
                (Self::Configured, Self::Importing)
                    | (Self::Importing, Self::Mounted)
                    | (Self::Configured, Self::Teardown)
                    | (Self::Importing, Self::Teardown)
                    | (Self::Mounted, Self::Teardown)
                    | (Self::Teardown, Self::Teardown)
            )
        }
    }

    /// Immutable pool configuration carried by KernelPoolCore.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct KernelPoolConfig {
        pub pool_uuid: [u8; 32],
        pub devices: KmodVec<LowerDeviceDesc>,
        pub mount_flags: u64,
    }

    impl KernelPoolConfig {
        #[must_use]
        pub fn new(
            pool_uuid: [u8; 32],
            devices: KmodVec<LowerDeviceDesc>,
            mount_flags: u64,
        ) -> Self {
            Self {
                pool_uuid,
                devices,
                mount_flags,
            }
        }

        #[must_use]
        pub fn total_capacity_bytes(&self) -> u64 {
            self.devices
                .iter()
                .fold(0u64, |acc, d| acc.saturating_add(d.capacity_bytes()))
        }

        #[must_use]
        pub fn device_count(&self) -> usize {
            self.devices.len()
        }
    }

    /// Errors returned by KernelPoolCore operations.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum KernelPoolError {
        InvalidTransition {
            from: KernelPoolState,
            to: KernelPoolState,
        },
        NotConfigured,
        NotImporting,
        ImportFailed,
        TeardownInProgress,
        AlreadyMounted,
        RefcountNotZero,
        NotMounted,
    }

    impl fmt::Display for KernelPoolError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidTransition { from, to } => {
                    write!(f, "illegal state transition from {from:?} to {to:?}")
                }
                Self::NotConfigured => write!(f, "pool is not configured"),
                Self::NotImporting => write!(f, "pool is not importing"),
                Self::ImportFailed => write!(f, "pool import failed"),
                Self::TeardownInProgress => write!(f, "pool teardown in progress"),
                Self::AlreadyMounted => write!(f, "pool is already mounted"),
                Self::RefcountNotZero => write!(f, "pool refcount is not zero"),
                Self::NotMounted => write!(f, "pool is not mounted — writes require mounted state"),
            }
        }
    }

    /// Refcounted kernel-resident pool context for writeback authority.
    ///
    /// Tracks pool lifecycle (Configured → Importing → Mounted → Teardown)
    /// with atomic refcounting. Writeback, allocator, and txg operations
    /// gate on Mounted state. The committed root is tracked externally;
    /// see KernelEngine for the kernel-side committed-root protocol.

    /// C-provided I/O context for writing committed-root records to disk.
    ///
    /// The C shim owns block-device I/O (sb_bread). This context bridges
    /// Rust-side committed-root encoding to C-side sector writes. All
    /// fields zero when unset; persistence gates on write_sectors_fn.
    #[derive(Clone, Copy)]
    pub struct CommittedRootIoCtx {
        /// C callback: write  bytes to . Returns 0 on
        /// success, negative errno on failure.
        pub data_area_offset: u64,
        pub write_sectors_fn: Option<
            unsafe extern "C" fn(start_sector: u64, data: *const u8, len: u32) -> core::ffi::c_int,
        >,
        /// C callback: read sectors from block device. Returns 0 on
        /// success, negative errno on failure.
        pub read_sectors_fn: Option<
            unsafe extern "C" fn(start_sector: u64, buf: *mut u8, len: u32) -> core::ffi::c_int,
        >,
        /// Device sector size in bytes.
        pub sector_size: u32,
        /// Byte offset of the superblock region on the block device.
        pub superblock_offset: u64,
        /// Size of the superblock region in bytes.
        pub superblock_size: u64,
        /// Current transaction group (monotonically increasing).
        pub committed_txg: u64,
        /// Root inode number.
        pub root_ino: u64,
        /// Pool UUID (32 bytes, matching C-side pool_uuid field).
        pub pool_uuid: [u8; 32],
    }

    impl CommittedRootIoCtx {
        #[must_use]
        pub const fn unset() -> Self {
            Self {
                data_area_offset: 0,
                write_sectors_fn: None,
                read_sectors_fn: None,
                sector_size: 0,
                superblock_offset: 0,
                superblock_size: 0,
                committed_txg: 0,
                root_ino: 0,
                pool_uuid: [0u8; 32],
            }
        }

        #[must_use]
        pub fn is_active(&self) -> bool {
            self.write_sectors_fn.is_some() && self.sector_size > 0
        }
    }

    impl Default for CommittedRootIoCtx {
        fn default() -> Self {
            Self::unset()
        }
    }

    pub struct KernelPoolCore {
        refcount: AtomicU64,
        state: AtomicU64,
        config: KernelPoolConfig,
        /// C-provided I/O context for on-disk committed-root writes.
        committed_root_io: CommittedRootIoCtx,
    }

    impl KernelPoolCore {
        #[inline]
        pub fn new(config: KernelPoolConfig) -> Result<Self, KernelPoolError> {
            if config.devices.is_empty() {
                return Err(KernelPoolError::NotConfigured);
            }
            Ok(Self {
                refcount: AtomicU64::new(1),
                state: AtomicU64::new(KernelPoolState::Configured.to_u64()),
                config,
                committed_root_io: CommittedRootIoCtx::unset(),
            })
        }

        /// Store the C-provided committed-root I/O context.
        ///
        /// Called from the C mount path once the block device and pool
        /// label are validated.
        pub fn set_committed_root_io_ctx(&mut self, ctx: CommittedRootIoCtx) {
            self.committed_root_io = ctx;
        }

        /// Return a copy of the current committed-root I/O context.
        #[must_use]
        pub fn committed_root_io_ctx(&self) -> CommittedRootIoCtx {
            self.committed_root_io
        }

        #[inline]
        pub fn begin_import(&self) -> Result<(), KernelPoolError> {
            self.try_transition(KernelPoolState::Configured, KernelPoolState::Importing)
        }

        #[inline]
        pub fn complete_import(&self) -> Result<(), KernelPoolError> {
            self.try_transition(KernelPoolState::Importing, KernelPoolState::Mounted)
        }

        #[inline]
        pub fn begin_teardown(&self) -> Result<bool, KernelPoolError> {
            loop {
                let current_raw = self.state.load(Ordering::Acquire);
                let current = KernelPoolState::from_u64(current_raw)
                    .expect("corrupt KernelPoolCore state word");
                if current == KernelPoolState::Teardown {
                    return Ok(false);
                }
                let target = KernelPoolState::Teardown;
                if !current.can_transition_to(target) {
                    return Err(KernelPoolError::InvalidTransition {
                        from: current,
                        to: target,
                    });
                }
                match self.state.compare_exchange_weak(
                    current_raw,
                    target.to_u64(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return Ok(true),
                    Err(_) => {
                        core::hint::spin_loop();
                    }
                }
            }
        }

        #[inline]
        pub fn ref_get(&self) {
            self.refcount.fetch_add(1, Ordering::Relaxed);
        }
        #[inline]
        pub fn ref_put(&self) -> bool {
            self.refcount.fetch_sub(1, Ordering::Acquire) == 1
        }
        #[inline]
        pub fn ref_count(&self) -> u64 {
            self.refcount.load(Ordering::Relaxed)
        }
        #[inline]
        pub fn state(&self) -> KernelPoolState {
            let raw = self.state.load(Ordering::Acquire);
            KernelPoolState::from_u64(raw).unwrap_or(KernelPoolState::Teardown)
        }
        #[inline]
        pub fn uuid(&self) -> [u8; 32] {
            self.config.pool_uuid
        }
        #[inline]
        pub fn device_count(&self) -> usize {
            self.config.device_count()
        }
        #[inline]
        pub fn total_capacity_bytes(&self) -> u64 {
            self.config.total_capacity_bytes()
        }
        #[inline]
        pub fn config(&self) -> &KernelPoolConfig {
            &self.config
        }
        #[inline]
        pub fn is_mounted(&self) -> bool {
            self.state() == KernelPoolState::Mounted
        }

        #[inline]
        fn try_transition(
            &self,
            expected: KernelPoolState,
            target: KernelPoolState,
        ) -> Result<(), KernelPoolError> {
            if !expected.can_transition_to(target) {
                return Err(KernelPoolError::InvalidTransition {
                    from: expected,
                    to: target,
                });
            }
            let expected_raw = expected.to_u64();
            let target_raw = target.to_u64();
            loop {
                match self.state.compare_exchange_weak(
                    expected_raw,
                    target_raw,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return Ok(()),
                    Err(actual_raw) => {
                        let actual = KernelPoolState::from_u64(actual_raw)
                            .expect("corrupt KernelPoolCore state word");
                        if actual != expected {
                            return Err(KernelPoolError::InvalidTransition {
                                from: actual,
                                to: target,
                            });
                        }
                        core::hint::spin_loop();
                    }
                }
            }
        }
    }

    // ── End pool label types ──────────────────────────────────────────
}

// Under Kbuild, re-export from the local module.
pub use kbuild_impl::*;

// ═══════════════════════════════════════════════════════════════════════════
// Minimal BLAKE3 implementation for Kbuild.
// Under cargo, the real blake3 crate is used directly by the leaf crates.
// ═══════════════════════════════════════════════════════════════════════════

pub mod blake3 {
    const OUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
    const CHUNK_LEN: usize = 1024;
    const CHUNK_START: u32 = 1 << 0;
    const CHUNK_END: u32 = 1 << 1;
    const PARENT: u32 = 1 << 2;
    const ROOT: u32 = 1 << 3;
    const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
    const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

    /// A BLAKE3-256 hash (32 bytes).
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Hash(pub [u8; 32]);

    impl Hash {
        #[must_use]
        pub const fn from_bytes(bytes: [u8; 32]) -> Self {
            Self(bytes)
        }

        #[must_use]
        pub fn as_bytes(&self) -> &[u8; 32] {
            &self.0
        }

        #[must_use]
        pub fn to_hex(&self) -> crate::tidefs_kmod_bridge::kernel_types::KmodString {
            use core::fmt::Write;
            let mut s = crate::tidefs_kmod_bridge::kernel_types::KmodString::with_capacity(64);
            for b in &self.0 {
                let _ = write!(s, "{b:02x}");
            }
            s
        }
    }

    impl core::fmt::Debug for Hash {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            for b in &self.0 {
                write!(f, "{b:02x}")?;
            }
            Ok(())
        }
    }

    impl From<Hash> for [u8; 32] {
        fn from(h: Hash) -> Self {
            h.0
        }
    }

    impl core::fmt::Display for Hash {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Debug::fmt(self, f)
        }
    }

    /// Compute a BLAKE3-256 hash of data.
    pub fn hash(data: &[u8]) -> Hash {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// A minimal BLAKE3 hasher for kernel label and committed-root integrity.
    pub struct Hasher {
        key_words: [u32; 8],
        flags: u32,
        buf: kernel::alloc::KVec<u8>,
    }

    impl Hasher {
        #[must_use]
        pub const fn new() -> Self {
            Self {
                key_words: IV,
                flags: 0,
                buf: kernel::alloc::KVec::<u8>::new(),
            }
        }

        #[must_use]
        pub fn new_derive_key(context: &str) -> Self {
            Self {
                key_words: derive_key_context_key(context.as_bytes()),
                flags: DERIVE_KEY_MATERIAL,
                buf: kernel::alloc::KVec::<u8>::new(),
            }
        }

        pub fn update(&mut self, data: &[u8]) {
            let _ = self
                .buf
                .extend_from_slice(data, kernel::alloc::flags::GFP_KERNEL);
        }

        #[must_use]
        pub fn finalize(&self) -> Hash {
            Hash(hash_with_key(
                self.buf.as_slice(),
                self.key_words,
                self.flags,
            ))
        }
    }

    impl Default for Hasher {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Returns `true` when a real BLAKE3-256 implementation is available.
    #[must_use]
    pub const fn blake3_available() -> bool {
        true
    }

    #[derive(Clone, Copy)]
    struct Output {
        input_cv: [u32; 8],
        block_words: [u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
    }

    impl Output {
        fn chaining_value(self) -> [u32; 8] {
            first_8_words(compress(
                self.input_cv,
                self.block_words,
                self.counter,
                self.block_len,
                self.flags,
            ))
        }

        fn root_hash(self) -> [u8; OUT_LEN] {
            let words = compress(
                self.input_cv,
                self.block_words,
                self.counter,
                self.block_len,
                self.flags | ROOT,
            );
            words_to_bytes_32(first_8_words(words))
        }
    }

    fn hash_with_key(data: &[u8], key_words: [u32; 8], flags: u32) -> [u8; OUT_LEN] {
        let chunk_count = if data.is_empty() {
            1
        } else {
            (data.len() + CHUNK_LEN - 1) / CHUNK_LEN
        };

        if chunk_count == 1 {
            return chunk_output(data, 0, key_words, flags).root_hash();
        }

        let mut stack = [[0u32; 8]; 64];
        let mut stack_len = 0usize;

        for chunk_index in 0..(chunk_count - 1) {
            let start = chunk_index * CHUNK_LEN;
            let end = (start + CHUNK_LEN).min(data.len());
            let cv = chunk_output(&data[start..end], chunk_index as u64, key_words, flags)
                .chaining_value();
            add_chunk_cv(
                &mut stack,
                &mut stack_len,
                cv,
                chunk_index + 1,
                key_words,
                flags,
            );
        }

        let last_start = (chunk_count - 1) * CHUNK_LEN;
        let mut output = chunk_output(
            &data[last_start..],
            (chunk_count - 1) as u64,
            key_words,
            flags,
        );

        while stack_len > 0 {
            stack_len -= 1;
            output = parent_output(stack[stack_len], output.chaining_value(), key_words, flags);
        }

        output.root_hash()
    }

    fn add_chunk_cv(
        stack: &mut [[u32; 8]; 64],
        stack_len: &mut usize,
        mut cv: [u32; 8],
        mut total_chunks: usize,
        key_words: [u32; 8],
        flags: u32,
    ) {
        while (total_chunks & 1) == 0 && *stack_len > 0 {
            *stack_len -= 1;
            cv = parent_output(stack[*stack_len], cv, key_words, flags).chaining_value();
            total_chunks >>= 1;
        }
        if *stack_len < stack.len() {
            stack[*stack_len] = cv;
            *stack_len += 1;
        }
    }

    fn chunk_output(chunk: &[u8], chunk_counter: u64, key_words: [u32; 8], flags: u32) -> Output {
        let mut cv = key_words;
        let mut offset = 0usize;

        while chunk.len().saturating_sub(offset) > BLOCK_LEN {
            let block = load_block(&chunk[offset..offset + BLOCK_LEN]);
            let block_flags = flags | if offset == 0 { CHUNK_START } else { 0 };
            cv = first_8_words(compress(
                cv,
                block,
                chunk_counter,
                BLOCK_LEN as u32,
                block_flags,
            ));
            offset += BLOCK_LEN;
        }

        let remaining = &chunk[offset..];
        let block_flags = flags | CHUNK_END | if offset == 0 { CHUNK_START } else { 0 };

        Output {
            input_cv: cv,
            block_words: load_block(remaining),
            counter: chunk_counter,
            block_len: remaining.len() as u32,
            flags: block_flags,
        }
    }

    fn parent_output(
        left_cv: [u32; 8],
        right_cv: [u32; 8],
        key_words: [u32; 8],
        flags: u32,
    ) -> Output {
        let mut block_words = [0u32; 16];
        block_words[..8].copy_from_slice(&left_cv);
        block_words[8..].copy_from_slice(&right_cv);

        Output {
            input_cv: key_words,
            block_words,
            counter: 0,
            block_len: BLOCK_LEN as u32,
            flags: flags | PARENT,
        }
    }

    fn derive_key_context_key(context: &[u8]) -> [u32; 8] {
        bytes_to_words_32(hash_with_key(context, IV, DERIVE_KEY_CONTEXT))
    }

    fn compress(
        cv: [u32; 8],
        block_words: [u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
    ) -> [u32; 16] {
        let mut state = [
            cv[0],
            cv[1],
            cv[2],
            cv[3],
            cv[4],
            cv[5],
            cv[6],
            cv[7],
            IV[0],
            IV[1],
            IV[2],
            IV[3],
            counter as u32,
            (counter >> 32) as u32,
            block_len,
            flags,
        ];
        let mut msg = block_words;

        for round_index in 0..7 {
            round(&mut state, &msg);
            if round_index != 6 {
                msg = permute(msg);
            }
        }

        for i in 0..8 {
            state[i] ^= state[i + 8];
            state[i + 8] ^= cv[i];
        }

        state
    }

    fn round(state: &mut [u32; 16], msg: &[u32; 16]) {
        g(state, 0, 4, 8, 12, msg[0], msg[1]);
        g(state, 1, 5, 9, 13, msg[2], msg[3]);
        g(state, 2, 6, 10, 14, msg[4], msg[5]);
        g(state, 3, 7, 11, 15, msg[6], msg[7]);
        g(state, 0, 5, 10, 15, msg[8], msg[9]);
        g(state, 1, 6, 11, 12, msg[10], msg[11]);
        g(state, 2, 7, 8, 13, msg[12], msg[13]);
        g(state, 3, 4, 9, 14, msg[14], msg[15]);
    }

    fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    fn permute(words: [u32; 16]) -> [u32; 16] {
        let mut out = [0u32; 16];
        for i in 0..16 {
            out[i] = words[MSG_PERMUTATION[i]];
        }
        out
    }

    fn load_block(input: &[u8]) -> [u32; 16] {
        let mut block = [0u8; BLOCK_LEN];
        let len = input.len().min(BLOCK_LEN);
        block[..len].copy_from_slice(&input[..len]);

        let mut words = [0u32; 16];
        for i in 0..16 {
            let j = i * 4;
            words[i] = u32::from_le_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        }
        words
    }

    fn first_8_words(words: [u32; 16]) -> [u32; 8] {
        [
            words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7],
        ]
    }

    fn words_to_bytes_32(words: [u32; 8]) -> [u8; OUT_LEN] {
        let mut bytes = [0u8; OUT_LEN];
        for i in 0..8 {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&words[i].to_le_bytes());
        }
        bytes
    }

    fn bytes_to_words_32(bytes: [u8; OUT_LEN]) -> [u32; 8] {
        let mut words = [0u32; 8];
        for i in 0..8 {
            let j = i * 4;
            words[i] = u32::from_le_bytes([bytes[j], bytes[j + 1], bytes[j + 2], bytes[j + 3]]);
        }
        words
    }
}

//! Filesystem operation reply
//!
//! A reply is passed to filesystem operation implementations and must be used to send back the
//! result of an operation. The reply can optionally be sent to another thread to asynchronously
//! work on an operation and provide the result later. Also it allows replying with a block of
//! data without cloning the data. A reply *must always* be used (by calling either ok() or
//! error() exactly once).
//!
//! ## ReplyBuilder
//!
//! All reply types delegate to a shared [`ReplyBuilder`] which enforces:
//! - **Reply uniqueness**: panics if a reply is sent twice for the same request (double-reply
//!   detection via `replied` flag).
//! - **Error convention**: validates that error values are non-positive (zero = success,
//!   negative = kernel errno) before constructing the `fuse_out_header`.
//! - **Size bounds**: verifies data payload length fits within `u32::MAX` for the FUSE wire
//!   protocol.
//! - **Drop guard**: if a reply is never sent, `ReplyBuilder::drop` auto-responds with EIO to
//!   prevent kernel hangs.

use crate::ll::{
    self,
    reply::{DirEntPlusList, DirEntryPlus},
    Generation,
};
use crate::ll::{
    reply::{DirEntList, DirEntOffset, DirEntry},
    INodeNo,
};
use libc::c_int;
use log::{error, warn};
use std::convert::AsRef;
use std::ffi::OsStr;
use std::fmt;
use std::io::IoSlice;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(target_os = "macos")]
use std::time::SystemTime;

use crate::{FileAttr, FileType};

/// Generic reply callback to send data
pub trait ReplySender: Send + Sync + Unpin + 'static {
    /// Send data.
    fn send(&self, data: &[IoSlice<'_>]) -> std::io::Result<()>;
}

impl fmt::Debug for Box<dyn ReplySender> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Box<ReplySender>")
    }
}

/// Generic reply trait
pub trait Reply {
    /// Create a new reply for the given request
    fn new<S: ReplySender>(unique: u64, sender: S) -> Self;
}

///
/// Unified reply builder that all reply types delegate to.
///
/// Enforces reply-header correctness (error convention, size bounds),
/// double-reply detection, and drop-guard auto-EIO for unreplied requests.
#[derive(Debug)]
pub(crate) struct ReplyBuilder {
    /// Unique id of the request to reply to
    unique: ll::RequestId,
    /// Closure to call for sending the reply
    sender: Option<Box<dyn ReplySender>>,
    /// Whether a reply has already been sent for this request
    replied: bool,
}

impl Reply for ReplyBuilder {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyBuilder {
        let sender = Box::new(sender);
        ReplyBuilder {
            unique: ll::RequestId(unique),
            sender: Some(sender),
            replied: false,
        }
    }
}

impl ReplyBuilder {
    /// Mark replied and take the sender. Panics if already replied (double-reply detection).
    fn take_sender(&mut self) -> Box<dyn ReplySender> {
        assert!(
            !self.replied,
            "BUG: double reply detected for request {}",
            self.unique.0
        );
        self.replied = true;
        self.sender.take().expect("BUG: sender already taken")
    }

    /// Send a reply via the low-level Response. Must be called only once.
    fn send_ll_mut(&mut self, response: &ll::Response<'_>) {
        let sender = self.take_sender();
        let res = response.with_iovec(self.unique, |iov| sender.send(iov));
        if let Err(err) = res {
            error!("Failed to send FUSE reply: {err}");
        }
    }

    /// Reply with an empty success (error=0, no data payload).
    pub(crate) fn reply_none(&mut self) {
        self.send_ll_mut(&ll::Response::new_empty());
    }

    /// Reply with the given error code (must be > 0, conventional POSIX errno).
    ///
    /// Panics if `errno` is zero (use `reply_none` for success).
    pub fn reply_err(&mut self, errno: c_int) {
        assert_ne!(
            errno, 0,
            "BUG: reply_err called with errno=0; use reply_none for success"
        );
        self.send_ll_mut(&ll::Response::new_error(ll::Errno::from_i32(errno)));
    }

    /// Reply with success (error=0) and a data payload.
    ///
    /// Panics if `data.len()` exceeds `u32::MAX` (FUSE wire size limit).
    pub(crate) fn reply_ok(&mut self, data: &[u8]) {
        assert!(
            data.len() <= u32::MAX as usize,
            "BUG: reply data length {} exceeds FUSE wire limit",
            data.len()
        );
        self.send_ll_mut(&ll::Response::new_slice(data));
    }

    /// Reply with a constructed low-level Response. Internal delegation for
    /// specialized reply types (entry, attr, directory, etc.).
    pub(crate) fn reply_raw(&mut self, response: &ll::Response<'_>) {
        self.send_ll_mut(response);
    }
}

impl Drop for ReplyBuilder {
    fn drop(&mut self) {
        if !self.replied && self.sender.is_some() {
            warn!(
                "Reply not sent for operation {}, replying with I/O error",
                self.unique.0
            );
            self.replied = true;
            let sender = self
                .sender
                .take()
                .expect("BUG: sender missing in drop guard");
            let response = ll::Response::new_error(ll::Errno::EIO);
            let res = response.with_iovec(self.unique, |iov| sender.send(iov));
            if let Err(err) = res {
                error!("Failed to send FUSE reply in drop: {err}");
            }
        }
    }
}

///
/// Empty reply
///
#[derive(Debug)]
pub struct ReplyEmpty {
    reply: ReplyBuilder,
}

impl Reply for ReplyEmpty {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyEmpty {
        ReplyEmpty {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyEmpty {
    /// Reply to a request with nothing
    pub fn ok(mut self) {
        self.reply.reply_none();
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Data reply
///
#[derive(Debug)]
pub struct ReplyData {
    reply: ReplyBuilder,
}

impl Reply for ReplyData {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyData {
        ReplyData {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyData {
    /// Reply to a request with the given data
    pub fn data(mut self, data: &[u8]) {
        self.reply.reply_ok(data);
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Entry reply
///
#[derive(Debug)]
pub struct ReplyEntry {
    reply: ReplyBuilder,
}

impl Reply for ReplyEntry {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyEntry {
        ReplyEntry {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyEntry {
    /// Reply to a request with the given entry
    pub fn entry(mut self, ttl: &Duration, attr: &FileAttr, generation: u64) {
        self.reply_entry_with_ttls(ttl, ttl, attr, generation);
    }

    /// Reply to a request with separate dentry and attribute cache TTLs.
    pub fn entry_with_ttls(
        mut self,
        entry_ttl: &Duration,
        attr_ttl: &Duration,
        attr: &FileAttr,
        generation: u64,
    ) {
        self.reply_entry_with_ttls(entry_ttl, attr_ttl, attr, generation);
    }

    fn reply_entry_with_ttls(
        &mut self,
        entry_ttl: &Duration,
        attr_ttl: &Duration,
        attr: &FileAttr,
        generation: u64,
    ) {
        self.reply.reply_raw(&ll::Response::new_entry(
            ll::INodeNo(attr.ino),
            ll::Generation(generation),
            &attr.into(),
            *attr_ttl,
            *entry_ttl,
        ));
    }

    /// Reply to a lookup miss with a cacheable negative dentry.
    pub fn negative(mut self, entry_ttl: &Duration) {
        let attr = FileAttr {
            ino: 0,
            size: 0,
            blocks: 0,
            atime: std::time::UNIX_EPOCH,
            mtime: std::time::UNIX_EPOCH,
            ctime: std::time::UNIX_EPOCH,
            crtime: std::time::UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 0,
            flags: 0,
        };
        self.reply.reply_raw(&ll::Response::new_entry(
            ll::INodeNo(0),
            ll::Generation(0),
            &attr.into(),
            Duration::ZERO,
            *entry_ttl,
        ));
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Attribute Reply
///
#[derive(Debug)]
pub struct ReplyAttr {
    reply: ReplyBuilder,
}

impl Reply for ReplyAttr {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyAttr {
        ReplyAttr {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyAttr {
    /// Reply to a request with the given attribute
    pub fn attr(mut self, ttl: &Duration, attr: &FileAttr) {
        self.reply
            .reply_raw(&ll::Response::new_attr(ttl, &attr.into()));
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// XTimes Reply
///
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct ReplyXTimes {
    reply: ReplyBuilder,
}

#[cfg(target_os = "macos")]
impl Reply for ReplyXTimes {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyXTimes {
        ReplyXTimes {
            reply: Reply::new(unique, sender),
        }
    }
}

#[cfg(target_os = "macos")]
impl ReplyXTimes {
    /// Reply to a request with the given xtimes
    pub fn xtimes(mut self, bkuptime: SystemTime, crtime: SystemTime) {
        self.reply
            .reply_raw(&ll::Response::new_xtimes(bkuptime, crtime))
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Open Reply
///
#[derive(Debug)]
pub struct ReplyOpen {
    reply: ReplyBuilder,
}

impl Reply for ReplyOpen {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyOpen {
        ReplyOpen {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyOpen {
    /// Reply to a request with the given open result
    pub fn opened(mut self, fh: u64, flags: u32) {
        self.reply
            .reply_raw(&ll::Response::new_open(ll::FileHandle(fh), flags))
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Write Reply
///
#[derive(Debug)]
pub struct ReplyWrite {
    reply: ReplyBuilder,
}

impl Reply for ReplyWrite {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyWrite {
        ReplyWrite {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyWrite {
    /// Reply to a request with the given open result
    pub fn written(mut self, size: u32) {
        self.reply.reply_raw(&ll::Response::new_write(size))
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Statfs Reply
///
#[derive(Debug)]
pub struct ReplyStatfs {
    reply: ReplyBuilder,
}

impl Reply for ReplyStatfs {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyStatfs {
        ReplyStatfs {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyStatfs {
    /// Reply to a request with the given open result
    #[allow(clippy::too_many_arguments)]
    pub fn statfs(
        mut self,
        blocks: u64,
        bfree: u64,
        bavail: u64,
        files: u64,
        ffree: u64,
        bsize: u32,
        namelen: u32,
        frsize: u32,
    ) {
        self.reply.reply_raw(&ll::Response::new_statfs(
            blocks, bfree, bavail, files, ffree, bsize, namelen, frsize,
        ))
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Statx Reply
///
#[cfg(feature = "abi-7-30")]
#[derive(Debug)]
pub struct ReplyStatx {
    reply: ReplyBuilder,
}

#[cfg(feature = "abi-7-30")]
impl Reply for ReplyStatx {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyStatx {
        ReplyStatx {
            reply: Reply::new(unique, sender),
        }
    }
}

#[cfg(feature = "abi-7-30")]
impl ReplyStatx {
    /// Reply with the statx data buffer matching `struct fuse_statx_out`.
    pub fn statx(mut self, data: &[u8]) {
        self.reply.reply_ok(data);
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Create reply
///
#[derive(Debug)]
pub struct ReplyCreate {
    reply: ReplyBuilder,
}

impl Reply for ReplyCreate {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyCreate {
        ReplyCreate {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyCreate {
    /// Reply to a request with the given entry
    pub fn created(
        mut self,
        ttl: &Duration,
        attr: &FileAttr,
        generation: u64,
        fh: u64,
        flags: u32,
    ) {
        self.reply.reply_raw(&ll::Response::new_create(
            ttl,
            &attr.into(),
            ll::Generation(generation),
            ll::FileHandle(fh),
            flags,
        ));
    }

    /// Reply to a create request with separate dentry and attribute TTLs.
    pub fn created_with_ttls(
        mut self,
        entry_ttl: &Duration,
        attr_ttl: &Duration,
        attr: &FileAttr,
        generation: u64,
        fh: u64,
        flags: u32,
    ) {
        self.reply_created_with_ttls(entry_ttl, attr_ttl, attr, generation, fh, flags);
    }

    fn reply_created_with_ttls(
        &mut self,
        entry_ttl: &Duration,
        attr_ttl: &Duration,
        attr: &FileAttr,
        generation: u64,
        fh: u64,
        flags: u32,
    ) {
        self.reply.reply_raw(&ll::Response::new_create_with_ttls(
            entry_ttl,
            attr_ttl,
            &attr.into(),
            ll::Generation(generation),
            ll::FileHandle(fh),
            flags,
        ))
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Lock Reply
///
#[derive(Debug)]
pub struct ReplyLock {
    reply: ReplyBuilder,
}

impl Reply for ReplyLock {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyLock {
        ReplyLock {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyLock {
    /// Reply to a request with the given open result
    pub fn locked(mut self, start: u64, end: u64, typ: i32, pid: u32) {
        self.reply.reply_raw(&ll::Response::new_lock(&ll::Lock {
            range: (start, end),
            typ,
            pid,
        }))
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Bmap Reply
///
#[derive(Debug)]
pub struct ReplyBmap {
    reply: ReplyBuilder,
}

impl Reply for ReplyBmap {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyBmap {
        ReplyBmap {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyBmap {
    /// Reply to a request with the given open result
    pub fn bmap(mut self, block: u64) {
        self.reply.reply_raw(&ll::Response::new_bmap(block))
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Ioctl Reply
///
#[derive(Debug)]
pub struct ReplyIoctl {
    reply: ReplyBuilder,
}

impl Reply for ReplyIoctl {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyIoctl {
        ReplyIoctl {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyIoctl {
    /// Reply to a request with the given open result
    pub fn ioctl(mut self, result: i32, data: &[u8]) {
        self.reply
            .reply_raw(&ll::Response::new_ioctl(result, &[IoSlice::new(data)]));
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Poll Reply
///
#[derive(Debug)]
#[cfg(feature = "abi-7-11")]
pub struct ReplyPoll {
    reply: ReplyBuilder,
}

#[cfg(feature = "abi-7-11")]
impl Reply for ReplyPoll {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyPoll {
        ReplyPoll {
            reply: Reply::new(unique, sender),
        }
    }
}

#[cfg(feature = "abi-7-11")]
impl ReplyPoll {
    /// Reply to a request with the given poll result
    pub fn poll(mut self, revents: u32) {
        self.reply.reply_raw(&ll::Response::new_poll(revents))
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Directory reply
///
#[derive(Debug)]
pub struct ReplyDirectory {
    reply: ReplyBuilder,
    data: DirEntList,
}

impl ReplyDirectory {
    /// Creates a new ReplyDirectory with a specified buffer size.
    pub fn new<S: ReplySender>(unique: u64, sender: S, size: usize) -> ReplyDirectory {
        ReplyDirectory {
            reply: Reply::new(unique, sender),
            data: DirEntList::new(size),
        }
    }

    /// Add an entry to the directory reply buffer. Returns true if the buffer is full.
    /// A transparent offset value can be provided for each entry. The kernel uses these
    /// value to request the next entries in further readdir calls
    #[must_use]
    pub fn add<T: AsRef<OsStr>>(&mut self, ino: u64, offset: i64, kind: FileType, name: T) -> bool {
        let name = name.as_ref();
        self.data.push(&DirEntry::new(
            INodeNo(ino),
            DirEntOffset(offset),
            kind,
            name,
        ))
    }

    /// Reply to a request with the filled directory buffer
    pub fn ok(mut self) {
        self.reply.reply_raw(&self.data.into());
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// DirectoryPlus reply
///
#[derive(Debug)]
pub struct ReplyDirectoryPlus {
    reply: ReplyBuilder,
    buf: DirEntPlusList,
}

impl ReplyDirectoryPlus {
    /// Creates a new ReplyDirectory with a specified buffer size.
    pub fn new<S: ReplySender>(unique: u64, sender: S, size: usize) -> ReplyDirectoryPlus {
        ReplyDirectoryPlus {
            reply: Reply::new(unique, sender),
            buf: DirEntPlusList::new(size),
        }
    }

    /// Add an entry to the directory reply buffer. Returns true if the buffer is full.
    /// A transparent offset value can be provided for each entry. The kernel uses these
    /// value to request the next entries in further readdir calls
    pub fn add<T: AsRef<OsStr>>(
        &mut self,
        ino: u64,
        offset: i64,
        name: T,
        ttl: &Duration,
        attr: &FileAttr,
        generation: u64,
    ) -> bool {
        self.add_with_ttls(ino, offset, name, ttl, ttl, attr, generation)
    }

    /// Add a directory-plus entry with separate dentry and attribute TTLs.
    pub fn add_with_ttls<T: AsRef<OsStr>>(
        &mut self,
        ino: u64,
        offset: i64,
        name: T,
        entry_ttl: &Duration,
        attr_ttl: &Duration,
        attr: &FileAttr,
        generation: u64,
    ) -> bool {
        let name = name.as_ref();
        self.buf.push(&DirEntryPlus::new(
            INodeNo(ino),
            Generation(generation),
            DirEntOffset(offset),
            name,
            *entry_ttl,
            attr.into(),
            *attr_ttl,
        ))
    }

    /// Reply to a request with the filled directory buffer
    pub fn ok(mut self) {
        self.reply.reply_raw(&self.buf.into());
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Xattr reply
///
#[derive(Debug)]
pub struct ReplyXattr {
    reply: ReplyBuilder,
}

impl Reply for ReplyXattr {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyXattr {
        ReplyXattr {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyXattr {
    /// Reply to a request with the size of the xattr.
    pub fn size(mut self, size: u32) {
        self.reply.reply_raw(&ll::Response::new_xattr_size(size))
    }

    /// Reply to a request with the data in the xattr.
    pub fn data(mut self, data: &[u8]) {
        self.reply.reply_ok(data);
    }

    /// Reply to a request with the given error code.
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

///
/// Lseek Reply
///
#[derive(Debug)]
pub struct ReplyLseek {
    reply: ReplyBuilder,
}

impl Reply for ReplyLseek {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyLseek {
        ReplyLseek {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyLseek {
    /// Reply to a request with seeked offset
    pub fn offset(mut self, offset: i64) {
        self.reply.reply_raw(&ll::Response::new_lseek(offset))
    }

    /// Reply to a request with the given error code
    pub fn error(mut self, err: c_int) {
        self.reply.reply_err(err);
    }
}

/// A `ReplySender` that captures all framed reply bytes into a shared buffer.
///
/// Each call to [`send`](ReplySender::send) appends the `IoSlice` data to an
/// internal `Vec<u8>` protected by a `Mutex`.  The accumulated data can be
/// inspected with [`data`](CapturingSender::data) or drained with
/// [`take_data`](CapturingSender::take_data).
///
/// This is intended for integration tests that need to validate FUSE reply
/// framing (header + payload) without a real kernel channel.  It is compiled
/// unconditionally as part of the production library.
///
/// # Thread safety
///
/// `CapturingSender` is `Send + Sync` and can be shared across threads.  The
/// internal buffer is protected by a `Mutex`.
#[derive(Clone, Debug)]
pub struct CapturingSender {
    data: Arc<Mutex<Vec<u8>>>,
}

impl CapturingSender {
    /// Create an empty `CapturingSender`.
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Return a copy of the accumulated reply data without clearing the buffer.
    #[allow(dead_code)]
    pub fn data(&self) -> Vec<u8> {
        self.data
            .lock()
            .expect("capturing reply buffer lock poisoned")
            .clone()
    }

    /// Take the accumulated reply data, leaving the buffer empty.
    #[allow(dead_code)]
    pub fn take_data(&self) -> Vec<u8> {
        std::mem::take(
            &mut *self
                .data
                .lock()
                .expect("capturing reply buffer lock poisoned"),
        )
    }
}

impl Default for CapturingSender {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplySender for CapturingSender {
    fn send(&self, data: &[IoSlice<'_>]) -> std::io::Result<()> {
        let mut buf = self
            .data
            .lock()
            .expect("capturing reply buffer lock poisoned");
        for slice in data {
            buf.extend_from_slice(slice);
        }
        Ok(())
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::{FileAttr, FileType};
    use std::io::IoSlice;
    use std::sync::mpsc::{sync_channel, SyncSender};
    use std::thread;
    use std::time::{Duration, UNIX_EPOCH};
    use zerocopy::AsBytes;

    #[derive(Debug, AsBytes)]
    #[repr(C)]
    struct Data {
        a: u8,
        b: u8,
        c: u16,
    }

    #[test]
    fn serialize_empty() {
        assert!(().as_bytes().is_empty());
    }

    #[test]
    fn serialize_slice() {
        let data: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(data.as_bytes(), [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn serialize_struct() {
        let data = Data {
            a: 0x12,
            b: 0x34,
            c: 0x5678,
        };
        assert_eq!(data.as_bytes(), [0x12, 0x34, 0x78, 0x56]);
    }

    struct AssertSender {
        expected: Vec<u8>,
    }

    impl super::ReplySender for AssertSender {
        fn send(&self, data: &[IoSlice<'_>]) -> std::io::Result<()> {
            let mut v = vec![];
            for x in data {
                v.extend_from_slice(x)
            }
            assert_eq!(self.expected, v);
            Ok(())
        }
    }

    #[test]
    fn reply_raw() {
        let data = Data {
            a: 0x12,
            b: 0x34,
            c: 0x5678,
        };
        let sender = AssertSender {
            expected: vec![
                0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x12, 0x34, 0x78, 0x56,
            ],
        };
        let mut reply: ReplyBuilder = Reply::new(0xdeadbeef, sender);
        reply.send_ll_mut(&ll::Response::new_data(data.as_bytes()));
    }

    #[test]
    fn reply_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xbe, 0xff, 0xff, 0xff, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let mut reply: ReplyBuilder = Reply::new(0xdeadbeef, sender);
        reply.reply_err(66);
    }

    #[test]
    fn reply_empty() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyEmpty = Reply::new(0xdeadbeef, sender);
        reply.ok();
    }

    #[test]
    fn reply_data() {
        let sender = AssertSender {
            expected: vec![
                0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
            ],
        };
        let reply: ReplyData = Reply::new(0xdeadbeef, sender);
        reply.data(&[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn reply_entry() {
        let mut expected = if cfg!(target_os = "macos") {
            vec![
                0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x87,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56,
                0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00,
                0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x99, 0x00, 0x00, 0x00,
            ]
        } else {
            vec![
                0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x87,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x66, 0x00,
                0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
            ]
        };

        if cfg!(feature = "abi-7-9") {
            expected.extend(vec![0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }
        expected[0] = (expected.len()) as u8;

        let sender = AssertSender { expected };
        let reply: ReplyEntry = Reply::new(0xdeadbeef, sender);
        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr = FileAttr {
            ino: 0x11,
            size: 0x22,
            blocks: 0x33,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 0x55,
            uid: 0x66,
            gid: 0x77,
            rdev: 0x88,
            flags: 0x99,
            blksize: 0xbb,
        };
        reply.entry(&ttl, &attr, 0xaa);
    }

    #[test]
    fn reply_attr() {
        let mut expected = if cfg!(target_os = "macos") {
            vec![
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56,
                0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00,
                0x66, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x99, 0x00,
                0x00, 0x00,
            ]
        } else {
            vec![
                0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00,
                0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
            ]
        };

        if cfg!(feature = "abi-7-9") {
            expected.extend_from_slice(&[0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }
        expected[0] = expected.len() as u8;

        let sender = AssertSender { expected };
        let reply: ReplyAttr = Reply::new(0xdeadbeef, sender);
        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr = FileAttr {
            ino: 0x11,
            size: 0x22,
            blocks: 0x33,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 0x55,
            uid: 0x66,
            gid: 0x77,
            rdev: 0x88,
            flags: 0x99,
            blksize: 0xbb,
        };
        reply.attr(&ttl, &attr);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn reply_xtimes() {
        let sender = AssertSender {
            expected: vec![
                0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00,
            ],
        };
        let reply: ReplyXTimes = Reply::new(0xdeadbeef, sender);
        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        reply.xtimes(time, time);
    }

    #[test]
    fn reply_open() {
        let sender = AssertSender {
            expected: vec![
                0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
        };
        let reply: ReplyOpen = Reply::new(0xdeadbeef, sender);
        reply.opened(0x1122, 0x33);
    }

    #[test]
    fn reply_write() {
        let sender = AssertSender {
            expected: vec![
                0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let reply: ReplyWrite = Reply::new(0xdeadbeef, sender);
        reply.written(0x1122);
    }

    #[test]
    fn reply_statfs() {
        let sender = AssertSender {
            expected: vec![
                0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x66, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let reply: ReplyStatfs = Reply::new(0xdeadbeef, sender);
        reply.statfs(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88);
    }

    #[test]
    fn reply_create() {
        let mut expected = if cfg!(target_os = "macos") {
            vec![
                0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x87,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56,
                0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00,
                0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x99, 0x00, 0x00, 0x00, 0xbb, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        } else {
            vec![
                0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x87,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x66, 0x00,
                0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0xbb, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        };

        if cfg!(feature = "abi-7-9") {
            let insert_at = expected.len() - 16;
            expected.splice(
                insert_at..insert_at,
                vec![0xdd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            );
        }
        expected[0] = (expected.len()) as u8;

        let sender = AssertSender { expected };
        let reply: ReplyCreate = Reply::new(0xdeadbeef, sender);
        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr = FileAttr {
            ino: 0x11,
            size: 0x22,
            blocks: 0x33,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 0x55,
            uid: 0x66,
            gid: 0x77,
            rdev: 0x88,
            flags: 0x99,
            blksize: 0xdd,
        };
        reply.created(&ttl, &attr, 0xaa, 0xbb, 0xcc);
    }

    #[test]
    fn reply_lock() {
        let sender = AssertSender {
            expected: vec![
                0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00,
            ],
        };
        let reply: ReplyLock = Reply::new(0xdeadbeef, sender);
        reply.locked(0x11, 0x22, 0x33, 0x44);
    }

    #[test]
    fn reply_bmap() {
        let sender = AssertSender {
            expected: vec![
                0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let reply: ReplyBmap = Reply::new(0xdeadbeef, sender);
        reply.bmap(0x1234);
    }

    #[test]
    fn reply_directory() {
        let sender = AssertSender {
            expected: vec![
                0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0xbb, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x68, 0x65,
                0x6c, 0x6c, 0x6f, 0x00, 0x00, 0x00, 0xdd, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00,
                0x00, 0x00, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x2e, 0x72, 0x73,
            ],
        };
        let mut reply = ReplyDirectory::new(0xdeadbeef, sender, 4096);
        assert!(!reply.add(0xaabb, 1, FileType::Directory, "hello"));
        assert!(!reply.add(0xccdd, 2, FileType::RegularFile, "world.rs"));
        reply.ok();
    }

    #[test]
    fn reply_xattr_size() {
        let sender = AssertSender {
            expected: vec![
                0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00,
                0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let reply = ReplyXattr::new(0xdeadbeef, sender);
        reply.size(0x12345678);
    }

    #[test]
    fn reply_xattr_data() {
        let sender = AssertSender {
            expected: vec![
                0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
            ],
        };
        let reply = ReplyXattr::new(0xdeadbeef, sender);
        reply.data(&[0x11, 0x22, 0x33, 0x44]);
    }

    /// A ReplySender that captures sent iovec data into a Vec<u8> for later inspection.
    struct CapturingSender {
        captured: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl CapturingSender {
        fn new() -> (Self, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
            let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                Self {
                    captured: captured.clone(),
                },
                captured,
            )
        }
    }

    impl super::ReplySender for CapturingSender {
        fn send(&self, data: &[IoSlice<'_>]) -> std::io::Result<()> {
            let mut v = self.captured.lock().unwrap();
            for x in data {
                v.extend_from_slice(x);
            }
            Ok(())
        }
    }

    /// Parse fuse_out_header fields from raw bytes.
    fn parse_header(bytes: &[u8]) -> (u32, i32, u64) {
        let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let error = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let unique = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        (len, error, unique)
    }

    #[test]
    fn reply_lseek() {
        let sender = AssertSender {
            expected: vec![
                0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let reply: ReplyLseek = Reply::new(0xdeadbeef, sender);
        reply.offset(0x1234);
    }

    #[test]
    fn reply_lseek_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xEA, 0xFF, 0xFF, 0xFF, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyLseek = Reply::new(0xdeadbeef, sender);
        reply.error(22); // EINVAL
    }

    #[test]
    fn reply_empty_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xFB, 0xFF, 0xFF, 0xFF, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyEmpty = Reply::new(0xdeadbeef, sender);
        reply.error(5); // EIO
    }

    #[test]
    fn reply_data_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyData = Reply::new(0xdeadbeef, sender);
        reply.error(2); // ENOENT
    }

    #[test]
    fn reply_entry_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyEntry = Reply::new(0xdeadbeef, sender);
        reply.error(2); // ENOENT
    }

    #[test]
    fn reply_attr_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xF3, 0xFF, 0xFF, 0xFF, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyAttr = Reply::new(0xdeadbeef, sender);
        reply.error(13); // EACCES
    }

    #[test]
    fn reply_open_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyOpen = Reply::new(0xdeadbeef, sender);
        reply.error(2); // ENOENT
    }

    #[test]
    fn reply_write_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xE4, 0xFF, 0xFF, 0xFF, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyWrite = Reply::new(0xdeadbeef, sender);
        reply.error(28); // ENOSPC
    }

    #[test]
    fn reply_create_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyCreate = Reply::new(0xdeadbeef, sender);
        reply.error(2); // ENOENT
    }

    #[test]
    fn reply_lock_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyLock = Reply::new(0xdeadbeef, sender);
        reply.error(2); // ENOENT
    }

    #[test]
    fn reply_statfs_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyStatfs = Reply::new(0xdeadbeef, sender);
        reply.error(2); // ENOENT
    }

    #[test]
    fn reply_xattr_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyXattr = Reply::new(0xdeadbeef, sender);
        reply.error(2); // ENOENT
    }

    #[test]
    fn reply_bmap_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyBmap = Reply::new(0xdeadbeef, sender);
        reply.error(2); // ENOENT
    }

    #[test]
    fn reply_directory_plus() {
        let (sender, captured) = CapturingSender::new();
        let mut reply = ReplyDirectoryPlus::new(0xdeadbeef, sender, 4096);
        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr = FileAttr {
            ino: 0xaabb,
            size: 0x22,
            blocks: 0x33,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 0x2,
            uid: 0x66,
            gid: 0x77,
            rdev: 0,
            flags: 0,
            blksize: 0x1000,
        };
        assert!(!reply.add(0xaabb, 1, "hello", &ttl, &attr, 0xaa));
        assert!(!reply.add(0xccdd, 2, "world.rs", &ttl, &attr, 0xbb));
        reply.ok();

        let bytes = captured.lock().unwrap();
        let (len, error, unique) = parse_header(&bytes);
        assert_eq!(unique, 0xdeadbeef, "unique must match request id");
        assert_eq!(error, 0, "error must be 0 for success");
        assert_eq!(
            len as usize,
            bytes.len(),
            "len field must match buffer size"
        );
        // Payload should contain directory entry data (fuse_direntplus headers + names)
        assert!(
            bytes.len() > 16,
            "payload must be non-empty for directory entries"
        );
    }

    #[test]
    fn reply_directory_plus_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyDirectoryPlus = ReplyDirectoryPlus::new(0xdeadbeef, sender, 4096);
        reply.error(2); // ENOENT
    }
    // ── readdirplus reply packing tests ─────────────────────────────────

    fn make_test_attr(ino: u64) -> FileAttr {
        let time = UNIX_EPOCH + Duration::new(60, 0);
        FileAttr {
            ino,
            size: 4096,
            blocks: 8,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }

    fn read_u64_le(buf: &[u8], offset: usize) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&buf[offset..offset + 8]);
        u64::from_le_bytes(bytes)
    }

    fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&buf[offset..offset + 4]);
        u32::from_le_bytes(bytes)
    }

    fn assert_entry_ttls(payload: &[u8], entry_ttl: Duration, attr_ttl: Duration) {
        assert_eq!(read_u64_le(payload, 16), entry_ttl.as_secs());
        assert_eq!(read_u64_le(payload, 24), attr_ttl.as_secs());
        assert_eq!(read_u32_le(payload, 32), entry_ttl.subsec_nanos());
        assert_eq!(read_u32_le(payload, 36), attr_ttl.subsec_nanos());
    }

    #[test]
    fn reply_entry_with_ttls_keeps_entry_cache_when_attrs_uncached() {
        let (sender, captured) = CapturingSender::new();
        let reply: ReplyEntry = Reply::new(0xdeadbeef, sender);
        let entry_ttl = Duration::new(5, 0);
        let attr_ttl = Duration::ZERO;
        let attr = make_test_attr(0x42);

        reply.entry_with_ttls(&entry_ttl, &attr_ttl, &attr, 0x01);

        let bytes = captured.lock().unwrap();
        let payload = &bytes[16..];
        assert_eq!(read_u64_le(payload, 0), 0x42);
        assert_eq!(read_u64_le(payload, 8), 0x01);
        assert_entry_ttls(payload, entry_ttl, attr_ttl);
    }

    #[test]
    fn reply_entry_negative_uses_nodeid_zero_and_entry_ttl() {
        let (sender, captured) = CapturingSender::new();
        let reply: ReplyEntry = Reply::new(0xdeadbeef, sender);
        let entry_ttl = Duration::new(0, 250_000_000);

        reply.negative(&entry_ttl);

        let bytes = captured.lock().unwrap();
        let payload = &bytes[16..];
        assert_eq!(read_u64_le(payload, 0), 0);
        assert_eq!(read_u64_le(payload, 8), 0);
        assert_entry_ttls(payload, entry_ttl, Duration::ZERO);
    }

    #[test]
    fn reply_create_with_ttls_keeps_entry_cache_when_attrs_uncached() {
        let (sender, captured) = CapturingSender::new();
        let reply: ReplyCreate = Reply::new(0xdeadbeef, sender);
        let entry_ttl = Duration::new(5, 0);
        let attr_ttl = Duration::ZERO;
        let attr = make_test_attr(0x55);

        reply.created_with_ttls(&entry_ttl, &attr_ttl, &attr, 0x02, 0xaa, 0);

        let bytes = captured.lock().unwrap();
        let payload = &bytes[16..];
        assert_eq!(read_u64_le(payload, 0), 0x55);
        assert_eq!(read_u64_le(payload, 8), 0x02);
        assert_entry_ttls(payload, entry_ttl, attr_ttl);
    }

    #[test]
    fn reply_directory_plus_add_with_ttls_keeps_entry_cache_when_attrs_uncached() {
        let (sender, captured) = CapturingSender::new();
        let mut reply = ReplyDirectoryPlus::new(0xdeadbeef, sender, 4096);
        let entry_ttl = Duration::new(5, 0);
        let attr_ttl = Duration::ZERO;
        let attr = make_test_attr(0x66);

        assert!(!reply.add_with_ttls(0x66, 1, "cached", &entry_ttl, &attr_ttl, &attr, 0x03));
        reply.ok();

        let bytes = captured.lock().unwrap();
        let payload = &bytes[16..];
        assert_eq!(read_u64_le(payload, 0), 0x66);
        assert_eq!(read_u64_le(payload, 8), 0x03);
        assert_entry_ttls(payload, entry_ttl, attr_ttl);
    }

    #[test]
    fn reply_directory_plus_empty_returns_header_only() {
        let (sender, captured) = CapturingSender::new();
        let reply = ReplyDirectoryPlus::new(0xdeadbeef, sender, 4096);
        reply.ok();

        let bytes = captured.lock().unwrap();
        assert_eq!(
            bytes.len(),
            16,
            "empty readdirplus reply must contain only the FUSE header"
        );
        let (_len, error, _unique) = parse_header(&bytes);
        assert_eq!(error, 0, "empty directory reply must succeed");
    }

    #[test]
    fn reply_directory_plus_single_entry_packs_correct_record() {
        let (sender, captured) = CapturingSender::new();
        let mut reply = ReplyDirectoryPlus::new(0xdeadbeef, sender, 4096);
        let ttl = Duration::new(60, 0);
        let attr = make_test_attr(0x42);
        assert!(
            !reply.add(0x42, 1, "file.txt", &ttl, &attr, 0x01),
            "single entry should fit in a 4K buffer"
        );
        reply.ok();

        let bytes = captured.lock().unwrap();
        let (_len, error, _unique) = parse_header(&bytes);
        assert_eq!(error, 0);
        assert!(bytes.len() > 16, "payload missing after header");
    }

    #[test]
    fn reply_directory_plus_size_truncation_drops_overflowing_entry() {
        let small_buf = 200;
        let (sender, captured) = CapturingSender::new();
        let mut reply = ReplyDirectoryPlus::new(0xdeadbeef, sender, small_buf);
        let ttl = Duration::new(30, 0);
        let attr1 = make_test_attr(0x10);

        let full1 = reply.add(0x10, 1, "hello", &ttl, &attr1, 0x01);
        assert!(!full1, "first entry should fit");

        let attr2 = make_test_attr(0x20);
        let full2 = reply.add(0x20, 2, "world", &ttl, &attr2, 0x02);
        assert!(full2, "second entry should overflow");

        reply.ok();
        let bytes = captured.lock().unwrap();
        let (_len, error, _unique) = parse_header(&bytes);
        assert_eq!(error, 0);
        assert!(bytes.len() > 16, "first entry must be present");
    }

    #[test]
    fn reply_directory_plus_timeout_values_roundtrip() {
        let (sender, captured) = CapturingSender::new();
        let mut reply = ReplyDirectoryPlus::new(0xdeadbeef, sender, 4096);
        let ttl = Duration::new(0x8765, 0x43210000);
        let attr = make_test_attr(0xaa);
        assert!(!reply.add(0xaa, 1, "e", &ttl, &attr, 0x01));
        reply.ok();

        let bytes = captured.lock().unwrap();
        let payload = &bytes[16..];
        let entry_valid = read_u64_le(payload, 16);
        let attr_valid = read_u64_le(payload, 24);
        let entry_valid_nsec = read_u32_le(payload, 32);
        let attr_valid_nsec = read_u32_le(payload, 36);

        assert_eq!(entry_valid, ttl.as_secs());
        assert_eq!(attr_valid, ttl.as_secs());
        assert_eq!(entry_valid_nsec, ttl.subsec_nanos());
        assert_eq!(attr_valid_nsec, ttl.subsec_nanos());
    }

    #[test]
    fn reply_directory_plus_nodeid_and_generation_are_consistent() {
        let (sender, captured) = CapturingSender::new();
        let mut reply = ReplyDirectoryPlus::new(0xdeadbeef, sender, 4096);
        let ttl = Duration::new(10, 0);
        let attr = make_test_attr(0xfeed);
        assert!(!reply.add(0xfeed, 42, "x", &ttl, &attr, 0xabcd));
        reply.ok();

        let bytes = captured.lock().unwrap();
        let payload = &bytes[16..];
        let nodeid = read_u64_le(payload, 0);
        let generation = read_u64_le(payload, 8);

        assert_eq!(nodeid, 0xfeed, "fuse_entry_out.nodeid must match attr.ino");
        assert_eq!(
            generation, 0xabcd,
            "fuse_entry_out.generation must match add() arg"
        );
    }
    impl super::ReplySender for SyncSender<()> {
        fn send(&self, _: &[IoSlice<'_>]) -> std::io::Result<()> {
            self.send(()).unwrap();
            Ok(())
        }
    }

    #[test]
    fn async_reply() {
        let (tx, rx) = sync_channel::<()>(1);
        let reply: ReplyEmpty = Reply::new(0xdeadbeef, tx);
        thread::spawn(move || {
            reply.ok();
        });
        rx.recv().unwrap();
    }

    // ── ReplyBuilder-specific tests ─────────────────────────────────────

    #[test]
    fn reply_builder_none() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let mut builder: ReplyBuilder = Reply::new(0xdeadbeef, sender);
        builder.reply_none();
    }

    #[test]
    fn reply_builder_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xbe, 0xff, 0xff, 0xff, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let mut builder: ReplyBuilder = Reply::new(0xdeadbeef, sender);
        builder.reply_err(66);
    }

    #[test]
    fn reply_builder_ok_with_data() {
        let sender = AssertSender {
            expected: vec![
                0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
            ],
        };
        let mut builder: ReplyBuilder = Reply::new(0xdeadbeef, sender);
        builder.reply_ok(&[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn reply_builder_empty_ok() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let mut builder: ReplyBuilder = Reply::new(0xdeadbeef, sender);
        builder.reply_ok(&[]);
    }

    #[test]
    #[should_panic(expected = "double reply")]
    fn reply_builder_double_reply_panics() {
        let (sender, _captured) = CapturingSender::new();
        let mut builder: ReplyBuilder = Reply::new(0xdeadbeef, sender);
        builder.reply_none();
        builder.reply_none(); // should panic: double reply
    }

    #[test]
    #[should_panic(expected = "errno=0")]
    fn reply_builder_error_zero_panics() {
        let (sender, _captured) = CapturingSender::new();
        let mut builder: ReplyBuilder = Reply::new(0xdeadbeef, sender);
        builder.reply_err(0); // should panic: errno must be non-zero
    }

    #[test]
    fn reply_builder_unique_propagation() {
        let (sender, captured) = CapturingSender::new();
        let mut builder: ReplyBuilder = Reply::new(0xcafebabe, sender);
        builder.reply_none();
        let bytes = captured.lock().unwrap();
        let (len, error, unique) = parse_header(&bytes);
        assert_eq!(unique, 0xcafebabe, "unique must match request id");
        assert_eq!(error, 0, "error must be 0 for success");
        assert_eq!(len, 16, "header-only reply has len=16");
    }

    #[test]
    fn reply_builder_drop_guard_sends_eio() {
        let (sender, captured) = CapturingSender::new();
        {
            let _builder: ReplyBuilder = Reply::new(0xdeadbeef, sender);
            // Drop without sending — should auto-reply EIO
        }
        let bytes = captured.lock().unwrap();
        let (len, error, _unique) = parse_header(&bytes);
        assert_eq!(len, 16);
        assert_eq!(error, -5); // -EIO
    }

    #[test]
    fn reply_builder_raw_delegation() {
        // reply_raw delegates to send_ll_mut for specialized types
        let sender = AssertSender {
            expected: vec![
                0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let mut builder: ReplyBuilder = Reply::new(0xdeadbeef, sender);
        builder.reply_raw(&ll::Response::new_bmap(0x1234));
    }
    #[test]
    fn reply_builder_drop_guard_after_reply_does_not_resend() {
        // Drop after explicit reply should NOT send an extra EIO.
        let (sender, captured) = CapturingSender::new();
        {
            let mut builder: ReplyBuilder = Reply::new(0xfeedface, sender);
            builder.reply_err(42); // explicit reply sent
                                   // builder dropped here — should be a no-op
        }
        let bytes = captured.lock().unwrap();
        let (len, error, unique) = parse_header(&bytes);
        assert_eq!(len, 16, "header-only error reply");
        assert_eq!(error, -42, "error must be the one we set, not EIO");
        assert_eq!(unique, 0xfeedface, "unique must match request id");
    }

    #[test]
    fn reply_builder_ok_large_data_no_panic() {
        // reply_ok with a large (but practical) data payload should succeed.
        // The size assertion (data.len() <= u32::MAX as usize) holds for any
        // allocatable Vec on 64-bit; we verify with 64 KiB.
        let data = vec![0xABu8; 65536];
        let sender = AssertSender {
            expected: {
                let mut exp = vec![];
                exp.extend_from_slice(&(16u32 + 65536u32).to_le_bytes());
                exp.extend_from_slice(&0u32.to_le_bytes()); // error=0
                exp.extend_from_slice(&0xdeadbeefu64.to_le_bytes());
                exp.extend_from_slice(&data);
                exp
            },
        };
        let mut builder: ReplyBuilder = Reply::new(0xdeadbeef, sender);
        builder.reply_ok(&data);
    }

    #[test]
    fn reply_builder_error_negative_errno() {
        // negative errno (non-zero) should be accepted; kernel uses -errno convention.
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let mut builder: ReplyBuilder = Reply::new(0xdeadbeef, sender);
        builder.reply_err(-4); // -EINTR: non-zero, should be accepted
    }
}

//! Filesystem operation request
//!
//! A request represents information about a filesystem operation the kernel driver wants us to
//! perform.
//!
//! TODO: This module is meant to go away soon in favor of `ll::Request`.

use crate::abort::AbortHandle;
use crate::ll::{fuse_abi as abi, Errno, Response};
use crate::trace::{errno_name, opcode_name, ERROR_COUNTERS};
use log::{debug, error, warn};
use std::cell::RefCell;
use std::convert::TryFrom;
#[cfg(feature = "abi-7-28")]
use std::convert::TryInto;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::abort::AbortRegistry;
use crate::channel::ChannelSender;
use crate::ll::Request as _;
#[cfg(feature = "abi-7-21")]
use crate::reply::ReplyDirectoryPlus;
use crate::reply::{Reply, ReplyDirectory, ReplySender};
use crate::session::{Session, SessionACL};
use crate::Filesystem;
use crate::{ll, KernelConfig};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DispatchLane {
    Inline,
    MetaRead,
    NamespaceMutation,
    DirStream,
    FileRead,
    FileWriteback,
    LockWait,
    Maintenance,
}

/// Request data structure
pub struct Request<'a> {
    /// Channel sender for sending the reply
    ch: ChannelSender,
    /// Request raw data
    #[allow(unused)]
    data: &'a [u8],
    /// Abort handle registered for interruptible blocking operations.
    /// Set by the dispatch loop before calling blocking filesystem methods.
    abort_handle: RefCell<Option<AbortHandle>>,
    /// Parsed request
    request: ll::AnyRequest<'a>,
}

impl<'a> std::fmt::Debug for Request<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("ch", &self.ch)
            .field("data_len", &self.data.len())
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

impl<'a> Request<'a> {
    /// Create a new request from the given data
    pub(crate) fn new(ch: ChannelSender, data: &'a [u8]) -> Option<Request<'a>> {
        let request = match ll::AnyRequest::try_from(data) {
            Ok(request) => request,
            Err(err) => {
                error!("{err}");
                return None;
            }
        };

        Some(Self {
            ch,
            data,
            request,
            abort_handle: RefCell::new(None),
        })
    }

    /// Dispatch request to the given filesystem.
    /// This calls the appropriate filesystem operation method for the
    /// request and sends back the returned reply to the kernel
    pub(crate) fn dispatch<FS: Filesystem>(&self, se: &mut Session<FS>) {
        debug!("{}", self.request);
        let unique = self.request.unique();
        let opcode = self.request.opcode();
        let inode: u64 = self.request.nodeid().into();

        // Per-opcode tracing span (gated behind fuse-tracing feature)
        #[cfg(feature = "fuse-tracing")]
        let _span = tracing::span!(
            tracing::Level::DEBUG,
            "FUSE",
            opcode = opcode_name(opcode),
            inode = inode,
        )
        .entered();

        let res = match self.dispatch_req(se) {
            Ok(Some(resp)) => resp,
            Ok(None) => return,
            Err(errno) => {
                // Increment per-opcode error counter and log at WARN level
                ERROR_COUNTERS.increment(opcode);
                warn!(
                    "FUSE {} error: ino={:#x?} errno={} ({})",
                    opcode_name(opcode),
                    inode,
                    i32::from(errno.0),
                    errno_name(i32::from(errno.0)),
                );
                self.request.reply_err(errno)
            }
        }
        .with_iovec(unique, |iov| self.ch.send(iov));

        if let Err(err) = res {
            warn!("Request {unique:?}: Failed to send reply: {err}")
        }
    }

    pub(crate) fn dispatch_lane(&self, initialized: bool, destroyed: bool) -> DispatchLane {
        if !initialized || destroyed {
            return DispatchLane::Inline;
        }
        let Ok(op) = self.request.operation() else {
            return DispatchLane::Inline;
        };
        match op {
            ll::Operation::Lookup(_)
            | ll::Operation::GetAttr(_)
            | ll::Operation::ReadLink(_)
            | ll::Operation::StatFs(_)
            | ll::Operation::GetXAttr(_)
            | ll::Operation::ListXAttr(_)
            | ll::Operation::Access(_)
            | ll::Operation::BMap(_) => DispatchLane::MetaRead,
            #[cfg(feature = "abi-7-30")]
            ll::Operation::Statx(_) => DispatchLane::MetaRead,
            ll::Operation::OpenDir(_)
            | ll::Operation::ReadDir(_)
            | ll::Operation::ReleaseDir(_)
            | ll::Operation::FSyncDir(_) => DispatchLane::DirStream,
            #[cfg(feature = "abi-7-21")]
            ll::Operation::ReadDirPlus(_) => DispatchLane::DirStream,
            ll::Operation::Open(_) | ll::Operation::Read(_) => DispatchLane::FileRead,
            #[cfg(feature = "abi-7-11")]
            ll::Operation::IoCtl(_) => DispatchLane::FileRead,
            #[cfg(feature = "abi-7-11")]
            ll::Operation::Poll(_) => DispatchLane::FileRead,
            #[cfg(feature = "abi-7-24")]
            ll::Operation::Lseek(_) => DispatchLane::FileRead,
            ll::Operation::MkNod(_)
            | ll::Operation::MkDir(_)
            | ll::Operation::Unlink(_)
            | ll::Operation::RmDir(_)
            | ll::Operation::SymLink(_)
            | ll::Operation::Rename(_)
            | ll::Operation::Link(_)
            | ll::Operation::SetXAttr(_)
            | ll::Operation::RemoveXAttr(_)
            | ll::Operation::Create(_)
            | ll::Operation::Exchange(_) => DispatchLane::NamespaceMutation,
            #[cfg(feature = "abi-7-23")]
            ll::Operation::Rename2(_) => DispatchLane::NamespaceMutation,
            ll::Operation::SetAttr(_)
            | ll::Operation::Write(_)
            | ll::Operation::Flush(_)
            | ll::Operation::Release(_)
            | ll::Operation::FSync(_) => DispatchLane::FileWriteback,
            #[cfg(feature = "abi-7-19")]
            ll::Operation::FAllocate(_) => DispatchLane::FileWriteback,
            #[cfg(feature = "abi-7-28")]
            ll::Operation::CopyFileRange(_) => DispatchLane::FileWriteback,
            #[cfg(feature = "abi-7-31")]
            ll::Operation::SyncFs(_) => DispatchLane::FileWriteback,
            ll::Operation::GetLk(_) | ll::Operation::SetLk(_) | ll::Operation::SetLkW(_) => {
                DispatchLane::LockWait
            }
            #[cfg(feature = "abi-7-32")]
            ll::Operation::Flock(_) => DispatchLane::LockWait,
            ll::Operation::Forget(_) => DispatchLane::Maintenance,
            #[cfg(feature = "abi-7-16")]
            ll::Operation::BatchForget(_) => DispatchLane::Maintenance,
            _ => DispatchLane::Inline,
        }
    }

    pub(crate) fn reply_error(&self, errno: Errno) {
        let unique = self.request.unique();
        let res = self
            .request
            .reply_err(errno)
            .with_iovec(unique, |iov| self.ch.send(iov));
        if let Err(err) = res {
            warn!("Request {unique:?}: Failed to send error reply: {err}")
        }
    }

    pub(crate) fn reply_io_error(&self) {
        self.reply_error(Errno::EIO);
    }

    pub(crate) fn dispatch_meta_read_worker<FS: Filesystem>(
        &self,
        filesystem: &Arc<Mutex<FS>>,
        allowed: SessionACL,
        session_owner: u32,
    ) {
        debug!("{}", self.request);
        let unique = self.request.unique();
        let opcode = self.request.opcode();
        let inode: u64 = self.request.nodeid().into();
        let res = match self.dispatch_meta_read_req(filesystem, allowed, session_owner) {
            Ok(Some(resp)) => resp,
            Ok(None) => return,
            Err(errno) => {
                ERROR_COUNTERS.increment(opcode);
                warn!(
                    "FUSE {} error: ino={:#x?} errno={} ({})",
                    opcode_name(opcode),
                    inode,
                    i32::from(errno.0),
                    errno_name(i32::from(errno.0)),
                );
                self.request.reply_err(errno)
            }
        }
        .with_iovec(unique, |iov| self.ch.send(iov));

        if let Err(err) = res {
            warn!("Request {unique:?}: Failed to send reply: {err}")
        }
    }

    pub(crate) fn dispatch_namespace_mutation_worker<FS: Filesystem>(
        &self,
        filesystem: &Arc<Mutex<FS>>,
        allowed: SessionACL,
        session_owner: u32,
    ) {
        debug!("{}", self.request);
        let unique = self.request.unique();
        let opcode = self.request.opcode();
        let inode: u64 = self.request.nodeid().into();
        let res = match self.dispatch_namespace_mutation_req(filesystem, allowed, session_owner) {
            Ok(Some(resp)) => resp,
            Ok(None) => return,
            Err(errno) => {
                ERROR_COUNTERS.increment(opcode);
                warn!(
                    "FUSE {} error: ino={:#x?} errno={} ({})",
                    opcode_name(opcode),
                    inode,
                    i32::from(errno.0),
                    errno_name(i32::from(errno.0)),
                );
                self.request.reply_err(errno)
            }
        }
        .with_iovec(unique, |iov| self.ch.send(iov));

        if let Err(err) = res {
            warn!("Request {unique:?}: Failed to send reply: {err}")
        }
    }

    pub(crate) fn dispatch_dir_stream_worker<FS: Filesystem>(
        &self,
        filesystem: &Arc<Mutex<FS>>,
        allowed: SessionACL,
        session_owner: u32,
    ) {
        debug!("{}", self.request);
        let unique = self.request.unique();
        let opcode = self.request.opcode();
        let inode: u64 = self.request.nodeid().into();
        let res = match self.dispatch_dir_stream_req(filesystem, allowed, session_owner) {
            Ok(Some(resp)) => resp,
            Ok(None) => return,
            Err(errno) => {
                ERROR_COUNTERS.increment(opcode);
                warn!(
                    "FUSE {} error: ino={:#x?} errno={} ({})",
                    opcode_name(opcode),
                    inode,
                    i32::from(errno.0),
                    errno_name(i32::from(errno.0)),
                );
                self.request.reply_err(errno)
            }
        }
        .with_iovec(unique, |iov| self.ch.send(iov));

        if let Err(err) = res {
            warn!("Request {unique:?}: Failed to send reply: {err}")
        }
    }

    pub(crate) fn dispatch_lock_wait_worker<FS: Filesystem>(
        &self,
        filesystem: &Arc<Mutex<FS>>,
        abort_registry: &AbortRegistry,
        allowed: SessionACL,
        session_owner: u32,
    ) {
        debug!("{}", self.request);
        let unique = self.request.unique();
        let opcode = self.request.opcode();
        let inode: u64 = self.request.nodeid().into();
        let res =
            match self.dispatch_lock_wait_req(filesystem, abort_registry, allowed, session_owner) {
                Ok(Some(resp)) => resp,
                Ok(None) => return,
                Err(errno) => {
                    ERROR_COUNTERS.increment(opcode);
                    warn!(
                        "FUSE {} error: ino={:#x?} errno={} ({})",
                        opcode_name(opcode),
                        inode,
                        i32::from(errno.0),
                        errno_name(i32::from(errno.0)),
                    );
                    self.request.reply_err(errno)
                }
            }
            .with_iovec(unique, |iov| self.ch.send(iov));

        if let Err(err) = res {
            warn!("Request {unique:?}: Failed to send reply: {err}")
        }
    }

    pub(crate) fn dispatch_file_read_worker<FS: Filesystem>(
        &self,
        filesystem: &Arc<Mutex<FS>>,
        allowed: SessionACL,
        session_owner: u32,
    ) {
        debug!("{}", self.request);
        let unique = self.request.unique();
        let opcode = self.request.opcode();
        let inode: u64 = self.request.nodeid().into();
        let res = match self.dispatch_file_read_req(filesystem, allowed, session_owner) {
            Ok(Some(resp)) => resp,
            Ok(None) => return,
            Err(errno) => {
                ERROR_COUNTERS.increment(opcode);
                warn!(
                    "FUSE {} error: ino={:#x?} errno={} ({})",
                    opcode_name(opcode),
                    inode,
                    i32::from(errno.0),
                    errno_name(i32::from(errno.0)),
                );
                self.request.reply_err(errno)
            }
        }
        .with_iovec(unique, |iov| self.ch.send(iov));

        if let Err(err) = res {
            warn!("Request {unique:?}: Failed to send reply: {err}")
        }
    }

    pub(crate) fn dispatch_file_writeback_worker<FS: Filesystem>(
        &self,
        filesystem: &Arc<Mutex<FS>>,
        abort_registry: &AbortRegistry,
        allowed: SessionACL,
        session_owner: u32,
    ) {
        debug!("{}", self.request);
        let unique = self.request.unique();
        let opcode = self.request.opcode();
        let inode: u64 = self.request.nodeid().into();
        let res = match self.dispatch_file_writeback_req(
            filesystem,
            abort_registry,
            allowed,
            session_owner,
        ) {
            Ok(Some(resp)) => resp,
            Ok(None) => return,
            Err(errno) => {
                ERROR_COUNTERS.increment(opcode);
                warn!(
                    "FUSE {} error: ino={:#x?} errno={} ({})",
                    opcode_name(opcode),
                    inode,
                    i32::from(errno.0),
                    errno_name(i32::from(errno.0)),
                );
                self.request.reply_err(errno)
            }
        }
        .with_iovec(unique, |iov| self.ch.send(iov));

        if let Err(err) = res {
            warn!("Request {unique:?}: Failed to send reply: {err}")
        }
    }

    pub(crate) fn dispatch_maintenance_worker<FS: Filesystem>(
        &self,
        filesystem: &Arc<Mutex<FS>>,
        allowed: SessionACL,
        session_owner: u32,
    ) {
        debug!("{}", self.request);
        if self.acl_denied(allowed, session_owner) {
            return;
        }
        let Ok(op) = self.request.operation() else {
            return;
        };
        let mut fs = filesystem.lock().expect("filesystem mutex poisoned");
        match op {
            ll::Operation::Forget(x) => {
                fs.forget(self, self.request.nodeid().into(), x.nlookup());
            }
            #[cfg(feature = "abi-7-16")]
            ll::Operation::BatchForget(x) => {
                fs.batch_forget(self, x.nodes());
            }
            _ => {}
        }
    }

    fn dispatch_meta_read_req<FS: Filesystem>(
        &self,
        filesystem: &Arc<Mutex<FS>>,
        allowed: SessionACL,
        session_owner: u32,
    ) -> Result<Option<Response<'_>>, Errno> {
        if self.acl_denied(allowed, session_owner) {
            return Err(Errno::EACCES);
        }
        let op = self.request.operation().map_err(|_| Errno::ENOSYS)?;
        let mut fs = filesystem.lock().expect("filesystem mutex poisoned");
        match op {
            ll::Operation::Lookup(x) => {
                fs.lookup(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::GetAttr(_) => {
                fs.getattr(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::ReadLink(_) => {
                fs.readlink(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::StatFs(_) => {
                fs.statfs(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::GetXAttr(x) => {
                fs.getxattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    x.size_u32(),
                    self.reply(),
                );
            }
            ll::Operation::ListXAttr(x) => {
                fs.listxattr(self, self.request.nodeid().into(), x.size(), self.reply());
            }
            ll::Operation::Access(x) => {
                fs.access(self, self.request.nodeid().into(), x.mask(), self.reply());
            }
            ll::Operation::BMap(x) => {
                fs.bmap(
                    self,
                    self.request.nodeid().into(),
                    x.block_size(),
                    x.block(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-30")]
            ll::Operation::Statx(x) => {
                fs.statx(
                    self,
                    self.request.nodeid().into(),
                    x.sx_flags(),
                    x.sx_mask(),
                    self.reply(),
                );
            }
            _ => return Err(Errno::ENOSYS),
        }
        Ok(None)
    }

    fn dispatch_file_read_req<FS: Filesystem>(
        &self,
        filesystem: &Arc<Mutex<FS>>,
        allowed: SessionACL,
        session_owner: u32,
    ) -> Result<Option<Response<'_>>, Errno> {
        if self.acl_denied(allowed, session_owner) {
            return Err(Errno::EACCES);
        }
        let op = self.request.operation().map_err(|_| Errno::ENOSYS)?;
        let mut fs = filesystem.lock().expect("filesystem mutex poisoned");
        match op {
            ll::Operation::Open(x) => {
                fs.open(self, self.request.nodeid().into(), x.flags(), self.reply());
            }
            ll::Operation::Read(x) => {
                fs.read(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.size(),
                    x.flags(),
                    x.lock_owner().map(|l| l.into()),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-11")]
            ll::Operation::IoCtl(x) => {
                if x.unrestricted() {
                    return Err(Errno::ENOSYS);
                }
                fs.ioctl(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    x.command(),
                    x.in_data(),
                    x.out_size(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-11")]
            ll::Operation::Poll(x) => {
                fs.poll(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.kernel_handle(),
                    x.events(),
                    x.flags(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-24")]
            ll::Operation::Lseek(x) => {
                fs.lseek(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.whence(),
                    self.reply(),
                );
            }
            _ => return Err(Errno::ENOSYS),
        }
        Ok(None)
    }

    fn dispatch_namespace_mutation_req<FS: Filesystem>(
        &self,
        filesystem: &Arc<Mutex<FS>>,
        allowed: SessionACL,
        session_owner: u32,
    ) -> Result<Option<Response<'_>>, Errno> {
        if self.acl_denied(allowed, session_owner) {
            return Err(Errno::EACCES);
        }
        let op = self.request.operation().map_err(|_| Errno::ENOSYS)?;
        let mut fs = filesystem.lock().expect("filesystem mutex poisoned");
        match op {
            ll::Operation::MkNod(x) => {
                fs.mknod(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    x.rdev(),
                    self.reply(),
                );
            }
            ll::Operation::MkDir(x) => {
                fs.mkdir(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    self.reply(),
                );
            }
            ll::Operation::Unlink(x) => {
                fs.unlink(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::RmDir(x) => {
                fs.rmdir(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::SymLink(x) => {
                fs.symlink(
                    self,
                    self.request.nodeid().into(),
                    x.link_name().as_ref(),
                    Path::new(x.target()),
                    self.reply(),
                );
            }
            ll::Operation::Rename(x) => {
                fs.rename(
                    self,
                    self.request.nodeid().into(),
                    x.src().name.as_ref(),
                    x.dest().dir.into(),
                    x.dest().name.as_ref(),
                    0,
                    self.reply(),
                );
            }
            ll::Operation::Link(x) => {
                fs.link(
                    self,
                    x.inode_no().into(),
                    self.request.nodeid().into(),
                    x.dest().name.as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::SetXAttr(x) => {
                fs.setxattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    x.value(),
                    x.flags(),
                    x.position(),
                    self.reply(),
                );
            }
            ll::Operation::RemoveXAttr(x) => {
                fs.removexattr(self, self.request.nodeid().into(), x.name(), self.reply());
            }
            ll::Operation::Create(x) => {
                fs.create(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    x.flags(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-23")]
            ll::Operation::Rename2(x) => {
                fs.rename(
                    self,
                    x.from().dir.into(),
                    x.from().name.as_ref(),
                    x.to().dir.into(),
                    x.to().name.as_ref(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::Exchange(x) => {
                fs.exchange(
                    self,
                    x.from().dir.into(),
                    x.from().name.as_ref(),
                    x.to().dir.into(),
                    x.to().name.as_ref(),
                    x.options(),
                    self.reply(),
                );
            }
            _ => return Err(Errno::ENOSYS),
        }
        Ok(None)
    }

    fn dispatch_file_writeback_req<FS: Filesystem>(
        &self,
        filesystem: &Arc<Mutex<FS>>,
        abort_registry: &AbortRegistry,
        allowed: SessionACL,
        session_owner: u32,
    ) -> Result<Option<Response<'_>>, Errno> {
        if self.acl_denied(allowed, session_owner) {
            return Err(Errno::EACCES);
        }
        let op = self.request.operation().map_err(|_| Errno::ENOSYS)?;
        let mut fs = filesystem.lock().expect("filesystem mutex poisoned");
        match op {
            ll::Operation::SetAttr(x) => {
                fs.setattr(
                    self,
                    self.request.nodeid().into(),
                    x.mode(),
                    x.uid(),
                    x.gid(),
                    x.size(),
                    x.atime(),
                    x.mtime(),
                    x.ctime(),
                    x.file_handle().map(|fh| fh.into()),
                    x.crtime(),
                    x.chgtime(),
                    x.bkuptime(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::Write(x) => {
                fs.write(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.data(),
                    x.write_flags(),
                    x.flags(),
                    x.lock_owner().map(|l| l.into()),
                    self.reply(),
                );
            }
            ll::Operation::Flush(x) => {
                fs.flush(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    self.reply(),
                );
            }
            ll::Operation::Release(x) => {
                fs.release(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    x.lock_owner().map(|x| x.into()),
                    x.flush(),
                    self.reply(),
                );
            }
            ll::Operation::FSync(x) => {
                let unique = self.request.unique().into();
                let handle = abort_registry.register(unique);
                self.attach_abort(handle);
                fs.fsync(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync(),
                    self.reply(),
                );
                abort_registry.remove(unique);
            }
            #[cfg(feature = "abi-7-19")]
            ll::Operation::FAllocate(x) => {
                fs.fallocate(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.len(),
                    x.mode(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-28")]
            ll::Operation::CopyFileRange(x) => {
                let flags: u32 = match x.flags().try_into() {
                    Ok(f) => f,
                    Err(_) => return Err(Errno::EINVAL),
                };
                let (i, o) = (x.src(), x.dest());
                fs.copy_file_range(
                    self,
                    i.inode.into(),
                    i.file_handle.into(),
                    i.offset,
                    o.inode.into(),
                    o.file_handle.into(),
                    o.offset,
                    x.len(),
                    flags,
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-31")]
            ll::Operation::SyncFs(_) => {
                fs.syncfs(self, self.reply());
            }
            _ => return Err(Errno::ENOSYS),
        }
        Ok(None)
    }

    fn dispatch_dir_stream_req<FS: Filesystem>(
        &self,
        filesystem: &Arc<Mutex<FS>>,
        allowed: SessionACL,
        session_owner: u32,
    ) -> Result<Option<Response<'_>>, Errno> {
        if self.acl_denied(allowed, session_owner) {
            return Err(Errno::EACCES);
        }
        let op = self.request.operation().map_err(|_| Errno::ENOSYS)?;
        let mut fs = filesystem.lock().expect("filesystem mutex poisoned");
        match op {
            ll::Operation::OpenDir(x) => {
                fs.opendir(self, self.request.nodeid().into(), x.flags(), self.reply());
            }
            ll::Operation::ReadDir(x) => {
                fs.readdir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    ReplyDirectory::new(
                        self.request.unique().into(),
                        self.ch.clone(),
                        x.size() as usize,
                    ),
                );
            }
            ll::Operation::ReleaseDir(x) => {
                fs.releasedir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::FSyncDir(x) => {
                fs.fsyncdir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-21")]
            ll::Operation::ReadDirPlus(x) => {
                fs.readdirplus(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    ReplyDirectoryPlus::new(
                        self.request.unique().into(),
                        self.ch.clone(),
                        x.size() as usize,
                    ),
                );
            }
            _ => return Err(Errno::ENOSYS),
        }
        Ok(None)
    }

    fn dispatch_lock_wait_req<FS: Filesystem>(
        &self,
        filesystem: &Arc<Mutex<FS>>,
        abort_registry: &AbortRegistry,
        allowed: SessionACL,
        session_owner: u32,
    ) -> Result<Option<Response<'_>>, Errno> {
        if self.acl_denied(allowed, session_owner) {
            return Err(Errno::EACCES);
        }
        let op = self.request.operation().map_err(|_| Errno::ENOSYS)?;
        let mut fs = filesystem.lock().expect("filesystem mutex poisoned");
        match op {
            ll::Operation::GetLk(x) => {
                fs.getlk(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    self.reply(),
                );
            }
            ll::Operation::SetLk(x) => {
                fs.setlk(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lk_flags(),
                    x.lock().pid,
                    false,
                    self.reply(),
                );
            }
            ll::Operation::SetLkW(x) => {
                let unique = self.request.unique().into();
                let handle = abort_registry.register(unique);
                self.attach_abort(handle);
                fs.setlk(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lk_flags(),
                    x.lock().pid,
                    true,
                    self.reply(),
                );
                abort_registry.remove(unique);
            }
            #[cfg(feature = "abi-7-32")]
            ll::Operation::Flock(x) => {
                fs.flock(
                    self,
                    self.request.nodeid().into(),
                    x.fh(),
                    x.owner(),
                    x.typ() as u32,
                    x.lk_flags(),
                    self.reply(),
                );
            }
            _ => return Err(Errno::ENOSYS),
        }
        Ok(None)
    }

    fn acl_denied(&self, allowed: SessionACL, session_owner: u32) -> bool {
        if !((allowed == SessionACL::RootAndOwner
            && self.request.uid() != session_owner
            && self.request.uid() != 0)
            || (allowed == SessionACL::Owner && self.request.uid() != session_owner))
        {
            return false;
        }

        let Ok(op) = self.request.operation() else {
            return true;
        };
        match op {
            ll::Operation::Init(_)
            | ll::Operation::Destroy(_)
            | ll::Operation::Read(_)
            | ll::Operation::ReadDir(_)
            | ll::Operation::Forget(_)
            | ll::Operation::Write(_)
            | ll::Operation::FSync(_)
            | ll::Operation::FSyncDir(_)
            | ll::Operation::Release(_)
            | ll::Operation::ReleaseDir(_)
            | ll::Operation::Flush(_) => false,
            #[cfg(feature = "abi-7-16")]
            ll::Operation::BatchForget(_) => false,
            #[cfg(feature = "abi-7-21")]
            ll::Operation::ReadDirPlus(_) => false,
            _ => true,
        }
    }

    fn dispatch_req<FS: Filesystem>(
        &self,
        se: &mut Session<FS>,
    ) -> Result<Option<Response<'_>>, Errno> {
        let op = self.request.operation().map_err(|_| Errno::ENOSYS)?;
        // Implement allow_root & access check for auto_unmount
        if (se.allowed == SessionACL::RootAndOwner
            && self.request.uid() != se.session_owner
            && self.request.uid() != 0)
            || (se.allowed == SessionACL::Owner && self.request.uid() != se.session_owner)
        {
            #[cfg(feature = "abi-7-21")]
            {
                match op {
                    // Only allow operations that the kernel may issue without a uid set
                    ll::Operation::Init(_)
                    | ll::Operation::Destroy(_)
                    | ll::Operation::Read(_)
                    | ll::Operation::ReadDir(_)
                    | ll::Operation::ReadDirPlus(_)
                    | ll::Operation::BatchForget(_)
                    | ll::Operation::Forget(_)
                    | ll::Operation::Write(_)
                    | ll::Operation::FSync(_)
                    | ll::Operation::FSyncDir(_)
                    | ll::Operation::Release(_)
                    | ll::Operation::ReleaseDir(_) => {}
                    _ => {
                        return Err(Errno::EACCES);
                    }
                }
            }
            #[cfg(all(feature = "abi-7-16", not(feature = "abi-7-21")))]
            {
                match op {
                    // Only allow operations that the kernel may issue without a uid set
                    ll::Operation::Init(_)
                    | ll::Operation::Destroy(_)
                    | ll::Operation::Read(_)
                    | ll::Operation::ReadDir(_)
                    | ll::Operation::BatchForget(_)
                    | ll::Operation::Forget(_)
                    | ll::Operation::Write(_)
                    | ll::Operation::FSync(_)
                    | ll::Operation::FSyncDir(_)
                    | ll::Operation::Release(_)
                    | ll::Operation::ReleaseDir(_) => {}
                    _ => {
                        return Err(Errno::EACCES);
                    }
                }
            }
            #[cfg(not(feature = "abi-7-16"))]
            {
                match op {
                    // Only allow operations that the kernel may issue without a uid set
                    ll::Operation::Init(_)
                    | ll::Operation::Destroy(_)
                    | ll::Operation::Read(_)
                    | ll::Operation::ReadDir(_)
                    | ll::Operation::Forget(_)
                    | ll::Operation::Write(_)
                    | ll::Operation::FSync(_)
                    | ll::Operation::FSyncDir(_)
                    | ll::Operation::Release(_)
                    | ll::Operation::ReleaseDir(_) => {}
                    _ => {
                        return Err(Errno::EACCES);
                    }
                }
            }
        }
        match op {
            // Filesystem initialization
            ll::Operation::Init(x) => {
                // We don't support ABI versions before 7.6
                let v = x.version();
                if v < ll::Version(7, 6) {
                    error!("Unsupported FUSE ABI version {v}");
                    return Err(Errno::EPROTO);
                }
                // Remember ABI version supported by kernel
                se.proto_major = v.major();
                se.proto_minor = v.minor();

                let mut config = KernelConfig::new(x.capabilities(), x.max_readahead());
                // Enable writeback cache if the mount option was set
                #[cfg(feature = "abi-7-23")]
                if se.wants_writeback_cache {
                    config.add_writeback_cache();
                }
                // Call filesystem init method and give it a chance to return an error
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .init(self, &mut config)
                    .map_err(Errno::from_i32)?;

                // Reply with our desired version and settings. If the kernel supports a
                // larger major version, it'll re-send a matching init message. If it
                // supports only lower major versions, we replied with an error above.
                debug!(
                    "INIT response: ABI {}.{}, flags {:#x}, max readahead {}, max write {}",
                    abi::FUSE_KERNEL_VERSION,
                    abi::FUSE_KERNEL_MINOR_VERSION,
                    x.capabilities() & config.requested,
                    config.max_readahead,
                    config.max_write
                );
                se.initialized = true;
                return Ok(Some(x.reply(&config)));
            }
            // Any operation is invalid before initialization
            _ if !se.initialized => {
                warn!("Ignoring FUSE operation before init: {}", self.request);
                return Err(Errno::EIO);
            }
            // Filesystem destroyed
            ll::Operation::Destroy(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .destroy();
                se.destroyed = true;
                return Ok(Some(x.reply()));
            }
            // Any operation is invalid after destroy
            _ if se.destroyed => {
                warn!("Ignoring FUSE operation after destroy: {}", self.request);
                return Err(Errno::EIO);
            }

            ll::Operation::Interrupt(x) => {
                // Signal the abort handle for the targeted request.
                // Per the FUSE protocol, reply with EAGAIN so the kernel
                // can requeue the interrupt if the original request hasn't
                // been dispatched yet.
                let target: u64 = x.unique().into();
                se.signal_abort(target);
                return Err(Errno::EAGAIN);
            }

            ll::Operation::Lookup(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .lookup(
                        self,
                        self.request.nodeid().into(),
                        x.name().as_ref(),
                        self.reply(),
                    );
            }
            ll::Operation::Forget(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .forget(self, self.request.nodeid().into(), x.nlookup()); // no reply
            }
            ll::Operation::GetAttr(_) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .getattr(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::SetAttr(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .setattr(
                        self,
                        self.request.nodeid().into(),
                        x.mode(),
                        x.uid(),
                        x.gid(),
                        x.size(),
                        x.atime(),
                        x.mtime(),
                        x.ctime(),
                        x.file_handle().map(|fh| fh.into()),
                        x.crtime(),
                        x.chgtime(),
                        x.bkuptime(),
                        x.flags(),
                        self.reply(),
                    );
            }
            ll::Operation::ReadLink(_) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .readlink(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::MkNod(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .mknod(
                        self,
                        self.request.nodeid().into(),
                        x.name().as_ref(),
                        x.mode(),
                        x.umask(),
                        x.rdev(),
                        self.reply(),
                    );
            }
            ll::Operation::MkDir(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .mkdir(
                        self,
                        self.request.nodeid().into(),
                        x.name().as_ref(),
                        x.mode(),
                        x.umask(),
                        self.reply(),
                    );
            }
            ll::Operation::Unlink(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .unlink(
                        self,
                        self.request.nodeid().into(),
                        x.name().as_ref(),
                        self.reply(),
                    );
            }
            ll::Operation::RmDir(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .rmdir(
                        self,
                        self.request.nodeid().into(),
                        x.name().as_ref(),
                        self.reply(),
                    );
            }
            ll::Operation::SymLink(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .symlink(
                        self,
                        self.request.nodeid().into(),
                        x.link_name().as_ref(),
                        Path::new(x.target()),
                        self.reply(),
                    );
            }
            ll::Operation::Rename(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .rename(
                        self,
                        self.request.nodeid().into(),
                        x.src().name.as_ref(),
                        x.dest().dir.into(),
                        x.dest().name.as_ref(),
                        0,
                        self.reply(),
                    );
            }
            ll::Operation::Link(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .link(
                        self,
                        x.inode_no().into(),
                        self.request.nodeid().into(),
                        x.dest().name.as_ref(),
                        self.reply(),
                    );
            }
            ll::Operation::Open(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .open(self, self.request.nodeid().into(), x.flags(), self.reply());
            }
            ll::Operation::Read(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .read(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.offset(),
                        x.size(),
                        x.flags(),
                        x.lock_owner().map(|l| l.into()),
                        self.reply(),
                    );
            }
            ll::Operation::Write(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .write(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.offset(),
                        x.data(),
                        x.write_flags(),
                        x.flags(),
                        x.lock_owner().map(|l| l.into()),
                        self.reply(),
                    );
            }
            ll::Operation::Flush(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .flush(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.lock_owner().into(),
                        self.reply(),
                    );
            }
            ll::Operation::Release(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .release(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.flags(),
                        x.lock_owner().map(|x| x.into()),
                        x.flush(),
                        self.reply(),
                    );
            }
            ll::Operation::FSync(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .fsync(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.fdatasync(),
                        self.reply(),
                    );
            }
            ll::Operation::OpenDir(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .opendir(self, self.request.nodeid().into(), x.flags(), self.reply());
            }
            ll::Operation::ReadDir(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .readdir(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.offset(),
                        ReplyDirectory::new(
                            self.request.unique().into(),
                            self.ch.clone(),
                            x.size() as usize,
                        ),
                    );
            }
            ll::Operation::ReleaseDir(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .releasedir(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.flags(),
                        self.reply(),
                    );
            }
            ll::Operation::FSyncDir(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .fsyncdir(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.fdatasync(),
                        self.reply(),
                    );
            }
            ll::Operation::StatFs(_) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .statfs(self, self.request.nodeid().into(), self.reply());
            }
            #[cfg(feature = "abi-7-31")]
            ll::Operation::SyncFs(_) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .syncfs(self, self.reply());
            }
            ll::Operation::SetXAttr(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .setxattr(
                        self,
                        self.request.nodeid().into(),
                        x.name(),
                        x.value(),
                        x.flags(),
                        x.position(),
                        self.reply(),
                    );
            }
            ll::Operation::GetXAttr(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .getxattr(
                        self,
                        self.request.nodeid().into(),
                        x.name(),
                        x.size_u32(),
                        self.reply(),
                    );
            }
            ll::Operation::ListXAttr(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .listxattr(self, self.request.nodeid().into(), x.size(), self.reply());
            }
            ll::Operation::RemoveXAttr(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .removexattr(self, self.request.nodeid().into(), x.name(), self.reply());
            }
            ll::Operation::Access(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .access(self, self.request.nodeid().into(), x.mask(), self.reply());
            }
            ll::Operation::Create(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .create(
                        self,
                        self.request.nodeid().into(),
                        x.name().as_ref(),
                        x.mode(),
                        x.umask(),
                        x.flags(),
                        self.reply(),
                    );
            }
            ll::Operation::GetLk(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .getlk(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.lock_owner().into(),
                        x.lock().range.0,
                        x.lock().range.1,
                        x.lock().typ,
                        x.lock().pid,
                        self.reply(),
                    );
            }
            ll::Operation::SetLk(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .setlk(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.lock_owner().into(),
                        x.lock().range.0,
                        x.lock().range.1,
                        x.lock().typ,
                        x.lk_flags(),
                        x.lock().pid,
                        false,
                        self.reply(),
                    );
            }
            ll::Operation::SetLkW(x) => {
                // Register an abort handle so the kernel can interrupt
                // the blocking lock wait via FUSE_INTERRUPT.
                let unique = self.request.unique().into();
                let handle = se.register_abort(unique);
                self.attach_abort(handle);
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .setlk(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.lock_owner().into(),
                        x.lock().range.0,
                        x.lock().range.1,
                        x.lock().typ,
                        x.lk_flags(),
                        x.lock().pid,
                        true,
                        self.reply(),
                    );
                se.clear_abort(unique);
            }
            ll::Operation::BMap(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .bmap(
                        self,
                        self.request.nodeid().into(),
                        x.block_size(),
                        x.block(),
                        self.reply(),
                    );
            }

            #[cfg(feature = "abi-7-11")]
            ll::Operation::IoCtl(x) => {
                if x.unrestricted() {
                    return Err(Errno::ENOSYS);
                } else {
                    se.filesystem
                        .lock()
                        .expect("filesystem mutex poisoned")
                        .ioctl(
                            self,
                            self.request.nodeid().into(),
                            x.file_handle().into(),
                            x.flags(),
                            x.command(),
                            x.in_data(),
                            x.out_size(),
                            self.reply(),
                        );
                }
            }
            #[cfg(feature = "abi-7-11")]
            ll::Operation::Poll(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .poll(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.kernel_handle(),
                        x.events(),
                        x.flags(),
                        self.reply(),
                    );
            }
            #[cfg(feature = "abi-7-16")]
            ll::Operation::BatchForget(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .batch_forget(self, x.nodes()); // no reply
            }
            #[cfg(feature = "abi-7-19")]
            ll::Operation::FAllocate(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .fallocate(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.offset(),
                        x.len(),
                        x.mode(),
                        self.reply(),
                    );
            }
            #[cfg(feature = "abi-7-21")]
            ll::Operation::ReadDirPlus(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .readdirplus(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.offset(),
                        ReplyDirectoryPlus::new(
                            self.request.unique().into(),
                            self.ch.clone(),
                            x.size() as usize,
                        ),
                    );
            }
            #[cfg(feature = "abi-7-23")]
            ll::Operation::Rename2(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .rename(
                        self,
                        x.from().dir.into(),
                        x.from().name.as_ref(),
                        x.to().dir.into(),
                        x.to().name.as_ref(),
                        x.flags(),
                        self.reply(),
                    );
            }
            #[cfg(feature = "abi-7-24")]
            ll::Operation::Lseek(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .lseek(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.offset(),
                        x.whence(),
                        self.reply(),
                    );
            }
            #[cfg(feature = "abi-7-28")]
            ll::Operation::CopyFileRange(x) => {
                let flags: u32 = match x.flags().try_into() {
                    Ok(f) => f,
                    Err(_) => return Err(Errno::EINVAL),
                };
                let (i, o) = (x.src(), x.dest());
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .copy_file_range(
                        self,
                        i.inode.into(),
                        i.file_handle.into(),
                        i.offset,
                        o.inode.into(),
                        o.file_handle.into(),
                        o.offset,
                        x.len(),
                        flags,
                        self.reply(),
                    );
            }
            #[cfg(feature = "abi-7-30")]
            ll::Operation::Statx(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .statx(
                        self,
                        self.request.nodeid().into(),
                        x.sx_flags(),
                        x.sx_mask(),
                        self.reply(),
                    );
            }
            #[cfg(feature = "abi-7-32")]
            ll::Operation::Flock(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .flock(
                        self,
                        self.request.nodeid().into(),
                        x.fh(),
                        x.owner(),
                        x.typ() as u32,
                        x.lk_flags(),
                        self.reply(),
                    );
            }
            #[cfg(target_os = "macos")]
            ll::Operation::SetVolName(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .setvolname(self, x.name(), self.reply());
            }
            #[cfg(target_os = "macos")]
            ll::Operation::GetXTimes(_) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .getxtimes(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::Exchange(x) => {
                se.filesystem
                    .lock()
                    .expect("filesystem mutex poisoned")
                    .exchange(
                        self,
                        x.from().dir.into(),
                        x.from().name.as_ref(),
                        x.to().dir.into(),
                        x.to().name.as_ref(),
                        x.options(),
                        self.reply(),
                    );
            }
        }
        Ok(None)
    }

    /// Create a reply object for this request that can be passed to the filesystem
    /// implementation and makes sure that a request is replied exactly once
    fn reply<T: Reply>(&self) -> T {
        Reply::new(self.request.unique().into(), self.ch.clone())
    }

    /// Returns the unique identifier of this request
    #[inline]
    pub fn unique(&self) -> u64 {
        self.request.unique().into()
    }

    /// Returns the uid of this request
    #[inline]
    pub fn uid(&self) -> u32 {
        self.request.uid()
    }

    /// Returns the gid of this request
    #[inline]
    pub fn gid(&self) -> u32 {
        self.request.gid()
    }

    /// Returns the pid of this request
    #[inline]
    pub fn pid(&self) -> u32 {
        self.request.pid()
    }

    /// Return a clone of the abort handle for this request, if one was
    /// registered by the dispatch loop before a blocking operation.
    ///
    /// The caller polls [`AbortHandle::is_aborted`] inside wait/retry
    /// loops and returns `EINTR` when signalled.
    #[inline]
    pub fn abort_handle(&self) -> Option<AbortHandle> {
        self.abort_handle.borrow().clone()
    }

    /// Attach an abort handle to this request (called by the dispatch loop).
    pub(crate) fn attach_abort(&self, handle: AbortHandle) {
        *self.abort_handle.borrow_mut() = Some(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::Channel;
    use crate::ll::test::AlignedData;
    use std::fs::File;
    use std::sync::{Arc, Mutex};

    fn dummy_channel() -> crate::channel::ChannelSender {
        Channel::new(Arc::new(File::open("/dev/null").unwrap())).sender()
    }

    /// Valid INIT request bytes (little-endian, len=56, opcode=26),
    /// wrapped in AlignedData for proper alignment.
    const INIT_REQUEST: AlignedData<[u8; 56]> = AlignedData([
        0x38, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, // len, opcode
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // major, minor
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // max_readahead, flags
    ]);

    #[cfg(target_endian = "little")]
    const READ_REQUEST: AlignedData<[u8; 80]> = AlignedData([
        0x50, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, // len=80, opcode=15
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fh=2
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset=4096
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // size=4096, read_flags=0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // lock_owner=0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // flags=0, padding=0
    ]);

    #[cfg(all(target_endian = "little", feature = "abi-7-9"))]
    const WRITE_REQUEST: AlignedData<[u8; 84]> = AlignedData([
        0x54, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // len=84, opcode=16
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fh=2
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset=0
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // size=4, write_flags=0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // lock_owner=0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // flags=0, padding=0
        0xde, 0xad, 0xbe, 0xef,
    ]);

    #[cfg(all(target_endian = "little", not(feature = "abi-7-9")))]
    const WRITE_REQUEST: AlignedData<[u8; 68]> = AlignedData([
        0x44, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // len=68, opcode=16
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fh=2
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset=0
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // size=4, write_flags=0
        0xde, 0xad, 0xbe, 0xef,
    ]);

    #[cfg(target_endian = "little")]
    const OPEN_REQUEST: AlignedData<[u8; 48]> = AlignedData([
        0x30, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, // len=48, opcode=14
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // flags=O_RDONLY, unused=0
    ]);

    #[cfg(all(target_endian = "little", feature = "abi-7-11"))]
    const POLL_REQUEST: AlignedData<[u8; 64]> = AlignedData([
        0x40, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, // len=64, opcode=40
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fh=2
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // kh=3
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // flags=0, events/padding=5
    ]);

    #[cfg(all(target_endian = "little", feature = "abi-7-24"))]
    const LSEEK_REQUEST: AlignedData<[u8; 64]> = AlignedData([
        0x40, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, // len=64, opcode=46
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fh=2
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset=4096
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // whence=SEEK_HOLE, padding=0
    ]);

    #[cfg(target_endian = "little")]
    const FORGET_REQUEST: AlignedData<[u8; 48]> = AlignedData([
        0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // len=48, opcode=2
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // nlookup=3
    ]);

    #[cfg(target_endian = "little")]
    const RENAME_REQUEST: AlignedData<[u8; 56]> = AlignedData([
        0x38, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, // len=56, opcode=12
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x99, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // newdir
        0x6f, 0x6c, 0x64, 0x00, 0x6e, 0x65, 0x77, 0x00, // "old\0new\0"
    ]);

    #[cfg(target_endian = "little")]
    const GETATTR_REQUEST: AlignedData<[u8; 40]> = AlignedData([
        0x28, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // len=40, opcode=3
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
    ]);

    #[cfg(target_endian = "little")]
    const READDIR_REQUEST: AlignedData<[u8; 80]> = AlignedData([
        0x50, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, // len=80, opcode=28
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fh=3
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset=0
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // size=4096
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // lock_owner=0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // flags=0, padding=0
    ]);

    #[cfg(all(target_endian = "little", feature = "abi-7-9"))]
    const GETLK_REQUEST: AlignedData<[u8; 88]> = AlignedData([
        0x58, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, // len=88, opcode=31
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fh=2
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // owner=3
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // lk.start=0
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, // lk.end=i64::MAX
        0x00, 0x00, 0x00, 0x00, 0xad, 0xde, 0x00, 0x00, // lk.typ=0, lk.pid=0xdead
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // lk_flags=0, padding=0
    ]);

    #[test]
    fn request_new_valid_init() {
        let ch = dummy_channel();
        let data = &INIT_REQUEST[..];
        let req = Request::new(ch, data);
        assert!(req.is_some());
        let req = req.unwrap();
        assert_eq!(req.unique(), 0xdead_beef_baad_f00d);
        assert_eq!(req.uid(), 0xc001_d00d);
        assert_eq!(req.gid(), 0xc001_cafe);
        assert_eq!(req.pid(), 0xc0de_ba5e);
    }

    #[test]
    fn request_new_short_header_returns_none() {
        let ch = dummy_channel();
        let data = &INIT_REQUEST[..20];
        let req = Request::new(ch, data);
        assert!(req.is_none(), "Short header should return None");
    }

    #[test]
    fn request_new_mismatched_len_returns_none() {
        let ch = dummy_channel();
        let mut buf = INIT_REQUEST.0.to_vec();
        buf[0] = 0x64; // set len to 100
        let req = Request::new(ch, &buf[..]);
        assert!(req.is_none(), "Mismatched len should return None");
    }

    #[test]
    fn request_new_unknown_opcode_returns_some() {
        let ch = dummy_channel();
        let mut buf = INIT_REQUEST.0.to_vec();
        buf[4] = 0xff; // set opcode to 255
        buf[0] = 0x28;
        buf[1] = 0x00; // len=40
        let req = Request::new(ch, &buf[..40]);
        assert!(
            req.is_some(),
            "Request::new should succeed on valid header even with unknown opcode"
        );
    }

    #[test]
    fn request_new_empty_buffer_returns_none() {
        // Empty buffer now returns None cleanly (ArgumentIterator crash fixed).
        let ch = dummy_channel();
        let req = Request::new(ch, &[]);
        assert!(req.is_none(), "Empty buffer should return None");
    }

    #[test]
    fn request_reply_creates_valid_reply() {
        let ch = dummy_channel();
        let req = Request::new(ch, &INIT_REQUEST[..]).unwrap();
        let _reply: crate::ReplyEmpty = req.reply();
    }

    #[test]
    fn request_unique_uid_gid_pid() {
        let ch = dummy_channel();
        let req = Request::new(ch, &INIT_REQUEST[..]).unwrap();
        assert_eq!(req.unique(), 0xdead_beef_baad_f00d);
        assert_eq!(req.uid(), 0xc001_d00d);
        assert_eq!(req.gid(), 0xc001_cafe);
        assert_eq!(req.pid(), 0xc0de_ba5e);
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn dispatch_lane_keeps_bootstrap_inline_and_defers_steady_state_work() {
        let ch = dummy_channel();
        let init = Request::new(ch.clone(), &INIT_REQUEST[..]).unwrap();
        let open = Request::new(ch.clone(), &OPEN_REQUEST[..]).unwrap();
        let read = Request::new(ch.clone(), &READ_REQUEST[..]).unwrap();
        let write = Request::new(ch.clone(), &WRITE_REQUEST[..]).unwrap();
        let forget = Request::new(ch.clone(), &FORGET_REQUEST[..]).unwrap();
        let rename = Request::new(ch.clone(), &RENAME_REQUEST[..]).unwrap();
        let getattr = Request::new(ch.clone(), &GETATTR_REQUEST[..]).unwrap();
        let readdir = Request::new(ch.clone(), &READDIR_REQUEST[..]).unwrap();
        #[cfg(feature = "abi-7-9")]
        let getlk = Request::new(ch.clone(), &GETLK_REQUEST[..]).unwrap();
        #[cfg(feature = "abi-7-11")]
        let poll = Request::new(ch.clone(), &POLL_REQUEST[..]).unwrap();
        #[cfg(feature = "abi-7-24")]
        let lseek = Request::new(ch, &LSEEK_REQUEST[..]).unwrap();

        assert_eq!(write.dispatch_lane(false, false), DispatchLane::Inline);
        assert_eq!(init.dispatch_lane(true, false), DispatchLane::Inline);
        assert_eq!(getattr.dispatch_lane(true, false), DispatchLane::MetaRead);
        assert_eq!(readdir.dispatch_lane(true, false), DispatchLane::DirStream);
        assert_eq!(open.dispatch_lane(true, false), DispatchLane::FileRead);
        assert_eq!(read.dispatch_lane(true, false), DispatchLane::FileRead);
        assert_eq!(read.dispatch_lane(true, true), DispatchLane::Inline);
        #[cfg(feature = "abi-7-11")]
        assert_eq!(poll.dispatch_lane(true, false), DispatchLane::FileRead);
        #[cfg(feature = "abi-7-24")]
        assert_eq!(lseek.dispatch_lane(true, false), DispatchLane::FileRead);
        assert_eq!(
            write.dispatch_lane(true, false),
            DispatchLane::FileWriteback
        );
        assert_eq!(
            rename.dispatch_lane(true, false),
            DispatchLane::NamespaceMutation
        );
        #[cfg(feature = "abi-7-9")]
        assert_eq!(getlk.dispatch_lane(true, false), DispatchLane::LockWait);
        assert_eq!(forget.dispatch_lane(true, false), DispatchLane::Maintenance);
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn file_writeback_worker_dispatches_owned_write_request() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct WriteSeenFS {
            seen: Arc<AtomicBool>,
        }

        impl Filesystem for WriteSeenFS {
            fn write(
                &mut self,
                _req: &Request<'_>,
                _ino: u64,
                _fh: u64,
                _offset: i64,
                data: &[u8],
                _write_flags: u32,
                _flags: i32,
                _lock_owner: Option<u64>,
                reply: crate::ReplyWrite,
            ) {
                assert_eq!(data, &[0xde, 0xad, 0xbe, 0xef]);
                self.seen.store(true, Ordering::Release);
                reply.written(data.len() as u32);
            }
        }

        let seen = Arc::new(AtomicBool::new(false));
        let filesystem = Arc::new(Mutex::new(WriteSeenFS {
            seen: Arc::clone(&seen),
        }));
        let req = Request::new(dummy_channel(), &WRITE_REQUEST[..]).unwrap();
        req.dispatch_file_writeback_worker(
            &filesystem,
            &AbortRegistry::default(),
            SessionACL::All,
            0,
        );

        assert!(seen.load(Ordering::Acquire));
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn file_read_worker_dispatches_owned_read_request() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct ReadSeenFS {
            seen: Arc<AtomicBool>,
        }

        impl Filesystem for ReadSeenFS {
            fn read(
                &mut self,
                _req: &Request<'_>,
                _ino: u64,
                fh: u64,
                offset: i64,
                size: u32,
                _flags: i32,
                _lock_owner: Option<u64>,
                reply: crate::ReplyData,
            ) {
                assert_eq!(fh, 2);
                assert_eq!(offset, 4096);
                assert_eq!(size, 4096);
                self.seen.store(true, Ordering::Release);
                reply.data(b"read-data");
            }
        }

        let seen = Arc::new(AtomicBool::new(false));
        let filesystem = Arc::new(Mutex::new(ReadSeenFS {
            seen: Arc::clone(&seen),
        }));
        let req = Request::new(dummy_channel(), &READ_REQUEST[..]).unwrap();
        req.dispatch_file_read_worker(&filesystem, SessionACL::All, 0);

        assert!(seen.load(Ordering::Acquire));
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn meta_read_worker_dispatches_owned_getattr_request() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, SystemTime};

        struct GetAttrSeenFS {
            seen: Arc<AtomicBool>,
        }

        impl Filesystem for GetAttrSeenFS {
            fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: crate::ReplyAttr) {
                assert_eq!(ino, 0x1122_3344_5566_7788);
                self.seen.store(true, Ordering::Release);
                let attr = crate::FileAttr {
                    ino,
                    size: 0,
                    blocks: 0,
                    atime: SystemTime::UNIX_EPOCH,
                    mtime: SystemTime::UNIX_EPOCH,
                    ctime: SystemTime::UNIX_EPOCH,
                    crtime: SystemTime::UNIX_EPOCH,
                    kind: crate::FileType::RegularFile,
                    perm: 0o644,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 4096,
                    flags: 0,
                };
                reply.attr(&Duration::ZERO, &attr);
            }
        }

        let seen = Arc::new(AtomicBool::new(false));
        let filesystem = Arc::new(Mutex::new(GetAttrSeenFS {
            seen: Arc::clone(&seen),
        }));
        let req = Request::new(dummy_channel(), &GETATTR_REQUEST[..]).unwrap();
        req.dispatch_meta_read_worker(&filesystem, SessionACL::All, 0);

        assert!(seen.load(Ordering::Acquire));
    }

    #[test]
    #[cfg(all(target_endian = "little", feature = "abi-7-9"))]
    fn lock_wait_worker_dispatches_owned_getlk_request() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct GetLkSeenFS {
            seen: Arc<AtomicBool>,
        }

        impl Filesystem for GetLkSeenFS {
            fn getlk(
                &mut self,
                _req: &Request<'_>,
                ino: u64,
                fh: u64,
                lock_owner: u64,
                start: u64,
                end: u64,
                typ: i32,
                pid: u32,
                reply: crate::ReplyLock,
            ) {
                assert_eq!(ino, 0x1122_3344_5566_7788);
                assert_eq!(fh, 2);
                assert_eq!(lock_owner, 3);
                assert_eq!(start, 0);
                assert_eq!(end, i64::MAX as u64);
                assert_eq!(typ, 0);
                assert_eq!(pid, 0xdead);
                self.seen.store(true, Ordering::Release);
                reply.locked(start, end, typ, pid);
            }
        }

        let seen = Arc::new(AtomicBool::new(false));
        let filesystem = Arc::new(Mutex::new(GetLkSeenFS {
            seen: Arc::clone(&seen),
        }));
        let req = Request::new(dummy_channel(), &GETLK_REQUEST[..]).unwrap();
        req.dispatch_lock_wait_worker(&filesystem, &AbortRegistry::default(), SessionACL::All, 0);

        assert!(seen.load(Ordering::Acquire));
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn namespace_mutation_worker_dispatches_owned_metadata_mutation() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct RenameSeenFS {
            seen: Arc<AtomicBool>,
        }

        impl Filesystem for RenameSeenFS {
            fn rename(
                &mut self,
                _req: &Request<'_>,
                parent: u64,
                name: &std::ffi::OsStr,
                newparent: u64,
                newname: &std::ffi::OsStr,
                flags: u32,
                reply: crate::ReplyEmpty,
            ) {
                assert_eq!(parent, 0x1122_3344_5566_7788);
                assert_eq!(name, std::ffi::OsStr::new("old"));
                assert_eq!(newparent, 0x1122_3344_5566_7799);
                assert_eq!(newname, std::ffi::OsStr::new("new"));
                assert_eq!(flags, 0);
                self.seen.store(true, Ordering::Release);
                reply.ok();
            }
        }

        let seen = Arc::new(AtomicBool::new(false));
        let filesystem = Arc::new(Mutex::new(RenameSeenFS {
            seen: Arc::clone(&seen),
        }));
        let req = Request::new(dummy_channel(), &RENAME_REQUEST[..]).unwrap();
        req.dispatch_namespace_mutation_worker(&filesystem, SessionACL::All, 0);

        assert!(seen.load(Ordering::Acquire));
    }

    // --- Filesystem trait dispatch smoke tests ---
    // Exercise each default trait method through a minimal Request.
    // These verify that the dispatch table arms exist and produce the
    // expected error codes without panicking.

    struct NullFS;
    impl Filesystem for NullFS {}

    #[test]
    fn dispatch_lookup_returns_reply() {
        let mut fs = NullFS;
        fs.lookup(
            &dummy_req(),
            1,
            std::ffi::OsStr::new("x"),
            dummy_reply_entry(),
        );
    }

    #[test]
    fn dispatch_getattr_returns_reply() {
        let mut fs = NullFS;
        fs.getattr(&dummy_req(), 1, dummy_reply_attr());
    }

    #[test]
    fn dispatch_read_returns_reply() {
        let mut fs = NullFS;
        fs.read(&dummy_req(), 1, 0, 0, 4096, 0, None, dummy_reply_data());
    }

    #[test]
    fn dispatch_write_returns_reply() {
        let mut fs = NullFS;
        fs.write(
            &dummy_req(),
            1,
            0,
            0,
            &[0u8; 16],
            0,
            0,
            None,
            dummy_reply_write(),
        );
    }

    #[test]
    fn dispatch_mkdir_returns_reply() {
        let mut fs = NullFS;
        fs.mkdir(
            &dummy_req(),
            1,
            std::ffi::OsStr::new("d"),
            0o755,
            0,
            dummy_reply_entry(),
        );
    }

    #[test]
    fn dispatch_rmdir_returns_reply() {
        let mut fs = NullFS;
        fs.rmdir(
            &dummy_req(),
            1,
            std::ffi::OsStr::new("d"),
            dummy_reply_empty(),
        );
    }

    #[test]
    fn dispatch_unlink_returns_reply() {
        let mut fs = NullFS;
        fs.unlink(
            &dummy_req(),
            1,
            std::ffi::OsStr::new("f"),
            dummy_reply_empty(),
        );
    }

    #[test]
    fn dispatch_rename_returns_reply() {
        let mut fs = NullFS;
        fs.rename(
            &dummy_req(),
            1,
            std::ffi::OsStr::new("a"),
            1,
            std::ffi::OsStr::new("b"),
            0,
            dummy_reply_empty(),
        );
    }

    #[test]
    fn dispatch_fsync_returns_reply() {
        let mut fs = NullFS;
        fs.fsync(&dummy_req(), 1, 0, false, dummy_reply_empty());
    }

    #[test]
    fn dispatch_fsyncdir_returns_reply() {
        let mut fs = NullFS;
        fs.fsyncdir(&dummy_req(), 1, 0, false, dummy_reply_empty());
    }

    #[test]
    fn dispatch_flush_returns_reply() {
        let mut fs = NullFS;
        fs.flush(&dummy_req(), 1, 0, 0, dummy_reply_empty());
    }

    #[test]
    fn dispatch_setattr_returns_reply() {
        let mut fs = NullFS;
        fs.setattr(
            &dummy_req(),
            1,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            dummy_reply_attr(),
        );
    }

    #[test]
    fn dispatch_readlink_returns_reply() {
        let mut fs = NullFS;
        fs.readlink(&dummy_req(), 1, dummy_reply_data());
    }

    #[test]
    fn dispatch_mknod_returns_reply() {
        let mut fs = NullFS;
        fs.mknod(
            &dummy_req(),
            1,
            std::ffi::OsStr::new("dev"),
            0o644,
            0,
            0,
            dummy_reply_entry(),
        );
    }

    #[test]
    fn dispatch_create_returns_reply() {
        let mut fs = NullFS;
        fs.create(
            &dummy_req(),
            1,
            std::ffi::OsStr::new("f"),
            0o644,
            0,
            0,
            dummy_reply_create(),
        );
    }

    #[test]
    fn dispatch_open_returns_reply() {
        let mut fs = NullFS;
        fs.open(&dummy_req(), 1, 0, dummy_reply_open());
    }

    #[test]
    fn dispatch_release_returns_reply() {
        let mut fs = NullFS;
        fs.release(&dummy_req(), 1, 0, 0, None, false, dummy_reply_empty());
    }

    #[test]
    fn dispatch_opendir_returns_reply() {
        let mut fs = NullFS;
        fs.opendir(&dummy_req(), 1, 0, dummy_reply_open());
    }

    #[test]
    fn dispatch_statfs_returns_reply() {
        let mut fs = NullFS;
        fs.statfs(&dummy_req(), 1, dummy_reply_statfs());
    }

    // -- Reply helpers (using the existing dummy_channel) --

    fn dummy_req() -> Request<'static> {
        let ch = dummy_channel();
        Request::new(ch, &INIT_REQUEST[..]).unwrap()
    }

    fn dummy_reply_entry() -> crate::ReplyEntry {
        crate::ReplyEntry::new(0, dummy_channel())
    }
    fn dummy_reply_attr() -> crate::ReplyAttr {
        crate::ReplyAttr::new(0, dummy_channel())
    }
    fn dummy_reply_data() -> crate::ReplyData {
        crate::ReplyData::new(0, dummy_channel())
    }
    fn dummy_reply_empty() -> crate::ReplyEmpty {
        crate::ReplyEmpty::new(0, dummy_channel())
    }
    fn dummy_reply_open() -> crate::ReplyOpen {
        crate::ReplyOpen::new(0, dummy_channel())
    }
    fn dummy_reply_write() -> crate::ReplyWrite {
        crate::ReplyWrite::new(0, dummy_channel())
    }
    fn dummy_reply_create() -> crate::ReplyCreate {
        crate::ReplyCreate::new(0, dummy_channel())
    }
    fn dummy_reply_statfs() -> crate::ReplyStatfs {
        crate::ReplyStatfs::new(0, dummy_channel())
    }

    // --- Feature-gated dispatch tests ---
    // These exercise dispatch paths gated behind abi-7-* features.

    #[test]
    #[cfg(feature = "abi-7-11")]
    fn dispatch_ioctl_returns_reply() {
        let mut fs = NullFS;
        fs.ioctl(&dummy_req(), 1, 0, 0, 0, &[], 0, dummy_reply_ioctl());
    }

    #[test]
    #[cfg(feature = "abi-7-11")]
    fn dispatch_poll_returns_reply() {
        let mut fs = NullFS;
        fs.poll(&dummy_req(), 1, 0, 0, 0, 0, dummy_reply_poll());
    }

    #[test]
    #[cfg(feature = "abi-7-16")]
    fn dispatch_batch_forget_returns_reply() {
        let mut fs = NullFS;
        fs.batch_forget(&dummy_req(), &[]);
    }

    #[test]
    #[cfg(feature = "abi-7-21")]
    fn dispatch_readdirplus_returns_reply() {
        let mut fs = NullFS;
        use crate::ReplyDirectoryPlus;
        let reply = ReplyDirectoryPlus::new(0, dummy_channel(), 4096);
        fs.readdirplus(&dummy_req(), 1, 0, 0, reply);
    }

    #[test]
    #[cfg(feature = "abi-7-24")]
    fn dispatch_lseek_returns_reply() {
        let mut fs = NullFS;
        fs.lseek(&dummy_req(), 1, 0, 0, 0, dummy_reply_lseek());
    }

    #[test]
    #[cfg(feature = "abi-7-28")]
    fn dispatch_copy_file_range_returns_reply() {
        let mut fs = NullFS;
        fs.copy_file_range(&dummy_req(), 1, 0, 0, 2, 0, 0, 4096, 0, dummy_reply_write());
    }

    #[test]
    #[cfg(feature = "abi-7-30")]
    fn dispatch_statx_returns_reply() {
        let mut fs = NullFS;
        fs.statx(&dummy_req(), 1, 0, 0, dummy_reply_statx());
    }

    #[test]
    #[cfg(feature = "abi-7-31")]
    fn dispatch_syncfs_returns_reply() {
        let mut fs = NullFS;
        fs.syncfs(&dummy_req(), dummy_reply_empty());
    }

    #[test]
    #[cfg(feature = "abi-7-32")]
    fn dispatch_flock_returns_reply() {
        let mut fs = NullFS;
        fs.flock(&dummy_req(), 1, 0, 0, 0, 0, dummy_reply_empty());
    }

    // -- Reply helpers for feature-gated types --

    #[cfg(feature = "abi-7-11")]
    fn dummy_reply_ioctl() -> crate::ReplyIoctl {
        crate::ReplyIoctl::new(0, dummy_channel())
    }
    #[cfg(feature = "abi-7-11")]
    fn dummy_reply_poll() -> crate::ReplyPoll {
        crate::ReplyPoll::new(0, dummy_channel())
    }
    #[cfg(feature = "abi-7-24")]
    fn dummy_reply_lseek() -> crate::ReplyLseek {
        crate::ReplyLseek::new(0, dummy_channel())
    }
    #[cfg(feature = "abi-7-30")]
    fn dummy_reply_statx() -> crate::ReplyStatx {
        crate::ReplyStatx::new(0, dummy_channel())
    }
}

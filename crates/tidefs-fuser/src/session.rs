//! Filesystem session
//!
//! A session runs a filesystem implementation while it is being mounted to a specific mount
//! point. A session begins by mounting the filesystem and ends by unmounting it. While the
//! filesystem is mounted, the session loop receives, dispatches and replies to kernel requests
//! for filesystem operations under its mount point.

use libc::{EAGAIN, EINTR, ENODEV, ENOENT};
use log::{info, warn};
use std::convert::TryInto;
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{
    mpsc::{self, SyncSender, TrySendError},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::{io, ops::DerefMut};

use crate::abort::{AbortHandle, AbortRegistry};
use crate::ll::{fuse_abi as abi, Errno, RequestError, Response};
#[cfg(feature = "abi-7-11")]
use crate::notify::Notifier;
use crate::reply::ReplySender;
use crate::request::{DispatchLane, Request};
use crate::Filesystem;
use crate::MountOption;
use crate::{channel::Channel, channel::ChannelSender, mnt::Mount};

/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 16M on macOS
/// and 128k on other systems.
pub const MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

/// Size of the buffer for reading a request from the kernel. Since the kernel may send
/// up to MAX_WRITE_SIZE bytes in a write request, we use that value plus some extra space.
const BUFFER_SIZE: usize = MAX_WRITE_SIZE + 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SessionACL {
    All,
    RootAndOwner,
    Owner,
}

/// The session data structure
#[derive(Debug)]
pub struct Session<FS: Filesystem> {
    /// Filesystem operation implementations
    pub(crate) filesystem: Arc<Mutex<FS>>,
    /// Communication channel to the kernel driver
    ch: Channel,
    /// Handle to the mount.  Dropping this unmounts.
    mount: Arc<Mutex<Option<Mount>>>,
    /// Mount point
    mountpoint: PathBuf,
    /// Whether to restrict access to owner, root + owner, or unrestricted
    /// Used to implement allow_root and auto_unmount
    pub(crate) allowed: SessionACL,
    /// User that launched the fuser process
    pub(crate) session_owner: u32,
    /// FUSE protocol major version
    pub(crate) proto_major: u32,
    /// FUSE protocol minor version
    pub(crate) proto_minor: u32,
    /// True if the filesystem is initialized (init operation done)
    pub(crate) initialized: bool,
    /// True if the filesystem was destroyed (destroy operation done)
    pub(crate) destroyed: bool,
    /// Whether the WritebackCache mount option was set
    #[cfg(feature = "abi-7-23")]
    pub(crate) wants_writeback_cache: bool,
    /// Registry of in-flight abort handles keyed by request unique
    abort_registry: Arc<AbortRegistry>,
    /// Bounded worker lane for small metadata reads.
    meta_read_tx: Option<SyncSender<WorkerJob>>,
    /// Bounded worker lane for namespace mutations.
    namespace_mutation_tx: Option<SyncSender<WorkerJob>>,
    /// Bounded worker lane for directory streams.
    dir_stream_tx: Option<SyncSender<WorkerJob>>,
    /// Bounded worker lane for file reads that may copy bulk data replies.
    file_read_tx: Option<SyncSender<WorkerJob>>,
    /// Bounded worker lane for file data/writeback operations that may block.
    file_writeback_tx: Option<SyncSender<WorkerJob>>,
    /// Bounded worker lane for blocking lock waits.
    lock_wait_tx: Option<SyncSender<WorkerJob>>,
    /// Bounded maintenance lane for no-reply forget traffic.
    maintenance_tx: Option<SyncSender<WorkerJob>>,
    /// Worker thread guards joined before filesystem destroy.
    worker_guards: Vec<JoinHandle<()>>,
}

impl<FS: Filesystem> Session<FS> {
    /// Create a new session by mounting the given filesystem to the given mountpoint
    pub fn new(
        filesystem: FS,
        mountpoint: &Path,
        options: &[MountOption],
    ) -> io::Result<Session<FS>> {
        info!("Mounting {}", mountpoint.display());
        // If AutoUnmount is requested, but not AllowRoot or AllowOther we enforce the ACL
        // ourself and implicitly set AllowOther because fusermount needs allow_root or allow_other
        // to handle the auto_unmount option
        let (file, mount) = if options.contains(&MountOption::AutoUnmount)
            && !(options.contains(&MountOption::AllowRoot)
                || options.contains(&MountOption::AllowOther))
        {
            warn!("Given auto_unmount without allow_root or allow_other; adding allow_other, with userspace permission handling");
            let mut modified_options = options.to_vec();
            modified_options.push(MountOption::AllowOther);
            Mount::new(mountpoint, &modified_options)?
        } else {
            Mount::new(mountpoint, options)?
        };

        let ch = Channel::new(file);
        let allowed = if options.contains(&MountOption::AllowRoot) {
            SessionACL::RootAndOwner
        } else if options.contains(&MountOption::AllowOther) {
            SessionACL::All
        } else {
            SessionACL::Owner
        };
        #[cfg(feature = "abi-7-23")]
        let wants_writeback_cache = options.contains(&MountOption::WritebackCache);
        #[cfg(not(feature = "abi-7-23"))]
        let _ = options; // suppress unused warning

        let session_owner = unsafe { libc::geteuid() };
        Ok(Session {
            filesystem: Arc::new(Mutex::new(filesystem)),
            ch,
            mount: Arc::new(Mutex::new(Some(mount))),
            mountpoint: mountpoint.to_owned(),
            allowed,
            // SAFETY: geteuid() is always safe to call; it returns the effective UID of
            // the calling process with no side effects and no preconditions.
            session_owner,
            #[cfg(feature = "abi-7-23")]
            wants_writeback_cache,
            abort_registry: Arc::new(AbortRegistry::default()),
            meta_read_tx: None,
            namespace_mutation_tx: None,
            dir_stream_tx: None,
            file_read_tx: None,
            file_writeback_tx: None,
            lock_wait_tx: None,
            maintenance_tx: None,
            worker_guards: Vec::new(),
            proto_major: 0,
            proto_minor: 0,
            initialized: false,
            destroyed: false,
        })
    }

    /// Return path of the mounted filesystem
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Run the session loop that receives kernel requests and dispatches them to method
    /// calls into the filesystem. This read-dispatch-loop is non-concurrent to prevent
    /// having multiple buffers (which take up much memory), but the filesystem methods
    /// may run concurrent by spawning threads.
    pub fn run(&mut self) -> io::Result<()> {
        // Buffer for receiving requests from the kernel. Only one is allocated and
        // it is reused immediately after dispatching to conserve memory and allocations.
        let mut buffer = vec![0; BUFFER_SIZE];
        let buf = aligned_sub_buf(
            buffer.deref_mut(),
            std::mem::align_of::<abi::fuse_in_header>(),
        );
        loop {
            // Read the next request from the given channel to kernel driver
            // The kernel driver makes sure that we get exactly one request per read
            match self.ch.receive(buf) {
                Ok(size) => match Request::try_new(self.ch.sender(), &buf[..size]) {
                    // Dispatch request
                    Ok(req) => {
                        let lane = req.dispatch_lane(self.initialized, self.destroyed);
                        match lane {
                            DispatchLane::Inline => req.dispatch(self),
                            _ => {
                                let job = WorkerJob::new(
                                    self.ch.sender(),
                                    buf[..size].to_vec(),
                                    req.unique(),
                                    req.expects_reply(),
                                );
                                match self.enqueue_worker_job(lane, job) {
                                    Ok(()) => {}
                                    Err(WorkerEnqueueError::Missing) => req.dispatch(self),
                                    Err(WorkerEnqueueError::Full)
                                        if lane == DispatchLane::Maintenance =>
                                    {
                                        req.dispatch(self);
                                    }
                                    Err(WorkerEnqueueError::Disconnected)
                                        if lane == DispatchLane::Maintenance =>
                                    {
                                        req.dispatch(self);
                                    }
                                    Err(WorkerEnqueueError::Full) => {
                                        req.reply_error(Errno::EAGAIN);
                                    }
                                    Err(WorkerEnqueueError::Disconnected) => {
                                        req.reply_io_error();
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => {
                        warn!("Invalid FUSE request: {err}");
                        if let Some(errno) = decode_error_errno(&err) {
                            if let Some(unique) = raw_request_unique(&buf[..size]) {
                                reply_request_error(&self.ch.sender(), unique, errno);
                                continue;
                            }
                        }
                        break;
                    }
                },
                Err(err) => match err.raw_os_error() {
                    // Operation interrupted. Accordingly to FUSE, this is safe to retry
                    Some(ENOENT) => continue,
                    // Interrupted system call, retry
                    Some(EINTR) => continue,
                    // Explicitly try again
                    Some(EAGAIN) => continue,
                    // Filesystem was unmounted, quit the loop
                    Some(ENODEV) => break,
                    // Unhandled error
                    _ => return Err(err),
                },
            }
        }
        Ok(())
    }

    /// Register a blocking operation and obtain an [`AbortHandle`].
    ///
    /// The caller should poll `handle.is_aborted()` inside any wait/retry
    /// loop and return `EINTR` when signalled.
    pub fn register_abort(&mut self, unique: u64) -> AbortHandle {
        self.abort_registry.register(unique)
    }

    /// Signal and remove the abort handle for `unique`.
    ///
    /// Called when the kernel delivers FUSE_INTERRUPT for the given
    /// request.  Returns `true` when a handle was found and signalled.
    pub(crate) fn signal_abort(&mut self, unique: u64) -> bool {
        self.abort_registry.signal(unique)
    }

    /// Remove the abort handle for `unique` without signalling.
    pub(crate) fn clear_abort(&mut self, unique: u64) {
        self.abort_registry.remove(unique);
    }

    fn enqueue_worker_job(
        &self,
        lane: DispatchLane,
        job: WorkerJob,
    ) -> Result<(), WorkerEnqueueError> {
        let Some(tx) = (match lane {
            DispatchLane::MetaRead => self.meta_read_tx.as_ref(),
            DispatchLane::NamespaceMutation => self.namespace_mutation_tx.as_ref(),
            DispatchLane::DirStream => self.dir_stream_tx.as_ref(),
            DispatchLane::FileRead => self.file_read_tx.as_ref(),
            DispatchLane::FileWriteback => self.file_writeback_tx.as_ref(),
            DispatchLane::LockWait => self.lock_wait_tx.as_ref(),
            DispatchLane::Maintenance => self.maintenance_tx.as_ref(),
            DispatchLane::Inline => None,
        }) else {
            return Err(WorkerEnqueueError::Missing);
        };

        tx.try_send(job).map_err(|err| match err {
            TrySendError::Full(_) => WorkerEnqueueError::Full,
            TrySendError::Disconnected(_) => WorkerEnqueueError::Disconnected,
        })
    }

    fn start_worker_lanes(&mut self) -> io::Result<()>
    where
        FS: Send + 'static,
    {
        if self.meta_read_tx.is_some()
            || self.namespace_mutation_tx.is_some()
            || self.dir_stream_tx.is_some()
            || self.file_read_tx.is_some()
            || self.file_writeback_tx.is_some()
            || self.lock_wait_tx.is_some()
            || self.maintenance_tx.is_some()
        {
            return Ok(());
        }
        let (meta_read_tx, meta_read_guard) = spawn_worker_lane(
            "fuse-meta-read",
            DispatchLane::MetaRead,
            Arc::clone(&self.filesystem),
            Arc::clone(&self.abort_registry),
            self.allowed.clone(),
            self.session_owner,
        )?;
        let (namespace_mutation_tx, namespace_mutation_guard) = spawn_worker_lane(
            "fuse-namespace-mut",
            DispatchLane::NamespaceMutation,
            Arc::clone(&self.filesystem),
            Arc::clone(&self.abort_registry),
            self.allowed.clone(),
            self.session_owner,
        )?;
        let (dir_stream_tx, dir_stream_guard) = spawn_worker_lane(
            "fuse-dir-stream",
            DispatchLane::DirStream,
            Arc::clone(&self.filesystem),
            Arc::clone(&self.abort_registry),
            self.allowed.clone(),
            self.session_owner,
        )?;
        let (file_read_tx, file_read_guard) = spawn_worker_lane(
            "fuse-file-read",
            DispatchLane::FileRead,
            Arc::clone(&self.filesystem),
            Arc::clone(&self.abort_registry),
            self.allowed.clone(),
            self.session_owner,
        )?;
        let (file_writeback_tx, file_writeback_guard) = spawn_worker_lane(
            "fuse-file-writeback",
            DispatchLane::FileWriteback,
            Arc::clone(&self.filesystem),
            Arc::clone(&self.abort_registry),
            self.allowed.clone(),
            self.session_owner,
        )?;
        let (lock_wait_tx, lock_wait_guard) = spawn_worker_lane(
            "fuse-lock-wait",
            DispatchLane::LockWait,
            Arc::clone(&self.filesystem),
            Arc::clone(&self.abort_registry),
            self.allowed.clone(),
            self.session_owner,
        )?;
        let (maintenance_tx, maintenance_guard) = spawn_worker_lane(
            "fuse-maintenance",
            DispatchLane::Maintenance,
            Arc::clone(&self.filesystem),
            Arc::clone(&self.abort_registry),
            self.allowed.clone(),
            self.session_owner,
        )?;
        self.meta_read_tx = Some(meta_read_tx);
        self.namespace_mutation_tx = Some(namespace_mutation_tx);
        self.dir_stream_tx = Some(dir_stream_tx);
        self.file_read_tx = Some(file_read_tx);
        self.file_writeback_tx = Some(file_writeback_tx);
        self.lock_wait_tx = Some(lock_wait_tx);
        self.maintenance_tx = Some(maintenance_tx);
        self.worker_guards.push(meta_read_guard);
        self.worker_guards.push(namespace_mutation_guard);
        self.worker_guards.push(dir_stream_guard);
        self.worker_guards.push(file_read_guard);
        self.worker_guards.push(file_writeback_guard);
        self.worker_guards.push(lock_wait_guard);
        self.worker_guards.push(maintenance_guard);
        Ok(())
    }

    /// Unmount the filesystem
    /// Safety: Mutex lock on mount handle. Since this is called
    /// from the owning Session, no other thread can poison this lock.
    #[allow(clippy::unwrap_used)]
    pub fn unmount(&mut self) {
        drop(std::mem::take(&mut *self.mount.lock().unwrap()));
    }

    /// Returns an object that can be used to send notifications to the kernel
    #[cfg(feature = "abi-7-11")]
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.ch.sender())
    }
}

fn aligned_sub_buf(buf: &mut [u8], alignment: usize) -> &mut [u8] {
    let off = alignment - (buf.as_ptr() as usize) % alignment;
    if off == alignment {
        buf
    } else {
        &mut buf[off..]
    }
}

impl<FS: 'static + Filesystem + Send> Session<FS> {
    /// Run the session loop in a background thread
    pub fn spawn(self) -> io::Result<BackgroundSession> {
        BackgroundSession::new(self)
    }
}

impl<FS: Filesystem> Drop for Session<FS> {
    fn drop(&mut self) {
        self.meta_read_tx.take();
        self.namespace_mutation_tx.take();
        self.dir_stream_tx.take();
        self.file_read_tx.take();
        self.file_writeback_tx.take();
        self.lock_wait_tx.take();
        self.maintenance_tx.take();
        for guard in self.worker_guards.drain(..) {
            if guard.join().is_err() {
                warn!("FUSE worker thread panicked");
            }
        }
        if !self.destroyed {
            self.filesystem
                .lock()
                .expect("filesystem mutex poisoned")
                .destroy();
            self.destroyed = true;
        }
        info!("Unmounted {}", self.mountpoint().display());
    }
}

struct WorkerJob {
    ch: ChannelSender,
    data: Vec<u8>,
    unique: u64,
    reply_expected: bool,
}

impl WorkerJob {
    fn new(ch: ChannelSender, data: Vec<u8>, unique: u64, reply_expected: bool) -> Self {
        Self {
            ch,
            data,
            unique,
            reply_expected,
        }
    }

    fn reply_error(&self, errno: Errno) {
        if self.reply_expected {
            reply_request_error(&self.ch, self.unique, errno);
        }
    }

    fn reply_decode_error(&self, err: &RequestError) {
        if let Some(errno) = decode_error_errno(err) {
            self.reply_error(errno);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerEnqueueError {
    Missing,
    Full,
    Disconnected,
}

fn spawn_worker_lane<FS: Filesystem + Send + 'static>(
    name: &'static str,
    lane: DispatchLane,
    filesystem: Arc<Mutex<FS>>,
    abort_registry: Arc<AbortRegistry>,
    allowed: SessionACL,
    session_owner: u32,
) -> io::Result<(SyncSender<WorkerJob>, JoinHandle<()>)> {
    const WORKER_QUEUE_DEPTH: usize = 1024;
    let (tx, rx) = mpsc::sync_channel::<WorkerJob>(WORKER_QUEUE_DEPTH);
    let guard = thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            while let Ok(job) = rx.recv() {
                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    dispatch_worker_job(
                        &job,
                        lane,
                        &filesystem,
                        &abort_registry,
                        allowed.clone(),
                        session_owner,
                    );
                }));
                if result.is_err() {
                    warn!(
                        "FUSE {lane:?} worker panicked while handling request {}",
                        job.unique
                    );
                    job.reply_error(Errno::EIO);
                }
            }
        })?;
    Ok((tx, guard))
}

fn dispatch_worker_job<FS: Filesystem>(
    job: &WorkerJob,
    lane: DispatchLane,
    filesystem: &Arc<Mutex<FS>>,
    abort_registry: &AbortRegistry,
    allowed: SessionACL,
    session_owner: u32,
) {
    match Request::try_new(job.ch.clone(), &job.data) {
        Ok(req) => match lane {
            DispatchLane::MetaRead => {
                req.dispatch_meta_read_worker(filesystem, allowed, session_owner)
            }
            DispatchLane::NamespaceMutation => {
                req.dispatch_namespace_mutation_worker(filesystem, allowed, session_owner)
            }
            DispatchLane::DirStream => {
                req.dispatch_dir_stream_worker(filesystem, allowed, session_owner)
            }
            DispatchLane::FileRead => {
                req.dispatch_file_read_worker(filesystem, allowed, session_owner)
            }
            DispatchLane::FileWriteback => req.dispatch_file_writeback_worker(
                filesystem,
                abort_registry,
                allowed,
                session_owner,
            ),
            DispatchLane::LockWait => {
                req.dispatch_lock_wait_worker(filesystem, abort_registry, allowed, session_owner)
            }
            DispatchLane::Maintenance => {
                req.dispatch_maintenance_worker(filesystem, allowed, session_owner)
            }
            DispatchLane::Inline => {}
        },
        Err(err) => {
            warn!("Invalid queued FUSE request {}: {err}", job.unique);
            job.reply_decode_error(&err);
        }
    }
}

fn decode_error_errno(err: &RequestError) -> Option<Errno> {
    match err {
        RequestError::ShortReadHeader(_) => None,
        RequestError::UnknownOperation(_) => Some(Errno::ENOSYS),
        RequestError::ShortRead(_, _) | RequestError::InsufficientData => Some(Errno::EIO),
    }
}

fn raw_request_unique(data: &[u8]) -> Option<u64> {
    let header_len = std::mem::size_of::<abi::fuse_in_header>();
    if data.len() < header_len {
        return None;
    }

    let packet_len = u32::from_ne_bytes(data[0..4].try_into().ok()?) as usize;
    if packet_len < header_len {
        return None;
    }

    Some(u64::from_ne_bytes(data[8..16].try_into().ok()?))
}

fn reply_request_error(ch: &ChannelSender, unique: u64, errno: Errno) {
    let response = Response::new_error(errno);
    if let Err(err) = response.with_iovec(crate::ll::RequestId(unique), |iov| ch.send(iov)) {
        warn!("Request {unique:?}: Failed to send terminal error reply: {err}");
    }
}

/// The background session data structure
pub struct BackgroundSession {
    /// Path of the mounted filesystem
    pub mountpoint: PathBuf,
    /// Thread guard of the background session
    pub guard: JoinHandle<io::Result<()>>,
    /// Object for creating Notifiers for client use
    #[cfg(feature = "abi-7-11")]
    sender: ChannelSender,
    /// Ensures the filesystem is unmounted when the session ends
    _mount: Mount,
}

impl BackgroundSession {
    /// Create a new background session for the given session by running its
    /// session loop in a background thread. If the returned handle is dropped,
    /// the filesystem is unmounted and the given session ends.
    pub fn new<FS: Filesystem + Send + 'static>(
        mut se: Session<FS>,
    ) -> io::Result<BackgroundSession> {
        se.start_worker_lanes()?;
        let mountpoint = se.mountpoint().to_path_buf();
        #[cfg(feature = "abi-7-11")]
        let sender = se.ch.sender();
        // Take the fuse_session, so that we can unmount it
        // Safety: Mutex lock is infallible unless the lock is poisoned by a panic
        // in another thread. Since this is the initialization path, no other
        // thread holds the lock.
        #[allow(clippy::unwrap_used)]
        let mount = std::mem::take(&mut *se.mount.lock().unwrap());
        let mount = mount.ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))?;
        let guard = thread::spawn(move || {
            let mut se = se;
            se.run()
        });
        Ok(BackgroundSession {
            mountpoint,
            guard,
            #[cfg(feature = "abi-7-11")]
            sender,
            _mount: mount,
        })
    }
    /// Unmount the filesystem and join the background thread.
    pub fn join(self) {
        let Self {
            mountpoint: _,
            guard,
            #[cfg(feature = "abi-7-11")]
                sender: _,
            _mount,
        } = self;
        drop(_mount);
        match guard.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!("Background session terminated with error: {e}"),
            Err(_) => warn!("Background session thread panicked"),
        }
    }

    /// Returns an object that can be used to send notifications to the kernel
    #[cfg(feature = "abi-7-11")]
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.sender.clone())
    }
}

// replace with #[derive(Debug)] if Debug ever gets implemented for
// thread_scoped::JoinGuard
impl fmt::Debug for BackgroundSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "BackgroundSession {{ mountpoint: {:?}, guard: JoinGuard<()> }}",
            self.mountpoint
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::io::FromRawFd;

    struct NullFS;
    impl Filesystem for NullFS {}

    fn channel_pair() -> (ChannelSender, File) {
        let mut fds = [0; 2];
        // SAFETY: pipe(2) writes two valid fds into the provided two-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: pipe(2) returned ownership of this read fd to the test.
        let reader = unsafe { File::from_raw_fd(fds[0]) };
        // SAFETY: pipe(2) returned ownership of this write fd to the test.
        let writer = unsafe { File::from_raw_fd(fds[1]) };
        (Channel::new(Arc::new(writer)).sender(), reader)
    }

    fn request_header(len: u32, opcode: u32, unique: u64) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&len.to_ne_bytes());
        data.extend_from_slice(&opcode.to_ne_bytes());
        data.extend_from_slice(&unique.to_ne_bytes());
        data.extend_from_slice(&0x1122_3344_5566_7788u64.to_ne_bytes());
        data.extend_from_slice(&1000u32.to_ne_bytes());
        data.extend_from_slice(&1000u32.to_ne_bytes());
        data.extend_from_slice(&42u32.to_ne_bytes());
        data.extend_from_slice(&0u32.to_ne_bytes());
        data
    }

    fn read_reply_header(mut reader: File) -> (u32, i32, u64) {
        let mut header = [0; 16];
        reader.read_exact(&mut header).unwrap();
        (
            u32::from_ne_bytes(header[0..4].try_into().unwrap()),
            i32::from_ne_bytes(header[4..8].try_into().unwrap()),
            u64::from_ne_bytes(header[8..16].try_into().unwrap()),
        )
    }

    #[test]
    fn raw_request_unique_requires_a_complete_header() {
        assert_eq!(raw_request_unique(&[]), None);
        assert_eq!(raw_request_unique(&request_header(16, 16, 7)), None);
        assert_eq!(raw_request_unique(&request_header(40, 16, 7)), Some(7));
    }

    #[test]
    fn queued_decode_error_replies_to_reply_expected_request() {
        let unique = 0xfeed_face_cafe_beefu64;
        let (sender, reader) = channel_pair();
        let job = WorkerJob::new(
            sender,
            request_header(80, abi::fuse_opcode::FUSE_WRITE as u32, unique),
            unique,
            true,
        );
        let filesystem = Arc::new(Mutex::new(NullFS));

        dispatch_worker_job(
            &job,
            DispatchLane::FileWriteback,
            &filesystem,
            &AbortRegistry::default(),
            SessionACL::All,
            0,
        );

        let (len, error, got_unique) = read_reply_header(reader);
        assert_eq!(len, 16);
        assert_eq!(error, -libc::EIO);
        assert_eq!(got_unique, unique);
    }

    #[test]
    fn no_reply_worker_job_does_not_emit_decode_error_reply() {
        let unique = 0xabba_cafe_0102_0304u64;
        let (sender, mut reader) = channel_pair();
        let job = WorkerJob::new(
            sender,
            request_header(80, abi::fuse_opcode::FUSE_WRITE as u32, unique),
            unique,
            false,
        );

        job.reply_error(Errno::EIO);
        drop(job);
        let mut byte = [0u8; 1];
        assert_eq!(reader.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn reply_request_error_writes_terminal_errno() {
        let unique = 0x1234_5678_9abc_def0u64;
        let (sender, reader) = channel_pair();

        reply_request_error(&sender, unique, Errno::ENOSYS);

        let (len, error, got_unique) = read_reply_header(reader);
        assert_eq!(len, 16);
        assert_eq!(error, -libc::ENOSYS);
        assert_eq!(got_unique, unique);
    }
}

//! Filesystem session
//!
//! A session runs a filesystem implementation while it is being mounted to a specific mount
//! point. A session begins by mounting the filesystem and ends by unmounting it. While the
//! filesystem is mounted, the session loop receives, dispatches and replies to kernel requests
//! for filesystem operations under its mount point.

use libc::{EAGAIN, EINTR, ENODEV, ENOENT};
use log::{info, warn};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{
    mpsc::{self, SyncSender},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::{io, ops::DerefMut};

use crate::abort::{AbortHandle, AbortRegistry};
use crate::ll::fuse_abi as abi;
#[cfg(feature = "abi-7-11")]
use crate::notify::Notifier;
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
    /// Bounded worker lane for file reads that may copy bulk data replies.
    file_read_tx: Option<SyncSender<WorkerJob>>,
    /// Bounded worker lane for file data/writeback operations that may block.
    file_writeback_tx: Option<SyncSender<WorkerJob>>,
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
            file_read_tx: None,
            file_writeback_tx: None,
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
                Ok(size) => match Request::new(self.ch.sender(), &buf[..size]) {
                    // Dispatch request
                    Some(req) => match req.dispatch_lane(self.initialized, self.destroyed) {
                        DispatchLane::Inline => req.dispatch(self),
                        DispatchLane::FileRead if self.file_read_tx.is_some() => {
                            let job = WorkerJob::new(self.ch.sender(), buf[..size].to_vec());
                            if let Some(tx) = &self.file_read_tx {
                                if tx.send(job).is_err() {
                                    req.reply_io_error();
                                }
                            } else {
                                req.reply_io_error();
                            }
                        }
                        DispatchLane::FileWriteback if self.file_writeback_tx.is_some() => {
                            let job = WorkerJob::new(self.ch.sender(), buf[..size].to_vec());
                            if let Some(tx) = &self.file_writeback_tx {
                                if tx.send(job).is_err() {
                                    req.reply_io_error();
                                }
                            } else {
                                req.reply_io_error();
                            }
                        }
                        DispatchLane::Maintenance if self.maintenance_tx.is_some() => {
                            let job = WorkerJob::new(self.ch.sender(), buf[..size].to_vec());
                            if let Some(tx) = &self.maintenance_tx {
                                let _ = tx.send(job);
                            }
                        }
                        DispatchLane::FileRead
                        | DispatchLane::FileWriteback
                        | DispatchLane::Maintenance => req.dispatch(self),
                    },
                    // Quit loop on illegal request
                    None => break,
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

    fn start_worker_lanes(&mut self) -> io::Result<()>
    where
        FS: Send + 'static,
    {
        if self.file_read_tx.is_some()
            || self.file_writeback_tx.is_some()
            || self.maintenance_tx.is_some()
        {
            return Ok(());
        }
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
        let (maintenance_tx, maintenance_guard) = spawn_worker_lane(
            "fuse-maintenance",
            DispatchLane::Maintenance,
            Arc::clone(&self.filesystem),
            Arc::clone(&self.abort_registry),
            self.allowed.clone(),
            self.session_owner,
        )?;
        self.file_read_tx = Some(file_read_tx);
        self.file_writeback_tx = Some(file_writeback_tx);
        self.maintenance_tx = Some(maintenance_tx);
        self.worker_guards.push(file_read_guard);
        self.worker_guards.push(file_writeback_guard);
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
        self.file_read_tx.take();
        self.file_writeback_tx.take();
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
}

impl WorkerJob {
    fn new(ch: ChannelSender, data: Vec<u8>) -> Self {
        Self { ch, data }
    }
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
                if let Some(req) = Request::new(job.ch, &job.data) {
                    match lane {
                        DispatchLane::FileRead => req.dispatch_file_read_worker(
                            &filesystem,
                            allowed.clone(),
                            session_owner,
                        ),
                        DispatchLane::FileWriteback => req.dispatch_file_writeback_worker(
                            &filesystem,
                            &abort_registry,
                            allowed.clone(),
                            session_owner,
                        ),
                        DispatchLane::Maintenance => req.dispatch_maintenance_worker(
                            &filesystem,
                            allowed.clone(),
                            session_owner,
                        ),
                        DispatchLane::Inline => {}
                    }
                }
            }
        })?;
    Ok((tx, guard))
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

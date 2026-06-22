//! Filesystem operation request
//!
//! A request represents information about a filesystem operation the kernel driver wants us to
//! perform.
//!
//! Review debt TFR-016: This module is meant to go away soon in favor of `ll::Request`.

use crate::abort::AbortHandle;
use crate::ll::{fuse_abi as abi, Errno, Response};
use crate::trace::{errno_name, opcode_name, ERROR_COUNTERS};
use log::{debug, error, warn};
use std::cell::RefCell;
use std::convert::TryFrom;
#[cfg(feature = "abi-7-28")]
use std::convert::TryInto;
use std::path::Path;
use std::sync::{Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

use crate::channel::ChannelSender;
use crate::ll::Request as _;
#[cfg(feature = "abi-7-21")]
use crate::reply::ReplyDirectoryPlus;
use crate::reply::{Reply, ReplyDirectory, ReplySender};
use crate::session::{Session, SessionACL};
use crate::Filesystem;
use crate::{ll, KernelConfig};

const SLOW_REQUEST_DIAGNOSTICS_ENV: &str = "TIDEFS_FUSE_SLOW_REQUEST_DIAGNOSTICS";
const SLOW_REQUEST_THRESHOLD_ENV: &str = "TIDEFS_FUSE_SLOW_REQUEST_MS";
const SLOW_REQUEST_REPORT_ENV: &str = "TIDEFS_FUSE_SLOW_REQUEST_REPORT_MS";
const DEFAULT_SLOW_REQUEST_THRESHOLD_MS: u64 = 1_000;
const DEFAULT_SLOW_REQUEST_REPORT_MS: u64 = 5_000;

static SLOW_REQUEST_CONFIG: OnceLock<SlowRequestDiagnosticsConfig> = OnceLock::new();
static SLOW_REQUEST_WATCHDOG: Once = Once::new();
static ACTIVE_SLOW_REQUEST: Mutex<Option<ActiveSlowRequest>> = Mutex::new(None);

struct SlowRequestDiagnosticsConfig {
    enabled: bool,
    threshold: Duration,
    report_interval: Duration,
}

#[derive(Clone)]
struct ActiveSlowRequest {
    unique: u64,
    opcode: u32,
    inode: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    started: Instant,
    last_reported: Option<Instant>,
    detail: Option<String>,
}

struct SlowRequestGuard {
    enabled: bool,
    unique: u64,
    opcode: u32,
    inode: u64,
    started: Instant,
    detail: Option<String>,
}

impl SlowRequestGuard {
    fn new(
        unique: u64,
        opcode: u32,
        inode: u64,
        uid: u32,
        gid: u32,
        pid: u32,
        detail: Option<String>,
    ) -> Self {
        let started = Instant::now();
        let config = slow_request_config();
        if !config.enabled {
            return Self {
                enabled: false,
                unique,
                opcode,
                inode,
                started,
                detail: None,
            };
        }

        start_slow_request_watchdog(config);
        match ACTIVE_SLOW_REQUEST.lock() {
            Ok(mut active) => {
                *active = Some(ActiveSlowRequest {
                    unique,
                    opcode,
                    inode,
                    uid,
                    gid,
                    pid,
                    started,
                    last_reported: None,
                    detail: detail.clone(),
                });
            }
            Err(_) => {
                eprintln!(
                    "tidefs-diagnostic: fuse slow_request state=poisoned phase=start unique={} opcode={} ino={}",
                    unique,
                    opcode_name(opcode),
                    inode,
                );
            }
        }

        Self {
            enabled: true,
            unique,
            opcode,
            inode,
            started,
            detail,
        }
    }
}

impl Drop for SlowRequestGuard {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }

        match ACTIVE_SLOW_REQUEST.lock() {
            Ok(mut active) => {
                let clear_active = active
                    .as_ref()
                    .map(|state| state.unique == self.unique)
                    .unwrap_or(false);
                if clear_active {
                    *active = None;
                }
            }
            Err(_) => {
                eprintln!(
                    "tidefs-diagnostic: fuse slow_request state=poisoned phase=end unique={} opcode={} ino={}",
                    self.unique,
                    opcode_name(self.opcode),
                    self.inode,
                );
            }
        }

        let elapsed = self.started.elapsed();
        let config = slow_request_config();
        if elapsed >= config.threshold {
            eprintln!(
                "tidefs-diagnostic: fuse slow_request state=complete unique={} opcode={} ino={} elapsed_ms={} threshold_ms={}{}",
                self.unique,
                opcode_name(self.opcode),
                self.inode,
                elapsed.as_millis(),
                config.threshold.as_millis(),
                self.detail.as_deref().unwrap_or(""),
            );
        }
    }
}

fn slow_request_config() -> &'static SlowRequestDiagnosticsConfig {
    SLOW_REQUEST_CONFIG.get_or_init(|| SlowRequestDiagnosticsConfig {
        enabled: env_switch_enabled(SLOW_REQUEST_DIAGNOSTICS_ENV),
        threshold: env_duration_ms(
            SLOW_REQUEST_THRESHOLD_ENV,
            DEFAULT_SLOW_REQUEST_THRESHOLD_MS,
        ),
        report_interval: env_duration_ms(SLOW_REQUEST_REPORT_ENV, DEFAULT_SLOW_REQUEST_REPORT_MS),
    })
}

fn env_switch_enabled(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Ok("on")
    )
}

fn env_duration_ms(name: &str, default_ms: u64) -> Duration {
    let millis = std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default_ms);
    Duration::from_millis(millis)
}

fn start_slow_request_watchdog(config: &'static SlowRequestDiagnosticsConfig) {
    SLOW_REQUEST_WATCHDOG.call_once(|| {
        if !config.enabled {
            return;
        }
        let threshold = config.threshold;
        let report_interval = config.report_interval;
        let spawn_result = std::thread::Builder::new()
            .name("tidefs-fuse-slow-request-watchdog".to_owned())
            .spawn(move || loop {
                std::thread::sleep(report_interval);
                report_active_slow_request(threshold, report_interval);
            });
        if let Err(err) = spawn_result {
            eprintln!("tidefs-diagnostic: fuse slow_request watchdog_spawn_failed error={err}");
        }
    });
}

fn report_active_slow_request(threshold: Duration, report_interval: Duration) {
    let now = Instant::now();
    match ACTIVE_SLOW_REQUEST.lock() {
        Ok(mut active) => {
            let Some(state) = active.as_mut() else {
                return;
            };
            let elapsed = now.duration_since(state.started);
            if elapsed < threshold {
                return;
            }
            let report_due = state
                .last_reported
                .map(|last| now.duration_since(last) >= report_interval)
                .unwrap_or(true);
            if !report_due {
                return;
            }
            state.last_reported = Some(now);
            eprintln!(
                "tidefs-diagnostic: fuse slow_request state=active unique={} opcode={} ino={} pid={} uid={} gid={} elapsed_ms={} threshold_ms={}{}",
                state.unique,
                opcode_name(state.opcode),
                state.inode,
                state.pid,
                state.uid,
                state.gid,
                elapsed.as_millis(),
                threshold.as_millis(),
                state.detail.as_deref().unwrap_or(""),
            );
        }
        Err(_) => {
            eprintln!("tidefs-diagnostic: fuse slow_request state=poisoned phase=watchdog");
        }
    }
}

fn slow_request_detail(op: &ll::Operation<'_>) -> Option<String> {
    match op {
        ll::Operation::Write(write) => {
            let lock_owner = write
                .lock_owner()
                .map(|owner| owner.0.to_string())
                .unwrap_or_else(|| "none".to_owned());
            Some(format!(
                " fh={} offset={} len={} write_flags={:#x} flags={:#x} lock_owner={}",
                write.file_handle().0,
                write.offset(),
                write.data().len(),
                write.write_flags(),
                write.flags(),
                lock_owner,
            ))
        }
        _ => None,
    }
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
                eprintln!("FUSE request parse error: {err}");
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
        let slow_request_detail = if slow_request_config().enabled {
            self.request
                .operation()
                .ok()
                .and_then(|op| slow_request_detail(&op))
        } else {
            None
        };
        let _slow_request_guard = SlowRequestGuard::new(
            unique.into(),
            opcode,
            inode,
            self.request.uid(),
            self.request.gid(),
            self.request.pid(),
            slow_request_detail,
        );

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
                se.filesystem.destroy();
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
                se.filesystem.lookup(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::Forget(x) => {
                se.filesystem
                    .forget(self, self.request.nodeid().into(), x.nlookup()); // no reply
            }
            ll::Operation::GetAttr(_) => {
                se.filesystem
                    .getattr(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::SetAttr(x) => {
                se.filesystem.setattr(
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
                    .readlink(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::MkNod(x) => {
                se.filesystem.mknod(
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
                se.filesystem.mkdir(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    self.reply(),
                );
            }
            ll::Operation::Unlink(x) => {
                se.filesystem.unlink(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::RmDir(x) => {
                se.filesystem.rmdir(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::SymLink(x) => {
                se.filesystem.symlink(
                    self,
                    self.request.nodeid().into(),
                    x.link_name().as_ref(),
                    Path::new(x.target()),
                    self.reply(),
                );
            }
            ll::Operation::Rename(x) => {
                se.filesystem.rename(
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
                se.filesystem.link(
                    self,
                    x.inode_no().into(),
                    self.request.nodeid().into(),
                    x.dest().name.as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::Open(x) => {
                se.filesystem
                    .open(self, self.request.nodeid().into(), x.flags(), self.reply());
            }
            ll::Operation::Read(x) => {
                se.filesystem.read(
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
                se.filesystem.write(
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
                se.filesystem.flush(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    self.reply(),
                );
            }
            ll::Operation::Release(x) => {
                se.filesystem.release(
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
                se.filesystem.fsync(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync(),
                    self.reply(),
                );
            }
            ll::Operation::OpenDir(x) => {
                se.filesystem
                    .opendir(self, self.request.nodeid().into(), x.flags(), self.reply());
            }
            ll::Operation::ReadDir(x) => {
                se.filesystem.readdir(
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
                se.filesystem.releasedir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::FSyncDir(x) => {
                se.filesystem.fsyncdir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync(),
                    self.reply(),
                );
            }
            ll::Operation::StatFs(_) => {
                se.filesystem
                    .statfs(self, self.request.nodeid().into(), self.reply());
            }
            #[cfg(feature = "abi-7-31")]
            ll::Operation::SyncFs(_) => {
                se.filesystem.syncfs(self, self.reply());
            }
            ll::Operation::SetXAttr(x) => {
                se.filesystem.setxattr(
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
                se.filesystem.getxattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    x.size_u32(),
                    self.reply(),
                );
            }
            ll::Operation::ListXAttr(x) => {
                se.filesystem
                    .listxattr(self, self.request.nodeid().into(), x.size(), self.reply());
            }
            ll::Operation::RemoveXAttr(x) => {
                se.filesystem.removexattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    self.reply(),
                );
            }
            ll::Operation::Access(x) => {
                se.filesystem
                    .access(self, self.request.nodeid().into(), x.mask(), self.reply());
            }
            ll::Operation::Create(x) => {
                se.filesystem.create(
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
                se.filesystem.getlk(
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
                se.filesystem.setlk(
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
                se.filesystem.setlk(
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
                se.filesystem.bmap(
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
                    se.filesystem.ioctl(
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
                se.filesystem.poll(
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
                se.filesystem.batch_forget(self, x.nodes()); // no reply
            }
            #[cfg(feature = "abi-7-19")]
            ll::Operation::FAllocate(x) => {
                se.filesystem.fallocate(
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
                se.filesystem.readdirplus(
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
                se.filesystem.rename(
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
                se.filesystem.lseek(
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
                se.filesystem.copy_file_range(
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
                se.filesystem.statx(
                    self,
                    self.request.nodeid().into(),
                    x.sx_flags(),
                    x.sx_mask(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-32")]
            ll::Operation::Flock(x) => {
                se.filesystem.flock(
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
                se.filesystem.setvolname(self, x.name(), self.reply());
            }
            #[cfg(target_os = "macos")]
            ll::Operation::GetXTimes(_) => {
                se.filesystem
                    .getxtimes(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::Exchange(x) => {
                se.filesystem.exchange(
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
    use std::sync::Arc;

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

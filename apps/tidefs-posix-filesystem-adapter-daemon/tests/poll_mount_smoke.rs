//! Mounted FUSE integration smoke for poll(2) through the VFS adapter.
//!
//! Covers POLLIN, POLLOUT, combined events, error paths (bad fd, bad mode),
//! and edge cases (zero events, multiple fds).  All regular files on a FUSE
//! mount are immediately readable and writable, so poll(2) returns without
//! blocking.
use std::os::unix::io::AsRawFd;

use std::fs::{self, File, OpenOptions};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_types_vfs_core::RequestCtx;
use tidefs_vfs_engine::VfsEngine;

// ── harness ──────────────────────────────────────────────────────────────

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("tidefs-poll-smoke-{}-{nanos}", std::process::id()))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-poll-smoke".to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::Subtype("tidefs".to_string()),
    ]
}

fn request_ctx() -> RequestCtx {
    let gid = unsafe { libc::getegid() } as u32;
    RequestCtx {
        uid: unsafe { libc::geteuid() } as u32,
        gid,
        pid: std::process::id(),
        umask: 0o022,
        groups: vec![gid],
    }
}

struct MountedVfs {
    root: PathBuf,
    mount: PathBuf,
    session: Option<fuser::BackgroundSession>,
}

impl MountedVfs {
    fn new_with_seed(seed: impl FnOnce(&VfsLocalFileSystem)) -> Self {
        let root = unique_test_root();
        let store = root.join("store");
        let mount = root.join("mnt");
        fs::create_dir_all(&store).expect("create store dir");
        fs::create_dir_all(&mount).expect("create mount dir");

        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem");
        let engine = VfsLocalFileSystem::new(filesystem);
        seed(&engine);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
        let session = fuser::spawn_mount2(adapter, &mount, &mount_options()).expect("mount FUSE");

        Self {
            root,
            mount,
            session: Some(session),
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.mount.join(relative.trim_start_matches('/'))
    }
}

impl Drop for MountedVfs {
    fn drop(&mut self) {
        drop(self.session.take());
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn seed_test_file(engine: &VfsLocalFileSystem, name: &[u8]) {
    let ctx = request_ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    let (_attr, fh) = engine
        .create(root, name, 0o644, 0, &ctx)
        .expect("create poll fixture");
    engine
        .write(&fh, 0, b"hello poll", &ctx)
        .expect("write poll fixture");
}

// ── helpers ───────────────────────────────────────────────────────────────

fn poll_fd(raw_fd: i32, events: i16, timeout_ms: i32) -> std::io::Result<libc::pollfd> {
    let mut pfd = libc::pollfd {
        fd: raw_fd,
        events,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(pfd)
    }
}

// ── tests ─────────────────────────────────────────────────────────────────

#[test]
fn poll_readable_fd_returns_pollin() {
    let mount = MountedVfs::new_with_seed(|engine| seed_test_file(engine, b"pollin.txt"));
    let file = File::open(mount.path("/pollin.txt")).expect("open O_RDONLY");
    let pfd = poll_fd(file.as_raw_fd(), libc::POLLIN, 1000).expect("poll should succeed");
    assert_eq!(
        pfd.revents as u32 & libc::POLLIN as u32,
        libc::POLLIN as u32
    );
}

#[test]
fn poll_writable_fd_returns_pollout() {
    let mount = MountedVfs::new_with_seed(|engine| seed_test_file(engine, b"pollout.txt"));
    let file = OpenOptions::new()
        .write(true)
        .open(mount.path("/pollout.txt"))
        .expect("open O_WRONLY");
    let pfd = poll_fd(file.as_raw_fd(), libc::POLLOUT, 1000).expect("poll should succeed");
    assert_eq!(
        pfd.revents as u32 & libc::POLLOUT as u32,
        libc::POLLOUT as u32
    );
}

#[test]
fn poll_rdwr_fd_returns_pollin_and_pollout() {
    let mount = MountedVfs::new_with_seed(|engine| seed_test_file(engine, b"rdwr.txt"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("/rdwr.txt"))
        .expect("open O_RDWR");
    let events = libc::POLLIN | libc::POLLOUT;
    let pfd = poll_fd(file.as_raw_fd(), events, 1000).expect("poll should succeed");
    assert_eq!(
        pfd.revents as u32 & libc::POLLIN as u32,
        libc::POLLIN as u32
    );
    assert_eq!(
        pfd.revents as u32 & libc::POLLOUT as u32,
        libc::POLLOUT as u32
    );
}

#[test]
fn poll_writeonly_fd_pollin_returns_pollerr() {
    let mount = MountedVfs::new_with_seed(|engine| seed_test_file(engine, b"wo-pollin.txt"));
    let file = OpenOptions::new()
        .write(true)
        .open(mount.path("/wo-pollin.txt"))
        .expect("open O_WRONLY");
    let pfd = poll_fd(file.as_raw_fd(), libc::POLLIN, 1000).expect("poll should succeed");
    // FUSE adapter returns EBADF when requesting read events on a write-only fd
    assert_ne!(
        pfd.revents as u32 & libc::POLLERR as u32,
        0,
        "POLLERR should be set when requesting POLLIN on O_WRONLY fd"
    );
}

#[test]
fn poll_readonly_fd_pollout_returns_pollerr() {
    let mount = MountedVfs::new_with_seed(|engine| seed_test_file(engine, b"ro-pollout.txt"));
    let file = File::open(mount.path("/ro-pollout.txt")).expect("open O_RDONLY");
    let pfd = poll_fd(file.as_raw_fd(), libc::POLLOUT, 1000).expect("poll should succeed");
    // FUSE adapter returns EBADF when requesting write events on a read-only fd
    assert_ne!(
        pfd.revents as u32 & libc::POLLERR as u32,
        0,
        "POLLERR should be set when requesting POLLOUT on O_RDONLY fd"
    );
}

#[test]
fn poll_closed_fd_returns_pollnval() {
    let mount = MountedVfs::new_with_seed(|engine| seed_test_file(engine, b"closed.txt"));
    let file = File::open(mount.path("/closed.txt")).expect("open");
    let raw_fd = file.as_raw_fd();
    drop(file); // close the fd
    let mut pfd = libc::pollfd {
        fd: raw_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
    assert!(ret >= 0, "poll should succeed even with a bad fd");
    assert_ne!(
        pfd.revents as u32 & libc::POLLNVAL as u32,
        0,
        "POLLNVAL should be set for a closed fd"
    );
}

#[test]
fn poll_zero_events_returns_no_revents() {
    let mount = MountedVfs::new_with_seed(|engine| seed_test_file(engine, b"zero.txt"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("/zero.txt"))
        .expect("open O_RDWR");
    let pfd = poll_fd(file.as_raw_fd(), 0, 1000).expect("poll should succeed");
    // A regular file is always ready, but with zero requested events,
    // FUSE may return revents according to open flags or nothing.
    // Either is acceptable; just verify poll doesn't error.
    let error_flags = libc::POLLERR | libc::POLLNVAL | libc::POLLHUP;
    assert_eq!(
        pfd.revents & !error_flags,
        0,
        "no events requested, so no events should be returned (got revents=0x{:x})",
        pfd.revents
    );
}

#[test]
fn poll_multiple_fds_returns_correct_counts() {
    let mount = MountedVfs::new_with_seed(|engine| {
        seed_test_file(engine, b"a.txt");
        seed_test_file(engine, b"b.txt");
    });
    let file_a = File::open(mount.path("/a.txt")).expect("open a");
    let file_b = OpenOptions::new()
        .write(true)
        .open(mount.path("/b.txt"))
        .expect("open b");
    let mut pfds = [
        libc::pollfd {
            fd: file_a.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: file_b.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        },
    ];
    let ret = unsafe { libc::poll(pfds.as_mut_ptr(), 2, 1000) };
    assert!(ret >= 0, "poll should succeed");
    assert_eq!(
        pfds[0].revents as u32 & libc::POLLIN as u32,
        libc::POLLIN as u32,
        "fd 0 (O_RDONLY, POLLIN) should return POLLIN"
    );
    assert_eq!(
        pfds[1].revents as u32 & libc::POLLOUT as u32,
        libc::POLLOUT as u32,
        "fd 1 (O_WRONLY, POLLOUT) should return POLLOUT"
    );
}

#[test]
fn poll_append_fd_returns_pollout() {
    let mount = MountedVfs::new_with_seed(|engine| seed_test_file(engine, b"append.txt"));
    let file = OpenOptions::new()
        .append(true)
        .open(mount.path("/append.txt"))
        .expect("open O_APPEND|O_WRONLY");
    let pfd = poll_fd(file.as_raw_fd(), libc::POLLOUT, 1000).expect("poll should succeed");
    assert_eq!(
        pfd.revents as u32 & libc::POLLOUT as u32,
        libc::POLLOUT as u32
    );
}

#[test]
fn poll_rdwr_fd_pollpri_returns_pollpri() {
    let mount = MountedVfs::new_with_seed(|engine| seed_test_file(engine, b"pollpri.txt"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("/pollpri.txt"))
        .expect("open O_RDWR");
    // POLLPRI is included in POLL_READ_EVENTS and should be returned for readable fds
    let pfd = poll_fd(file.as_raw_fd(), libc::POLLPRI, 1000).expect("poll should succeed");
    assert_eq!(
        pfd.revents as u32 & libc::POLLPRI as u32,
        libc::POLLPRI as u32
    );
}

#[test]
fn poll_live_regular_file_does_not_return_pollhup() {
    let mount = MountedVfs::new_with_seed(|engine| seed_test_file(engine, b"nohup.txt"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("/nohup.txt"))
        .expect("open O_RDWR");
    // POLLHUP is for pipes/sockets where the remote end closes;
    // regular files on FUSE should never set it spuriously.
    let pfd =
        poll_fd(file.as_raw_fd(), libc::POLLIN | libc::POLLHUP, 1000).expect("poll should succeed");
    assert_eq!(
        pfd.revents as u32 & libc::POLLIN as u32,
        libc::POLLIN as u32,
        "POLLIN should be set for a readable fd"
    );
    assert_eq!(
        pfd.revents as u32 & libc::POLLHUP as u32,
        0,
        "POLLHUP should not be set for a live regular file (got revents=0x{:x})",
        pfd.revents
    );
}

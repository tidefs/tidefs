//! FUSE kernel driver communication
//!
//! Raw communication channel to the FUSE kernel driver.

#[cfg(fuser_libfuse2)]
mod fuse2;
#[cfg(any(feature = "libfuse", test))]
mod fuse2_sys;
#[cfg(fuser_libfuse3)]
mod fuse3;
#[cfg(fuser_libfuse3)]
mod fuse3_sys;

#[cfg(not(feature = "libfuse"))]
mod fuse_pure;
pub mod mount_options;

#[cfg(any(feature = "libfuse", test))]
use fuse2_sys::fuse_args;
#[cfg(any(test, not(feature = "libfuse")))]
use std::fs::File;
#[cfg(any(test, not(feature = "libfuse"), not(fuser_libfuse3)))]
use std::io;

#[cfg(any(feature = "libfuse", test))]
use mount_options::{is_driver_mount_option, MountOption};

/// Helper function to provide options as a fuse_args struct
/// (which contains an argc count and an argv pointer)
#[cfg(any(feature = "libfuse", test))]
// The CString::new("rust-fuse") and CString::new("-o") calls use hardcoded
// strings with no NUL bytes, so they are infallible.
#[allow(clippy::unwrap_used)]
fn with_fuse_args<T, F: FnOnce(&fuse_args) -> T>(options: &[MountOption], f: F) -> T {
    use mount_options::option_to_string;
    use std::ffi::CString;

    let mut args = vec![CString::new("rust-fuse").unwrap()]; // hardcoded string, never contains NUL
    for x in options.iter().filter(|x| is_driver_mount_option(x)) {
        // "-o" is hardcoded, never contains NUL
        // Mount options with interior NUL bytes are rejected gracefully
        let opt_str = match CString::new(option_to_string(x)) {
            Ok(s) => s,
            Err(_) => continue, // silently skip malformed options
        };
        args.extend_from_slice(&[CString::new("-o").unwrap(), opt_str]);
    }
    let argptrs: Vec<_> = args.iter().map(|s| s.as_ptr()).collect();
    f(&fuse_args {
        argc: argptrs.len() as i32,
        argv: argptrs.as_ptr(),
        allocated: 0,
    })
}

#[cfg(fuser_libfuse2)]
pub use fuse2::Mount;
#[cfg(fuser_libfuse3)]
pub use fuse3::Mount;
#[cfg(not(feature = "libfuse"))]
pub use fuse_pure::Mount;
#[cfg(not(fuser_libfuse3))]
use std::ffi::CStr;

#[cfg(not(fuser_libfuse3))]
#[inline]
fn libc_umount(mnt: &CStr) -> io::Result<()> {
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    // SAFETY: mnt is a valid null-terminated path string pointing to the
    // FUSE mount point. MNT_FORCE (0) is not used, so this is a normal unmount.
    let r = unsafe { libc::unmount(mnt.as_ptr(), 0) };

    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    // SAFETY: mnt is a valid null-terminated path to the FUSE mount point.
    let r = unsafe { libc::umount(mnt.as_ptr()) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Warning: This will return true if the filesystem has been detached (lazy unmounted), but not
/// yet destroyed by the kernel.
#[cfg(any(test, not(feature = "libfuse")))]
fn is_mounted(fuse_device: &File) -> bool {
    use libc::{poll, pollfd};
    use std::os::unix::prelude::AsRawFd;

    let mut poll_result = pollfd {
        fd: fuse_device.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    loop {
        // SAFETY: poll(2) is safe; poll_result is a live struct on the stack,
        // 1 is the correct nfds count, and timeout 0 is non-blocking.
        let res = unsafe { poll(&mut poll_result, 1, 0) };
        break match res {
            0 => true,
            1 => (poll_result.revents & libc::POLLERR) != 0,
            -1 => {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                } else {
                    // This should never happen. The fd is guaranteed good as `File` owns it.
                    // According to man poll ENOMEM is the only error code unhandled, so we panic
                    // consistent with rust's usual ENOMEM behaviour.
                    panic!("Poll failed with error {}", err)
                }
            }
            _ => unreachable!(),
        };
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{ffi::CStr, mem::ManuallyDrop};

    #[test]
    fn fuse_args() {
        with_fuse_args(
            &[
                MountOption::CUSTOM("foo".into()),
                MountOption::WritebackCache,
                MountOption::CUSTOM("bar".into()),
            ],
            |args| {
                let v: Vec<_> = (0..args.argc)
                    // SAFETY: args.argv is a valid pointer from libfuse; offset(n)
                    // stays within argc bounds (0 <= n < argc). CStr::from_ptr
                    // reads from that pointer, which points to a valid NUL-
                    // terminated string per the libfuse argc/argv contract.
                    .map(|n| unsafe {
                        CStr::from_ptr(*args.argv.offset(n as isize))
                            .to_str()
                            .unwrap()
                    })
                    .collect();
                assert_eq!(*v, ["rust-fuse", "-o", "foo", "-o", "bar"]);
            },
        );
    }

    #[test]
    fn fuse_args_include_atime_policy_options() {
        with_fuse_args(
            &[
                MountOption::Atime,
                MountOption::Relatime,
                MountOption::StrictAtime,
                MountOption::NoAtime,
                MountOption::WritebackCache,
            ],
            |args| {
                let v: Vec<_> = (0..args.argc)
                    // SAFETY: args.argv points at argc valid NUL-terminated
                    // strings owned by with_fuse_args for this callback.
                    .map(|n| unsafe {
                        CStr::from_ptr(*args.argv.offset(n as isize))
                            .to_str()
                            .unwrap()
                    })
                    .collect();
                assert_eq!(
                    *v,
                    [
                        "rust-fuse",
                        "-o",
                        "atime",
                        "-o",
                        "relatime",
                        "-o",
                        "strictatime",
                        "-o",
                        "noatime",
                    ]
                );
            },
        );
    }
    fn cmd_mount() -> String {
        std::str::from_utf8(
            std::process::Command::new("sh")
                .arg("-c")
                .arg("mount | grep fuse")
                .output()
                .unwrap()
                .stdout
                .as_ref(),
        )
        .unwrap()
        .to_owned()
    }

    #[test]
    fn mount_unmount() {
        // Skip when FUSE is not available (e.g. Nix build sandbox, container
        // without /dev/fuse).
        if !std::path::Path::new("/dev/fuse").exists() {
            return;
        }

        // We use ManuallyDrop here to leak the directory on test failure.  We don't
        // want to try and clean up the directory if it's a mountpoint otherwise we'll
        // deadlock.
        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let (file, mount) = Mount::new(tmp.path(), &[]).unwrap();
        let mnt = cmd_mount();
        eprintln!("Our mountpoint: {:?}\nfuse mounts:\n{}", tmp.path(), mnt,);
        assert!(mnt.contains(&*tmp.path().to_string_lossy()));
        assert!(is_mounted(&file));
        drop(mount);
        let mnt = cmd_mount();
        eprintln!("Our mountpoint: {:?}\nfuse mounts:\n{}", tmp.path(), mnt,);

        let detached = !mnt.contains(&*tmp.path().to_string_lossy());
        // Linux supports MNT_DETACH, so we expect unmount to succeed even if the FS
        // is busy.  Other systems don't so the unmount may fail and we will still
        // have the mount listed.  The mount will get cleaned up later.
        #[cfg(target_os = "linux")]
        assert!(detached);

        if detached {
            // We've detached successfully, it's safe to clean up:
            std::mem::ManuallyDrop::<_>::into_inner(tmp);
        }

        // Filesystem may have been lazy unmounted, so we can't assert this:
        // assert!(!is_mounted(&file));
    }
}

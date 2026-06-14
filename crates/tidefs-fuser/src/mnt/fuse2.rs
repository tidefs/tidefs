use super::{fuse2_sys::*, with_fuse_args, MountOption};
use log::warn;
use std::{
    ffi::CString,
    fs::File,
    io,
    os::unix::prelude::{FromRawFd, OsStrExt},
    path::Path,
    sync::Arc,
};

/// Ensures that an os error is never 0/Success
fn ensure_last_os_error() -> io::Error {
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(0) => io::Error::other("Unspecified Error"),
        _ => err,
    }
}

#[derive(Debug)]
pub struct Mount {
    mountpoint: CString,
}
impl Mount {
    pub fn new(mountpoint: &Path, options: &[MountOption]) -> io::Result<(Arc<File>, Mount)> {
        let mountpoint = CString::new(mountpoint.as_os_str().as_bytes()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid mountpoint: {e}"),
            )
        })?;
        with_fuse_args(options, |args| {
            // SAFETY: fuse_mount_compat25 is a C FFI call; mountpoint is a
            // valid null-terminated C string and args is a valid pointer to
            // a fuse_args struct (or null). Returns a raw fd or -1.
            let fd = unsafe { fuse_mount_compat25(mountpoint.as_ptr(), args) };
            if fd < 0 {
                Err(ensure_last_os_error())
            } else {
                // SAFETY: fd was just returned by fuse_mount_compat25 as a
                // valid open file descriptor. Ownership is transferred to File.
                let file = unsafe { File::from_raw_fd(fd) };
                if let Err(err) = super::apply_libfuse_atime_remount(mountpoint.as_c_str(), options)
                {
                    let _ = super::libc_umount(mountpoint.as_c_str());
                    return Err(err);
                }
                Ok((Arc::new(file), Mount { mountpoint }))
            }
        })
    }
}
impl Drop for Mount {
    fn drop(&mut self) {
        use std::io::ErrorKind::PermissionDenied;

        // fuse_unmount_compat22 unfortunately doesn't return a status. Additionally,
        // it attempts to call realpath, which in turn calls into the filesystem. So
        // if the filesystem returns an error, the unmount does not take place, with
        // no indication of the error available to the caller. So we call unmount
        // directly, which is what osxfuse does anyway, since we already converted
        // to the real path when we first mounted.
        if let Err(err) = super::libc_umount(&self.mountpoint) {
            // Linux always returns EPERM for non-root users.  We have to let the
            // library go through the setuid-root "fusermount -u" to unmount.
            if err.kind() == PermissionDenied {
                #[cfg(not(any(
                    target_os = "macos",
                    target_os = "freebsd",
                    target_os = "dragonfly",
                    target_os = "openbsd",
                    target_os = "netbsd"
                )))]
                // SAFETY: mountpoint is a valid null-terminated CStr created
                // during Mount::new; fuse_unmount_compat22 is a libfuse C FFI
                // function requiring only a valid path pointer.
                unsafe {
                    fuse_unmount_compat22(self.mountpoint.as_ptr());
                    return;
                }
            }
            warn!("umount failed with {err:?}");
        }
    }
}

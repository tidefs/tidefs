use super::fuse3_sys::{
    fuse_session_destroy, fuse_session_fd, fuse_session_mount, fuse_session_new,
    fuse_session_unmount,
};
use super::{with_fuse_args, MountOption};
use std::{
    ffi::{c_void, CString},
    fs::File,
    io,
    os::unix::{ffi::OsStrExt, io::FromRawFd},
    path::Path,
    ptr,
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
    fuse_session: *mut c_void,
}
impl Mount {
    pub fn new(mnt: &Path, options: &[MountOption]) -> io::Result<(Arc<File>, Mount)> {
        let mnt = CString::new(mnt.as_os_str().as_bytes()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid mountpoint: {e}"),
            )
        })?;
        with_fuse_args(options, |args| {
            // SAFETY: fuse_session_new is a C FFI call; args is a valid pointer
            // to fuse_args, null op and userdata are valid per libfuse API.
            let fuse_session = unsafe { fuse_session_new(args, ptr::null(), 0, ptr::null_mut()) };
            if fuse_session.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mount = Mount { fuse_session };
            // SAFETY: session is valid (just created), mnt is a valid null-
            // terminated mountpoint path string.
            let result = unsafe { fuse_session_mount(mount.fuse_session, mnt.as_ptr()) };
            if result != 0 {
                return Err(ensure_last_os_error());
            }
            super::apply_libfuse_atime_remount(mnt.as_c_str(), options)?;
            // SAFETY: session is valid and mounted; returns the FUSE fd or -1.
            let fd = unsafe { fuse_session_fd(mount.fuse_session) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // We dup the fd here as the existing fd is owned by the fuse_session, and we
            // don't want it being closed out from under us:
            // SAFETY: dup(2) is safe; fd is a valid open FUSE device fd.
            let fd = unsafe { libc::dup(fd) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd was just returned by dup(2) and is a valid open fd.
            // Ownership is transferred to File.
            let file = unsafe { File::from_raw_fd(fd) };
            Ok((Arc::new(file), mount))
        })
    }
}
impl Drop for Mount {
    fn drop(&mut self) {
        // SAFETY: self.fuse_session is a valid fuse_session pointer created
        // during mount; unmount + destroy is the correct teardown sequence.
        unsafe {
            fuse_session_unmount(self.fuse_session);
            fuse_session_destroy(self.fuse_session);
        }
    }
}
// SAFETY: Mount owns the raw fuse_session pointer; libfuse sessions are
// thread-safe per the FUSE protocol contract. The underlying fuse_session
// is reference-counted internally by libfuse, so sending across threads is safe.
// SAFETY: Mount owns a raw fuse_session pointer. Per the libfuse API
// contract, fuse_session internals are reference-counted and thread-safe,
// so sending the pointer across threads is safe.
unsafe impl Send for Mount {}

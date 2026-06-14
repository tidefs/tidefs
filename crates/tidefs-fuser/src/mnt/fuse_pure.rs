//! Native FFI bindings to libfuse.
//!
//! This is a small set of bindings that are required to mount/unmount FUSE filesystems and
//! open/close a fd to the FUSE kernel driver.

#![warn(missing_debug_implementations)]
#![allow(missing_docs)]

use super::is_mounted;
use super::mount_options::{
    atime_remount_flags, is_fusermount_mount_option, option_group, option_to_flag,
    option_to_string, MountOption, MountOptionGroup,
};
use libc::c_int;
use log::{debug, error};
use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Error, ErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::{mem, ptr};

const FUSERMOUNT_BIN: &str = "fusermount";
const FUSERMOUNT3_BIN: &str = "fusermount3";
const FUSERMOUNT_COMM_ENV: &str = "_FUSE_COMMFD";

#[derive(Debug)]
pub struct Mount {
    mountpoint: CString,
    auto_unmount_socket: Option<UnixStream>,
    fuse_device: Arc<File>,
}
impl Mount {
    pub fn new(mountpoint: &Path, options: &[MountOption]) -> io::Result<(Arc<File>, Mount)> {
        let mountpoint = mountpoint.canonicalize()?;
        let (file, sock) = fuse_mount_pure(mountpoint.as_os_str(), options)?;
        let file = Arc::new(file);
        Ok((
            file.clone(),
            Mount {
                mountpoint: CString::new(mountpoint.as_os_str().as_bytes())?,
                auto_unmount_socket: sock,
                fuse_device: file,
            },
        ))
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        use std::io::ErrorKind::PermissionDenied;
        if !is_mounted(&self.fuse_device) {
            // If the filesystem has already been unmounted, avoid unmounting it again.
            // Unmounting it a second time could cause a race with a newly mounted filesystem
            // living at the same mountpoint
            return;
        }
        if let Some(sock) = mem::take(&mut self.auto_unmount_socket) {
            drop(sock);
            // fusermount in auto-unmount mode, no more work to do.
            return;
        }
        if let Err(err) = super::libc_umount(&self.mountpoint) {
            if err.kind() == PermissionDenied {
                // Linux always returns EPERM for non-root users.  We have to let the
                // library go through the setuid-root "fusermount -u" to unmount.
                fuse_unmount_pure(&self.mountpoint)
            } else {
                error!("Unmount failed: {}", err)
            }
        }
    }
}

fn fuse_mount_pure(
    mountpoint: &OsStr,
    options: &[MountOption],
) -> Result<(File, Option<UnixStream>), io::Error> {
    if options.contains(&MountOption::AutoUnmount) {
        // Auto unmount is only supported via fusermount
        return fuse_mount_fusermount(mountpoint, options);
    }

    let res = fuse_mount_sys(mountpoint, options)?;
    if let Some(file) = res {
        Ok((file, None))
    } else {
        // Retry
        fuse_mount_fusermount(mountpoint, options)
    }
}

// SAFETY: mountpoint is a valid null-terminated CStr; MNT_DETACH is
// a valid flag for umount2(2) with no other safety preconditions.
fn fuse_unmount_pure(mountpoint: &CStr) {
    #[cfg(target_os = "linux")]
    unsafe {
        // SAFETY: mountpoint is a valid null-terminated CStr; MNT_DETACH
        // is a valid umount2 flag. The call has no memory safety
        // preconditions beyond the pointer validity already satisfied.
        let result = libc::umount2(mountpoint.as_ptr(), libc::MNT_DETACH);
        if result == 0 {
            return;
        }
    }
    #[cfg(target_os = "macos")]
    unsafe {
        // SAFETY: mountpoint is a valid null-terminated CStr; MNT_FORCE
        // is a valid unmount flag. No additional safety preconditions.
        let result = libc::unmount(mountpoint.as_ptr(), libc::MNT_FORCE);
        if result == 0 {
            return;
        }
    }

    let mut builder = Command::new(detect_fusermount_bin());
    builder.stdout(Stdio::piped()).stderr(Stdio::piped());
    builder
        .arg("-u")
        .arg("-q")
        .arg("-z")
        .arg("--")
        .arg(OsStr::new(&mountpoint.to_string_lossy().into_owned()));

    if let Ok(output) = builder.output() {
        debug!("fusermount: {}", String::from_utf8_lossy(&output.stdout));
        debug!("fusermount: {}", String::from_utf8_lossy(&output.stderr));
    }
}

fn detect_fusermount_bin() -> String {
    for name in [
        FUSERMOUNT3_BIN.to_string(),
        FUSERMOUNT_BIN.to_string(),
        format!("/bin/{FUSERMOUNT3_BIN}"),
        format!("/bin/{FUSERMOUNT_BIN}"),
    ]
    .iter()
    {
        if Command::new(name).arg("-h").output().is_ok() {
            return name.to_string();
        }
    }
    // Default to fusermount3
    FUSERMOUNT3_BIN.to_string()
}

fn receive_fusermount_message(socket: &UnixStream) -> Result<File, Error> {
    let mut io_vec_buf = [0u8];
    let mut io_vec = libc::iovec {
        iov_base: io_vec_buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: io_vec_buf.len(),
    };
    // SAFETY: CMSG_SPACE is a pure C macro that computes buffer size from
    // a known type (c_int); it has no side effects or pointer dependencies.
    // SAFETY: CMSG_SPACE is a pure C macro computing buffer size from a
    // known type (c_int); has no side effects or pointer dependencies.
    let cmsg_buffer_len = unsafe { libc::CMSG_SPACE(mem::size_of::<c_int>() as libc::c_uint) };
    let mut cmsg_buffer = vec![0u8; cmsg_buffer_len as usize];
    let mut message: libc::msghdr;
    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    {
        message = libc::msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut io_vec,
            msg_iovlen: 1,
            msg_control: cmsg_buffer.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: cmsg_buffer.len(),
            msg_flags: 0,
        };
    }
    #[cfg(all(target_os = "linux", target_env = "musl"))]
    {
        // SAFETY: libc::msghdr is a C struct of integer/pointer fields;
        // zero-initialization via MaybeUninit::zeroed() is valid because
        // every bit pattern is valid for integers and pointers (null is
        // valid). All fields are overwritten immediately below.
        // SAFETY: libc::msghdr is a C struct of integer/pointer fields;
        // zero-initialization via MaybeUninit::zeroed() is valid because every
        // bit pattern is valid for integers and pointers. All fields are
        // overwritten immediately below, so no UB from uninitialized reads.
        message = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        message.msg_name = ptr::null_mut();
        message.msg_namelen = 0;
        message.msg_iov = &mut io_vec;
        message.msg_iovlen = 1;
        message.msg_control = (&mut cmsg_buffer).as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = cmsg_buffer.len() as u32;
        message.msg_flags = 0;
    }
    #[cfg(target_os = "macos")]
    {
        message = libc::msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut io_vec,
            msg_iovlen: 1,
            msg_control: (&mut cmsg_buffer).as_mut_ptr() as *mut libc::c_void,
            msg_controllen: cmsg_buffer.len() as u32,
            msg_flags: 0,
        };
    }

    let mut result;
    loop {
        // SAFETY: recvmsg is a C FFI call; socket is a valid open fd,
        // message is a properly initialized msghdr on the stack with
        // iovec and control buffer correctly set up. flags=0 means
        // no special behavior.
        unsafe {
            result = libc::recvmsg(socket.as_raw_fd(), &mut message, 0);
        }
        if result != -1 {
            break;
        }
        let err = Error::last_os_error();
        if err.kind() != ErrorKind::Interrupted {
            return Err(err);
        }
    }
    if result == 0 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "Unexpected EOF reading from fusermount",
        ));
    }

    // SAFETY: CMSG_FIRSTHDR and CMSG_DATA are macros operating on the
    // message returned by a successful recvmsg call. The message contains
    // a valid control-message buffer with a file descriptor passed via
    // SCM_RIGHTS. Dereferencing the fd pointer is safe because CMSG_DATA
    // returns a pointer into the validated control buffer.
    // SAFETY: CMSG_FIRSTHDR and CMSG_DATA are macros operating on a message
    // returned by a successful recvmsg call. The message contains a valid
    // control-message buffer. CMSG_DATA returns a pointer into the validated
    // buffer, so dereferencing the fd is safe.
    unsafe {
        let control_msg = libc::CMSG_FIRSTHDR(&message);
        if (*control_msg).cmsg_type != libc::SCM_RIGHTS {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Unknown control message from fusermount: {}",
                    (*control_msg).cmsg_type
                ),
            ));
        }
        let fd_data = libc::CMSG_DATA(control_msg);

        let fd = *(fd_data as *const c_int);
        if fd < 0 {
            Err(ErrorKind::InvalidData.into())
        } else {
            Ok(File::from_raw_fd(fd))
        }
    }
}

fn fuse_mount_fusermount(
    mountpoint: &OsStr,
    options: &[MountOption],
) -> Result<(File, Option<UnixStream>), Error> {
    let (child_socket, receive_socket) = UnixStream::pair()?;

    // SAFETY: fcntl F_SETFD/0 clears close-on-exec on a valid open fd;
    // this is a standard POSIX operation with no UB risk.
    // SAFETY: fcntl F_SETFD/0 clears close-on-exec on a valid open fd;
    // this is a standard POSIX operation with no UB risk.
    unsafe {
        libc::fcntl(child_socket.as_raw_fd(), libc::F_SETFD, 0);
    }

    let mut builder = Command::new(detect_fusermount_bin());
    builder.stdout(Stdio::piped()).stderr(Stdio::piped());
    let driver_options: Vec<String> = options
        .iter()
        .filter(|option| is_fusermount_mount_option(option))
        .map(option_to_string)
        .collect();
    if !driver_options.is_empty() {
        builder.arg("-o");
        builder.arg(driver_options.join(","));
    }
    builder
        .arg("--")
        .arg(mountpoint)
        .env(FUSERMOUNT_COMM_ENV, child_socket.as_raw_fd().to_string());

    let fusermount_child = builder.spawn()?;

    drop(child_socket); // close socket in parent

    let file = match receive_fusermount_message(&receive_socket) {
        Ok(f) => f,
        Err(_) => {
            // Drop receive socket, since fusermount has exited with an error
            drop(receive_socket);
            let output = match fusermount_child.wait_with_output() {
                Ok(output) => output,
                Err(e) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("fusermount failed and could not get error output: {e}"),
                    ))
                }
            };
            let stderr_string = String::from_utf8_lossy(&output.stderr).to_string();
            return if stderr_string.contains("only allowed if 'user_allow_other' is set") {
                Err(io::Error::new(ErrorKind::PermissionDenied, stderr_string))
            } else {
                Err(io::Error::new(ErrorKind::Other, stderr_string))
            };
        }
    };
    let mut receive_socket = Some(receive_socket);

    if let Err(err) = apply_fuse_atime_remount(mountpoint, options) {
        drop(file);
        drop(mem::take(&mut receive_socket));
        if let Ok(c_mountpoint) = CString::new(mountpoint.as_bytes()) {
            fuse_unmount_pure(&c_mountpoint);
        }
        if !options.contains(&MountOption::AutoUnmount) {
            let _ = fusermount_child.wait_with_output();
        }
        return Err(err);
    }

    if !options.contains(&MountOption::AutoUnmount) {
        // Only close the socket, if auto unmount is not set.
        // fusermount will keep running until the socket is closed, if auto unmount is set
        drop(mem::take(&mut receive_socket));
        let output = fusermount_child.wait_with_output()?;
        debug!("fusermount: {}", String::from_utf8_lossy(&output.stdout));
        debug!("fusermount: {}", String::from_utf8_lossy(&output.stderr));
    } else {
        if let Some(mut stdout) = fusermount_child.stdout {
            let stdout_fd = stdout.as_raw_fd();
            // SAFETY: stdout_fd is a valid fd from the spawned child
            // process. F_GETFL/F_SETFL are standard fcntl ops on a live fd.
            // SAFETY: stdout_fd is a valid fd from the spawned child process.
            // F_GETFL/F_SETFL are standard fcntl ops on a live fd; O_NONBLOCK
            // is a valid status flag.
            unsafe {
                let mut flags = libc::fcntl(stdout_fd, libc::F_GETFL, 0);
                flags |= libc::O_NONBLOCK;
                libc::fcntl(stdout_fd, libc::F_SETFL, flags);
            }
            let mut buf = vec![0; 64 * 1024];
            if let Ok(len) = stdout.read(&mut buf) {
                debug!("fusermount: {}", String::from_utf8_lossy(&buf[..len]));
            }
        }
        if let Some(mut stderr) = fusermount_child.stderr {
            let stderr_fd = stderr.as_raw_fd();
            // SAFETY: stderr_fd is a valid fd from the child process.
            // F_GETFL/F_SETFL are safe fcntl ops on a live fd.
            // SAFETY: stderr_fd is a valid fd from the child process.
            // F_GETFL/F_SETFL are standard fcntl ops on a live fd; O_NONBLOCK
            // is a valid status flag.
            unsafe {
                let mut flags = libc::fcntl(stderr_fd, libc::F_GETFL, 0);
                flags |= libc::O_NONBLOCK;
                libc::fcntl(stderr_fd, libc::F_SETFL, flags);
            }
            let mut buf = vec![0; 64 * 1024];
            if let Ok(len) = stderr.read(&mut buf) {
                debug!("fusermount: {}", String::from_utf8_lossy(&buf[..len]));
            }
        }
    }

    // SAFETY: fcntl F_SETFD/FD_CLOEXEC sets close-on-exec on a valid
    // open fd; standard POSIX operation with no UB risk.
    // SAFETY: fcntl F_SETFD/FD_CLOEXEC sets close-on-exec on a valid open fd;
    // this is a standard POSIX operation with no UB risk.
    unsafe {
        libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
    }

    Ok((file, receive_socket))
}

#[cfg(target_os = "linux")]
fn apply_fuse_atime_remount(mountpoint: &OsStr, options: &[MountOption]) -> Result<(), io::Error> {
    let Some(flags) = atime_remount_flags(options) else {
        return Ok(());
    };
    let c_mountpoint = CString::new(mountpoint.as_bytes())
        .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("Invalid mountpoint: {e}")))?;

    // SAFETY: remounting uses a valid null-terminated mountpoint string.
    // For MS_REMOUNT, Linux ignores the null source, filesystem type, and data
    // pointers; flags are assembled from MS_* constants only.
    let result = unsafe {
        libc::mount(
            ptr::null::<libc::c_char>(),
            c_mountpoint.as_ptr(),
            ptr::null::<libc::c_char>(),
            flags,
            ptr::null::<libc::c_void>(),
        )
    };
    if result == -1 {
        let err = Error::last_os_error();
        Err(Error::new(
            err.kind(),
            format!("Error remounting FUSE atime policy at {mountpoint:?}: {err}"),
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
fn apply_fuse_atime_remount(
    _mountpoint: &OsStr,
    _options: &[MountOption],
) -> Result<(), io::Error> {
    Ok(())
}

// If returned option is none. Then fusermount binary should be tried
fn fuse_mount_sys(mountpoint: &OsStr, options: &[MountOption]) -> Result<Option<File>, Error> {
    let fuse_device_name = "/dev/fuse";

    let mountpoint_mode = File::open(mountpoint)?.metadata()?.permissions().mode();

    // Auto unmount requests must be sent to fusermount binary
    assert!(!options.contains(&MountOption::AutoUnmount));

    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .open(fuse_device_name)
    {
        Ok(file) => file,
        Err(error) => {
            if error.kind() == ErrorKind::NotFound {
                error!("{} not found. Try 'modprobe fuse'", fuse_device_name);
            }
            return Err(error);
        }
    };
    assert!(
        file.as_raw_fd() > 2,
        "Conflict with stdin/stdout/stderr. fd={}",
        file.as_raw_fd()
    );

    let mut mount_options = format!(
        "fd={},rootmode={:o},user_id={},group_id={}",
        file.as_raw_fd(),
        mountpoint_mode,
        // SAFETY: getuid() is always safe; returns real UID with no
        // side effects or preconditions.
        unsafe { libc::getuid() },
        // SAFETY: getgid() is always safe; returns real GID with no
        // side effects or preconditions.
        unsafe { libc::getgid() }
    );

    for option in options
        .iter()
        .filter(|x| option_group(x) == MountOptionGroup::KernelOption)
    {
        mount_options.push(',');
        mount_options.push_str(&option_to_string(option));
    }

    let mut flags = 0;
    if !options.contains(&MountOption::Dev) {
        // Default to nodev
        #[cfg(target_os = "linux")]
        {
            flags |= libc::MS_NODEV;
        }
        #[cfg(target_os = "macos")]
        {
            flags |= libc::MNT_NODEV;
        }
    }
    if !options.contains(&MountOption::Suid) {
        // Default to nosuid
        #[cfg(target_os = "linux")]
        {
            flags |= libc::MS_NOSUID;
        }
        #[cfg(target_os = "macos")]
        {
            flags |= libc::MNT_NOSUID;
        }
    }
    for flag in options
        .iter()
        .filter(|x| option_group(x) == MountOptionGroup::KernelFlag)
    {
        flags |= option_to_flag(flag);
    }

    // Default name is "/dev/fuse", then use the subtype, and lastly prefer the name
    let mut source = fuse_device_name;
    if let Some(MountOption::Subtype(subtype)) = options
        .iter()
        .find(|x| matches!(**x, MountOption::Subtype(_)))
    {
        source = subtype;
    }
    if let Some(MountOption::FSName(name)) = options
        .iter()
        .find(|x| matches!(**x, MountOption::FSName(_)))
    {
        source = name;
    }

    let c_source = CString::new(source)
        .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("Invalid source: {e}")))?;
    let c_mountpoint = CString::new(mountpoint.as_bytes())
        .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("Invalid mountpoint: {e}")))?;

    // SAFETY: mount(2) is a C FFI call. All pointer arguments are valid
    // null-terminated C strings from CString values that live through the
    // call. flags is built from MS_* constants. The void pointer cast from
    // c_options.as_ptr() is valid per mount(2) API contract.
    // SAFETY: mount(2) is a C FFI call. All pointer args are valid null-
    // terminated C strings from CString values that live through the call.
    // flags is built from MS_* constants. The void pointer cast from
    // c_options.as_ptr() is valid per the mount(2) API contract.
    let result = unsafe {
        #[cfg(target_os = "linux")]
        {
            let c_options = CString::new(mount_options).map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Invalid mount options: {e}"),
                )
            })?;
            let c_type = CString::new("fuse")
                .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("Invalid type: {e}")))?;
            libc::mount(
                c_source.as_ptr(),
                c_mountpoint.as_ptr(),
                c_type.as_ptr(),
                flags,
                c_options.as_ptr() as *const libc::c_void,
            )
        }
        #[cfg(target_os = "macos")]
        {
            let mut c_options = CString::new(mount_options).map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Invalid mount options: {e}"),
                )
            })?;
            libc::mount(
                c_source.as_ptr(),
                c_mountpoint.as_ptr(),
                flags,
                c_options.as_ptr() as *mut libc::c_void,
            )
        }
    };
    if result == -1 {
        let err = Error::last_os_error();
        if err.kind() == ErrorKind::PermissionDenied {
            return Ok(None); // Retry with fusermount
        } else {
            return Err(Error::new(
                err.kind(),
                format!("Error calling mount() at {mountpoint:?}: {err}"),
            ));
        }
    }

    if let Err(err) = apply_fuse_atime_remount(mountpoint, options) {
        fuse_unmount_pure(&c_mountpoint);
        return Err(err);
    }

    Ok(Some(file))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn atime_policy_options_set_linux_mount_flags() {
        assert_eq!(option_to_flag(&MountOption::Atime), libc::MS_STRICTATIME);
        assert_eq!(option_to_flag(&MountOption::Relatime), libc::MS_RELATIME);
        assert_eq!(
            option_to_flag(&MountOption::StrictAtime),
            libc::MS_STRICTATIME
        );
        assert_eq!(option_to_flag(&MountOption::NoAtime), libc::MS_NOATIME);
    }

    #[test]
    fn fusermount_options_skip_kernel_atime_policy_flags() {
        let options = [
            MountOption::FSName("tidefs".to_string()),
            MountOption::Atime,
            MountOption::Relatime,
            MountOption::StrictAtime,
            MountOption::NoAtime,
            MountOption::RO,
            MountOption::WritebackCache,
        ];

        let driver_options: Vec<String> = options
            .iter()
            .filter(|option| is_fusermount_mount_option(option))
            .map(option_to_string)
            .collect();

        assert_eq!(driver_options, ["fsname=tidefs", "ro"]);
    }

    #[test]
    fn fuse_strictatime_remount_preserves_default_flags() {
        assert_eq!(
            atime_remount_flags(&[MountOption::StrictAtime]),
            Some(libc::MS_REMOUNT | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_STRICTATIME)
        );
    }

    #[test]
    fn fuse_atime_remount_uses_strictatime_flag() {
        assert_eq!(
            atime_remount_flags(&[MountOption::Atime]),
            Some(libc::MS_REMOUNT | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_STRICTATIME)
        );
    }

    #[test]
    fn fuse_noatime_remount_respects_dev_and_suid() {
        assert_eq!(
            atime_remount_flags(&[MountOption::NoAtime, MountOption::Dev, MountOption::Suid]),
            Some(libc::MS_REMOUNT | libc::MS_NOATIME)
        );
    }

    #[test]
    fn fuse_noatime_remount_preserves_read_only() {
        assert_eq!(
            atime_remount_flags(&[MountOption::RO, MountOption::NoAtime, MountOption::Dev]),
            Some(libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NOATIME)
        );
    }

    #[test]
    fn fuse_relatime_remount_preserves_default_flags() {
        assert_eq!(
            atime_remount_flags(&[MountOption::Relatime]),
            Some(libc::MS_REMOUNT | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_RELATIME)
        );
    }
}

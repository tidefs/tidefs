use std::collections::HashSet;
use std::io;
use std::io::ErrorKind;

/// Mount options accepted by the FUSE filesystem type
/// See 'man mount.fuse' for details
// TODO: add all options that 'man mount.fuse' documents and libfuse supports
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum MountOption {
    /// Set the name of the source in mtab
    FSName(String),
    /// Set the filesystem subtype in mtab
    Subtype(String),
    /// Allows passing an option which is not otherwise supported in these enums
    #[allow(clippy::upper_case_acronyms)]
    CUSTOM(String),

    /* Parameterless options */
    /// Allow all users to access files on this filesystem. By default access is restricted to the
    /// user who mounted it
    AllowOther,
    /// Allow the root user to access this filesystem, in addition to the user who mounted it
    AllowRoot,
    /// Automatically unmount when the mounting process exits
    ///
    /// `AutoUnmount` requires `AllowOther` or `AllowRoot`. If `AutoUnmount` is set and neither `Allow...` is set, the FUSE configuration must permit `allow_other`, otherwise mounting will fail.
    AutoUnmount,
    /// Enable permission checking in the kernel
    DefaultPermissions,

    /* Flags */
    /// Enable special character and block devices
    Dev,
    /// Disable special character and block devices
    NoDev,
    /// Honor set-user-id and set-groupd-id bits on files
    Suid,
    /// Don't honor set-user-id and set-groupd-id bits on files
    NoSuid,
    /// Read-only filesystem
    RO,
    /// Read-write filesystem
    RW,
    /// Allow execution of binaries
    Exec,
    /// Don't allow execution of binaries
    NoExec,
    /// Support inode access time
    Atime,
    /// Update inode access time using Linux relatime rules
    Relatime,
    /// Update inode access time on every access
    StrictAtime,
    /// Don't update inode access time
    NoAtime,
    /// All modifications to directories will be done synchronously
    DirSync,
    /// All I/O will be done synchronously
    Sync,
    /// All I/O will be done asynchronously
    Async,
    /// Enable kernel writeback cache: the kernel buffers writes and sends
    /// them asynchronously with FUSE_WRITE_CACHE flag.
    WritebackCache,
    /* libfuse library options, such as "direct_io", are not included since they are specific
    to libfuse, and not part of the kernel ABI */
}

pub(crate) fn is_driver_mount_option(option: &MountOption) -> bool {
    !matches!(option, MountOption::WritebackCache)
}

pub(crate) fn is_fusermount_mount_option(option: &MountOption) -> bool {
    is_driver_mount_option(option)
        && !matches!(
            option,
            MountOption::Atime
                | MountOption::Relatime
                | MountOption::StrictAtime
                | MountOption::NoAtime
        )
}

pub fn check_option_conflicts(options: &[MountOption]) -> Result<(), io::Error> {
    let mut options_set = HashSet::new();
    options_set.extend(options.iter().cloned());
    let conflicting: HashSet<MountOption> = options.iter().flat_map(conflicts_with).collect();
    let intersection: Vec<MountOption> = conflicting.intersection(&options_set).cloned().collect();
    if !intersection.is_empty() {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("Conflicting mount options found: {intersection:?}"),
        ))
    } else {
        Ok(())
    }
}

fn conflicts_with(option: &MountOption) -> Vec<MountOption> {
    match option {
        MountOption::FSName(_) => vec![],
        MountOption::Subtype(_) => vec![],
        MountOption::CUSTOM(_) => vec![],
        MountOption::AllowOther => vec![MountOption::AllowRoot],
        MountOption::AllowRoot => vec![MountOption::AllowOther],
        MountOption::AutoUnmount => vec![],
        MountOption::DefaultPermissions => vec![],
        MountOption::Dev => vec![MountOption::NoDev],
        MountOption::NoDev => vec![MountOption::Dev],
        MountOption::Suid => vec![MountOption::NoSuid],
        MountOption::NoSuid => vec![MountOption::Suid],
        MountOption::RO => vec![MountOption::RW],
        MountOption::RW => vec![MountOption::RO],
        MountOption::Exec => vec![MountOption::NoExec],
        MountOption::NoExec => vec![MountOption::Exec],
        MountOption::Atime => vec![
            MountOption::NoAtime,
            MountOption::Relatime,
            MountOption::StrictAtime,
        ],
        MountOption::Relatime => vec![
            MountOption::Atime,
            MountOption::NoAtime,
            MountOption::StrictAtime,
        ],
        MountOption::StrictAtime => vec![
            MountOption::Atime,
            MountOption::Relatime,
            MountOption::NoAtime,
        ],
        MountOption::NoAtime => vec![
            MountOption::Atime,
            MountOption::Relatime,
            MountOption::StrictAtime,
        ],
        MountOption::DirSync => vec![],
        MountOption::Sync => vec![MountOption::Async],
        MountOption::Async => vec![MountOption::Sync],
        MountOption::WritebackCache => vec![],
    }
}

// Format option to be passed to libfuse or kernel
pub fn option_to_string(option: &MountOption) -> String {
    match option {
        MountOption::FSName(name) => format!("fsname={name}"),
        MountOption::Subtype(subtype) => format!("subtype={subtype}"),
        MountOption::CUSTOM(value) => value.to_string(),
        MountOption::AutoUnmount => "auto_unmount".to_string(),
        MountOption::AllowOther => "allow_other".to_string(),
        // AllowRoot is implemented by allowing everyone access and then restricting to
        // root + owner within fuser
        MountOption::AllowRoot => "allow_other".to_string(),
        MountOption::DefaultPermissions => "default_permissions".to_string(),
        MountOption::Dev => "dev".to_string(),
        MountOption::NoDev => "nodev".to_string(),
        MountOption::Suid => "suid".to_string(),
        MountOption::NoSuid => "nosuid".to_string(),
        MountOption::RO => "ro".to_string(),
        MountOption::RW => "rw".to_string(),
        MountOption::Exec => "exec".to_string(),
        MountOption::NoExec => "noexec".to_string(),
        MountOption::Atime => "atime".to_string(),
        MountOption::Relatime => "relatime".to_string(),
        MountOption::StrictAtime => "strictatime".to_string(),
        MountOption::NoAtime => "noatime".to_string(),
        MountOption::DirSync => "dirsync".to_string(),
        MountOption::Sync => "sync".to_string(),
        MountOption::Async => "async".to_string(),
        MountOption::WritebackCache => "writeback_cache".to_string(),
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn option_checking() {
        assert!(check_option_conflicts(&[MountOption::Suid, MountOption::NoSuid]).is_err());
        assert!(check_option_conflicts(&[MountOption::Suid, MountOption::NoExec]).is_ok());
        assert!(check_option_conflicts(&[MountOption::Relatime, MountOption::NoAtime]).is_err());
        assert!(
            check_option_conflicts(&[MountOption::StrictAtime, MountOption::Relatime]).is_err()
        );
    }

    #[test]
    fn writeback_cache_is_session_only() {
        assert!(!is_driver_mount_option(&MountOption::WritebackCache));
        assert!(is_driver_mount_option(&MountOption::Relatime));
        assert!(is_driver_mount_option(&MountOption::StrictAtime));
        assert!(is_driver_mount_option(&MountOption::NoAtime));
    }

    #[test]
    fn atime_policy_options_are_not_fusermount_cli_options() {
        assert!(is_fusermount_mount_option(&MountOption::AllowOther));
        assert!(is_fusermount_mount_option(&MountOption::Dev));
        assert!(!is_fusermount_mount_option(&MountOption::Atime));
        assert!(!is_fusermount_mount_option(&MountOption::Relatime));
        assert!(!is_fusermount_mount_option(&MountOption::StrictAtime));
        assert!(!is_fusermount_mount_option(&MountOption::NoAtime));
        assert!(!is_fusermount_mount_option(&MountOption::WritebackCache));
    }
}

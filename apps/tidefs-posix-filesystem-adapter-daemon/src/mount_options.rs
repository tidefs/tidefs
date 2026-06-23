// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE daemon mount-option parser.
//!
//! Parses `-o atime,relatime,noatime,nodiratime,sync,async,dev,nodev,...` comma-separated
//! FUSE mount options into a typed [`MountOptions`] struct with
//! timestamp policy, directory-atime suppression, sync-mode flags, and
//! device-node enablement.

use std::str::FromStr;
use tidefs_dataset_lifecycle::SyncGuarantee;

/// Timestamp update policy for atime handling.
///
/// Mirrors the Linux atime/relatime/noatime mount options and
/// controls the FUSE daemon's atime-update behaviour in
/// setattr, lookup, and read dispatch paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampPolicy {
    /// Always update atime on every access (POSIX strict atime).
    StrictAtime,
    /// Linux relatime: update atime only when older than mtime, older
    /// than ctime, or more than 24 hours in the past.
    RelativeAtime,
    /// Never update atime.
    NoAtime,
}

impl TimestampPolicy {
    /// Return the FUSE kernel mount option needed for this timestamp policy.
    ///
    /// The daemon also records read access in the backing VFS engine, but the
    /// kernel still needs the matching mount flag for reads served from its
    /// page cache without crossing the daemon boundary.
    pub fn to_fuse_mount_option(self) -> Option<fuser::MountOption> {
        match self {
            TimestampPolicy::StrictAtime => Some(fuser::MountOption::StrictAtime),
            TimestampPolicy::RelativeAtime => Some(fuser::MountOption::Relatime),
            TimestampPolicy::NoAtime => Some(fuser::MountOption::NoAtime),
        }
    }

    /// Human-readable name for diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            TimestampPolicy::StrictAtime => "atime",
            TimestampPolicy::RelativeAtime => "relatime",
            TimestampPolicy::NoAtime => "noatime",
        }
    }
}

impl Default for TimestampPolicy {
    /// Linux default: relatime.
    fn default() -> Self {
        TimestampPolicy::RelativeAtime
    }
}

impl FromStr for TimestampPolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "atime" | "strictatime" => Ok(TimestampPolicy::StrictAtime),
            "relatime" => Ok(TimestampPolicy::RelativeAtime),
            "noatime" => Ok(TimestampPolicy::NoAtime),
            other => Err(format!(
                "unknown atime policy `{other}`; expected atime, relatime, or noatime"
            )),
        }
    }
}

/// Parsed FUSE `-o` mount options.
///
/// Supports the options relevant to the TideFS daemon: atime policy
/// sync/async write mode, cross-user mount access, device-node enablement,
/// and intent-log
/// buffered-write toggle.
/// Unrecognized options are rejected.
/// Idmapped mounts are explicitly refused (not yet supported).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountOptions {
    /// Timestamp update policy.
    pub timestamp_policy: TimestampPolicy,
    /// When true, suppress automatic atime updates on directories.
    pub suppress_dir_atime: bool,
    /// When true, every write waits for a durability barrier before
    /// replying to the kernel (FUSE `-o sync`).
    pub sync: bool,
    /// Per-dataset write-acknowledgment durability guarantee.
    pub sync_guarantee: SyncGuarantee,
    /// When true, allow users other than the mount owner to access the FUSE
    /// mount, leaving permission decisions to the daemon.
    pub allow_other: bool,
    /// When true, allow special character and block devices on the mounted
    /// filesystem by passing the kernel FUSE `dev` mount option.
    pub dev: bool,
    /// When true, tiny buffered writes may record inline `BufferedWrite`
    /// entries before acknowledging the kernel. Larger writes are left to the
    /// storage commit path so the FUSE hot path does not hash user payloads.
    pub intent_log_write: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        MountOptions {
            timestamp_policy: TimestampPolicy::default(),
            suppress_dir_atime: false,
            sync: false,
            sync_guarantee: SyncGuarantee::Local,
            allow_other: false,
            dev: false,
            intent_log_write: false,
        }
    }
}

impl MountOptions {
    /// Parse a comma-separated `-o` option string.
    ///
    /// Supported keys: `atime`, `strictatime`, `relatime`, `noatime`,
    /// `nodiratime`, `diratime`,
    /// `sync`, `async`, `allow_other`, `noallow_other`, `dev`, `nodev`,
    /// `intent_log_write=true`,
    /// `intent_log_write=false`.
    /// Unknown options produce an error.
    ///
    /// If multiple atime-policy options appear, the last one wins.
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut opts = MountOptions::default();

        if input.is_empty() {
            return Ok(opts);
        }

        for token in input.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            match token {
                "atime" | "strictatime" => {
                    opts.timestamp_policy = TimestampPolicy::StrictAtime;
                }
                "relatime" => {
                    opts.timestamp_policy = TimestampPolicy::RelativeAtime;
                }
                "noatime" => {
                    opts.timestamp_policy = TimestampPolicy::NoAtime;
                }
                "nodiratime" => {
                    opts.suppress_dir_atime = true;
                }
                "diratime" => {
                    opts.suppress_dir_atime = false;
                }
                "sync" => opts.sync = true,
                "async" => opts.sync = false,
                "allow_other" => opts.allow_other = true,
                "noallow_other" => opts.allow_other = false,
                "dev" => opts.dev = true,
                "nodev" => opts.dev = false,
                "intent_log_write=true" => opts.intent_log_write = true,
                "intent_log_write=false" => opts.intent_log_write = false,
                other => {
                    // Explicitly refuse idmapped mount attempts.
                    // TideFS does not support idmapped mounts; this is the
                    // user-facing refusal contract for idmapped mounts.
                    if other == "idmap" || other.starts_with("idmap=") {
                        return Err(
                            "TideFS does not support idmapped mounts.                              Mount refused -- idmapped mounts are not yet supported.".to_string()
                        );
                    }
                    if other.starts_with("intent_log_write=") || other == "intent_log_write" {
                        return Err(format!(
                            "mount option `{other}`: intent_log_write requires                              =true or =false"
                        ));
                    }
                    return Err(format!(
                        "unsupported mount option `{other}`; \
                         supported: atime, relatime, noatime, nodiratime, diratime, sync, async,                          allow_other, noallow_other, dev, nodev,                          intent_log_write=true|false.                          Idmapped mounts are not supported."
                    ));
                }
            }
        }

        Ok(opts)
    }

    /// Convert to the FUSE kernel `MountOption` slice for use with
    /// `fuser::spawn_mount2`.
    pub fn to_fuse_mount_options(&self) -> Vec<fuser::MountOption> {
        let mut v = Vec::with_capacity(3);
        if let Some(option) = self.timestamp_policy.to_fuse_mount_option() {
            v.push(option);
        }
        if self.sync {
            v.push(fuser::MountOption::Sync);
        }
        if self.allow_other {
            v.push(fuser::MountOption::AllowOther);
        }
        if self.dev {
            v.push(fuser::MountOption::Dev);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- TimestampPolicy --------------------------------------------

    #[test]
    fn timestamp_policy_default_is_relatime() {
        assert_eq!(TimestampPolicy::default(), TimestampPolicy::RelativeAtime);
    }

    #[test]
    fn timestamp_policy_from_str_strictatime() {
        assert_eq!(
            "atime".parse::<TimestampPolicy>().unwrap(),
            TimestampPolicy::StrictAtime
        );
        assert_eq!(
            "strictatime".parse::<TimestampPolicy>().unwrap(),
            TimestampPolicy::StrictAtime
        );
    }

    #[test]
    fn timestamp_policy_from_str_relatime() {
        assert_eq!(
            "relatime".parse::<TimestampPolicy>().unwrap(),
            TimestampPolicy::RelativeAtime
        );
    }

    #[test]
    fn timestamp_policy_from_str_noatime() {
        assert_eq!(
            "noatime".parse::<TimestampPolicy>().unwrap(),
            TimestampPolicy::NoAtime
        );
    }

    #[test]
    fn timestamp_policy_from_str_unknown() {
        assert!("bogus".parse::<TimestampPolicy>().is_err());
    }

    #[test]
    fn timestamp_policy_to_fuse_mount_option_atime() {
        assert_eq!(
            TimestampPolicy::StrictAtime.to_fuse_mount_option(),
            Some(fuser::MountOption::StrictAtime)
        );
    }

    #[test]
    fn timestamp_policy_to_fuse_mount_option_relatime() {
        assert_eq!(
            TimestampPolicy::RelativeAtime.to_fuse_mount_option(),
            Some(fuser::MountOption::Relatime)
        );
    }

    #[test]
    fn timestamp_policy_to_fuse_mount_option_noatime() {
        assert_eq!(
            TimestampPolicy::NoAtime.to_fuse_mount_option(),
            Some(fuser::MountOption::NoAtime)
        );
    }

    // -- MountOptions ----------------------------------------------

    #[test]
    fn mount_options_explicitly_refuses_idmap() {
        let err = MountOptions::parse("idmap").unwrap_err();
        assert!(
            err.contains("idmapped"),
            "idmap rejection should mention idmapped mounts: {err}"
        );
        let err = MountOptions::parse("idmap=/path/to/idmap").unwrap_err();
        assert!(
            err.contains("idmapped"),
            "idmap= value rejection should mention idmapped: {err}"
        );
    }

    #[test]
    fn mount_options_default() {
        let opts = MountOptions::default();
        assert_eq!(opts.timestamp_policy, TimestampPolicy::RelativeAtime);
        assert!(!opts.suppress_dir_atime);
        assert!(!opts.sync);
        assert!(!opts.allow_other);
        assert!(!opts.dev);
        assert!(!opts.intent_log_write);
    }

    #[test]
    fn mount_options_parse_empty() {
        let opts = MountOptions::parse("").unwrap();
        assert_eq!(opts, MountOptions::default());
    }

    #[test]
    fn mount_options_parse_relatime() {
        let opts = MountOptions::parse("relatime").unwrap();
        assert_eq!(opts.timestamp_policy, TimestampPolicy::RelativeAtime);
        assert!(!opts.sync);
    }

    #[test]
    fn mount_options_parse_noatime() {
        let opts = MountOptions::parse("noatime").unwrap();
        assert_eq!(opts.timestamp_policy, TimestampPolicy::NoAtime);
    }

    #[test]
    fn mount_options_parse_strictatime() {
        let opts = MountOptions::parse("strictatime").unwrap();
        assert_eq!(opts.timestamp_policy, TimestampPolicy::StrictAtime);
    }

    #[test]
    fn mount_options_parse_atime() {
        let opts = MountOptions::parse("atime").unwrap();
        assert_eq!(opts.timestamp_policy, TimestampPolicy::StrictAtime);
    }

    #[test]
    fn mount_options_parse_nodiratime_and_diratime() {
        let opts = MountOptions::parse("relatime,nodiratime").unwrap();
        assert_eq!(opts.timestamp_policy, TimestampPolicy::RelativeAtime);
        assert!(opts.suppress_dir_atime);

        let opts = MountOptions::parse("relatime,nodiratime,diratime").unwrap();
        assert_eq!(opts.timestamp_policy, TimestampPolicy::RelativeAtime);
        assert!(!opts.suppress_dir_atime);
    }

    #[test]
    fn mount_options_parse_sync() {
        let opts = MountOptions::parse("sync").unwrap();
        assert!(opts.sync);
    }

    #[test]
    fn mount_options_parse_async() {
        let opts = MountOptions::parse("async").unwrap();
        assert!(!opts.sync);
    }

    #[test]
    fn mount_options_parse_dev_and_nodev() {
        let opts = MountOptions::parse("dev").unwrap();
        assert!(opts.dev);

        let opts = MountOptions::parse("dev,nodev").unwrap();
        assert!(!opts.dev);
    }

    #[test]
    fn mount_options_parse_allow_other_and_noallow_other() {
        let opts = MountOptions::parse("allow_other").unwrap();
        assert!(opts.allow_other);

        let opts = MountOptions::parse("allow_other,noallow_other").unwrap();
        assert!(!opts.allow_other);
    }

    #[test]
    fn mount_options_parse_combined() {
        let opts = MountOptions::parse("noatime,sync,allow_other,dev").unwrap();
        assert_eq!(opts.timestamp_policy, TimestampPolicy::NoAtime);
        assert!(!opts.suppress_dir_atime);
        assert!(opts.sync);
        assert!(opts.allow_other);
        assert!(opts.dev);
    }

    #[test]
    fn mount_options_parse_last_wins() {
        let opts = MountOptions::parse("noatime,relatime,atime").unwrap();
        assert_eq!(opts.timestamp_policy, TimestampPolicy::StrictAtime);

        let opts = MountOptions::parse("atime,noatime").unwrap();
        assert_eq!(opts.timestamp_policy, TimestampPolicy::NoAtime);

        let opts = MountOptions::parse("sync,async,sync").unwrap();
        assert!(opts.sync);

        let opts = MountOptions::parse("sync,async").unwrap();
        assert!(!opts.sync);

        let opts = MountOptions::parse("nodev,dev").unwrap();
        assert!(opts.dev);

        let opts = MountOptions::parse("noallow_other,allow_other").unwrap();
        assert!(opts.allow_other);

        let opts = MountOptions::parse("diratime,nodiratime").unwrap();
        assert!(opts.suppress_dir_atime);

        let opts = MountOptions::parse("nodiratime,diratime").unwrap();
        assert!(!opts.suppress_dir_atime);
    }

    #[test]
    fn mount_options_parse_unknown_rejected() {
        let err = MountOptions::parse("bogus").unwrap_err();
        assert!(
            err.contains("bogus"),
            "error should name the bad option: {err}"
        );
    }

    #[test]
    fn mount_options_parse_whitespace_tolerant() {
        let opts = MountOptions::parse(" noatime , sync ").unwrap();
        assert_eq!(opts.timestamp_policy, TimestampPolicy::NoAtime);
        assert!(opts.sync);
    }

    #[test]
    fn mount_options_to_fuse_mount_options() {
        let opts = MountOptions {
            timestamp_policy: TimestampPolicy::NoAtime,
            suppress_dir_atime: false,
            sync: true,
            sync_guarantee: SyncGuarantee::Local,
            allow_other: true,
            dev: true,
            intent_log_write: true,
        };
        let v = opts.to_fuse_mount_options();
        assert!(v.contains(&fuser::MountOption::NoAtime));
        assert!(v.contains(&fuser::MountOption::Sync));
        assert!(v.contains(&fuser::MountOption::AllowOther));
        assert!(v.contains(&fuser::MountOption::Dev));
    }

    #[test]
    fn strict_atime_emits_kernel_strictatime_option() {
        let opts = MountOptions {
            timestamp_policy: TimestampPolicy::StrictAtime,
            suppress_dir_atime: false,
            sync: false,
            sync_guarantee: SyncGuarantee::Local,
            allow_other: false,
            dev: false,
            intent_log_write: true,
        };
        assert_eq!(
            opts.to_fuse_mount_options(),
            vec![fuser::MountOption::StrictAtime]
        );
    }

    #[test]
    fn relative_atime_emits_kernel_relatime_option() {
        let opts = MountOptions {
            timestamp_policy: TimestampPolicy::RelativeAtime,
            suppress_dir_atime: false,
            sync: false,
            sync_guarantee: SyncGuarantee::Local,
            allow_other: false,
            dev: false,
            intent_log_write: true,
        };
        assert_eq!(
            opts.to_fuse_mount_options(),
            vec![fuser::MountOption::Relatime]
        );
    }
    // -- intent_log_write mount-option parsing ------------------------

    #[test]
    fn mount_options_intent_log_write_defaults_false() {
        let opts = MountOptions::default();
        assert!(!opts.intent_log_write);
    }

    #[test]
    fn mount_options_parse_intent_log_write_true() {
        let opts = MountOptions::parse("intent_log_write=true").unwrap();
        assert!(opts.intent_log_write);
    }

    #[test]
    fn mount_options_parse_intent_log_write_false() {
        let opts = MountOptions::parse("intent_log_write=false").unwrap();
        assert!(!opts.intent_log_write);
    }

    #[test]
    fn mount_options_parse_intent_log_write_combined() {
        let opts = MountOptions::parse("noatime,intent_log_write=false").unwrap();
        assert_eq!(opts.timestamp_policy, TimestampPolicy::NoAtime);
        assert!(!opts.intent_log_write);
    }

    #[test]
    fn mount_options_parse_intent_log_write_bare_rejected() {
        let err = MountOptions::parse("intent_log_write").unwrap_err();
        assert!(
            err.contains("requires"),
            "bare intent_log_write should be rejected: {err}"
        );
    }

    #[test]
    fn mount_options_parse_intent_log_write_bad_value_rejected() {
        let err = MountOptions::parse("intent_log_write=1").unwrap_err();
        assert!(
            err.contains("intent_log_write"),
            "bad value should be rejected: {err}"
        );
    }
}

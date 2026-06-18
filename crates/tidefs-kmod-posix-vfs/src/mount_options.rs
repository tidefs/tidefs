// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel VFS mount option parsing and runtime configuration.
//!
//! Parses the comma-separated key=value mount option string passed by the
//! Linux VFS mount(2) path into a validated [`MountOptions`] struct, with
//! feature-flag refusal and explicit engine-authority-mode disclosure.

#[cfg(CONFIG_RUST)]
use crate::blake3;
use crate::TideString as String;
use core::fmt;

// ---------------------------------------------------------------------------
// Mount option error types
// ---------------------------------------------------------------------------

/// Errors returned by mount-option parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountOptionError {
    /// An unrecognized option key was supplied.
    UnknownOption { key: String },
    /// A value for a recognized key could not be parsed (e.g. non-integer
    /// timeout).
    InvalidValue {
        key: String,
        value: String,
        reason: String,
    },
    /// A required option was not supplied.
    MissingRequired { key: String },
    /// The same option key appeared more than once.
    DuplicateOption { key: String },
    /// A requested feature name is not recognized.
    UnknownFeature { name: String },
    /// A requested feature is not supported by the current engine.
    FeatureRefused {
        requested_name: String,
        requested_bit: u64,
    },
}

impl fmt::Display for MountOptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountOptionError::UnknownOption { key } => {
                write!(f, "unknown mount option: {key}")
            }
            MountOptionError::InvalidValue { key, value, reason } => {
                write!(f, "invalid value for {key}: {value} ({reason})")
            }
            MountOptionError::MissingRequired { key } => {
                write!(f, "missing required mount option: {key}")
            }
            MountOptionError::DuplicateOption { key } => {
                write!(f, "duplicate mount option: {key}")
            }
            MountOptionError::UnknownFeature { name } => {
                write!(f, "unknown mount feature: {name}")
            }
            MountOptionError::FeatureRefused { requested_name, .. } => {
                write!(
                    f,
                    "requested feature not supported by current engine: {requested_name}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Feature flags
// ---------------------------------------------------------------------------

/// Kernel feature flags bitmask.
///
/// Each bit represents a named kernel-mode capability.  During mount, the
/// parsed feature flags are checked against the engine's supported set;
/// a requested feature that is not supported causes mount refusal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeatureFlags(u64);

impl FeatureFlags {
    /// No features requested.
    pub const NONE: Self = Self(0);

    /// Named feature constants.
    pub const DIRECT_IO: u64 = 1 << 0;
    pub const WRITEBACK_CACHE: u64 = 1 << 1;
    pub const COMPRESSION: u64 = 1 << 2;
    pub const ENCRYPTION: u64 = 1 << 3;
    pub const DEDUP: u64 = 1 << 4;
    pub const SNAPSHOTS: u64 = 1 << 5;
    pub const RDMA: u64 = 1 << 6;

    /// Human-readable name for a single feature bit, or `None` if unknown.
    pub fn name(bit: u64) -> Option<&'static str> {
        match bit {
            Self::DIRECT_IO => Some("direct_io"),
            Self::WRITEBACK_CACHE => Some("writeback_cache"),
            Self::COMPRESSION => Some("compression"),
            Self::ENCRYPTION => Some("encryption"),
            Self::DEDUP => Some("dedup"),
            Self::SNAPSHOTS => Some("snapshots"),
            Self::RDMA => Some("rdma"),
            _ => None,
        }
    }

    /// Parse a colon-separated list of feature names into a bitmask.
    ///
    /// Unknown feature names are reported via [`MountOptionError::UnknownFeature`].
    pub fn parse_names(input: &str) -> Result<Self, MountOptionError> {
        let mut flags = 0u64;
        if input.is_empty() {
            return Ok(Self(0));
        }
        for name in input.split(':') {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let bit = match name {
                "direct_io" => Self::DIRECT_IO,
                "writeback_cache" => Self::WRITEBACK_CACHE,
                "compression" => Self::COMPRESSION,
                "encryption" => Self::ENCRYPTION,
                "dedup" => Self::DEDUP,
                "snapshots" => Self::SNAPSHOTS,
                "rdma" => Self::RDMA,
                _ => {
                    return Err(MountOptionError::UnknownFeature {
                        name: String::from(name),
                    });
                }
            };
            flags |= bit;
        }
        Ok(Self(flags))
    }

    /// True if no features are set.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Test a single feature bit.
    pub fn contains(self, bit: u64) -> bool {
        (self.0 & bit) != 0
    }

    /// Return the raw bitmask.
    pub fn bits(self) -> u64 {
        self.0
    }

    /// Return the set of feature bits that are present in `self` but not
    /// in `supported`.
    pub fn unsupported_against(self, supported: Self) -> Self {
        Self(self.0 & !supported.0)
    }
}

// ---------------------------------------------------------------------------
// Engine authority mode — mixed-mode disclosure
// ---------------------------------------------------------------------------

/// Declares the authority residency of the VfsEngine backing this mount.
///
/// In **full-kernel** mode every normal-operation VFS and block I/O dispatch
/// resolves through kernel-resident code paths.  **Mixed-mode** means one or
/// more authority operations (read, write, alloc, reserve, placement, repair)
/// require a userspace daemon or helper thread.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EngineAuthorityMode {
    /// Authority mode has not been explicitly set.
    #[default]
    Unspecified,
    /// All authority is kernel-resident — no userspace daemon required.
    FullKernel,
    /// At least one authority operation requires userspace assistance.
    MixedMode,
}

impl EngineAuthorityMode {
    /// Parse a mode string from mount options.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "full-kernel" | "full_kernel" => Some(Self::FullKernel),
            "mixed" | "mixed-mode" | "mixed_mode" => Some(Self::MixedMode),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Transport carrier — cluster I/O path disclosure
// ---------------------------------------------------------------------------

/// Transport carrier used for inter-node communication.
///
/// Disclosed during mount so that each validation run
/// records the actual transport path.  Required by the acceptance
/// criteria for issue #6671: clustered kernel validation must disclose
/// whether TCP, RDMA, or another carrier is active.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TransportCarrier {
    /// No transport carrier declared — standalone or local-only mount.
    #[default]
    None,
    /// TCP transport (kernel or userspace socket path).
    Tcp,
    /// RDMA transport (kernel or userspace verbs path).
    Rdma,
    /// Loopback transport for single-node development.
    Loopback,
}

impl TransportCarrier {
    /// Parse a carrier string from mount options.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "none" | "" => Some(Self::None),
            "tcp" => Some(Self::Tcp),
            "rdma" => Some(Self::Rdma),
            "loopback" => Some(Self::Loopback),
            _ => None,
        }
    }

    /// Returns true when a real transport carrier is declared.
    pub fn is_active(self) -> bool {
        !matches!(self, Self::None)
    }
}

// ---------------------------------------------------------------------------
// MountOptions
// ---------------------------------------------------------------------------

/// Parsed kernel mount options for TideFS.
///
/// These are the minimum sane mount options required for full-kernel
/// validation. The struct supports BLAKE3-256 deterministic hashing for
/// validation-harness integration so that mount configuration can be
/// verified and reproduced across test runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountOptions {
    /// Path to the backing device or pool (e.g. `/dev/tidefs/pool0`).
    pub device_path: String,
    /// Mount the filesystem read-only.
    pub read_only: bool,
    /// Enable debug-level diagnostic output.
    pub debug: bool,
    /// Mount in recovery mode: replay the intent log and perform committed-root
    /// verification before accepting any new writes.
    pub recovery_mode: bool,
    /// Commit timeout in milliseconds. The engine will flush dirty data to
    /// stable storage at least this often when there is pending write traffic.
    pub commit_timeout_ms: u64,
    /// Requested feature flags for this mount.  Unknown or unsupported
    /// features cause mount refusal via [`MountOptionError::FeatureRefused`].
    pub feature_flags: FeatureFlags,
    /// Cluster node identity for clustered pool mounts.
    /// When non-empty, the mount declares itself as a named cluster node.
    /// Required when opening a pool with CLUSTER_POOL_INCOMPAT set.
    pub cluster_node_id: String,
    /// Explicit engine-authority-mode disclosure.
    ///
    /// Set to `FullKernel` when all authority is kernel-resident, `MixedMode`
    /// when any operation requires userspace, and `Unspecified` when the
    /// mount-option string did not declare an authority mode.
    pub authority_mode: EngineAuthorityMode,
    /// Transport carrier for inter-node communication disclosure.
    pub transport_carrier: TransportCarrier,
}

impl Default for MountOptions {
    /// Return sensible defaults: read-write, no debug, recovery mode off,
    /// 5000 ms commit timeout, no feature flags, authority mode unspecified.
    fn default() -> Self {
        Self {
            device_path: String::new(),
            read_only: false,
            debug: false,
            recovery_mode: false,
            commit_timeout_ms: 5000,
            feature_flags: FeatureFlags::NONE,
            cluster_node_id: String::new(),
            authority_mode: EngineAuthorityMode::Unspecified,
            transport_carrier: TransportCarrier::None,
        }
    }
}

impl MountOptions {
    /// Domain separator for BLAKE3 configuration hashing.
    const HASH_DOMAIN: &'static str = "tidefs-kmod-mount-options-v1";

    /// Valid option keys recognized by this parser.
    const VALID_KEYS: &'static [&'static str] = &[
        "device",
        "ro",
        "rw",
        "debug",
        "recovery",
        "commit_timeout_ms",
        "features",
        "cluster_node_id",
        "transport_carrier",
        "authority_mode",
    ];

    /// Parse a comma-separated mount-option string.
    ///
    /// Supported options:
    /// - `device=<path>` — backing device path (required)
    /// - `ro` — read-only mount
    /// - `rw` — read-write mount (default)
    /// - `debug` — enable debug output
    /// - `recovery` — mount in recovery mode
    /// - `commit_timeout_ms=<N>` — commit timeout in milliseconds (default 5000)
    /// - `features=<name:...>` — colon-separated feature names to request
    /// - `authority_mode=<full-kernel|mixed>` — explicit engine authority disclosure
    /// - `cluster_node_id=<id>` — cluster node identity for clustered pools
    /// - `transport_carrier=<none|tcp|rdma|loopback>` — transport carrier disclosure
    ///
    /// The option string may be empty, in which case defaults are returned
    /// (with an empty device_path — callers should validate this separately).
    pub fn parse(input: &str) -> Result<Self, MountOptionError> {
        let mut opts = Self::default();
        if input.is_empty() {
            return Ok(opts);
        }

        let mut seen_keys: crate::TideVec<&str> = crate::TideVec::new();

        for token in input.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }

            let (key, value) = match token.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim())),
                None => (token, None),
            };

            // Validate the key is recognized.
            if !Self::VALID_KEYS.contains(&key) {
                return Err(MountOptionError::UnknownOption {
                    key: String::from(key),
                });
            }

            // Check for duplicates.
            if seen_keys.contains(&key) {
                return Err(MountOptionError::DuplicateOption {
                    key: String::from(key),
                });
            }
            seen_keys.push(key);

            // Dispatch on the recognized key.
            match key {
                "device" => {
                    let path = value.ok_or_else(|| MountOptionError::InvalidValue {
                        key: String::from("device"),
                        value: String::from(""),
                        reason: String::from("device path must be non-empty"),
                    })?;
                    if path.is_empty() {
                        return Err(MountOptionError::InvalidValue {
                            key: String::from("device"),
                            value: String::from(path),
                            reason: String::from("device path must be non-empty"),
                        });
                    }
                    opts.device_path = String::from(path);
                }
                "ro" => {
                    if value.is_some() {
                        return Err(MountOptionError::InvalidValue {
                            key: String::from("ro"),
                            value: String::from(value.unwrap_or("")),
                            reason: String::from("ro is a flag, not a key=value option"),
                        });
                    }
                    opts.read_only = true;
                }
                "rw" => {
                    if value.is_some() {
                        return Err(MountOptionError::InvalidValue {
                            key: String::from("rw"),
                            value: String::from(value.unwrap_or("")),
                            reason: String::from("rw is a flag, not a key=value option"),
                        });
                    }
                    opts.read_only = false;
                }
                "debug" => {
                    if value.is_some() {
                        return Err(MountOptionError::InvalidValue {
                            key: String::from("debug"),
                            value: String::from(value.unwrap_or("")),
                            reason: String::from("debug is a flag, not a key=value option"),
                        });
                    }
                    opts.debug = true;
                }
                "recovery" => {
                    if value.is_some() {
                        return Err(MountOptionError::InvalidValue {
                            key: String::from("recovery"),
                            value: String::from(value.unwrap_or("")),
                            reason: String::from("recovery is a flag, not a key=value option"),
                        });
                    }
                    opts.recovery_mode = true;
                }
                "commit_timeout_ms" => {
                    let val_str = value.unwrap_or("5000");
                    let ms: u64 = val_str
                        .parse()
                        .map_err(|_| MountOptionError::InvalidValue {
                            key: String::from("commit_timeout_ms"),
                            value: String::from(val_str),
                            reason: String::from("must be a non-negative integer"),
                        })?;
                    opts.commit_timeout_ms = ms;
                }
                "features" => {
                    let names = value.unwrap_or("");
                    opts.feature_flags = FeatureFlags::parse_names(names)?;
                }
                "cluster_node_id" => {
                    let node_id = value.unwrap_or("");
                    if node_id.is_empty() {
                        return Err(MountOptionError::InvalidValue {
                            key: String::from("cluster_node_id"),
                            value: String::from(""),
                            reason: String::from("cluster node id must be non-empty"),
                        });
                    }
                    opts.cluster_node_id = String::from(node_id);
                }
                "transport_carrier" => {
                    let carrier_str = value.unwrap_or("none");
                    opts.transport_carrier =
                        TransportCarrier::parse(carrier_str).ok_or_else(|| {
                            MountOptionError::InvalidValue {
                                key: String::from("transport_carrier"),
                                value: String::from(carrier_str),
                                reason: String::from("must be none, tcp, rdma, or loopback"),
                            }
                        })?;
                }
                "authority_mode" => {
                    let mode_str = value.unwrap_or("");
                    opts.authority_mode =
                        EngineAuthorityMode::parse(mode_str).ok_or_else(|| {
                            MountOptionError::InvalidValue {
                                key: String::from("authority_mode"),
                                value: String::from(mode_str),
                                reason: String::from("must be full-kernel or mixed"),
                            }
                        })?;
                }
                _ => unreachable!("VALID_KEYS guard prevents this branch"),
            }
        }

        Ok(opts)
    }

    /// Check requested features against the engine's supported set.
    ///
    /// Returns `Ok(())` when every requested feature is supported.
    /// Returns the first unsupported feature as
    /// [`MountOptionError::FeatureRefused`] when a gap is found.
    pub fn refuse_unsupported_features(
        &self,
        supported: FeatureFlags,
    ) -> Result<(), MountOptionError> {
        let unsupported = self.feature_flags.unsupported_against(supported);
        if unsupported.is_empty() {
            return Ok(());
        }
        // Find the first unsupported bit and report it by name.
        let mut bit: u64 = 1;
        loop {
            if bit > unsupported.bits() {
                return Err(MountOptionError::FeatureRefused {
                    requested_name: String::from("unknown"),
                    requested_bit: 0,
                });
            }
            if unsupported.contains(bit) {
                let name = FeatureFlags::name(bit).unwrap_or("unknown");
                return Err(MountOptionError::FeatureRefused {
                    requested_name: String::from(name),
                    requested_bit: bit,
                });
            }
            bit <<= 1;
        }
    }

    /// Return true when the mount is configured for read-only access.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Compute a BLAKE3-256 domain-separated digest of the mount options.
    ///
    /// The digest covers (`device_path` || `read_only` || `debug` ||
    /// `recovery_mode` || `commit_timeout_ms` || `feature_flags` ||
    /// `authority_mode`) and is domain-separated with [`Self::HASH_DOMAIN`].
    /// This allows validation harnesses to verify that a mount operation was
    /// configured with the expected parameters.
    #[must_use]
    pub fn compute_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(Self::HASH_DOMAIN);
        hasher.update(self.device_path.as_bytes());
        hasher.update(self.cluster_node_id.as_bytes());
        hasher.update(&[self.transport_carrier as u8]);
        hasher.update(&[u8::from(self.read_only)]);
        hasher.update(&[u8::from(self.debug)]);
        hasher.update(&[u8::from(self.recovery_mode)]);
        hasher.update(&self.commit_timeout_ms.to_le_bytes());
        hasher.update(&self.feature_flags.bits().to_le_bytes());
        hasher.update(&[self.authority_mode as u8]);
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Default ──────────────────────────────────────────────────────────

    #[test]
    fn default_values() {
        let opts = MountOptions::default();
        assert!(opts.device_path.is_empty());
        assert!(!opts.read_only);
        assert!(!opts.debug);
        assert!(!opts.recovery_mode);
        assert_eq!(opts.commit_timeout_ms, 5000);
        assert!(opts.feature_flags.is_empty());
        assert_eq!(opts.authority_mode, EngineAuthorityMode::Unspecified);
    }

    // ── Empty input ──────────────────────────────────────────────────────

    #[test]
    fn parse_empty_string_returns_defaults() {
        let opts = MountOptions::parse("").unwrap();
        assert_eq!(opts, MountOptions::default());
    }

    #[test]
    fn parse_whitespace_only_returns_defaults() {
        let opts = MountOptions::parse("  ,  ,  ").unwrap();
        assert_eq!(opts, MountOptions::default());
    }

    // ── device parsing ──────────────────────────────────────────────────

    #[test]
    fn parse_device_path() {
        let opts = MountOptions::parse("device=/dev/tidefs/pool0").unwrap();
        assert_eq!(opts.device_path, "/dev/tidefs/pool0");
    }

    #[test]
    fn parse_device_path_with_spaces() {
        let opts = MountOptions::parse("device = /dev/tidefs/pool0").unwrap();
        assert_eq!(opts.device_path, "/dev/tidefs/pool0");
    }

    #[test]
    fn parse_device_empty_value_rejected() {
        let err = MountOptions::parse("device=").unwrap_err();
        match err {
            MountOptionError::InvalidValue { key, .. } => {
                assert_eq!(key, "device");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // ── Flag options ────────────────────────────────────────────────────

    #[test]
    fn parse_ro_flag() {
        let opts = MountOptions::parse("ro").unwrap();
        assert!(opts.read_only);
    }

    #[test]
    fn parse_rw_flag() {
        let opts = MountOptions::parse("rw").unwrap();
        assert!(!opts.read_only);
    }

    #[test]
    fn parse_debug_flag() {
        let opts = MountOptions::parse("debug").unwrap();
        assert!(opts.debug);
    }

    #[test]
    fn parse_recovery_flag() {
        let opts = MountOptions::parse("recovery").unwrap();
        assert!(opts.recovery_mode);
    }

    #[test]
    fn parse_multiple_flags() {
        let opts = MountOptions::parse("device=/dev/pool,ro,debug,recovery").unwrap();
        assert_eq!(opts.device_path, "/dev/pool");
        assert!(opts.read_only);
        assert!(opts.debug);
        assert!(opts.recovery_mode);
    }

    // ── Flag with value rejected ────────────────────────────────────────

    #[test]
    fn ro_with_value_rejected() {
        let err = MountOptions::parse("ro=1").unwrap_err();
        assert!(matches!(err, MountOptionError::InvalidValue { .. }));
    }

    #[test]
    fn debug_with_value_rejected() {
        let err = MountOptions::parse("debug=true").unwrap_err();
        assert!(matches!(err, MountOptionError::InvalidValue { .. }));
    }

    #[test]
    fn recovery_with_value_rejected() {
        let err = MountOptions::parse("recovery=yes").unwrap_err();
        assert!(matches!(err, MountOptionError::InvalidValue { .. }));
    }

    #[test]
    fn rw_with_value_rejected() {
        let err = MountOptions::parse("rw=1").unwrap_err();
        assert!(matches!(err, MountOptionError::InvalidValue { .. }));
    }

    // ── commit_timeout_ms ───────────────────────────────────────────────

    #[test]
    fn parse_commit_timeout_ms() {
        let opts = MountOptions::parse("commit_timeout_ms=10000").unwrap();
        assert_eq!(opts.commit_timeout_ms, 10000);
    }

    #[test]
    fn parse_commit_timeout_ms_default_when_omitted() {
        let opts = MountOptions::parse("device=/dev/pool").unwrap();
        assert_eq!(opts.commit_timeout_ms, 5000);
    }

    #[test]
    fn commit_timeout_ms_invalid_value() {
        let err = MountOptions::parse("commit_timeout_ms=abc").unwrap_err();
        assert!(matches!(err, MountOptionError::InvalidValue { .. }));
    }

    #[test]
    fn commit_timeout_ms_negative_rejected() {
        let err = MountOptions::parse("commit_timeout_ms=-1").unwrap_err();
        assert!(matches!(err, MountOptionError::InvalidValue { .. }));
    }

    #[test]
    fn commit_timeout_ms_zero_allowed() {
        let opts = MountOptions::parse("commit_timeout_ms=0").unwrap();
        assert_eq!(opts.commit_timeout_ms, 0);
    }

    // ── features parsing ─────────────────────────────────────────────────

    #[test]
    fn parse_features_empty() {
        let opts = MountOptions::parse("features=").unwrap();
        assert!(opts.feature_flags.is_empty());
    }

    #[test]
    fn parse_single_feature() {
        let opts = MountOptions::parse("features=direct_io").unwrap();
        assert!(opts.feature_flags.contains(FeatureFlags::DIRECT_IO));
    }

    #[test]
    fn parse_multiple_features() {
        let opts = MountOptions::parse("features=direct_io:writeback_cache").unwrap();
        assert!(opts.feature_flags.contains(FeatureFlags::DIRECT_IO));
        assert!(opts.feature_flags.contains(FeatureFlags::WRITEBACK_CACHE));
    }

    #[test]
    fn parse_features_with_spaces() {
        let opts = MountOptions::parse("features = direct_io : rdma").unwrap();
        assert!(opts.feature_flags.contains(FeatureFlags::DIRECT_IO));
        assert!(opts.feature_flags.contains(FeatureFlags::RDMA));
    }

    #[test]
    fn parse_unknown_feature_rejected() {
        let err = MountOptions::parse("features=nonexistent_feature").unwrap_err();
        assert!(matches!(err, MountOptionError::UnknownFeature { .. }));
    }

    #[test]
    fn parse_all_features() {
        let opts = MountOptions::parse(
            "features=direct_io:writeback_cache:compression:encryption:dedup:snapshots:rdma",
        )
        .unwrap();
        assert!(opts.feature_flags.contains(FeatureFlags::DIRECT_IO));
        assert!(opts.feature_flags.contains(FeatureFlags::WRITEBACK_CACHE));
        assert!(opts.feature_flags.contains(FeatureFlags::COMPRESSION));
        assert!(opts.feature_flags.contains(FeatureFlags::ENCRYPTION));
        assert!(opts.feature_flags.contains(FeatureFlags::DEDUP));
        assert!(opts.feature_flags.contains(FeatureFlags::SNAPSHOTS));
        assert!(opts.feature_flags.contains(FeatureFlags::RDMA));
    }

    // ── authority_mode parsing ───────────────────────────────────────────

    #[test]
    fn parse_authority_mode_full_kernel() {
        let opts = MountOptions::parse("authority_mode=full-kernel").unwrap();
        assert_eq!(opts.authority_mode, EngineAuthorityMode::FullKernel);
    }

    #[test]
    fn parse_authority_mode_mixed() {
        let opts = MountOptions::parse("authority_mode=mixed").unwrap();
        assert_eq!(opts.authority_mode, EngineAuthorityMode::MixedMode);
    }

    #[test]
    fn parse_authority_mode_mixed_mode() {
        let opts = MountOptions::parse("authority_mode=mixed-mode").unwrap();
        assert_eq!(opts.authority_mode, EngineAuthorityMode::MixedMode);
    }

    #[test]
    fn parse_authority_mode_invalid_rejected() {
        let err = MountOptions::parse("authority_mode=userspace").unwrap_err();
        assert!(matches!(err, MountOptionError::InvalidValue { .. }));
    }

    #[test]
    fn parse_authority_mode_empty_rejected() {
        let err = MountOptions::parse("authority_mode=").unwrap_err();
        assert!(matches!(err, MountOptionError::InvalidValue { .. }));
    }

    // ── Feature refusal (refuse_unsupported_features) ────────────────────

    #[test]
    fn refuse_no_features_when_empty() {
        let opts = MountOptions::default();
        let supported = FeatureFlags::NONE;
        opts.refuse_unsupported_features(supported).unwrap();
    }

    #[test]
    fn refuse_all_requested_supported() {
        let opts = MountOptions::parse("features=direct_io:rdma").unwrap();
        let supported = FeatureFlags(FeatureFlags::DIRECT_IO | FeatureFlags::RDMA);
        opts.refuse_unsupported_features(supported).unwrap();
    }

    #[test]
    fn refuse_unsupported_feature_detected() {
        let opts = MountOptions::parse("features=compression").unwrap();
        let supported = FeatureFlags::NONE;
        let err = opts.refuse_unsupported_features(supported).unwrap_err();
        assert!(matches!(err, MountOptionError::FeatureRefused { .. }));
    }

    #[test]
    fn refuse_partial_support_rejected() {
        let opts = MountOptions::parse("features=direct_io:compression").unwrap();
        let supported = FeatureFlags(FeatureFlags::DIRECT_IO);
        let err = opts.refuse_unsupported_features(supported).unwrap_err();
        match err {
            MountOptionError::FeatureRefused { requested_name, .. } => {
                assert_eq!(requested_name, "compression");
            }
            other => panic!("expected FeatureRefused, got {other:?}"),
        }
    }

    // ── FeatureFlags helpers ─────────────────────────────────────────────

    #[test]
    fn feature_flags_contains() {
        let flags = FeatureFlags(FeatureFlags::DIRECT_IO | FeatureFlags::RDMA);
        assert!(flags.contains(FeatureFlags::DIRECT_IO));
        assert!(flags.contains(FeatureFlags::RDMA));
        assert!(!flags.contains(FeatureFlags::COMPRESSION));
    }

    #[test]
    fn feature_flags_unsupported_against() {
        let requested = FeatureFlags(FeatureFlags::DIRECT_IO | FeatureFlags::COMPRESSION);
        let supported = FeatureFlags(FeatureFlags::DIRECT_IO);
        let unsupported = requested.unsupported_against(supported);
        assert!(unsupported.contains(FeatureFlags::COMPRESSION));
        assert!(!unsupported.contains(FeatureFlags::DIRECT_IO));
    }

    #[test]
    fn feature_flags_name_roundtrip() {
        for bit in [
            FeatureFlags::DIRECT_IO,
            FeatureFlags::WRITEBACK_CACHE,
            FeatureFlags::COMPRESSION,
            FeatureFlags::ENCRYPTION,
            FeatureFlags::DEDUP,
            FeatureFlags::SNAPSHOTS,
            FeatureFlags::RDMA,
        ] {
            let name = FeatureFlags::name(bit).unwrap();
            let parsed = FeatureFlags::parse_names(name).unwrap();
            assert!(parsed.contains(bit));
        }
    }

    #[test]
    fn feature_flags_default_is_empty() {
        let flags = FeatureFlags::default();
        assert!(flags.is_empty());
        assert_eq!(flags.bits(), 0);
    }

    // ── is_read_only helper ──────────────────────────────────────────────

    #[test]
    fn is_read_only_reflects_flag() {
        let opts = MountOptions::parse("ro").unwrap();
        assert!(opts.is_read_only());
        let opts = MountOptions::parse("rw").unwrap();
        assert!(!opts.is_read_only());
    }

    // ── Unknown option ──────────────────────────────────────────────────

    #[test]
    fn unknown_option_rejected() {
        let err = MountOptions::parse("foo=bar").unwrap_err();
        match err {
            MountOptionError::UnknownOption { key } => {
                assert_eq!(key, "foo");
            }
            other => panic!("expected UnknownOption, got {other:?}"),
        }
    }

    // ── Duplicate option ────────────────────────────────────────────────

    #[test]
    fn duplicate_option_rejected() {
        let err = MountOptions::parse("ro,ro").unwrap_err();
        match err {
            MountOptionError::DuplicateOption { key } => {
                assert_eq!(key, "ro");
            }
            other => panic!("expected DuplicateOption, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_device_rejected() {
        let err = MountOptions::parse("device=/dev/a,device=/dev/b").unwrap_err();
        match err {
            MountOptionError::DuplicateOption { key } => {
                assert_eq!(key, "device");
            }
            other => panic!("expected DuplicateOption, got {other:?}"),
        }
    }

    // ── Complex combinations ────────────────────────────────────────────

    #[test]
    fn parse_full_option_set() {
        let opts = MountOptions::parse(
            "device=/dev/tidefs/test,ro,debug,recovery,commit_timeout_ms=10000,features=direct_io,authority_mode=full-kernel",
        )
        .unwrap();
        assert_eq!(opts.device_path, "/dev/tidefs/test");
        assert!(opts.read_only);
        assert!(opts.debug);
        assert!(opts.recovery_mode);
        assert_eq!(opts.commit_timeout_ms, 10000);
        assert!(opts.feature_flags.contains(FeatureFlags::DIRECT_IO));
        assert_eq!(opts.authority_mode, EngineAuthorityMode::FullKernel);
    }

    #[test]
    fn rw_overrides_ro() {
        // Last flag wins when both are present (rw is parsed after ro).
        let opts = MountOptions::parse("ro,rw").unwrap();
        assert!(!opts.read_only);
    }

    #[test]
    fn ro_overrides_rw() {
        // Last flag wins (ro is parsed after rw).
        let opts = MountOptions::parse("rw,ro").unwrap();
        assert!(opts.read_only);
    }

    #[test]
    fn rw_and_ro_is_not_duplicate_error() {
        // rw and ro are distinct keys, so no duplicate error.
        let opts = MountOptions::parse("rw,ro").unwrap();
        assert!(opts.read_only);
    }

    // ── MountOptionError Display ──────────────────────────────────────

    #[test]
    fn mount_option_error_display() {
        let e = MountOptionError::UnknownOption {
            key: String::from("foo"),
        };
        assert_eq!(alloc::format!("{e}"), "unknown mount option: foo");

        let e = MountOptionError::InvalidValue {
            key: String::from("commit_timeout_ms"),
            value: String::from("abc"),
            reason: String::from("must be a non-negative integer"),
        };
        assert_eq!(
            alloc::format!("{e}"),
            "invalid value for commit_timeout_ms: abc (must be a non-negative integer)"
        );

        let e = MountOptionError::MissingRequired {
            key: String::from("device"),
        };
        assert_eq!(
            alloc::format!("{e}"),
            "missing required mount option: device"
        );

        let e = MountOptionError::DuplicateOption {
            key: String::from("ro"),
        };
        assert_eq!(alloc::format!("{e}"), "duplicate mount option: ro");

        let e = MountOptionError::UnknownFeature {
            name: String::from("bogus"),
        };
        assert_eq!(alloc::format!("{e}"), "unknown mount feature: bogus");

        let e = MountOptionError::FeatureRefused {
            requested_name: String::from("compression"),
            requested_bit: 4,
        };
        assert_eq!(
            alloc::format!("{e}"),
            "requested feature not supported by current engine: compression"
        );
    }

    // ── BLAKE3 deterministic hashing ────────────────────────────────────

    #[test]
    fn blake3_digest_deterministic() {
        let a = MountOptions {
            device_path: String::from("/dev/tidefs/pool0"),
            read_only: true,
            debug: false,
            recovery_mode: true,
            commit_timeout_ms: 7000,
            feature_flags: FeatureFlags(FeatureFlags::DIRECT_IO),
            cluster_node_id: String::new(),
            authority_mode: EngineAuthorityMode::FullKernel,
            transport_carrier: TransportCarrier::None,
        };
        let b = MountOptions {
            device_path: String::from("/dev/tidefs/pool0"),
            read_only: true,
            debug: false,
            recovery_mode: true,
            commit_timeout_ms: 7000,
            feature_flags: FeatureFlags(FeatureFlags::DIRECT_IO),
            cluster_node_id: String::new(),
            authority_mode: EngineAuthorityMode::FullKernel,
            transport_carrier: TransportCarrier::None,
        };
        assert_eq!(a.compute_digest(), b.compute_digest());
    }

    #[test]
    fn blake3_digest_distinct_for_different_paths() {
        let a = MountOptions {
            device_path: String::from("/dev/tidefs/pool0"),
            ..MountOptions::default()
        };
        let b = MountOptions {
            device_path: String::from("/dev/tidefs/pool1"),
            ..MountOptions::default()
        };
        assert_ne!(a.compute_digest(), b.compute_digest());
    }

    #[test]
    fn blake3_digest_distinct_for_different_bool_flags() {
        let a = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let b = MountOptions {
            read_only: true,
            ..MountOptions::default()
        };
        assert_ne!(a.compute_digest(), b.compute_digest());

        let a = MountOptions {
            debug: false,
            ..MountOptions::default()
        };
        let b = MountOptions {
            debug: true,
            ..MountOptions::default()
        };
        assert_ne!(a.compute_digest(), b.compute_digest());

        let a = MountOptions {
            recovery_mode: false,
            ..MountOptions::default()
        };
        let b = MountOptions {
            recovery_mode: true,
            ..MountOptions::default()
        };
        assert_ne!(a.compute_digest(), b.compute_digest());
    }

    #[test]
    fn blake3_digest_distinct_for_different_timeout() {
        let a = MountOptions {
            commit_timeout_ms: 5000,
            ..MountOptions::default()
        };
        let b = MountOptions {
            commit_timeout_ms: 10000,
            ..MountOptions::default()
        };
        assert_ne!(a.compute_digest(), b.compute_digest());
    }

    #[test]
    fn blake3_digest_distinct_for_different_features() {
        let a = MountOptions {
            feature_flags: FeatureFlags::NONE,
            ..MountOptions::default()
        };
        let b = MountOptions {
            feature_flags: FeatureFlags(FeatureFlags::DIRECT_IO),
            ..MountOptions::default()
        };
        assert_ne!(a.compute_digest(), b.compute_digest());
    }

    #[test]
    fn blake3_digest_distinct_for_different_authority_mode() {
        let a = MountOptions {
            authority_mode: EngineAuthorityMode::FullKernel,
            ..MountOptions::default()
        };
        let b = MountOptions {
            authority_mode: EngineAuthorityMode::MixedMode,
            ..MountOptions::default()
        };
        assert_ne!(a.compute_digest(), b.compute_digest());
    }

    #[test]
    fn blake3_digest_parse_roundtrip() {
        let input = "device=/dev/tidefs/test,ro,recovery,commit_timeout_ms=7000,features=direct_io,authority_mode=full-kernel";
        let a = MountOptions::parse(input).unwrap();
        let b = MountOptions::parse(input).unwrap();
        assert_eq!(a.compute_digest(), b.compute_digest());
        assert_ne!(a.compute_digest(), [0u8; 32]);
    }

    #[test]
    fn blake3_digest_domain_isolation() {
        let opts = MountOptions {
            device_path: String::from("/dev/tidefs/test"),
            read_only: false,
            debug: true,
            recovery_mode: false,
            commit_timeout_ms: 3000,
            feature_flags: FeatureFlags::NONE,
            cluster_node_id: String::new(),
            authority_mode: EngineAuthorityMode::Unspecified,
            transport_carrier: TransportCarrier::None,
        };

        let domain_digest = opts.compute_digest();

        let mut hasher = blake3::Hasher::new();
        hasher.update(opts.device_path.as_bytes());
        hasher.update(&[u8::from(opts.read_only)]);
        hasher.update(&[u8::from(opts.debug)]);
        hasher.update(&[u8::from(opts.recovery_mode)]);
        hasher.update(&opts.commit_timeout_ms.to_le_bytes());
        hasher.update(&opts.feature_flags.bits().to_le_bytes());
        hasher.update(&[opts.authority_mode as u8]);
        let raw_digest: [u8; 32] = hasher.finalize().into();

        assert_ne!(domain_digest, raw_digest);
    }
}

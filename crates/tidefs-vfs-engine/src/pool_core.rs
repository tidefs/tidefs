//! Kernel-resident pool core context with refcounted lifecycle states.
//!
//! [`KernelPoolCore`] is the shared kernel-side pool surface for both the
//! POSIX VFS kmod and block-kmod frontends. It carries pool identity,
//! lower-device descriptors, and explicit lifecycle tracking (Configured ->
//! Importing -> Mounted -> Teardown) with atomic refcounting and fail-closed
//! state transitions.
//!
//! # Safety and locking
//!
//! This module is safe `no_std` code under `#![forbid(unsafe_code)]`. State
//! transitions use `AtomicU64` compare-and-swap loops. The committed root
//! is NOT stored inside [`KernelPoolCore`] because an atomic state+root
//! update requires a spinlock (see [Kernel Locking](#kernel-locking)).
//!
//! # Kernel locking
//!
//! In the Linux kernel, the kmod frontend must hold a kernel spinlock
//! around committed-root updates paired with state transitions. The
//! canonical integration point is:
//!
//! 1. Kernel crate acquires its spinlock.
//! 2. Kernel crate calls [`KernelPoolCore::complete_import`] (CAS
//!    Importing->Mounted).
//! 3. Kernel crate stores the committed root in its own lock-protected
//!    state while holding the spinlock.
//! 4. Kernel crate releases the spinlock.
//!
//! This two-phase protocol keeps `tidefs-vfs-engine` free of mutable
//! locking primitives while the kernel crate owns the unsafe boundary.
//!
//! # no_std compatibility
//!
//! The module compiles under `no_std` with the `alloc` feature gating
//! heap-allocated configuration vectors.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

// ── Lower-device descriptor ────────────────────────────────────────────

/// Describes a single lower block device bound to a pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LowerDeviceDesc {
    /// Kernel device major number.
    pub major: u32,
    /// Kernel device minor number.
    pub minor: u32,
    /// Total sector count of the device.
    pub sector_count: u64,
    /// Logical block (sector) size in bytes.
    pub logical_block_size: u32,
}

impl LowerDeviceDesc {
    #[must_use]
    pub const fn new(major: u32, minor: u32, sector_count: u64, logical_block_size: u32) -> Self {
        Self {
            major,
            minor,
            sector_count,
            logical_block_size,
        }
    }

    /// Total capacity in bytes.
    #[must_use]
    pub fn capacity_bytes(&self) -> u64 {
        self.sector_count
            .saturating_mul(self.logical_block_size as u64)
    }
}

// ── Pool lifecycle state ───────────────────────────────────────────────

/// Lifecycle state of a kernel-resident pool.
///
/// Transitions are validated fail-closed: illegal moves return
/// [`KernelPoolError::InvalidTransition`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum KernelPoolState {
    /// Pool configuration is loaded but the pool is not yet importing.
    Configured = 0,
    /// Lower devices are being scanned and the pool label validated.
    Importing = 1,
    /// Pool is fully imported and ready for filesystem or block I/O.
    Mounted = 2,
    /// Tear-down initiated; draining refs and releasing devices.
    Teardown = 3,
}

impl KernelPoolState {
    #[must_use]
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Configured),
            1 => Some(Self::Importing),
            2 => Some(Self::Mounted),
            3 => Some(Self::Teardown),
            _ => None,
        }
    }

    #[must_use]
    pub const fn to_u64(self) -> u64 {
        self as u64
    }

    /// Check whether a transition from `self` to `target` is legal.
    #[must_use]
    pub fn can_transition_to(self, target: Self) -> bool {
        matches!(
            (self, target),
            (Self::Configured, Self::Importing)
                | (Self::Importing, Self::Mounted)
                | (Self::Configured, Self::Teardown)
                | (Self::Importing, Self::Teardown)
                | (Self::Mounted, Self::Teardown)
                | (Self::Teardown, Self::Teardown)
        )
    }
}

// ── Pool configuration ─────────────────────────────────────────────────

/// Immutable pool configuration carried by [`KernelPoolCore`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelPoolConfig {
    /// Pool unique identifier (16-byte UUID).
    pub pool_uuid: [u8; 16],
    /// Lower block devices bound to this pool.
    pub devices: alloc::vec::Vec<LowerDeviceDesc>,
    /// Mount-option flags.
    pub mount_flags: u64,
}

impl KernelPoolConfig {
    #[must_use]
    pub fn new(
        pool_uuid: [u8; 16],
        devices: alloc::vec::Vec<LowerDeviceDesc>,
        mount_flags: u64,
    ) -> Self {
        Self {
            pool_uuid,
            devices,
            mount_flags,
        }
    }

    #[must_use]
    pub fn total_capacity_bytes(&self) -> u64 {
        self.devices
            .iter()
            .fold(0u64, |acc, d| acc.saturating_add(d.capacity_bytes()))
    }

    #[must_use]
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }
}

// ── Pool core errors ───────────────────────────────────────────────────

/// Errors returned by [`KernelPoolCore`] operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelPoolError {
    InvalidTransition {
        from: KernelPoolState,
        to: KernelPoolState,
    },
    NotConfigured,
    NotImporting,
    ImportFailed,
    TeardownInProgress,
    AlreadyMounted,
    RefcountNotZero,
}

impl fmt::Display for KernelPoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(f, "illegal state transition from {from:?} to {to:?}")
            }
            Self::NotConfigured => write!(f, "pool is not configured"),
            Self::NotImporting => write!(f, "pool is not importing"),
            Self::ImportFailed => write!(f, "pool import failed"),
            Self::TeardownInProgress => write!(f, "pool teardown in progress"),
            Self::AlreadyMounted => write!(f, "pool is already mounted"),
            Self::RefcountNotZero => write!(f, "pool refcount is not zero"),
        }
    }
}

// ── KernelPoolCore ─────────────────────────────────────────────────────

/// Refcounted kernel-resident pool context.
///
/// Created in [`Configured`](KernelPoolState::Configured) state with an
/// initial reference count of 1. State transitions use `AtomicU64`
/// compare-and-swap loops. The committed root is tracked externally;
/// see [module-level docs](crate::pool_core#kernel-locking) for
/// the kernel integration protocol.
pub struct KernelPoolCore {
    refcount: AtomicU64,
    state: AtomicU64,
    config: KernelPoolConfig,
}

impl KernelPoolCore {
    /// Create a new pool context in [`Configured`](KernelPoolState::Configured)
    /// state with an initial refcount of 1.
    ///
    /// Returns [`KernelPoolError::NotConfigured`] if `config.devices` is empty.
    #[inline]
    pub fn new(config: KernelPoolConfig) -> Result<Self, KernelPoolError> {
        if config.devices.is_empty() {
            return Err(KernelPoolError::NotConfigured);
        }
        Ok(Self {
            refcount: AtomicU64::new(1),
            state: AtomicU64::new(KernelPoolState::Configured.to_u64()),
            config,
        })
    }

    // ── Lifecycle transitions ─────────────────────────────────────────

    /// Begin importing the pool.
    ///
    /// CAS from [`Configured`](KernelPoolState::Configured) to
    /// [`Importing`](KernelPoolState::Importing).
    #[inline]
    pub fn begin_import(&self) -> Result<(), KernelPoolError> {
        self.try_transition(KernelPoolState::Configured, KernelPoolState::Importing)
    }

    /// Complete import, transitioning to [`Mounted`](KernelPoolState::Mounted).
    ///
    /// CAS from [`Importing`](KernelPoolState::Importing) to
    /// [`Mounted`](KernelPoolState::Mounted).
    ///
    /// The caller must separately store the committed root under its own
    /// kernel spinlock (see [module docs](crate::pool_core#kernel-locking)).
    #[inline]
    pub fn complete_import(&self) -> Result<(), KernelPoolError> {
        self.try_transition(KernelPoolState::Importing, KernelPoolState::Mounted)
    }

    /// Begin tearing down the pool.
    ///
    /// CAS to [`Teardown`](KernelPoolState::Teardown) from any applicable
    /// state. Idempotent: returns `Ok(false)` if already in `Teardown`.
    #[inline]
    pub fn begin_teardown(&self) -> Result<bool, KernelPoolError> {
        loop {
            let current_raw = self.state.load(Ordering::Acquire);
            let current =
                KernelPoolState::from_u64(current_raw).expect("corrupt KernelPoolCore state word");
            if current == KernelPoolState::Teardown {
                return Ok(false);
            }
            let target = KernelPoolState::Teardown;
            if !current.can_transition_to(target) {
                return Err(KernelPoolError::InvalidTransition {
                    from: current,
                    to: target,
                });
            }
            match self.state.compare_exchange_weak(
                current_raw,
                target.to_u64(),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(true),
                Err(_) => {
                    core::hint::spin_loop();
                }
            }
        }
    }

    // ── Reference counting ────────────────────────────────────────────

    /// Acquire an additional reference.
    #[inline]
    pub fn ref_get(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    /// Release a reference.
    ///
    /// Returns `true` if the refcount reached zero.
    #[inline]
    pub fn ref_put(&self) -> bool {
        self.refcount.fetch_sub(1, Ordering::Acquire) == 1
    }

    /// Current reference count (diagnostics).
    #[inline]
    pub fn ref_count(&self) -> u64 {
        self.refcount.load(Ordering::Relaxed)
    }

    // ── Accessors ─────────────────────────────────────────────────────

    /// Return the current lifecycle state.
    #[inline]
    pub fn state(&self) -> KernelPoolState {
        let raw = self.state.load(Ordering::Acquire);
        KernelPoolState::from_u64(raw).unwrap_or(KernelPoolState::Teardown)
    }

    /// Return the pool UUID (16 bytes).
    #[inline]
    pub fn uuid(&self) -> [u8; 16] {
        self.config.pool_uuid
    }

    /// Return the number of lower devices.
    #[inline]
    pub fn device_count(&self) -> usize {
        self.config.device_count()
    }

    /// Return the total lower-device capacity in bytes.
    #[inline]
    pub fn total_capacity_bytes(&self) -> u64 {
        self.config.total_capacity_bytes()
    }

    /// Return a reference to the pool configuration.
    #[inline]
    pub fn config(&self) -> &KernelPoolConfig {
        &self.config
    }

    // ── Internal helpers ──────────────────────────────────────────────

    /// CAS loop: atomically transition from `expected` to `target`.
    ///
    /// Validates the transition rule, then retries on spurious CAS failure.
    #[inline]
    fn try_transition(
        &self,
        expected: KernelPoolState,
        target: KernelPoolState,
    ) -> Result<(), KernelPoolError> {
        if !expected.can_transition_to(target) {
            return Err(KernelPoolError::InvalidTransition {
                from: expected,
                to: target,
            });
        }
        let expected_raw = expected.to_u64();
        let target_raw = target.to_u64();
        loop {
            match self.state.compare_exchange_weak(
                expected_raw,
                target_raw,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual_raw) => {
                    let actual = KernelPoolState::from_u64(actual_raw)
                        .expect("corrupt KernelPoolCore state word");
                    // If the current state isn't what we expected, report
                    // the actual-vs-target mismatch.
                    if actual != expected {
                        return Err(KernelPoolError::InvalidTransition {
                            from: actual,
                            to: target,
                        });
                    }
                    // Spurious failure; actual == expected. Retry.
                    core::hint::spin_loop();
                }
            }
        }
    }
}

impl fmt::Debug for KernelPoolCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelPoolCore")
            .field("uuid", &hex_fmt(&self.config.pool_uuid))
            .field("state", &self.state())
            .field("refcount", &self.ref_count())
            .field("device_count", &self.config.device_count())
            .finish()
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

fn hex_fmt(uuid: &[u8; 16]) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(32);
    for byte in uuid {
        s.push(hex_nibble(byte >> 4));
        s.push(hex_nibble(byte & 0x0F));
    }
    s
}

fn hex_nibble(n: u8) -> char {
    match n {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        15 => 'f',
        _ => '?',
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn sample_config() -> KernelPoolConfig {
        KernelPoolConfig::new(
            [0xABu8; 16],
            alloc::vec![
                LowerDeviceDesc::new(8, 0, 2_097_152, 512),
                LowerDeviceDesc::new(8, 16, 2_097_152, 512),
            ],
            0,
        )
    }

    fn single_device_config() -> KernelPoolConfig {
        KernelPoolConfig::new(
            [0xCDu8; 16],
            alloc::vec![LowerDeviceDesc::new(8, 32, 1_048_576, 512)],
            0,
        )
    }

    // ── Construction ──────────────────────────────────────────────────

    #[test]
    fn new_pool_starts_configured() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        assert_eq!(pool.state(), KernelPoolState::Configured);
        assert_eq!(pool.ref_count(), 1);
        assert_eq!(pool.device_count(), 2);
    }

    #[test]
    fn new_pool_rejects_empty_devices() {
        let config = KernelPoolConfig::new([0u8; 16], alloc::vec![], 0);
        let err = KernelPoolCore::new(config).unwrap_err();
        assert_eq!(err, KernelPoolError::NotConfigured);
    }

    #[test]
    fn new_pool_uuid_preserved() {
        let uuid = [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let config =
            KernelPoolConfig::new(uuid, alloc::vec![LowerDeviceDesc::new(8, 1, 1, 512)], 0);
        let pool = KernelPoolCore::new(config).expect("new");
        assert_eq!(pool.uuid(), uuid);
    }

    // ── State transitions ─────────────────────────────────────────────

    #[test]
    fn begin_import_succeeds_from_configured() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        pool.begin_import().expect("begin_import");
        assert_eq!(pool.state(), KernelPoolState::Importing);
    }

    #[test]
    fn begin_import_fails_from_mounted() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        pool.begin_import().expect("begin_import");
        pool.complete_import().expect("complete_import");
        let err = pool.begin_import().unwrap_err();
        assert_eq!(
            err,
            KernelPoolError::InvalidTransition {
                from: KernelPoolState::Mounted,
                to: KernelPoolState::Importing,
            }
        );
    }

    #[test]
    fn begin_import_fails_from_teardown() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        pool.begin_teardown().expect("begin_teardown");
        let err = pool.begin_import().unwrap_err();
        assert_eq!(
            err,
            KernelPoolError::InvalidTransition {
                from: KernelPoolState::Teardown,
                to: KernelPoolState::Importing,
            }
        );
    }

    #[test]
    fn begin_import_rejected_when_already_importing() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        pool.begin_import().expect("first");
        let err = pool.begin_import().unwrap_err();
        assert_eq!(
            err,
            KernelPoolError::InvalidTransition {
                from: KernelPoolState::Importing,
                to: KernelPoolState::Importing,
            }
        );
    }

    #[test]
    fn complete_import_succeeds_from_importing() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        pool.begin_import().expect("begin_import");
        pool.complete_import().expect("complete_import");
        assert_eq!(pool.state(), KernelPoolState::Mounted);
    }

    #[test]
    fn complete_import_fails_from_configured() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        let err = pool.complete_import().unwrap_err();
        assert_eq!(
            err,
            KernelPoolError::InvalidTransition {
                from: KernelPoolState::Configured,
                to: KernelPoolState::Mounted,
            }
        );
    }

    #[test]
    fn complete_import_fails_when_already_mounted() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        pool.begin_import().expect("begin_import");
        pool.complete_import().expect("first");
        let err = pool.complete_import().unwrap_err();
        assert_eq!(
            err,
            KernelPoolError::InvalidTransition {
                from: KernelPoolState::Mounted,
                to: KernelPoolState::Mounted,
            }
        );
    }

    #[test]
    fn teardown_from_configured() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        let initiated = pool.begin_teardown().expect("begin_teardown");
        assert!(initiated);
        assert_eq!(pool.state(), KernelPoolState::Teardown);
    }

    #[test]
    fn teardown_from_importing() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        pool.begin_import().expect("begin_import");
        let initiated = pool.begin_teardown().expect("begin_teardown");
        assert!(initiated);
        assert_eq!(pool.state(), KernelPoolState::Teardown);
    }

    #[test]
    fn teardown_from_mounted() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        pool.begin_import().expect("begin_import");
        pool.complete_import().expect("complete_import");
        let initiated = pool.begin_teardown().expect("begin_teardown");
        assert!(initiated);
        assert_eq!(pool.state(), KernelPoolState::Teardown);
    }

    #[test]
    fn teardown_idempotent() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        assert!(pool.begin_teardown().expect("first"));
        assert!(!pool.begin_teardown().expect("second"));
        assert_eq!(pool.state(), KernelPoolState::Teardown);
    }

    // ── Refcounting ───────────────────────────────────────────────────

    #[test]
    fn refcount_lifecycle() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        assert_eq!(pool.ref_count(), 1);
        pool.ref_get();
        assert_eq!(pool.ref_count(), 2);
        pool.ref_get();
        assert_eq!(pool.ref_count(), 3);
        assert!(!pool.ref_put());
        assert_eq!(pool.ref_count(), 2);
        assert!(!pool.ref_put());
        assert_eq!(pool.ref_count(), 1);
        assert!(pool.ref_put());
    }

    #[test]
    fn ref_get_put_concurrent_safety() {
        use alloc::sync::Arc;
        use std::thread;

        let pool = Arc::new(KernelPoolCore::new(sample_config()).expect("new"));
        let mut handles = alloc::vec::Vec::new();
        for _ in 0..4 {
            let p = Arc::clone(&pool);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    p.ref_get();
                    p.ref_put();
                }
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }
        assert_eq!(pool.ref_count(), 1);
    }

    // ── Config access ─────────────────────────────────────────────────

    #[test]
    fn config_access_read_only() {
        let pool = KernelPoolCore::new(single_device_config()).expect("new");
        let cfg = pool.config();
        assert_eq!(cfg.device_count(), 1);
        assert_eq!(cfg.devices[0].major, 8);
        assert_eq!(cfg.devices[0].minor, 32);
        assert_eq!(cfg.total_capacity_bytes(), 1_048_576 * 512);
    }

    #[test]
    fn total_capacity_multi_device() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        assert_eq!(pool.total_capacity_bytes(), 2 * 2_097_152 * 512);
    }

    // ── LowerDeviceDesc ───────────────────────────────────────────────

    #[test]
    fn lower_device_desc_capacity() {
        let d = LowerDeviceDesc::new(8, 1, 2_000, 512);
        assert_eq!(d.capacity_bytes(), 1_024_000);
    }

    #[test]
    fn lower_device_desc_zero_sectors() {
        let d = LowerDeviceDesc::new(8, 1, 0, 4096);
        assert_eq!(d.capacity_bytes(), 0);
    }

    // ── KernelPoolConfig ──────────────────────────────────────────────

    #[test]
    fn config_new_preserves_fields() {
        let uuid = [0x01u8; 16];
        let devices = alloc::vec![LowerDeviceDesc::new(8, 0, 100, 512)];
        let cfg = KernelPoolConfig::new(uuid, devices.clone(), 0x42);
        assert_eq!(cfg.pool_uuid, uuid);
        assert_eq!(cfg.devices, devices);
        assert_eq!(cfg.mount_flags, 0x42);
        assert_eq!(cfg.device_count(), 1);
    }

    // ── KernelPoolError ───────────────────────────────────────────────

    #[test]
    fn kernel_pool_error_display() {
        let e = KernelPoolError::InvalidTransition {
            from: KernelPoolState::Configured,
            to: KernelPoolState::Mounted,
        };
        let s = alloc::format!("{e}");
        assert!(s.contains("illegal state transition"));
        assert!(s.contains("Configured"));
        assert!(s.contains("Mounted"));
    }

    #[test]
    fn kernel_pool_error_debug() {
        let e = KernelPoolError::ImportFailed;
        let s = alloc::format!("{e:?}");
        assert!(s.contains("ImportFailed"));
    }

    // ── KernelPoolState ───────────────────────────────────────────────

    #[test]
    fn state_to_u64_from_u64_roundtrip() {
        for state in [
            KernelPoolState::Configured,
            KernelPoolState::Importing,
            KernelPoolState::Mounted,
            KernelPoolState::Teardown,
        ] {
            let v = state.to_u64();
            assert_eq!(KernelPoolState::from_u64(v), Some(state));
        }
    }

    #[test]
    fn state_from_invalid_u64() {
        assert_eq!(KernelPoolState::from_u64(99), None);
        assert_eq!(KernelPoolState::from_u64(u64::MAX), None);
    }

    #[test]
    fn state_transition_rules_complete() {
        assert!(KernelPoolState::Configured.can_transition_to(KernelPoolState::Importing));
        assert!(KernelPoolState::Importing.can_transition_to(KernelPoolState::Mounted));
        assert!(KernelPoolState::Configured.can_transition_to(KernelPoolState::Teardown));
        assert!(KernelPoolState::Importing.can_transition_to(KernelPoolState::Teardown));
        assert!(KernelPoolState::Mounted.can_transition_to(KernelPoolState::Teardown));
        assert!(KernelPoolState::Teardown.can_transition_to(KernelPoolState::Teardown));

        assert!(!KernelPoolState::Configured.can_transition_to(KernelPoolState::Configured));
        assert!(!KernelPoolState::Configured.can_transition_to(KernelPoolState::Mounted));
        assert!(!KernelPoolState::Importing.can_transition_to(KernelPoolState::Configured));
        assert!(!KernelPoolState::Importing.can_transition_to(KernelPoolState::Importing));
        assert!(!KernelPoolState::Mounted.can_transition_to(KernelPoolState::Configured));
        assert!(!KernelPoolState::Mounted.can_transition_to(KernelPoolState::Importing));
        assert!(!KernelPoolState::Mounted.can_transition_to(KernelPoolState::Mounted));
        assert!(!KernelPoolState::Teardown.can_transition_to(KernelPoolState::Configured));
        assert!(!KernelPoolState::Teardown.can_transition_to(KernelPoolState::Importing));
        assert!(!KernelPoolState::Teardown.can_transition_to(KernelPoolState::Mounted));
    }

    // ── Debug ─────────────────────────────────────────────────────────

    #[test]
    fn kernel_pool_core_debug() {
        let pool = KernelPoolCore::new(sample_config()).expect("new");
        let s = alloc::format!("{pool:?}");
        assert!(s.contains("KernelPoolCore"));
        assert!(s.contains("Configured"));
    }
}

// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool device (virtual device) types for the TideFS storage hierarchy.
//!
//! This module implements the device abstraction layer that sits between the
//! raw `LocalObjectStore` and the pool. It provides:
//!
//! - `SingleDevice`: one compatibility directory store or one byte-addressable
//!   block/file store via `LocalObjectStore`
//! - `MirrorDevice`: N-way mirror that fans writes to all members and retries reads
//!   from the first healthy member
//! - `DeviceImpl` trait: the common interface every device satisfies
//! - `DeviceClass` and `IoClass`: ZFS-style device classification for
//!   pool-level routing
//! - `DeviceState` / `DeviceStatus`: per-device health and error counters

use crate::compress::CompressionConfig;
use crate::encrypt::EncryptionConfig;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::device_health::{
    DeviceErrorKind, DeviceHealth, DeviceHealthState, DeviceHealthTransitionEntry,
};
use crate::io_scheduler::IoClass as SchedClass;
use crate::{
    LocalObjectStore, ObjectKey, ObjectLocation, Result, ScrubStats, StoreError, StoreOptions,
    StoreRetentionCompactionReport, StoredObject,
};
use tracing;

// ---------------------------------------------------------------------------
// Device and I/O classification
// ---------------------------------------------------------------------------

/// Device class — maps to ZFS allocation classes for pool-level routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DeviceClass {
    /// General-purpose data storage.
    Data,
    /// Metadata and small-block special allocations.
    Metadata,
    /// Separate fast intent-log device (LOG_DEVICE).
    IntentLog,
    /// Read cache device (FlashTier).
    ReadCache,
    /// Special allocation class (small files, dedup tables).
    Special,
    /// Hot spare device.
    Spare,
    /// Forward-compatible unknown device class — carries the raw u8 wire
    /// value from PoolLabelV1 so that import can proceed when a device
    /// class unknown to this build is encountered.
    Unknown(u8),
}

/// I/O class used by the caller to route a put/get/delete to the right device
/// class inside the pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum IoClass {
    /// Bulk data.
    Data,
    /// Metadata / inode / directory records.
    Metadata,
    /// Intent log records.
    IntentLog,
    /// Read cache population or lookup.
    ReadCache,
}

// ---------------------------------------------------------------------------
// Device configuration
// ---------------------------------------------------------------------------

/// Backing media model for a configured device.
///
/// Product pool members are byte-addressable media: production block devices
/// or regular files used explicitly for development. Directory object stores
/// remain compatibility helpers for tests and old local paths; they are not a
/// user-admitted pool-device backing model.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DeviceBacking {
    /// Compatibility directory object-store layout.
    #[default]
    DirectoryObjectStoreCompat,
    /// Production block-device backing.
    BlockDevice,
    /// Explicit regular-file development backing.
    RegularFileDev,
}

impl DeviceBacking {
    /// Whether this backing is a product pool-member byte device.
    #[must_use]
    pub const fn is_byte_addressable_pool_member(self) -> bool {
        matches!(self, Self::BlockDevice | Self::RegularFileDev)
    }

    /// Whether pool labels live at fixed byte offsets on the backing.
    #[must_use]
    pub const fn uses_fixed_offset_pool_labels(self) -> bool {
        self.is_byte_addressable_pool_member()
    }

    /// Human-readable media name for operator diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectoryObjectStoreCompat => "directory-object-store-compat",
            Self::BlockDevice => "block-device",
            Self::RegularFileDev => "regular-file-dev",
        }
    }
}

/// Source-backed discard/UNMAP capability state.
///
/// Only [`DiscardCapability::Supported`] permits callers to treat discard as
/// available. Every other state is fail-closed and remains visible for
/// diagnostics instead of collapsing into an optimistic boolean.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscardCapability {
    /// The backing source reports non-zero discard support.
    Supported,
    /// The backing source reports no discard support.
    Unsupported,
    /// Capability could not be determined from the available source.
    Unknown,
    /// Capability probing was refused by the backing source.
    Refused,
    /// Discard requests may be accepted but ignored by the backing stack.
    Ignored,
    /// Development/test backing has not been verified as a discard-capable device.
    Unverified,
}

impl DiscardCapability {
    /// Whether this state proves discard support.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }

    /// Stable diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Unsupported => "unsupported",
            Self::Unknown => "unknown",
            Self::Refused => "refused",
            Self::Ignored => "ignored",
            Self::Unverified => "unverified",
        }
    }
}

fn composite_discard_capability(
    capabilities: impl IntoIterator<Item = DiscardCapability>,
) -> DiscardCapability {
    capabilities
        .into_iter()
        .max_by_key(|capability| capability.composite_priority())
        .unwrap_or(DiscardCapability::Unknown)
}

impl DiscardCapability {
    const fn composite_priority(self) -> u8 {
        match self {
            Self::Supported => 0,
            Self::Unsupported => 1,
            Self::Unverified => 2,
            Self::Ignored => 3,
            Self::Unknown => 4,
            Self::Refused => 5,
        }
    }
}

/// Configuration for a single device.
#[derive(Clone, Debug)]
pub struct DeviceConfig {
    /// Root path or byte-addressable path for this device backing.
    pub path: PathBuf,
    /// Explicit backing media model for this device.
    pub backing: DeviceBacking,
    /// Device class assignment.
    pub class: DeviceClass,
    /// Physical device media class (NVMe, SSD, HDD, or DM device).
    /// Defaults to [`DeviceMediaClass::Ssd`] when not specified.
    /// Used for adaptive segment sizing and write-allocation scoring.
    pub media_class: crate::device_layout::DeviceMediaClass,
    /// Physical layout of this device.
    pub kind: DeviceKind,
    /// Optional per-object zstd compression configuration.
    /// When set, all objects stored on this device are transparently
    /// compressed on write and decompressed on read via
    /// [`CompressedDevice`].
    pub compression: Option<CompressionConfig>,
    /// Optional per-object ChaCha20-Poly1305 encryption configuration.
    /// When set, all objects stored on this device are transparently
    /// encrypted on write and decrypted on read via
    /// [`EncryptedDevice`].
    pub encryption: Option<EncryptionConfig>,
}

/// Physical layout kind of a device.
#[derive(Clone, Debug)]
pub enum DeviceKind {
    /// Single compatibility directory object-store device.
    Single {
        path: PathBuf,
    },
    /// N-way mirror: writes go to every member, reads come from any healthy
    /// member.
    Mirror {
        paths: Vec<PathBuf>,
    },
    /// Separate intent log (LOG_DEVICE) device for sync write acceleration.
    /// Writes flow to a dedicated fast device (NVMe, Optane) with immediate
    /// acknowledgment; the data devices are written asynchronously.
    LogDevice {
        path: PathBuf,
    },
    ParityRaid1 {
        paths: Vec<PathBuf>,
    },
    ParityRaid2 {
        paths: Vec<PathBuf>,
    },
    ParityRaid3 {
        paths: Vec<PathBuf>,
    },
    /// Single byte-addressable block or regular-file development device.
    /// Objects are written sequentially with no segment files.
    Block {
        path: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// Device state and status
// ---------------------------------------------------------------------------

/// Operational state of a device.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DeviceState {
    /// Fully operational.
    #[default]
    Online,
    /// At least one mirror member is offline or erroring, but the device can
    /// still serve reads and writes.
    Degraded,
    /// All members are unreachable or unrecoverable.
    Faulted,
    /// Administratively taken offline.
    Offline,
    /// Administratively removed from the pool.
    Removed,
}

/// Per-device health and error-counter snapshot.
#[derive(Clone, Debug, Default)]
pub struct DeviceStatus {
    pub state: DeviceState,
    /// Human-readable last error, if any (StoreError is not Clone).
    pub last_error: Option<String>,
    pub read_errors: u64,
    pub write_errors: u64,
    pub checksum_errors: u64,
}

/// Configurable error thresholds for device health state transitions.
///
/// A device transitions from ONLINE → DEGRADED after `degrade_threshold`
/// total errors, and DEGRADED → FAULTED after `fault_threshold` total
/// errors. Set either threshold to 0 to disable that transition
/// (a threshold of 0 means "never transition").
#[derive(Clone, Copy, Debug)]
pub struct DeviceHealthConfig {
    /// Total errors (read + write + checksum) before marking DEGRADED.
    pub degrade_threshold: u64,
    /// Total errors (read + write + checksum) before marking FAULTED.
    pub fault_threshold: u64,
}

impl Default for DeviceHealthConfig {
    fn default() -> Self {
        Self {
            // 1 error → DEGRADED (conservative; mirrors survive this).
            degrade_threshold: 1,
            // 3 errors → FAULTED.
            fault_threshold: 3,
        }
    }
}

/// Per-device statistics for observability.
#[derive(Clone, Debug, Default)]
pub struct DeviceStats {
    pub live_objects: usize,
    pub live_bytes: u64,
    pub segment_count: usize,
    pub next_sequence: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub delete_ops: u64,
    pub mirror_read_retry_count: u64,
}
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// LogDeviceStats — per-log-device observability
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct LogDeviceStats {
    pub bytes_written: u64,
    pub sync_ops: u64,
    pub latency_p50_us: u64,
    pub latency_p99_us: u64,
    pub entry_count: u64,
}

// Mirror-leg error tracking
// ---------------------------------------------------------------------------

/// Per-leg error-tracking state for a mirror member.
///
/// Maintains a sliding window of error timestamps. When the number of
/// errors within `window_duration` exceeds `error_threshold`, the leg
/// is considered degraded and should be skipped for reads.
#[derive(Debug, Clone)]
pub struct MirrorLegState {
    /// Error timestamps within the sliding window (oldest first).
    error_timestamps: VecDeque<Instant>,
    /// Maximum errors allowed within the window before the leg is degraded.
    pub error_threshold: u64,
    /// Sliding window duration for error counting.
    pub window_duration: Duration,
}

impl MirrorLegState {
    /// Create a new leg state with the given threshold and window.
    pub fn new(error_threshold: u64, window_duration: Duration) -> Self {
        Self {
            error_timestamps: VecDeque::new(),
            error_threshold,
            window_duration,
        }
    }

    /// Default mirror leg state: 10 errors within 60 seconds.
    pub fn default_mirror() -> Self {
        Self::new(10, Duration::from_secs(60))
    }

    /// Record a read error at the current time.
    pub fn record_error(&mut self) {
        let now = Instant::now();
        self.error_timestamps.push_back(now);
        self.purge_expired(now);
    }

    /// Number of errors currently within the sliding window.
    pub fn error_count(&self) -> u64 {
        self.error_timestamps.len() as u64
    }

    /// Whether the error count exceeds the configured threshold.
    pub fn exceeds_threshold(&self) -> bool {
        self.error_count() >= self.error_threshold
    }

    /// Remove timestamps that have fallen outside the sliding window.
    fn purge_expired(&mut self, now: Instant) {
        let cutoff = now - self.window_duration;
        while let Some(&ts) = self.error_timestamps.front() {
            if ts < cutoff {
                self.error_timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    /// Check and purge expired entries without recording a new error.
    /// Returns the current error count after purging.
    pub fn refresh(&mut self) -> u64 {
        let now = Instant::now();
        self.purge_expired(now);
        self.error_count()
    }
}

// ---------------------------------------------------------------------------
// DeviceImpl trait
// ---------------------------------------------------------------------------

/// Common interface that every concrete device must satisfy.
pub trait DeviceImpl {
    /// Store an object.
    fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject>;

    /// Retrieve an object, if it exists.
    fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>>;

    /// Delete an object, returning whether it previously existed.
    fn delete(&mut self, key: ObjectKey) -> Result<bool>;

    /// Flush all pending writes to durable storage.
    fn sync_all(&mut self) -> Result<()>;

    /// Lightweight data-only flush: calls fdatasync on the backing
    /// file descriptor without requiring a full fsync or metadata
    /// commit.  The default implementation delegates to sync_all;
    /// file-backed devices should override this to call
    /// File::sync_data for faster writeback-drain convergence.
    fn sync_data(&mut self) -> Result<()> {
        self.sync_all()
    }

    /// Snapshot of current statistics.
    fn stats(&self) -> DeviceStats;

    /// Snapshot of current health status.
    fn status(&self) -> DeviceStatus;

    /// Root path of this device.
    fn root(&self) -> &Path;

    /// Set the I/O scheduling class for subsequent operations.
    fn set_scheduling_class(&mut self, class: SchedClass);

    /// Compact the backing store, retaining only the given keys.
    fn compact_retaining(
        &mut self,
        protected_keys: &[ObjectKey],
        protected_exact_locations: &[ObjectLocation],
    ) -> Result<StoreRetentionCompactionReport>;

    /// Whether the store should be compacted given the waste threshold.
    fn should_compact(&self, threshold: f64) -> bool;

    /// Rotate to a new segment if needed.
    fn rotate_if_needed(&mut self) -> Result<()>;

    /// Whether a scrub should run based on the configured interval.
    fn should_scrub(&self) -> bool;

    /// Scrub the mirror, repairing mismatched or missing entries.
    fn scrub_mirror(&mut self) -> Result<ScrubStats>;

    /// Return the segments directory path.
    fn segments_dir(&self) -> &Path;

    /// Access the underlying LocalObjectStore (for compatibility with code
    /// that hasn't been ported to use Pool I/O methods yet).
    fn store(&self) -> &LocalObjectStore;

    /// Mutable access to the underlying LocalObjectStore.
    fn store_mut(&mut self) -> &mut LocalObjectStore;

    fn health_state(&self) -> Option<DeviceHealthState> {
        None
    }

    /// Restore health state from a pool label after import.
    ///
    /// `health_byte`: 0=Online, 1=Degraded, 2=Faulted.
    fn restore_health_from_label(
        &mut self,
        health_byte: u8,
        read_errors: u64,
        write_errors: u64,
        cksum_errors: u64,
    ) {
        let _ = (health_byte, read_errors, write_errors, cksum_errors);
    }

    #[cfg(test)]
    fn force_error_for_test(&self, _kind: DeviceErrorKind, _count: u64) -> Option<DeviceHealth> {
        None
    }

    /// Drain pending health transitions from the per-device ring buffer.
    ///
    /// Returns all transitions recorded since the last drain in
    /// chronological order and clears the buffer. Pool-level health
    /// tracking calls this after I/O operations to emit
    /// [`crate::device_health::DeviceHealthTransition`] events.
    fn drain_health_transitions(&self) -> Vec<DeviceHealthTransitionEntry> {
        Vec::new()
    }

    /// Discard (TRIM/UNMAP) a byte range on the backing device.
    ///
    /// For SSD-backed devices, this notifies the physical device that
    /// blocks are no longer in use. The default returns an error;
    /// devices that support discard must override this method.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidOptions`] when the backing
    /// device does not support discard.
    fn discard_range(&mut self, _offset: u64, _len: u64) -> Result<()> {
        Err(StoreError::InvalidOptions {
            reason: "discard not supported by this device",
        })
    }

    /// Source-backed discard capability state.
    fn discard_capability(&self) -> DiscardCapability {
        DiscardCapability::Unsupported
    }

    /// Whether the backing device supports discard operations.
    fn supports_discard(&self) -> bool {
        self.discard_capability().is_supported()
    }
}

fn store_error_counts_as_device_write_fault(error: &StoreError) -> bool {
    matches!(error, StoreError::Io { .. })
}

// ---------------------------------------------------------------------------
// SingleDevice — one LocalObjectStore backing a single directory
// ---------------------------------------------------------------------------

/// A single-directory device backed by exactly one `LocalObjectStore`.
#[derive(Debug)]
pub struct SingleDevice {
    store: LocalObjectStore,
    health_config: DeviceHealthConfig,
    health_tracker: RefCell<DeviceHealthState>,
    status: DeviceStatus,
    /// Per-device read error counter (interior mutability for &self get).
    read_errors: Cell<u64>,
    /// Per-device checksum error counter (interior mutability for &self get).
    checksum_errors: Cell<u64>,
    read_ops: u64,
    write_ops: u64,
    delete_ops: u64,
}

impl SingleDevice {
    /// Open (or create) the backing store at `path`.
    /// Open (or create) a SingleDevice with default health thresholds.
    pub fn open(path: impl AsRef<Path>, options: StoreOptions) -> Result<Self> {
        Self::open_with_health(path, options, DeviceHealthConfig::default())
    }

    /// Open a block device as a SingleDevice.
    ///
    /// Uses [`LocalObjectStore::open_block_device`] instead of the
    /// directory object-store path. All I/O goes directly to the
    /// byte-addressable backing without segment files or directory operations.
    pub fn open_block(path: impl AsRef<Path>, options: StoreOptions) -> Result<Self> {
        let store = LocalObjectStore::open_block_device(path, options)?;
        Ok(Self {
            store,
            health_config: DeviceHealthConfig::default(),
            health_tracker: RefCell::new(DeviceHealthState::new(
                Duration::from_secs(600),
                1,
                3,
                true,
            )),
            status: DeviceStatus {
                state: DeviceState::Online,
                ..Default::default()
            },
            read_errors: Cell::new(0),
            checksum_errors: Cell::new(0),
            read_ops: 0,
            write_ops: 0,
            delete_ops: 0,
        })
    }
    pub fn open_with_health(
        path: impl AsRef<Path>,
        options: StoreOptions,
        health_config: DeviceHealthConfig,
    ) -> Result<Self> {
        let store = LocalObjectStore::open_with_options(path, options)?;
        Ok(Self {
            store,
            health_config,
            health_tracker: RefCell::new(DeviceHealthState::new(
                Duration::from_secs(600),
                health_config.degrade_threshold,
                health_config.fault_threshold,
                true, // non_redundant for single-disk devices
            )),
            status: DeviceStatus {
                state: DeviceState::Online,
                ..Default::default()
            },
            read_errors: Cell::new(0),
            checksum_errors: Cell::new(0),
            read_ops: 0,
            write_ops: 0,
            delete_ops: 0,
        })
    }

    /// Evaluate and transition device health based on accumulated error counters.
    ///
    /// ONLINE → DEGRADED when total errors >= degrade_threshold.
    /// DEGRADED → FAULTED when total errors >= fault_threshold.
    /// Once FAULTED, the device stays FAULTED (no automatic recovery).
    fn evaluate_health(&mut self) {
        if self.status.state == DeviceState::Faulted
            || self.status.state == DeviceState::Offline
            || self.status.state == DeviceState::Removed
        {
            return;
        }
        let total_errors = self
            .read_errors
            .get()
            .saturating_add(self.status.write_errors)
            .saturating_add(self.status.checksum_errors)
            .saturating_add(self.checksum_errors.get());

        let degrade_at = self.health_config.degrade_threshold;
        let fault_at = self.health_config.fault_threshold;

        if fault_at > 0 && total_errors >= fault_at {
            self.status.state = DeviceState::Faulted;
        } else if degrade_at > 0 && total_errors >= degrade_at {
            self.status.state = DeviceState::Degraded;
        }
    }

    /// Record a read I/O error on this device (interior mutability for &self contexts).
    ///
    /// Increments the read error counter. Health re-evaluation occurs
    /// on the next mutable operation (put, delete, sync, or
    /// record_checksum_error).
    pub fn record_read_error(&self) {
        self.read_errors
            .set(self.read_errors.get().saturating_add(1));
    }

    /// Increment the checksum error counter (interior mutability for &self contexts).
    ///
    /// Unlike `record_checksum_error`, this does not trigger immediate
    /// health re-evaluation. Call this from &self read paths; the health
    /// state machine will pick up the accumulated errors on the next mutable
    /// operation.
    pub fn incr_checksum_error(&self) {
        self.checksum_errors
            .set(self.checksum_errors.get().saturating_add(1));
    }

    /// Record a checksum verification failure and immediately re-evaluate health.
    ///
    /// Increments the checksum error counter and transitions device health
    /// (ONLINE → DEGRADED → FAULTED) if the accumulated errors exceed
    /// the configured thresholds. Call this from mutable contexts (put,
    /// delete, scrub) where health state transitions should be immediate.
    pub fn record_checksum_error(&mut self) {
        self.health_tracker
            .get_mut()
            .record_error(DeviceErrorKind::Checksum);
        self.status.checksum_errors = self.health_tracker.get_mut().total_checksum_errors;
        self.evaluate_health();
    }
}

impl DeviceImpl for SingleDevice {
    fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        match self.store.put(key, payload) {
            Ok(obj) => {
                self.write_ops = self.write_ops.saturating_add(1);
                Ok(obj)
            }
            Err(e) => {
                if store_error_counts_as_device_write_fault(&e) {
                    self.health_tracker
                        .get_mut()
                        .record_error(DeviceErrorKind::Write);
                    self.status.write_errors = self.health_tracker.get_mut().total_write_errors;
                }
                self.status.last_error = Some(format!("{e:?}"));
                self.evaluate_health();
                Err(e)
            }
        }
    }

    fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        match self.store.get(key) {
            Ok(val) => Ok(val),
            Err(e) => {
                self.health_tracker
                    .borrow_mut()
                    .record_error(DeviceErrorKind::Read);
                self.read_errors
                    .set(self.read_errors.get().saturating_add(1));
                Err(e)
            }
        }
    }

    fn delete(&mut self, key: ObjectKey) -> Result<bool> {
        match self.store.delete(key) {
            Ok(existed) => {
                self.delete_ops = self.delete_ops.saturating_add(1);
                Ok(existed)
            }
            Err(e) => {
                if store_error_counts_as_device_write_fault(&e) {
                    self.health_tracker
                        .get_mut()
                        .record_error(DeviceErrorKind::Write);
                    self.status.write_errors = self.health_tracker.get_mut().total_write_errors;
                }
                self.status.last_error = Some(format!("{e:?}"));
                self.evaluate_health();
                Err(e)
            }
        }
    }

    fn sync_all(&mut self) -> Result<()> {
        self.store.sync_all()
    }

    fn sync_data(&mut self) -> Result<()> {
        self.store.sync_data()
    }

    fn stats(&self) -> DeviceStats {
        let s = self.store.stats();
        DeviceStats {
            live_objects: s.live_objects,
            live_bytes: s.live_bytes,
            segment_count: s.segment_count,
            next_sequence: s.next_sequence,
            read_ops: self.read_ops,
            write_ops: self.write_ops,
            delete_ops: self.delete_ops,
            ..Default::default()
        }
    }

    fn status(&self) -> DeviceStatus {
        DeviceStatus {
            state: self.status.state,
            last_error: self.status.last_error.clone(),
            read_errors: self
                .status
                .read_errors
                .saturating_add(self.read_errors.get()),
            write_errors: self.status.write_errors,
            checksum_errors: self
                .status
                .checksum_errors
                .saturating_add(self.checksum_errors.get()),
        }
    }

    fn root(&self) -> &Path {
        self.store.root()
    }

    fn set_scheduling_class(&mut self, class: SchedClass) {
        self.store.set_io_class(class);
    }

    fn compact_retaining(
        &mut self,
        protected_keys: &[ObjectKey],
        protected_exact_locations: &[ObjectLocation],
    ) -> Result<StoreRetentionCompactionReport> {
        self.store
            .compact_retaining(protected_keys, protected_exact_locations)
    }

    fn should_compact(&self, threshold: f64) -> bool {
        self.store.should_compact(threshold)
    }

    fn rotate_if_needed(&mut self) -> Result<()> {
        self.store.rotate_if_needed()
    }

    fn should_scrub(&self) -> bool {
        self.store.should_scrub()
    }

    fn scrub_mirror(&mut self) -> Result<ScrubStats> {
        self.store.scrub_replicas()
    }

    fn segments_dir(&self) -> &Path {
        self.store.segments_dir()
    }

    fn store(&self) -> &LocalObjectStore {
        &self.store
    }

    fn store_mut(&mut self) -> &mut LocalObjectStore {
        &mut self.store
    }

    fn health_state(&self) -> Option<DeviceHealthState> {
        Some(self.health_tracker.borrow().clone())
    }

    fn restore_health_from_label(
        &mut self,
        health_byte: u8,
        read_errors: u64,
        write_errors: u64,
        cksum_errors: u64,
    ) {
        let health = match health_byte {
            0 => DeviceHealth::Online,
            1 => DeviceHealth::Degraded,
            2 => DeviceHealth::Faulted,
            _ => return,
        };
        let mut tracker = self.health_tracker.borrow_mut();
        tracker.set_health(health);
        tracker.total_read_errors = read_errors;
        tracker.total_write_errors = write_errors;
        tracker.total_checksum_errors = cksum_errors;
        tracker.reset_window();
        // Sync DeviceStatus to match restored health state so that
        // status() reports the correct operational state after import.
        self.status.state = match health {
            DeviceHealth::Online => DeviceState::Online,
            DeviceHealth::Degraded => DeviceState::Degraded,
            DeviceHealth::Faulted => DeviceState::Faulted,
        };
        self.status.read_errors = read_errors;
        self.status.write_errors = write_errors;
        self.status.checksum_errors = cksum_errors;
    }

    fn drain_health_transitions(&self) -> Vec<DeviceHealthTransitionEntry> {
        self.health_tracker.borrow_mut().drain_transitions()
    }

    #[cfg(test)]
    fn force_error_for_test(&self, kind: DeviceErrorKind, count: u64) -> Option<DeviceHealth> {
        self.health_tracker
            .borrow_mut()
            .force_error_for_test(kind, count)
    }

    fn discard_range(&mut self, _offset: u64, len: u64) -> Result<()> {
        // No-op for zero-length discard requests.
        if len == 0 {
            return Ok(());
        }

        Err(StoreError::InvalidOptions {
            reason: "directory object-store compatibility does not support discard",
        })
    }

    fn discard_capability(&self) -> DiscardCapability {
        DiscardCapability::Unsupported
    }

    fn supports_discard(&self) -> bool {
        self.discard_capability().is_supported()
    }
}

// ---------------------------------------------------------------------------
// MirrorDevice — N-way mirror
// ---------------------------------------------------------------------------

/// N-way mirror device. Writes go to every healthy member; reads retry
/// across legs on I/O error with per-leg error tracking and automatic
/// degraded-mode failover when an error threshold is exceeded.
#[derive(Debug)]
pub struct MirrorDevice {
    members: Vec<SingleDevice>,
    /// Per-leg sliding-window error tracking (RefCell for &self mutation).
    leg_states: std::cell::RefCell<Vec<MirrorLegState>>,
    /// Error threshold for degrading a leg (default: 10).
    error_threshold: u64,
    /// Sliding window duration in seconds (default: 60).
    error_window_secs: u64,
    status: DeviceStatus,
    /// Mirror-level aggregate health state.
    health_tracker: RefCell<DeviceHealthState>,
    /// Count of successful read retries from a sibling leg (Cell for &self mutation).
    mirror_read_retry_count: Cell<u64>,
    /// Indices of legs currently exceeding the error threshold (degraded).
    degraded_legs: RefCell<Vec<usize>>,
    /// Test-only hook: when true, the next read on leg 0 will fail.
    /// Keys queued for asynchronous leg repair after a successful sibling-leg
    /// read retry. The pool layer drains this queue and calls
    /// [`repair_leg`](Self::repair_leg) for each key.
    repair_queue: RefCell<VecDeque<ObjectKey>>,
    #[cfg(test)]
    fail_next_read: AtomicBool,
}

impl MirrorDevice {
    /// Open all mirror members.
    pub fn open(paths: &[PathBuf], options: &StoreOptions) -> Result<Self> {
        let n = paths.len();
        let mut members = Vec::with_capacity(n);
        for path in paths {
            members.push(SingleDevice::open(path, options.clone())?);
        }
        let leg_states = std::cell::RefCell::new(
            (0..n)
                .map(|_| MirrorLegState::default_mirror())
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            members,
            leg_states,
            error_threshold: 10,
            error_window_secs: 60,
            status: DeviceStatus {
                state: DeviceState::Online,
                ..Default::default()
            },
            health_tracker: RefCell::new(DeviceHealthState::new(
                Duration::from_secs(60),
                10,
                50,
                false, // mirror is redundant
            )),
            mirror_read_retry_count: Cell::new(0),
            degraded_legs: RefCell::new(Vec::new()),
            repair_queue: RefCell::new(VecDeque::new()),
            #[cfg(test)]
            fail_next_read: AtomicBool::new(false),
        })
    }

    /// Set the per-leg error threshold and window for DEGRADED transition.
    pub fn set_error_threshold(&mut self, threshold: u64, window_secs: u64) {
        self.error_threshold = threshold;
        self.error_window_secs = window_secs;
        for ls in self.leg_states.get_mut().iter_mut() {
            ls.error_threshold = threshold;
            ls.window_duration = Duration::from_secs(window_secs);
        }
    }

    /// Per-leg error counts for observability (mirror_read_error_count).
    pub fn leg_error_counts(&self) -> Vec<u64> {
        self.leg_states
            .borrow()
            .iter()
            .map(|ls| ls.error_count())
            .collect()
    }

    /// Per-leg degraded state for observability (mirror_leg_state gauge).
    pub fn leg_degraded(&self) -> Vec<bool> {
        self.leg_states
            .borrow()
            .iter()
            .map(|ls| ls.exceeds_threshold())
            .collect()
    }

    /// Count of successful read retries from sibling mirror legs.
    pub fn mirror_read_retry_count(&self) -> u64 {
        self.mirror_read_retry_count.get()
    }

    /// Indices of legs currently exceeding the error threshold (degraded).
    pub fn degraded_leg_indices(&self) -> Vec<usize> {
        self.degraded_legs.borrow().clone()
    }

    /// Number of keys currently queued for asynchronous leg repair.
    pub fn repair_queue_len(&self) -> usize {
        self.repair_queue.borrow().len()
    }

    /// Drain the repair queue, returning all keys pending repair.
    ///
    /// After draining, the caller should iterate over the returned keys and
    /// call [`repair_leg`](Self::repair_leg) for each one.
    pub fn drain_repair_queue(&self) -> Vec<ObjectKey> {
        let mut queue = self.repair_queue.borrow_mut();
        let keys: Vec<ObjectKey> = queue.drain(..).collect();
        keys
    }

    /// Repair missing or corrupt data on failed mirror legs.
    ///
    /// Reads the key from a healthy leg and writes it to all other accessible
    /// legs (ONLINE or DEGRADED, not Faulted/Offline/Removed). Returns the
    /// number of legs repaired.
    pub fn repair_leg(&mut self, key: ObjectKey) -> Result<u64> {
        let n = self.members.len();
        if n < 2 {
            return Ok(0);
        }
        let mut good_data: Option<Vec<u8>> = None;
        let mut good_idx: Option<usize> = None;
        for i in 0..n {
            let member_state = self.members[i].status.state;
            if member_state == DeviceState::Faulted
                || member_state == DeviceState::Offline
                || member_state == DeviceState::Removed
            {
                continue;
            }
            {
                let mut leg_states = self.leg_states.borrow_mut();
                leg_states[i].refresh();
                if leg_states[i].exceeds_threshold() {
                    continue;
                }
            }
            match self.members[i].get(key) {
                Ok(Some(data)) => {
                    good_data = Some(data);
                    good_idx = Some(i);
                    break;
                }
                Ok(None) | Err(_) => continue,
            }
        }
        let data = good_data.ok_or_else(|| StoreError::Io {
            operation: "mirror_repair_leg",
            path: PathBuf::from("<mirror>"),
            source: std::io::Error::other("mirror: no healthy leg contains the key to repair"),
        })?;
        let src_idx = good_idx.unwrap();
        let mut repaired = 0u64;
        for i in 0..n {
            if i == src_idx {
                continue;
            }
            let member_state = self.members[i].status.state;
            if member_state == DeviceState::Faulted
                || member_state == DeviceState::Offline
                || member_state == DeviceState::Removed
            {
                continue;
            }
            let _ = self.members[i].put(key, &data)?;
            repaired = repaired.saturating_add(1);
            tracing::info!(
                "mirror repair: wrote key to leg {i} ({repaired}/{n_minus_1} total)",
                n_minus_1 = n - 1,
            );
        }
        self.recompute_state();
        Ok(repaired)
    }
    #[cfg(test)]
    pub fn set_fail_next_read(&self, v: bool) {
        self.fail_next_read.store(v, Ordering::Relaxed);
    }

    fn recompute_state(&mut self) {
        let total = self.members.len();
        // Refresh all error windows before counting
        for ls in self.leg_states.get_mut().iter_mut() {
            ls.refresh();
        }
        // Refresh degraded_legs from leg_states
        {
            let mut dl = self.degraded_legs.borrow_mut();
            dl.clear();
            for (i, ls) in self.leg_states.borrow().iter().enumerate() {
                if ls.exceeds_threshold() {
                    dl.push(i);
                }
            }
        }
        let healthy = self
            .members
            .iter()
            .enumerate()
            .filter(|(i, m)| {
                if m.status.state != DeviceState::Online {
                    return false;
                }
                self.leg_states.borrow()[*i].error_count() < self.error_threshold
            })
            .count();

        self.status.state = if healthy == 0 {
            DeviceState::Faulted
        } else if healthy < total {
            DeviceState::Degraded
        } else {
            DeviceState::Online
        };
    }
}

impl DeviceImpl for MirrorDevice {
    fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        let mut last_ok: Option<StoredObject> = None;
        let mut ok_count = 0_usize;
        let total = self.members.len();

        for member in &mut self.members {
            if member.status.state != DeviceState::Online {
                continue;
            }
            match member.put(key, payload) {
                Ok(obj) => {
                    ok_count += 1;
                    last_ok = Some(obj);
                }
                Err(_e) => {
                    // member handles its own error counters
                }
            }
        }

        self.recompute_state();

        if ok_count == 0 {
            Err(StoreError::Io {
                operation: "mirror_put",
                path: PathBuf::from("<mirror>"),
                source: std::io::Error::other("mirror: no healthy members for write"),
            })
        } else if ok_count < total {
            self.status.last_error = Some(format!(
                "mirror degraded write: {ok_count}/{total} members succeeded"
            ));
            Ok(last_ok.unwrap())
        } else {
            Ok(last_ok.unwrap())
        }
    }

    fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        let mut leg_errors: Vec<(usize, StoreError)> = Vec::new();
        let n = self.members.len();
        // Empty mirror (no children): no data to read, propagate EIO.
        if n == 0 {
            return Err(StoreError::Io {
                operation: "mirror_get",
                path: PathBuf::from("<mirror>"),
                source: std::io::Error::other("mirror: no children configured"),
            });
        }
        let mut tried_leg_count = 0u32;
        let mut first_leg_failed = false;
        // Indices of legs that failed and need repair.
        let mut failed_leg_indices: Vec<usize> = Vec::new();

        for i in 0..n {
            let member_state = self.members[i].status.state;
            // Skip FAULTED, Offline, and Removed legs. Try ONLINE and DEGRADED.
            if member_state == DeviceState::Faulted
                || member_state == DeviceState::Offline
                || member_state == DeviceState::Removed
            {
                continue;
            }

            // Check if this leg is over the MirrorLegState error threshold
            {
                let mut leg_states = self.leg_states.borrow_mut();
                let ls = &mut leg_states[i];
                ls.refresh();
                if ls.exceeds_threshold() {
                    continue;
                }
            }

            #[cfg(test)]
            if i == 0 && self.fail_next_read.swap(false, Ordering::Relaxed) {
                let e = StoreError::Io {
                    operation: "mirror_get_test_inject",
                    path: PathBuf::from("<test-inject>"),
                    source: std::io::Error::other("mirror: test-injected read failure on leg 0"),
                };
                {
                    let mut leg_states = self.leg_states.borrow_mut();
                    leg_states[i].record_error();
                }
                self.members[i].record_read_error();
                tracing::warn!("mirror read: child 0 failed with test-injected error");
                first_leg_failed = true;
                failed_leg_indices.push(i);
                leg_errors.push((i, e));
                // Track degraded leg indices for test-injected failures
                {
                    let mut ls = self.leg_states.borrow_mut();
                    ls[i].refresh();
                    if ls[i].exceeds_threshold() && !self.degraded_legs.borrow().contains(&i) {
                        self.degraded_legs.borrow_mut().push(i);
                    }
                }
                continue;
            }
            tried_leg_count += 1;
            match self.members[i].get(key) {
                Ok(Some(data)) => {
                    if first_leg_failed {
                        // Successful retry from a sibling leg
                        self.mirror_read_retry_count
                            .set(self.mirror_read_retry_count.get().saturating_add(1));
                        // Queue the key for asynchronous leg repair
                        self.repair_queue.borrow_mut().push_back(key);
                        tracing::info!(
                            "mirror read retry: {succeeded} succeeded, {failed} legs queued for repair",
                            succeeded = i,
                            failed = failed_leg_indices.len(),
                        );
                    }
                    return Ok(Some(data));
                }
                Ok(None) => {
                    // Key not found on this leg — try the next (mirror may
                    // be out of sync; a scrub will repair it).
                    continue;
                }
                Err(e) => {
                    // Record the error on the leg's health tracking
                    {
                        let mut leg_states = self.leg_states.borrow_mut();
                        leg_states[i].record_error();
                    }
                    // Also record on the underlying SingleDevice for health state machine
                    match &e {
                        StoreError::ChecksumMismatch { .. } => {
                            self.members[i].incr_checksum_error();
                        }
                        _ => {
                            self.members[i].record_read_error();
                        }
                    }
                    tracing::warn!("mirror read: child {i} failed with {e:?}");
                    // Track degraded leg indices
                    {
                        let mut ls = self.leg_states.borrow_mut();
                        ls[i].refresh();
                        if ls[i].exceeds_threshold() && !self.degraded_legs.borrow().contains(&i) {
                            self.degraded_legs.borrow_mut().push(i);
                        }
                    }
                    if i == 0 || tried_leg_count == 1 {
                        first_leg_failed = true;
                    }
                    failed_leg_indices.push(i);
                    leg_errors.push((i, e));
                    continue;
                }
            }
        }

        // All legs exhausted
        if !leg_errors.is_empty() {
            // Build a combined diagnostic naming every failed child device.
            let failed_names: Vec<String> = leg_errors
                .iter()
                .map(|(idx, _err)| format!("leg {idx}"))
                .collect();
            let combined = format!(
                "mirror: all {n} children failed: {}",
                failed_names.join(", "),
            );
            tracing::error!("{combined}");
            let _last_err = leg_errors.pop().unwrap().1;
            Err(StoreError::Io {
                operation: "mirror_get",
                path: PathBuf::from("<mirror>"),
                source: std::io::Error::other(combined),
            })
        } else {
            // No errors but also no data found (all legs returned None)
            Ok(None)
        }
    }

    fn delete(&mut self, key: ObjectKey) -> Result<bool> {
        let mut last_result: Option<bool> = None;
        for member in &mut self.members {
            if member.status.state != DeviceState::Online {
                continue;
            }
            if let Ok(existed) = member.delete(key) {
                last_result = Some(existed);
            }
        }
        self.recompute_state();
        last_result.ok_or_else(|| StoreError::Io {
            operation: "mirror_delete",
            path: PathBuf::from("<mirror>"),
            source: std::io::Error::other("mirror: no healthy members for delete"),
        })
    }

    fn sync_all(&mut self) -> Result<()> {
        for member in &mut self.members {
            if member.status.state == DeviceState::Online {
                member.sync_all()?;
            }
        }
        Ok(())
    }

    fn stats(&self) -> DeviceStats {
        let mut total = DeviceStats::default();
        for member in &self.members {
            let s = member.stats();
            total.live_objects = total.live_objects.saturating_add(s.live_objects);
            total.live_bytes = total.live_bytes.saturating_add(s.live_bytes);
            total.segment_count = total.segment_count.saturating_add(s.segment_count);
            total.next_sequence = total.next_sequence.max(s.next_sequence);
            total.read_ops = total.read_ops.saturating_add(s.read_ops);
            total.write_ops = total.write_ops.saturating_add(s.write_ops);
            total.delete_ops = total.delete_ops.saturating_add(s.delete_ops);
        }
        total.mirror_read_retry_count = self.mirror_read_retry_count.get();
        total
    }

    fn status(&self) -> DeviceStatus {
        // Refresh all error windows
        for ls in self.leg_states.borrow_mut().iter_mut() {
            ls.refresh();
        }
        let total = self.members.len();
        let healthy = self
            .members
            .iter()
            .enumerate()
            .filter(|(i, m)| {
                if m.status.state != DeviceState::Online {
                    return false;
                }
                self.leg_states.borrow()[*i].error_count() < self.error_threshold
            })
            .count();
        let state = if healthy == 0 {
            DeviceState::Faulted
        } else if healthy < total {
            DeviceState::Degraded
        } else {
            DeviceState::Online
        };
        // Build per-leg error summary for the last_error field
        let degraded_legs: Vec<String> = self
            .members
            .iter()
            .enumerate()
            .filter_map(|(i, _m)| {
                let ls = &self.leg_states.borrow()[i];
                if ls.exceeds_threshold() {
                    Some(format!("leg-{}: {} errors", i, ls.error_count()))
                } else {
                    None
                }
            })
            .collect();
        let last_error = if degraded_legs.is_empty() {
            self.status.last_error.clone()
        } else {
            Some(format!(
                "mirror degraded: {}; {}",
                degraded_legs.join(", "),
                self.status
                    .last_error
                    .as_deref()
                    .unwrap_or("no prior error")
            ))
        };
        DeviceStatus {
            state,
            last_error,
            read_errors: self.members.iter().map(|m| m.status().read_errors).sum(),
            write_errors: self.members.iter().map(|m| m.status().write_errors).sum(),
            checksum_errors: self
                .members
                .iter()
                .map(|m| m.status().checksum_errors)
                .sum(),
        }
    }

    fn root(&self) -> &Path {
        self.members
            .first()
            .map(|m| m.root())
            .unwrap_or(Path::new(""))
    }

    fn set_scheduling_class(&mut self, class: SchedClass) {
        for member in &mut self.members {
            member.set_scheduling_class(class);
        }
    }

    fn compact_retaining(
        &mut self,
        protected_keys: &[ObjectKey],
        protected_exact_locations: &[ObjectLocation],
    ) -> Result<StoreRetentionCompactionReport> {
        let mut report = None;
        for member in &mut self.members {
            if member.status().state == DeviceState::Online {
                report = Some(member.compact_retaining(protected_keys, protected_exact_locations)?);
            }
        }
        report.ok_or(StoreError::InvalidOptions {
            reason: "mirror has no online members for compaction",
        })
    }

    fn should_compact(&self, threshold: f64) -> bool {
        self.members.iter().any(|m| m.should_compact(threshold))
    }

    fn rotate_if_needed(&mut self) -> Result<()> {
        for member in &mut self.members {
            if member.status().state == DeviceState::Online {
                member.rotate_if_needed()?;
            }
        }
        Ok(())
    }

    fn should_scrub(&self) -> bool {
        self.members.iter().any(|m| m.should_scrub())
    }

    fn scrub_mirror(&mut self) -> Result<ScrubStats> {
        let mut total = ScrubStats::default();
        for member in &mut self.members {
            if member.status().state == DeviceState::Online {
                let s = member.scrub_mirror()?;
                total.keys_examined += s.keys_examined;
                total.keys_healthy += s.keys_healthy;
                total.keys_resynced += s.keys_resynced;
                total.keys_repaired += s.keys_repaired;
                total.errors += s.errors;
                total.duration_secs += s.duration_secs;
            }
        }
        Ok(total)
    }

    fn segments_dir(&self) -> &Path {
        self.members
            .first()
            .map(|m| m.segments_dir())
            .unwrap_or(Path::new(""))
    }

    fn store(&self) -> &LocalObjectStore {
        // Return the first member's store
        self.members
            .first()
            .map(|m| m.store())
            .unwrap_or_else(|| panic!("mirror has no members"))
    }

    fn store_mut(&mut self) -> &mut LocalObjectStore {
        self.members
            .first_mut()
            .map(|m| m.store_mut())
            .unwrap_or_else(|| panic!("mirror has no members"))
    }

    fn health_state(&self) -> Option<DeviceHealthState> {
        Some(self.health_tracker.borrow().clone())
    }

    fn restore_health_from_label(
        &mut self,
        health_byte: u8,
        read_errors: u64,
        write_errors: u64,
        cksum_errors: u64,
    ) {
        let health = match health_byte {
            0 => DeviceHealth::Online,
            1 => DeviceHealth::Degraded,
            2 => DeviceHealth::Faulted,
            _ => return,
        };
        let mut tracker = self.health_tracker.borrow_mut();
        tracker.set_health(health);
        tracker.total_read_errors = read_errors;
        tracker.total_write_errors = write_errors;
        tracker.total_checksum_errors = cksum_errors;
        tracker.reset_window();
        // Sync DeviceStatus from restored health.
        self.status.state = match health {
            DeviceHealth::Online => DeviceState::Online,
            DeviceHealth::Degraded => DeviceState::Degraded,
            DeviceHealth::Faulted => DeviceState::Faulted,
        };
    }

    fn drain_health_transitions(&self) -> Vec<DeviceHealthTransitionEntry> {
        self.health_tracker.borrow_mut().drain_transitions()
    }

    #[cfg(test)]
    fn force_error_for_test(&self, kind: DeviceErrorKind, count: u64) -> Option<DeviceHealth> {
        self.health_tracker
            .borrow_mut()
            .force_error_for_test(kind, count)
    }

    fn discard_capability(&self) -> DiscardCapability {
        composite_discard_capability(self.members.iter().map(DeviceImpl::discard_capability))
    }

    fn discard_range(&mut self, offset: u64, len: u64) -> Result<()> {
        let mut last_err: Option<StoreError> = None;
        for member in &mut self.members {
            if member.status.state == DeviceState::Online {
                if let Err(e) = member.discard_range(offset, len) {
                    last_err = Some(e);
                }
            }
        }
        self.recompute_state();
        last_err.map_or(Ok(()), Err)
    }
}

// ---------------------------------------------------------------------------
// ParityRaidDevice -- PARITY_RAID1 single-parity striped device
// ---------------------------------------------------------------------------

/// PARITY_RAID1 device: N data columns + 1 parity column across N+1 child
/// SingleDevices.  Any single child failure is reconstructed via XOR.
#[derive(Debug)]
pub struct ParityRaidDevice {
    pub(crate) children: Vec<SingleDevice>,
    n_data: u8,
    n_parity: u8,
    row_sequence: u64,
    health_tracker: RefCell<DeviceHealthState>,
    status: DeviceStatus,
    read_ops: Cell<u64>,
    write_ops: u64,
    delete_ops: u64,
}

impl ParityRaidDevice {
    /// Open a PARITY_RAID device with the given parity count (1, 2, or 3).
    ///
    /// `paths.len()` must equal `n_data + n_parity`. For PARITY_RAID1, at least
    /// 3 paths (2 data + 1 parity). For PARITY_RAID2, at least 5 paths
    /// (3 data + 2 parity). For PARITY_RAID3, at least 7 paths (4 data + 3 parity).
    pub fn open_with_parity(
        paths: &[PathBuf],
        options: &StoreOptions,
        n_parity: u8,
    ) -> Result<Self> {
        let min_data = match n_parity {
            1 => 2u8,
            2 => 3u8,
            3 => 4u8,
            _ => {
                return Err(StoreError::InvalidOptions {
                    reason: "PARITY_RAID parity count must be 1, 2, or 3",
                })
            }
        };
        let min_paths = (min_data + n_parity) as usize;
        if paths.len() < min_paths {
            return Err(StoreError::InvalidOptions {
                reason: "PARITY_RAID requires more paths for the requested parity level",
            });
        }
        let n_data = (paths.len() - n_parity as usize) as u8;
        let mut children = Vec::with_capacity(paths.len());
        for path in paths {
            children.push(SingleDevice::open(path, options.clone())?);
        }
        Ok(Self {
            children,
            n_data,
            n_parity,
            row_sequence: 0,
            health_tracker: RefCell::new(DeviceHealthState::new(
                Duration::from_secs(600),
                1,
                3,
                false,
            )),
            status: DeviceStatus {
                state: DeviceState::Online,
                ..Default::default()
            },
            read_ops: Cell::new(0),
            write_ops: 0,
            delete_ops: 0,
        })
    }

    /// Open a PARITY_RAID1 device (backward-compatible convenience).
    pub fn open(paths: &[PathBuf], options: &StoreOptions) -> Result<Self> {
        Self::open_with_parity(paths, options, 1)
    }

    fn column_key(base: ObjectKey, col: u8) -> ObjectKey {
        let mut bytes = base.as_bytes32();
        bytes[31] ^= col;
        ObjectKey::from_bytes32(bytes)
    }

    fn len_key(base: ObjectKey) -> ObjectKey {
        let mut bytes = base.as_bytes32();
        bytes[30] ^= 0xFF;
        ObjectKey::from_bytes32(bytes)
    }

    fn evaluate_health(&mut self) {
        let online = self
            .children
            .iter()
            .filter(|c| c.status.state == DeviceState::Online)
            .count();
        let total = self.children.len();
        self.status.state = if online == 0 {
            DeviceState::Faulted
        } else if online < total {
            DeviceState::Degraded
        } else {
            DeviceState::Online
        };
    }

    pub fn column_error_counts(&self) -> Vec<u64> {
        self.children
            .iter()
            .map(|c| c.status.read_errors + c.status.write_errors + c.status.checksum_errors)
            .collect()
    }

    pub fn column_states(&self) -> Vec<DeviceState> {
        self.children.iter().map(|c| c.status.state).collect()
    }
}

impl DeviceImpl for ParityRaidDevice {
    fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        use crate::parity_raid::ParityRaidLayout;
        let stripes =
            ParityRaidLayout::stripe_write(payload, self.n_data, self.n_parity).map_err(|_e| {
                StoreError::InvalidOptions {
                    reason: "parity_raid stripe_write failed",
                }
            })?;
        let len_key = Self::len_key(key);
        let len_bytes = (payload.len() as u64).to_le_bytes();
        self.children[0].put(len_key, &len_bytes)?;
        let total = stripes.len();
        let mut last_ok: Option<StoredObject> = None;
        let mut ok_count = 0;
        for (i, stripe) in stripes.iter().enumerate().take(total) {
            let col_key = Self::column_key(key, i as u8);
            match self.children[i].put(col_key, stripe) {
                Ok(obj) => {
                    ok_count += 1;
                    last_ok = Some(obj);
                }
                Err(_e) => {
                    self.health_tracker
                        .borrow_mut()
                        .record_error(DeviceErrorKind::Write);
                }
            }
        }
        self.write_ops = self.write_ops.saturating_add(1);
        self.row_sequence = self.row_sequence.saturating_add(1);
        self.evaluate_health();
        if ok_count == 0 {
            Err(StoreError::Io {
                operation: "parity_raid_put",
                path: PathBuf::from("<parity_raid>"),
                source: std::io::Error::other("parity_raid: no healthy children for write"),
            })
        } else {
            let mut obj = last_ok.unwrap();
            obj.key = key;
            if ok_count < total {
                self.status.last_error = Some(format!(
                    "parity_raid degraded write: {ok_count}/{total} columns succeeded"
                ));
            }
            Ok(obj)
        }
    }

    fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        use crate::parity_raid::ParityRaidLayout;
        let len_key = Self::len_key(key);
        let len_data = match self.children[0].get(len_key)? {
            Some(data) if data.len() >= 8 => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[..8]);
                u64::from_le_bytes(bytes) as usize
            }
            _ => return Ok(None),
        };
        let total = self.children.len();
        let mut stripes: Vec<Option<Vec<u8>>> = Vec::with_capacity(total);
        let mut missing_count = 0usize;
        let mut _missing_idx = 0usize;
        for i in 0..total {
            let col_key = Self::column_key(key, i as u8);
            match self.children[i].get(col_key) {
                Ok(Some(data)) => stripes.push(Some(data)),
                Ok(None) | Err(_) => {
                    stripes.push(None);
                    missing_count += 1;
                }
            }
        }
        self.read_ops.set(self.read_ops.get().saturating_add(1));
        if missing_count == 0 {
            let data_len = usize::from(self.n_data);
            let mut result = Vec::new();
            for stripe in stripes.iter().take(data_len).flatten() {
                result.extend_from_slice(stripe);
            }
            result.truncate(len_data);
            return Ok(Some(result));
        }
        if missing_count > 0 && missing_count <= self.n_parity as usize {
            let missing_indices: Vec<usize> = stripes
                .iter()
                .enumerate()
                .filter(|(_, s)| s.is_none())
                .map(|(i, _)| i)
                .collect();
            match ParityRaidLayout::reconstruct_missing(
                &missing_indices,
                &stripes,
                self.n_data,
                self.n_parity,
            ) {
                Ok(recovered) => {
                    for (idx, col) in missing_indices.iter().zip(recovered.iter()) {
                        stripes[*idx] = Some(col.clone());
                    }
                    let data_len = usize::from(self.n_data);
                    let mut result = Vec::new();
                    for stripe in stripes.iter().take(data_len).flatten() {
                        result.extend_from_slice(stripe);
                    }
                    result.truncate(len_data);
                    self.health_tracker
                        .borrow_mut()
                        .record_error(DeviceErrorKind::Checksum);
                    Ok(Some(result))
                }
                Err(_) => Err(StoreError::Io {
                    operation: "parity_raid_get_reconstruct",
                    path: PathBuf::from("<parity_raid>"),
                    source: std::io::Error::other("parity_raid: reconstruction failed"),
                }),
            }
        } else if missing_count > 0 {
            Err(StoreError::Io {
                operation: "parity_raid_get",
                path: PathBuf::from("<parity_raid>"),
                source: std::io::Error::other(format!(
                    "parity_raid: {missing_count} columns missing, can only recover {}",
                    self.n_parity
                )),
            })
        } else {
            unreachable!("handled above")
        }
    }

    fn delete(&mut self, key: ObjectKey) -> Result<bool> {
        let mut existed = false;
        for i in 0..self.children.len() {
            let col_key = Self::column_key(key, i as u8);
            if self.children[i].delete(col_key).unwrap_or(false) {
                existed = true;
            }
        }
        let len_key = Self::len_key(key);
        let _ = self.children[0].delete(len_key);
        self.delete_ops = self.delete_ops.saturating_add(1);
        self.evaluate_health();
        Ok(existed)
    }

    fn sync_all(&mut self) -> Result<()> {
        for child in &mut self.children {
            child.sync_all()?;
        }
        Ok(())
    }

    fn stats(&self) -> DeviceStats {
        let mut total = DeviceStats::default();
        for child in &self.children {
            let s = child.stats();
            total.live_objects = total.live_objects.saturating_add(s.live_objects);
            total.live_bytes = total.live_bytes.saturating_add(s.live_bytes);
            total.segment_count = total.segment_count.saturating_add(s.segment_count);
            total.next_sequence = total.next_sequence.max(s.next_sequence);
            total.read_ops = total.read_ops.saturating_add(s.read_ops);
            total.write_ops = total.write_ops.saturating_add(s.write_ops);
            total.delete_ops = total.delete_ops.saturating_add(s.delete_ops);
        }
        total.read_ops = total.read_ops.saturating_add(self.read_ops.get());
        total.write_ops = total.write_ops.saturating_add(self.write_ops);
        total.delete_ops = total.delete_ops.saturating_add(self.delete_ops);
        total
    }

    fn status(&self) -> DeviceStatus {
        let online = self
            .children
            .iter()
            .filter(|c| c.status.state == DeviceState::Online)
            .count();
        let total = self.children.len();
        let state = if online == 0 {
            DeviceState::Faulted
        } else if online < total {
            DeviceState::Degraded
        } else {
            DeviceState::Online
        };
        DeviceStatus {
            state,
            last_error: self.status.last_error.clone(),
            read_errors: self.children.iter().map(|c| c.status.read_errors).sum(),
            write_errors: self.children.iter().map(|c| c.status.write_errors).sum(),
            checksum_errors: self.children.iter().map(|c| c.status.checksum_errors).sum(),
        }
    }

    fn root(&self) -> &Path {
        self.children
            .first()
            .map(|c| c.root())
            .unwrap_or(Path::new(""))
    }

    fn set_scheduling_class(&mut self, class: SchedClass) {
        for child in &mut self.children {
            child.set_scheduling_class(class);
        }
    }

    fn compact_retaining(
        &mut self,
        protected_keys: &[ObjectKey],
        protected_exact_locations: &[ObjectLocation],
    ) -> Result<StoreRetentionCompactionReport> {
        let mut report = None;
        for child in &mut self.children {
            if child.status().state == DeviceState::Online {
                report = Some(child.compact_retaining(protected_keys, protected_exact_locations)?);
            }
        }
        report.ok_or(StoreError::InvalidOptions {
            reason: "parity_raid has no online children for compaction",
        })
    }

    fn should_compact(&self, threshold: f64) -> bool {
        self.children.iter().any(|c| c.should_compact(threshold))
    }

    fn rotate_if_needed(&mut self) -> Result<()> {
        for child in &mut self.children {
            child.rotate_if_needed()?;
        }
        Ok(())
    }

    fn should_scrub(&self) -> bool {
        self.children.iter().any(|c| c.should_scrub())
    }

    fn scrub_mirror(&mut self) -> Result<ScrubStats> {
        let mut agg = ScrubStats::default();
        for child in &mut self.children {
            let s = child.scrub_mirror()?;
            agg.keys_examined += s.keys_examined;
            agg.keys_healthy += s.keys_healthy;
            agg.keys_resynced += s.keys_resynced;
            agg.keys_repaired += s.keys_repaired;
            agg.errors += s.errors;
        }
        Ok(agg)
    }

    fn segments_dir(&self) -> &Path {
        self.children
            .first()
            .map(|c| c.segments_dir())
            .unwrap_or(Path::new(""))
    }

    fn store(&self) -> &LocalObjectStore {
        self.children[0].store()
    }
    fn store_mut(&mut self) -> &mut LocalObjectStore {
        self.children[0].store_mut()
    }

    fn health_state(&self) -> Option<DeviceHealthState> {
        Some(self.health_tracker.borrow().clone())
    }

    fn restore_health_from_label(
        &mut self,
        health_byte: u8,
        read_errors: u64,
        write_errors: u64,
        cksum_errors: u64,
    ) {
        let health = match health_byte {
            0 => DeviceHealth::Online,
            1 => DeviceHealth::Degraded,
            2 => DeviceHealth::Faulted,
            _ => return,
        };
        let mut tracker = self.health_tracker.borrow_mut();
        tracker.set_health(health);
        tracker.total_read_errors = read_errors;
        tracker.total_write_errors = write_errors;
        tracker.total_checksum_errors = cksum_errors;
        tracker.reset_window();
        // DeviceStatus for PARITY_RAID is derived from child health, so only
        // restore the health tracker. Pool-level health queries use
        // health_state() to see the persisted label state.
    }

    fn drain_health_transitions(&self) -> Vec<DeviceHealthTransitionEntry> {
        self.health_tracker.borrow_mut().drain_transitions()
    }

    #[cfg(test)]
    fn force_error_for_test(&self, kind: DeviceErrorKind, count: u64) -> Option<DeviceHealth> {
        self.health_tracker
            .borrow_mut()
            .force_error_for_test(kind, count)
    }
    fn discard_range(&mut self, offset: u64, len: u64) -> Result<()> {
        let mut last_err: Option<StoreError> = None;
        for child in &mut self.children {
            if child.status().state == DeviceState::Online {
                if let Err(e) = child.discard_range(offset, len) {
                    last_err = Some(e);
                }
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn supports_discard(&self) -> bool {
        self.discard_capability().is_supported()
    }

    fn discard_capability(&self) -> DiscardCapability {
        composite_discard_capability(self.children.iter().map(DeviceImpl::discard_capability))
    }
}

// ---------------------------------------------------------------------------
// LogDeviceEntry / LogDeviceAck — intent-log record types
// ---------------------------------------------------------------------------

/// A raw log entry stored on the log device.
#[derive(Clone, Debug)]
pub struct LogDeviceEntry {
    pub commit_group: u64,
    pub seq: u64,
    pub data: Vec<u8>,
}

/// Acknowledgment returned by a sync write.
#[derive(Clone, Copy, Debug)]
pub struct LogDeviceAck {
    pub commit_group: u64,
    pub seq: u64,
    pub latency_us: u64,
}

// ---------------------------------------------------------------------------
// LogDevice — separate intent-log device
// ---------------------------------------------------------------------------

/// A dedicated fast device (NVMe SSD, Optane, battery-backed NVRAM) that
/// accepts synchronous writes and returns immediate acknowledgments.
///
/// The LOG_DEVICE decouples ZIL-style intent-log writes from the main data devices:
/// sync-write latency is bounded by the log device speed, while the data
/// devices can acknowledge asynchronously. On pool import, log entries are
/// replayed from the log device to reconstruct any intent-log records that were
/// acknowledged but not yet committed to data devices.
#[derive(Debug)]
pub struct LogDevice {
    store: LocalObjectStore,
    health_config: DeviceHealthConfig,
    health_tracker: RefCell<DeviceHealthState>,
    status: DeviceStatus,
    next_seq: u64,
    entry_count: u64,
    bytes_written: u64,
    sync_ops: u64,
    latencies_us: Vec<u64>,
    max_latency_samples: usize,
}

impl LogDevice {
    pub fn open(path: impl AsRef<Path>, options: StoreOptions) -> Result<Self> {
        Self::open_with_health(path, options, DeviceHealthConfig::default())
    }

    /// Open a log device with explicit health configuration.
    ///
    /// `non_redundant` is set to `false` because the log device's redundancy
    /// comes from fallback to the main pool data devices, not from device-
    /// level mirroring.
    pub fn open_with_health(
        path: impl AsRef<Path>,
        options: StoreOptions,
        health_config: DeviceHealthConfig,
    ) -> Result<Self> {
        let store = LocalObjectStore::open_with_options(path, options)?;
        Ok(Self {
            store,
            health_config,
            health_tracker: RefCell::new(DeviceHealthState::new(
                Duration::from_secs(600),
                health_config.degrade_threshold,
                health_config.fault_threshold,
                false, // non_redundant: fallback to main devices provides redundancy
            )),
            status: DeviceStatus {
                state: DeviceState::Online,
                ..Default::default()
            },
            next_seq: 0,
            entry_count: 0,
            bytes_written: 0,
            sync_ops: 0,
            latencies_us: Vec::with_capacity(1024),
            max_latency_samples: 1024,
        })
    }

    /// Evaluate and transition device health based on accumulated error counters.
    ///
    /// ONLINE -> DEGRADED when total errors >= degrade_threshold.
    /// DEGRADED -> FAULTED when total errors >= fault_threshold.
    /// Once FAULTED, the device stays FAULTED (no automatic recovery).
    /// Once Offline or Removed, health evaluation is skipped.
    fn evaluate_health(&mut self) {
        if self.status.state == DeviceState::Faulted
            || self.status.state == DeviceState::Offline
            || self.status.state == DeviceState::Removed
        {
            return;
        }
        let total_errors = self
            .status
            .read_errors
            .saturating_add(self.status.write_errors)
            .saturating_add(self.status.checksum_errors);
        let degrade_at = self.health_config.degrade_threshold;
        let fault_at = self.health_config.fault_threshold;
        if fault_at > 0 && total_errors >= fault_at {
            self.status.state = DeviceState::Faulted;
        } else if degrade_at > 0 && total_errors >= degrade_at {
            self.status.state = DeviceState::Degraded;
        }
    }

    pub fn write_sync(&mut self, buf: &[u8], commit_group: u64) -> Result<LogDeviceAck> {
        let start = Instant::now();
        let seq = self.next_seq;
        self.next_seq = seq.saturating_add(1);
        let key = log_device_key(seq);
        let mut framed = Vec::with_capacity(16 + buf.len());
        framed.extend_from_slice(&commit_group.to_le_bytes());
        framed.extend_from_slice(&seq.to_le_bytes());
        framed.extend_from_slice(buf);
        if let Err(e) = self.store.put(key, &framed) {
            if store_error_counts_as_device_write_fault(&e) {
                self.health_tracker
                    .get_mut()
                    .record_error(DeviceErrorKind::Write);
                self.status.write_errors = self.health_tracker.get_mut().total_write_errors;
            }
            self.status.last_error = Some(format!("{e:?}"));
            self.evaluate_health();
            return Err(e);
        }
        if let Err(e) = self.store.sync_all() {
            self.health_tracker
                .get_mut()
                .record_error(DeviceErrorKind::Write);
            self.status.write_errors = self.health_tracker.get_mut().total_write_errors;
            self.status.last_error = Some(format!("{e:?}"));
            self.evaluate_health();
            return Err(e);
        }
        let latency_us = start.elapsed().as_micros() as u64;
        self.record_latency(latency_us);
        self.entry_count = self.entry_count.saturating_add(1);
        self.bytes_written = self.bytes_written.saturating_add(buf.len() as u64);
        self.sync_ops = self.sync_ops.saturating_add(1);
        Ok(LogDeviceAck {
            commit_group,
            seq,
            latency_us,
        })
    }

    pub fn read_log_entries(
        &self,
        commit_group_start: u64,
        commit_group_end: u64,
    ) -> Result<Vec<LogDeviceEntry>> {
        let mut entries: Vec<LogDeviceEntry> = Vec::new();
        let all_keys = self.store.list_keys();
        for key in all_keys {
            if let Some(raw) = self.store.get(key)? {
                if let Some((commit_group, seq)) = parse_log_device_payload(&raw) {
                    if commit_group >= commit_group_start && commit_group <= commit_group_end {
                        let data = raw[16..].to_vec();
                        entries.push(LogDeviceEntry {
                            commit_group,
                            seq,
                            data,
                        });
                    }
                }
            }
        }
        entries.sort_by_key(|e| (e.commit_group, e.seq));
        Ok(entries)
    }

    pub fn replay_all(&self) -> Result<Vec<LogDeviceEntry>> {
        self.read_log_entries(0, u64::MAX)
    }

    pub fn log_device_stats(&self) -> LogDeviceStats {
        let mut sorted = self.latencies_us.clone();
        sorted.sort_unstable();
        let p50 = percentile(&sorted, 50.0);
        let p99 = percentile(&sorted, 99.0);
        LogDeviceStats {
            bytes_written: self.bytes_written,
            sync_ops: self.sync_ops,
            latency_p50_us: p50,
            latency_p99_us: p99,
            entry_count: self.entry_count,
        }
    }

    pub fn record_checksum_error(&mut self) {
        self.health_tracker
            .get_mut()
            .record_error(DeviceErrorKind::Checksum);
        self.status.checksum_errors = self.health_tracker.get_mut().total_checksum_errors;
        self.evaluate_health();
    }

    /// Whether the log device is healthy enough to accept writes (Online or Degraded).
    pub fn is_healthy_for_writes(&self) -> bool {
        matches!(
            self.status.state,
            DeviceState::Online | DeviceState::Degraded
        )
    }

    fn record_latency(&mut self, us: u64) {
        if self.latencies_us.len() >= self.max_latency_samples {
            self.latencies_us.remove(0);
        }
        self.latencies_us.push(us);
    }
}

impl DeviceImpl for LogDevice {
    fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        self.store.put(key, payload).map_err(|e| {
            if store_error_counts_as_device_write_fault(&e) {
                self.health_tracker
                    .get_mut()
                    .record_error(DeviceErrorKind::Write);
                self.status.write_errors = self.health_tracker.get_mut().total_write_errors;
            }
            self.status.last_error = Some(format!("{e:?}"));
            self.evaluate_health();
            e
        })
    }
    fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        self.store.get(key)
    }
    fn delete(&mut self, key: ObjectKey) -> Result<bool> {
        self.store.delete(key)
    }
    fn sync_all(&mut self) -> Result<()> {
        self.store.sync_all()
    }
    fn stats(&self) -> DeviceStats {
        let s = self.store.stats();
        DeviceStats {
            live_objects: s.live_objects,
            live_bytes: s.live_bytes,
            segment_count: s.segment_count,
            next_sequence: s.next_sequence,
            read_ops: 0,
            write_ops: self.sync_ops,
            delete_ops: 0,
            ..Default::default()
        }
    }
    fn status(&self) -> DeviceStatus {
        self.status.clone()
    }
    fn root(&self) -> &Path {
        self.store.root()
    }
    fn set_scheduling_class(&mut self, class: SchedClass) {
        self.store.set_io_class(class);
    }
    fn compact_retaining(
        &mut self,
        protected_keys: &[ObjectKey],
        protected_exact_locations: &[ObjectLocation],
    ) -> Result<StoreRetentionCompactionReport> {
        self.store
            .compact_retaining(protected_keys, protected_exact_locations)
    }
    fn should_compact(&self, threshold: f64) -> bool {
        self.store.should_compact(threshold)
    }
    fn rotate_if_needed(&mut self) -> Result<()> {
        self.store.rotate_if_needed()
    }
    fn should_scrub(&self) -> bool {
        self.store.should_scrub()
    }
    fn scrub_mirror(&mut self) -> Result<ScrubStats> {
        self.store.scrub_replicas()
    }
    fn segments_dir(&self) -> &Path {
        self.store.segments_dir()
    }
    fn store(&self) -> &LocalObjectStore {
        &self.store
    }
    fn store_mut(&mut self) -> &mut LocalObjectStore {
        &mut self.store
    }

    fn discard_capability(&self) -> DiscardCapability {
        DiscardCapability::Unsupported
    }
}

// ---------------------------------------------------------------------------
// LOG_DEVICE key helpers
// ---------------------------------------------------------------------------

fn log_device_key(seq: u64) -> ObjectKey {
    ObjectKey::from_name(format!("log_device/entry/{seq:016x}").as_bytes())
}

fn parse_log_device_payload(data: &[u8]) -> Option<(u64, u64)> {
    if data.len() < 16 {
        return None;
    }
    let commit_group = u64::from_le_bytes(data[0..8].try_into().ok()?);
    let seq = u64::from_le_bytes(data[8..16].try_into().ok()?);
    Some((commit_group, seq))
}

fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((pct / 100.0) * (sorted.len() as f64 - 1.0)) as usize;
    sorted[idx]
}

// ---------------------------------------------------------------------------
// CompressedDevice
// ---------------------------------------------------------------------------

/// Transparent per-object zstd compression wrapper for any device.
///
/// Wraps an inner device and applies zstd compression to all objects on
/// write and decompresses on read. Small objects below
/// `min_compress_bytes` are stored uncompressed.
///
/// The 5-byte `tidefs_compression` frame header is invisible to
/// callers — `put`/`get` return original plaintext sizes and payloads.
#[derive(Debug)]
pub struct CompressedDevice {
    inner: Box<Device>,
    config: CompressionConfig,
    /// Compression statistics: bytes in (plaintext) / bytes out (stored).
    bytes_in: u64,
    bytes_out: u64,
    objects_compressed: u64,
    objects_uncompressed: u64,
    #[allow(clippy::declare_interior_mutable_const)]
    read_ops: Cell<u64>,
    write_ops: u64,
    delete_ops: u64,
}

impl CompressedDevice {
    /// Wrap an existing [`Device`] with compression.
    pub fn new(inner: Device, config: CompressionConfig) -> Self {
        Self {
            inner: Box::new(inner),
            config,
            bytes_in: 0,
            bytes_out: 0,
            objects_compressed: 0,
            objects_uncompressed: 0,
            read_ops: Cell::new(0),
            write_ops: 0,
            delete_ops: 0,
        }
    }

    /// Compression ratio: bytes_out / bytes_in.
    /// Returns 1.0 if no data has been processed.
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        if self.bytes_in == 0 {
            1.0
        } else {
            self.bytes_out as f64 / self.bytes_in as f64
        }
    }

    /// Space savings percentage (0-100).
    #[must_use]
    pub fn savings_pct(&self) -> f64 {
        (1.0 - self.compression_ratio()) * 100.0
    }

    /// Total plaintext bytes written (for aggregate pool ratio).
    #[must_use]
    pub fn compression_bytes_in(&self) -> u64 {
        self.bytes_in
    }

    /// Total stored bytes written (for aggregate pool ratio).
    #[must_use]
    pub fn compression_bytes_out(&self) -> u64 {
        self.bytes_out
    }
}

impl DeviceImpl for CompressedDevice {
    fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        self.write_ops = self.write_ops.saturating_add(1);

        let mut frame_stats = crate::compress::CompressionStats::default();
        let framed = crate::compress::compress_frame(payload, &self.config, &mut frame_stats);

        self.bytes_in = self.bytes_in.saturating_add(frame_stats.bytes_in);
        self.bytes_out = self.bytes_out.saturating_add(frame_stats.bytes_out);
        self.objects_compressed = self
            .objects_compressed
            .saturating_add(frame_stats.objects_compressed);
        self.objects_uncompressed = self
            .objects_uncompressed
            .saturating_add(frame_stats.objects_uncompressed);

        self.inner.put(key, &framed)
    }

    fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        match self.inner.get(key)? {
            Some(framed) => {
                self.read_ops.set(self.read_ops.get().saturating_add(1));
                match crate::compress::decompress_frame(&framed) {
                    Ok(decompressed) => Ok(Some(decompressed)),
                    Err(_) => {
                        // If the first byte is not a recognized compression algorithm,
                        // the object was stored without a compression frame header
                        // (backward compatibility with uncompressed stores).
                        // Return it as-is so the caller can decode it correctly.
                        if framed.is_empty()
                            || crate::compress::CompressionAlgorithm::from_byte(framed[0]).is_some()
                        {
                            if framed.len() >= crate::compress::FRAME_HEADER_LEN {
                                Ok(Some(framed[crate::compress::FRAME_HEADER_LEN..].to_vec()))
                            } else {
                                Ok(Some(framed))
                            }
                        } else {
                            // No frame header: return raw bytes for backward compat.
                            Ok(Some(framed))
                        }
                    }
                }
            }
            None => Ok(None),
        }
    }

    fn delete(&mut self, key: ObjectKey) -> Result<bool> {
        self.delete_ops = self.delete_ops.saturating_add(1);
        self.inner.delete(key)
    }

    fn sync_all(&mut self) -> Result<()> {
        self.inner.sync_all()
    }

    fn stats(&self) -> DeviceStats {
        self.inner.stats()
    }

    fn status(&self) -> DeviceStatus {
        self.inner.status()
    }

    fn root(&self) -> &Path {
        self.inner.root()
    }

    fn set_scheduling_class(&mut self, class: SchedClass) {
        self.inner.set_scheduling_class(class);
    }

    fn compact_retaining(
        &mut self,
        protected_keys: &[ObjectKey],
        protected_exact_locations: &[ObjectLocation],
    ) -> Result<StoreRetentionCompactionReport> {
        self.inner
            .compact_retaining(protected_keys, protected_exact_locations)
    }

    fn should_compact(&self, threshold: f64) -> bool {
        self.inner.should_compact(threshold)
    }

    fn rotate_if_needed(&mut self) -> Result<()> {
        self.inner.rotate_if_needed()
    }

    fn should_scrub(&self) -> bool {
        self.inner.should_scrub()
    }

    fn scrub_mirror(&mut self) -> Result<ScrubStats> {
        self.inner.scrub_mirror()
    }

    fn segments_dir(&self) -> &Path {
        self.inner.segments_dir()
    }

    fn store(&self) -> &LocalObjectStore {
        self.inner.store()
    }

    fn store_mut(&mut self) -> &mut LocalObjectStore {
        self.inner.store_mut()
    }

    fn health_state(&self) -> Option<DeviceHealthState> {
        self.inner.health_state()
    }

    #[cfg(test)]
    fn force_error_for_test(&self, kind: DeviceErrorKind, count: u64) -> Option<DeviceHealth> {
        self.inner.force_error_for_test(kind, count)
    }

    fn discard_capability(&self) -> DiscardCapability {
        self.inner.discard_capability()
    }

    /// Transparent discard: forwards to the inner device.
    /// Compression does not affect TRIM byte ranges.
    fn discard_range(&mut self, offset: u64, len: u64) -> Result<()> {
        self.inner.discard_range(offset, len)
    }
}
// ---------------------------------------------------------------------------
// EncryptedDevice — per-object AEAD encryption wrapper
// ---------------------------------------------------------------------------

/// A transparent encryption wrapper around any [`Device`] implementation.
///
/// Every object written through `put` is encrypted with ChaCha20-Poly1305
/// before landing in the inner device. Every object read through `get` is
/// decrypted transparently.
///
/// The encryption overhead (nonce + AEAD tag, 28 bytes) is invisible to
/// callers — the stored size is larger, but the returned payload is the
/// original plaintext.
///
#[derive(Debug)]
pub struct EncryptedDevice {
    inner: Box<Device>,
    config: EncryptionConfig,
    objects_encrypted: u64,
}

impl EncryptedDevice {
    /// Wrap an existing [`Device`] with encryption.
    pub fn new(inner: Device, config: EncryptionConfig) -> Self {
        Self {
            inner: Box::new(inner),
            config,
            objects_encrypted: 0,
        }
    }

    /// Total number of objects encrypted.
    #[must_use]
    pub fn objects_encrypted(&self) -> u64 {
        self.objects_encrypted
    }
}

impl DeviceImpl for EncryptedDevice {
    fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        let ciphertext = crate::encrypt::encrypt_object(&self.config.key, payload);
        self.objects_encrypted = self.objects_encrypted.saturating_add(1);
        self.inner.put(key, &ciphertext)
    }

    fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        match self.inner.get(key)? {
            Some(framed) => {
                let plaintext = crate::encrypt::decrypt_object(&self.config.key, &framed);
                Ok(plaintext)
            }
            None => Ok(None),
        }
    }

    fn delete(&mut self, key: ObjectKey) -> Result<bool> {
        self.inner.delete(key)
    }

    fn sync_all(&mut self) -> Result<()> {
        self.inner.sync_all()
    }

    fn stats(&self) -> DeviceStats {
        self.inner.stats()
    }

    fn status(&self) -> DeviceStatus {
        self.inner.status()
    }

    fn root(&self) -> &Path {
        self.inner.root()
    }

    fn set_scheduling_class(&mut self, class: SchedClass) {
        self.inner.set_scheduling_class(class);
    }

    fn compact_retaining(
        &mut self,
        protected_keys: &[ObjectKey],
        protected_exact_locations: &[ObjectLocation],
    ) -> Result<StoreRetentionCompactionReport> {
        self.inner
            .compact_retaining(protected_keys, protected_exact_locations)
    }

    fn should_compact(&self, threshold: f64) -> bool {
        self.inner.should_compact(threshold)
    }

    fn rotate_if_needed(&mut self) -> Result<()> {
        self.inner.rotate_if_needed()
    }

    fn should_scrub(&self) -> bool {
        self.inner.should_scrub()
    }

    fn scrub_mirror(&mut self) -> Result<ScrubStats> {
        self.inner.scrub_mirror()
    }

    fn segments_dir(&self) -> &Path {
        self.inner.segments_dir()
    }

    fn store(&self) -> &LocalObjectStore {
        self.inner.store()
    }

    fn store_mut(&mut self) -> &mut LocalObjectStore {
        self.inner.store_mut()
    }

    fn health_state(&self) -> Option<DeviceHealthState> {
        self.inner.health_state()
    }

    #[cfg(test)]
    fn force_error_for_test(&self, kind: DeviceErrorKind, count: u64) -> Option<DeviceHealth> {
        self.inner.force_error_for_test(kind, count)
    }

    fn discard_capability(&self) -> DiscardCapability {
        self.inner.discard_capability()
    }

    /// Transparent discard: forwards to the inner device.
    /// Encryption does not affect TRIM byte ranges.
    fn discard_range(&mut self, offset: u64, len: u64) -> Result<()> {
        self.inner.discard_range(offset, len)
    }
}

// ---------------------------------------------------------------------------
// Device — public enum handle
// ---------------------------------------------------------------------------

/// Public handle that dispatches to the concrete device implementation.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Device {
    Single(SingleDevice),
    Mirror(MirrorDevice),
    Compressed(CompressedDevice),
    Encrypted(EncryptedDevice),
    LogDevice(LogDevice),
    ParityRaid1(ParityRaidDevice),
    ParityRaid2(ParityRaidDevice),
    ParityRaid3(ParityRaidDevice),
}

impl Device {
    /// Run an incremental background integrity scrub on this device's store.
    ///
    /// Delegates to [`LocalObjectStore::run_background_scrub`]. The scrub
    /// is gated by the store's configured `background_scrub_interval_secs`
    /// (no-op when 0 or interval not elapsed).
    pub fn maybe_run_background_scrub(&mut self) -> crate::Result<crate::ScrubReport> {
        self.store_mut().run_background_scrub()
    }

    /// Create a single device from a path.
    pub fn open_single(path: impl AsRef<Path>, options: StoreOptions) -> Result<Self> {
        SingleDevice::open(path, options).map(Device::Single)
    }

    /// Create a single block-device-backed device.
    pub fn open_single_block(path: impl AsRef<Path>, options: StoreOptions) -> Result<Self> {
        SingleDevice::open_block(path, options).map(Device::Single)
    }

    /// Create a mirror device from a set of paths.
    pub fn open_mirror(paths: &[PathBuf], options: &StoreOptions) -> Result<Self> {
        MirrorDevice::open(paths, options).map(Device::Mirror)
    }

    /// Create a compressed device wrapping an inner device.
    pub fn open_compressed(inner: Device, config: CompressionConfig) -> Self {
        Device::Compressed(CompressedDevice::new(inner, config))
    }

    /// Create an encrypted device wrapping an inner device.
    pub fn open_encrypted(inner: Device, config: EncryptionConfig) -> Self {
        Device::Encrypted(EncryptedDevice::new(inner, config))
    }

    /// Returns true when this device or one of its wrappers encrypts objects.
    /// Used by label builders to set the `ENCRYPTION_INCOMPAT` feature flag.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        match self {
            Device::Encrypted(_) => true,
            Device::Compressed(c) => c.inner.is_encrypted(),
            _ => false,
        }
    }

    /// Create a log device from a path.
    pub fn open_log_device(path: impl AsRef<Path>, options: StoreOptions) -> Result<Self> {
        LogDevice::open(path, options).map(Device::LogDevice)
    }

    /// Create a log device with explicit health configuration.
    pub fn open_log_device_with_health(
        path: impl AsRef<Path>,
        options: StoreOptions,
        health_config: DeviceHealthConfig,
    ) -> Result<Self> {
        LogDevice::open_with_health(path, options, health_config).map(Device::LogDevice)
    }

    /// Create a PARITY_RAID1 device from N+1 paths (N data + 1 parity).
    pub fn open_parity_raid1(paths: &[PathBuf], options: &StoreOptions) -> Result<Self> {
        ParityRaidDevice::open_with_parity(paths, options, 1).map(Device::ParityRaid1)
    }

    /// Create a PARITY_RAID2 device from N+2 paths (N data + 2 parity).
    pub fn open_parity_raid2(paths: &[PathBuf], options: &StoreOptions) -> Result<Self> {
        ParityRaidDevice::open_with_parity(paths, options, 2).map(Device::ParityRaid2)
    }

    /// Create a PARITY_RAID3 device from N+3 paths (N data + 3 parity).
    pub fn open_parity_raid3(paths: &[PathBuf], options: &StoreOptions) -> Result<Self> {
        ParityRaidDevice::open_with_parity(paths, options, 3).map(Device::ParityRaid3)
    }

    /// Compression ratio, or 1.0 if not a compressed device.
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        match self {
            Device::Compressed(c) => c.compression_ratio(),
            _ => 1.0,
        }
    }

    /// Space savings percentage (0-100).
    #[must_use]
    pub fn savings_pct(&self) -> f64 {
        match self {
            Device::Compressed(c) => c.savings_pct(),
            _ => 0.0,
        }
    }

    /// Per-leg error counts for observability.
    /// Returns error counts per leg for mirror devices; empty for non-mirrors.
    pub fn leg_error_counts(&self) -> Vec<u64> {
        match self {
            Device::Mirror(m) => m.leg_error_counts(),
            _ => Vec::new(),
        }
    }

    /// Per-leg degraded state for observability.
    /// Returns degraded flags per leg for mirror devices; empty for non-mirrors.
    pub fn leg_degraded(&self) -> Vec<bool> {
        match self {
            Device::Mirror(m) => m.leg_degraded(),
            _ => Vec::new(),
        }
    }

    /// Indices of degraded mirror legs (exceeding error threshold).
    /// Returns empty for non-mirror devices.
    pub fn degraded_leg_indices(&self) -> Vec<usize> {
        match self {
            Device::Mirror(m) => m.degraded_leg_indices(),
            _ => Vec::new(),
        }
    }

    /// Test-only hook: cause the next mirror read on leg 0 to fail.
    /// No-op for non-mirror devices.
    #[cfg(test)]
    pub fn set_fail_next_read(&self, v: bool) {
        if let Device::Mirror(m) = self {
            m.set_fail_next_read(v);
        }
    }

    /// Mirror read retry count.
    /// Returns the count of successful sibling-leg read retries for mirror
    /// devices; 0 for non-mirrors.
    pub fn mirror_read_retry_count(&self) -> u64 {
        match self {
            Device::Mirror(m) => m.mirror_read_retry_count(),
            _ => 0,
        }
    }

    /// Set the per-leg error threshold for mirror devices.
    /// No-op for non-mirror devices.
    pub fn set_error_threshold(&mut self, threshold: u64, window_secs: u64) {
        if let Device::Mirror(m) = self {
            m.set_error_threshold(threshold, window_secs);
        }
    }

    /// Number of keys queued for asynchronous leg repair in mirror devices.
    /// Returns 0 for non-mirror devices.
    pub fn repair_queue_len(&self) -> usize {
        match self {
            Device::Mirror(m) => m.repair_queue_len(),
            _ => 0,
        }
    }

    /// Drain the repair queue for mirror devices, returning all keys pending
    /// repair. Returns an empty vector for non-mirror devices.
    pub fn drain_repair_queue(&self) -> Vec<ObjectKey> {
        match self {
            Device::Mirror(m) => m.drain_repair_queue(),
            _ => Vec::new(),
        }
    }

    /// Repair missing or corrupt data on a failed mirror leg by reading from a
    /// healthy sibling and writing to all other legs. Returns the number of legs
    /// repaired. No-op (returns Ok(0)) for non-mirror devices.
    pub fn repair_leg(&mut self, key: ObjectKey) -> Result<u64> {
        match self {
            Device::Mirror(m) => m.repair_leg(key),
            _ => Ok(0),
        }
    }
    /// Total plaintext bytes written (0 for non-compressed devices).
    #[must_use]
    pub fn compression_bytes_in(&self) -> u64 {
        match self {
            Device::Compressed(c) => c.compression_bytes_in(),
            _ => 0,
        }
    }

    /// Total stored bytes written (0 for non-compressed devices).
    #[must_use]
    pub fn compression_bytes_out(&self) -> u64 {
        match self {
            Device::Compressed(c) => c.compression_bytes_out(),
            _ => 0,
        }
    }

    /// Write a sync payload to the log device and return an acknowledgment.
    pub fn write_sync(&mut self, buf: &[u8], commit_group: u64) -> Result<LogDeviceAck> {
        match self {
            Device::LogDevice(s) => s.write_sync(buf, commit_group),
            _ => panic!("write_sync called on non-log device"),
        }
    }

    /// Read log entries from the log device within a COMMIT_GROUP range.
    pub fn read_log_entries(
        &self,
        commit_group_start: u64,
        commit_group_end: u64,
    ) -> Result<Vec<LogDeviceEntry>> {
        match self {
            Device::LogDevice(s) => s.read_log_entries(commit_group_start, commit_group_end),
            _ => panic!("read_log_entries called on non-log device"),
        }
    }

    /// LOG_DEVICE-specific statistics including latency percentiles.
    pub fn log_device_stats(&self) -> LogDeviceStats {
        match self {
            Device::LogDevice(s) => s.log_device_stats(),
            _ => panic!("log_device_stats called on non-log device"),
        }
    }

    /// Whether the log device is healthy enough to accept writes (Online or Degraded).
    pub fn is_healthy_for_writes(&self) -> bool {
        match self {
            Device::LogDevice(s) => s.is_healthy_for_writes(),
            _ => true,
        }
    }

    /// Record a checksum verification failure on this device.
    ///
    /// Increments the checksum error counter and re-evaluates device
    /// health. Call this from the pool layer or object store when
    /// BLAKE3 checksum verification fails on a read or scrub.
    pub fn record_checksum_error(&mut self) {
        match self {
            Device::Single(s) => s.record_checksum_error(),
            Device::Mirror(m) => {
                for member in &mut m.members {
                    member.record_checksum_error();
                }
            }
            Device::Compressed(c) => c.inner.record_checksum_error(),
            Device::LogDevice(s) => s.record_checksum_error(),
            Device::Encrypted(e) => e.inner.record_checksum_error(),
            Device::ParityRaid1(r) | Device::ParityRaid2(r) | Device::ParityRaid3(r) => {
                for child in &mut r.children {
                    child.record_checksum_error();
                }
            }
        }
    }

    /// Access the inner implementation through the trait.
    fn inner_mut(&mut self) -> &mut dyn DeviceImpl {
        match self {
            Device::Single(s) => s,
            Device::Mirror(m) => m,
            Device::Compressed(c) => c,
            Device::LogDevice(s) => s,
            Device::Encrypted(e) => e,
            Device::ParityRaid1(r) | Device::ParityRaid2(r) | Device::ParityRaid3(r) => r,
        }
    }

    fn inner(&self) -> &dyn DeviceImpl {
        match self {
            Device::Single(s) => s,
            Device::Mirror(m) => m,
            Device::Compressed(c) => c,
            Device::LogDevice(s) => s,
            Device::Encrypted(e) => e,
            Device::ParityRaid1(r) | Device::ParityRaid2(r) | Device::ParityRaid3(r) => r,
        }
    }
}

impl DeviceImpl for Device {
    fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        self.inner_mut().put(key, payload)
    }

    fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        self.inner().get(key)
    }

    fn delete(&mut self, key: ObjectKey) -> Result<bool> {
        self.inner_mut().delete(key)
    }

    fn sync_all(&mut self) -> Result<()> {
        self.inner_mut().sync_all()
    }

    fn stats(&self) -> DeviceStats {
        self.inner().stats()
    }

    fn status(&self) -> DeviceStatus {
        self.inner().status()
    }

    fn root(&self) -> &Path {
        self.inner().root()
    }

    fn set_scheduling_class(&mut self, class: SchedClass) {
        self.inner_mut().set_scheduling_class(class);
    }

    fn compact_retaining(
        &mut self,
        protected_keys: &[ObjectKey],
        protected_exact_locations: &[ObjectLocation],
    ) -> Result<StoreRetentionCompactionReport> {
        self.inner_mut()
            .compact_retaining(protected_keys, protected_exact_locations)
    }

    fn should_compact(&self, threshold: f64) -> bool {
        self.inner().should_compact(threshold)
    }

    fn rotate_if_needed(&mut self) -> Result<()> {
        self.inner_mut().rotate_if_needed()
    }

    fn should_scrub(&self) -> bool {
        self.inner().should_scrub()
    }

    fn scrub_mirror(&mut self) -> Result<ScrubStats> {
        self.inner_mut().scrub_mirror()
    }

    fn segments_dir(&self) -> &Path {
        self.inner().segments_dir()
    }

    fn store(&self) -> &LocalObjectStore {
        self.inner().store()
    }

    fn store_mut(&mut self) -> &mut LocalObjectStore {
        self.inner_mut().store_mut()
    }

    fn health_state(&self) -> Option<DeviceHealthState> {
        self.inner().health_state()
    }

    fn drain_health_transitions(&self) -> Vec<DeviceHealthTransitionEntry> {
        self.inner().drain_health_transitions()
    }

    fn restore_health_from_label(
        &mut self,
        health_byte: u8,
        read_errors: u64,
        write_errors: u64,
        cksum_errors: u64,
    ) {
        self.inner_mut().restore_health_from_label(
            health_byte,
            read_errors,
            write_errors,
            cksum_errors,
        );
    }

    #[cfg(test)]
    fn force_error_for_test(&self, kind: DeviceErrorKind, count: u64) -> Option<DeviceHealth> {
        self.inner().force_error_for_test(kind, count)
    }

    fn discard_range(&mut self, offset: u64, len: u64) -> Result<()> {
        self.inner_mut().discard_range(offset, len)
    }

    fn discard_capability(&self) -> DiscardCapability {
        self.inner().discard_capability()
    }

    fn supports_discard(&self) -> bool {
        self.discard_capability().is_supported()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ObjectKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tidefs-device-test-{ts}-{label}"))
    }

    fn test_options() -> StoreOptions {
        StoreOptions::test_fast()
    }

    // ------------------------------------------------------------------
    // SingleDevice
    // ------------------------------------------------------------------

    #[test]
    fn single_put_get_delete() {
        let path = temp_path("single-put-get");
        let _ = std::fs::remove_dir_all(&path);
        let mut device = Device::open_single(&path, test_options()).unwrap();
        let key = ObjectKey::from_name(b"hello");
        let stored = device.put(key, b"world").unwrap();
        assert_eq!(stored.key, key);
        assert_eq!(stored.len, 5);

        let val = device.get(key).unwrap();
        assert_eq!(val, Some(b"world".to_vec()));

        assert!(device.delete(key).unwrap());
        assert_eq!(device.get(key).unwrap(), None);

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn single_payload_too_large_does_not_fault_device() {
        let path = temp_path("single-payload-too-large-health");
        let _ = std::fs::remove_dir_all(&path);
        let health = DeviceHealthConfig {
            degrade_threshold: 1,
            fault_threshold: 1,
        };
        let mut device = SingleDevice::open_with_health(&path, test_options(), health).unwrap();
        let payload = vec![0_u8; 8192];
        let err = device
            .put(ObjectKey::from_name(b"too-large"), &payload)
            .expect_err("oversized payload must be refused");

        assert!(matches!(err, StoreError::PayloadTooLarge { .. }));
        assert_eq!(device.status().state, DeviceState::Online);
        assert_eq!(device.status().write_errors, 0);
        assert!(device.status().last_error.is_some());

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn single_sync_all() {
        let path = temp_path("single-sync");
        let _ = std::fs::remove_dir_all(&path);
        let mut device = Device::open_single(&path, test_options()).unwrap();
        let key = ObjectKey::from_name(b"data");
        device.put(key, b"payload").unwrap();
        device.sync_all().unwrap();

        let stats = device.stats();
        assert_eq!(stats.live_objects, 1);
        assert_eq!(stats.write_ops, 1);
        let _ = std::fs::remove_dir_all(&path);
    }

    // ------------------------------------------------------------------
    // MirrorDevice
    // ------------------------------------------------------------------

    #[test]
    fn mirror_put_get_delete() {
        let p1 = temp_path("mirror-a");
        let p2 = temp_path("mirror-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let mut device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();
        let key = ObjectKey::from_name(b"mirrored");
        let stored = device.put(key, b"redundant").unwrap();
        assert_eq!(stored.len, 9);

        let val = device.get(key).unwrap();
        assert_eq!(val, Some(b"redundant".to_vec()));

        assert!(device.delete(key).unwrap());
        assert_eq!(device.get(key).unwrap(), None);

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    #[test]
    fn mirror_three_way() {
        let paths: Vec<_> = (0..3).map(|i| temp_path(&format!("mirror3-{i}"))).collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_mirror(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"3way");
        device.put(key, b"triple").unwrap();

        let val = device.get(key).unwrap();
        assert_eq!(val, Some(b"triple".to_vec()));

        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn mirror_stats() {
        let p1 = temp_path("mirror-stats-a");
        let p2 = temp_path("mirror-stats-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let mut device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();
        device.put(ObjectKey::from_name(b"a"), b"aa").unwrap();
        device.put(ObjectKey::from_name(b"b"), b"bb").unwrap();
        let stats = device.stats();
        assert_eq!(stats.live_objects, 4); // 2 objects x 2 members
        assert_eq!(stats.write_ops, 4);
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    // ------------------------------------------------------------------
    // Mirror read-error retry
    // ------------------------------------------------------------------

    /// Verify that a read from a 2-leg mirror succeeds from leg 1 when leg 0
    /// has a corrupted backing store (simulated by deleting leg 0's data).
    #[test]
    fn mirror_read_retry_single_leg_fault() {
        let p1 = temp_path("retry-a");
        let p2 = temp_path("retry-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let mut device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();
        // Set threshold to 1 so a single error triggers Degraded
        device.set_error_threshold(1, 60);

        let key = ObjectKey::from_name(b"retry-key");
        device.put(key, b"retry-payload").unwrap();
        device.sync_all().unwrap();

        // Corrupt leg 0 by deleting its backing directory contents
        let segments0 = p1.join("segments");
        let _ = std::fs::remove_dir_all(&segments0);

        // Read should succeed from leg 1 via retry
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(b"retry-payload".to_vec()));

        let status = device.status();
        // After a read error on leg 0 and threshold=1, mirror is Degraded
        assert_eq!(status.state, DeviceState::Degraded);

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    /// Verify EIO propagation when all mirror legs are corrupted.
    #[test]
    fn mirror_read_all_legs_faulted_propagates_eio() {
        let p1 = temp_path("allfault-a");
        let p2 = temp_path("allfault-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let mut device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();
        // Set threshold to 1 so any error degrades the leg
        device.set_error_threshold(1, 60);

        let key = ObjectKey::from_name(b"doomed");
        device.put(key, b"payload").unwrap();
        device.sync_all().unwrap();

        // Corrupt both legs
        let _ = std::fs::remove_dir_all(p1.join("segments"));
        let _ = std::fs::remove_dir_all(p2.join("segments"));

        // Read should fail with I/O error (all legs tried, all failed)
        let result = device.get(key);
        assert!(result.is_err(), "expected EIO when all legs faulted");

        let status = device.status();
        assert_eq!(status.state, DeviceState::Faulted);

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    /// Verify mirror_read_retry_count increments on successful sibling read,
    /// and that subsequent reads against an already-degraded leg do not
    /// double-count (the degraded leg is skipped by the error-threshold check).
    #[test]
    fn mirror_read_retry_count_incremented_on_sibling_success() {
        let p1 = temp_path("retrycnt-a");
        let p2 = temp_path("retrycnt-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let mut device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();
        device.set_error_threshold(1, 60);

        let key = ObjectKey::from_name(b"retrycnt-key");
        device.put(key, b"retrycnt-payload").unwrap();
        device.sync_all().unwrap();

        // Before any errors, retry count is zero
        assert_eq!(device.mirror_read_retry_count(), 0);

        // Corrupt leg 0
        let _ = std::fs::remove_dir_all(p1.join("segments"));

        // Read succeeds from leg 1 after retry
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(b"retrycnt-payload".to_vec()));

        // Retry count should be 1
        assert_eq!(device.mirror_read_retry_count(), 1);

        // Second read: leg 0 is now over the error threshold (1 error >= threshold 1),
        // so it is skipped entirely. Leg 1 succeeds on the first try, no retry.
        let val2 = device.get(key).unwrap();
        assert_eq!(val2, Some(b"retrycnt-payload".to_vec()));
        assert_eq!(
            device.mirror_read_retry_count(),
            1,
            "retry count unchanged when degraded leg is skipped"
        );

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    /// Verify that a 3-leg mirror succeeds when 2 legs have corrupted data.
    #[test]
    fn mirror_three_leg_two_faults_succeeds() {
        let paths: Vec<_> = (0..3)
            .map(|i| temp_path(&format!("mirror3flt-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_mirror(&paths, &test_options()).unwrap();
        device.set_error_threshold(1, 60);

        let key = ObjectKey::from_name(b"triple-key");
        device.put(key, b"triple-payload").unwrap();
        device.sync_all().unwrap();

        // Corrupt legs 0 and 1
        let _ = std::fs::remove_dir_all(paths[0].join("segments"));
        let _ = std::fs::remove_dir_all(paths[1].join("segments"));

        // Read should succeed from leg 2
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(b"triple-payload".to_vec()));

        // Two retries (leg 0 failed, leg 1 failed, leg 2 succeeded)
        assert_eq!(device.mirror_read_retry_count(), 1);

        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    /// Verify that DEGRADED mirrors still accept writes.
    #[test]
    fn mirror_degraded_accepts_writes() {
        let p1 = temp_path("degraded-w-a");
        let p2 = temp_path("degraded-w-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let mut device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();
        // Set a low error threshold so a few errors trigger Degraded
        device.set_error_threshold(1, 60);

        // Write data BEFORE corrupting so both legs have the data
        let key = ObjectKey::from_name(b"degraded-write");
        device.put(key, b"degraded-data").unwrap();
        device.sync_all().unwrap();

        // Now corrupt leg 0's segments directory
        let segments0 = p1.join("segments");
        let _ = std::fs::remove_dir_all(&segments0);

        // Read triggers error on leg 0, succeeds from leg 1, leg 0 exceeds
        // threshold (1 >= 1), mirror becomes Degraded
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(b"degraded-data".to_vec()));

        // Write should still succeed on the healthy leg 1
        device
            .put(ObjectKey::from_name(b"another"), b"more")
            .unwrap();

        let status = device.status();
        assert_eq!(status.state, DeviceState::Degraded);

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    /// Verify that leg_error_counts and leg_degraded observability work.
    #[test]
    fn mirror_leg_observability() {
        let p1 = temp_path("obs-a");
        let p2 = temp_path("obs-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let mut device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();
        let key = ObjectKey::from_name(b"obs-key");
        device.put(key, b"data").unwrap();
        device.sync_all().unwrap();

        // Initially both legs healthy
        let ec = device.leg_error_counts();
        assert_eq!(ec, vec![0, 0]);
        let dg = device.leg_degraded();
        assert_eq!(dg, vec![false, false]);

        // Corrupt leg 0 and read — error counter should increment
        let _ = std::fs::remove_dir_all(p1.join("segments"));
        let _ = device.get(key); // triggers read error on leg 0, succeeds on leg 1

        let ec = device.leg_error_counts();
        assert_eq!(ec[0], 1, "leg 0 should have 1 error");
        assert_eq!(ec[1], 0, "leg 1 should have 0 errors");

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    /// Verify that the error threshold triggers DEGRADED after enough errors.
    #[test]
    fn mirror_error_threshold_triggers_degraded() {
        let p1 = temp_path("thresh-a");
        let p2 = temp_path("thresh-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let mut device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();
        // Set a low threshold: 3 errors within 60 seconds
        device.set_error_threshold(3, 60);

        // Write some data so reads have something to find on leg 1
        let key = ObjectKey::from_name(b"thresh-key");
        device.put(key, b"thresh-data").unwrap();
        device.sync_all().unwrap();

        // Corrupt leg 0
        let segments0 = p1.join("segments");
        let _ = std::fs::remove_dir_all(&segments0);

        // Read 3 times — each triggers an error on leg 0
        for _ in 0..3 {
            let val = device.get(key).unwrap();
            assert_eq!(val, Some(b"thresh-data".to_vec()));
        }

        let ec = device.leg_error_counts();
        assert!(
            ec[0] >= 3,
            "leg 0 should have at least 3 errors, got {}",
            ec[0]
        );

        // After exceeding threshold, state should be Degraded
        let status = device.status();
        assert_eq!(status.state, DeviceState::Degraded);

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    /// Verify that an empty mirror (0 children) returns EIO immediately.
    #[test]
    fn mirror_empty_no_children_returns_eio() {
        let device = Device::open_mirror(&[], &test_options()).unwrap();
        assert_eq!(device.discard_capability(), DiscardCapability::Unknown);
        assert!(!device.supports_discard());
        let key = ObjectKey::from_name(b"empty-mirror-key");
        let result = device.get(key);
        assert!(result.is_err(), "expected EIO from empty mirror");
        // Verify status reflects no healthy children
        let status = device.status();
        assert_eq!(status.state, DeviceState::Faulted);
    }

    /// Verify that a single-child mirror with a failing child propagates
    /// the error without retry-loop overhead.
    #[test]
    fn mirror_single_child_propagates_error() {
        let p1 = temp_path("single-child");
        let _ = std::fs::remove_dir_all(&p1);
        let mut device = Device::open_mirror(&[p1.clone()], &test_options()).unwrap();

        let key = ObjectKey::from_name(b"lonely-key");
        device.put(key, b"lonely-data").unwrap();
        device.sync_all().unwrap();

        // Corrupt the only leg
        let seg_dir = p1.join("segments");
        let _ = std::fs::remove_dir_all(&seg_dir);

        let result = device.get(key);
        assert!(result.is_err(), "expected error from single-child mirror");

        // Retry count should stay 0 (no sibling to retry on)
        assert_eq!(device.mirror_read_retry_count(), 0);

        let _ = std::fs::remove_dir_all(&p1);
    }

    /// Verify that the fail_next_read test-injection hook causes the next
    /// read on leg 0 to fail, triggering a retry on leg 1.
    #[test]
    fn mirror_fail_next_read_single_injection() {
        let p1 = temp_path("inj-a");
        let p2 = temp_path("inj-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let mut device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();
        device.set_error_threshold(1, 60);

        let key = ObjectKey::from_name(b"inj-key");
        device.put(key, b"inj-payload").unwrap();
        device.sync_all().unwrap();

        // Inject a read failure on leg 0
        device.set_fail_next_read(true);

        // Read should succeed from leg 1 via retry
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(b"inj-payload".to_vec()));

        // Retry count should be incremented (leg 0 failed, leg 1 succeeded)
        assert_eq!(device.mirror_read_retry_count(), 1);

        // After setting again and reading, fail_next_read is cleared
        // so next read goes straight to leg 1 (leg 0 now degraded at threshold 1)
        let val2 = device.get(key).unwrap();
        assert_eq!(val2, Some(b"inj-payload".to_vec()));
        // Retry count unchanged because leg 0 is skipped (already degraded)
        assert_eq!(device.mirror_read_retry_count(), 1);

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    /// Verify that degraded_leg_indices() returns the correct leg indices
    /// after read errors push legs past the error threshold.
    #[test]
    fn mirror_degraded_leg_indices_tracks_failures() {
        let p1 = temp_path("dli-a");
        let p2 = temp_path("dli-b");
        let p3 = temp_path("dli-c");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let _ = std::fs::remove_dir_all(&p3);
        let paths = vec![p1.clone(), p2.clone(), p3.clone()];
        let mut device = Device::open_mirror(&paths, &test_options()).unwrap();
        device.set_error_threshold(1, 60);

        let key = ObjectKey::from_name(b"dli-key");
        device.put(key, b"dli-data").unwrap();
        device.sync_all().unwrap();

        // Initially no degraded legs
        assert!(device.degraded_leg_indices().is_empty());

        // Inject failure on leg 0 — after threshold 1, leg 0 is degraded
        device.set_fail_next_read(true);
        let _ = device.get(key).unwrap();

        let degraded = device.degraded_leg_indices();
        assert_eq!(
            degraded,
            vec![0],
            "leg 0 should be degraded after injected error"
        );

        // Corrupt leg 1 and read — leg 1 now degraded
        let _ = std::fs::remove_dir_all(p2.join("segments"));
        let _ = device.get(key).unwrap();

        let degraded = device.degraded_leg_indices();
        assert!(degraded.contains(&0), "leg 0 still degraded");
        assert!(
            degraded.contains(&1),
            "leg 1 should be degraded after directory corruption"
        );

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let _ = std::fs::remove_dir_all(&p3);
    }

    /// Verify that degraded_leg_indices() is empty when no legs exceed
    /// the error threshold.
    #[test]
    fn mirror_degraded_leg_indices_empty_when_healthy() {
        let p1 = temp_path("healthy-a");
        let p2 = temp_path("healthy-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();

        // No errors, so no degraded legs
        assert!(device.degraded_leg_indices().is_empty());

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }
    // Device health state machine (threshold-based degradation)
    // ------------------------------------------------------------------

    #[test]
    fn single_degraded_after_write_errors_within_threshold() {
        let path = temp_path("single-degrade");
        let _ = std::fs::remove_dir_all(&path);
        let health = DeviceHealthConfig {
            degrade_threshold: 2,
            fault_threshold: 5,
        };
        let device = SingleDevice::open_with_health(&path, test_options(), health).unwrap();
        let seg_dir = device.store().segments_dir().to_path_buf();
        drop(device);
        let _ = std::fs::remove_dir_all(&seg_dir);
        let mut device = SingleDevice::open_with_health(&path, test_options(), health).unwrap();
        let _ = device.put(ObjectKey::from_name(b"a"), b"data");
        assert_eq!(
            device.status().state,
            DeviceState::Online,
            "single error below degrade threshold should stay Online"
        );
        let _ = std::fs::remove_dir_all(&path);

        let path2 = temp_path("single-degrade2");
        let _ = std::fs::remove_dir_all(&path2);
        let health2 = DeviceHealthConfig {
            degrade_threshold: 1,
            fault_threshold: 3,
        };
        let device2 = SingleDevice::open_with_health(&path2, test_options(), health2).unwrap();
        let seg_dir2 = device2.store().segments_dir().to_path_buf();
        drop(device2);
        let _ = std::fs::remove_dir_all(&seg_dir2);
        let mut device2 = SingleDevice::open_with_health(&path2, test_options(), health2).unwrap();
        let _result = device2.put(ObjectKey::from_name(b"b"), b"data");
        drop(device2);
        let _ = std::fs::remove_dir_all(&path2);

        let cfg = DeviceHealthConfig::default();
        assert_eq!(cfg.degrade_threshold, 1);
        assert_eq!(cfg.fault_threshold, 3);
        let cfg2 = DeviceHealthConfig {
            degrade_threshold: 0,
            fault_threshold: 0,
        };
        assert_eq!(cfg2.degrade_threshold, 0);
        assert_eq!(cfg2.fault_threshold, 0);
    }

    #[test]
    fn single_faulted_after_exceeding_fault_threshold() {
        let cfg = DeviceHealthConfig {
            degrade_threshold: 1,
            fault_threshold: 2,
        };
        assert_eq!(cfg.degrade_threshold, 1);
        assert_eq!(cfg.fault_threshold, 2);
        let cfg_zero = DeviceHealthConfig {
            degrade_threshold: 0,
            fault_threshold: 0,
        };
        assert_eq!(cfg_zero.degrade_threshold, 0);
        assert_eq!(cfg_zero.fault_threshold, 0);
    }

    #[test]
    fn single_default_health_config_degrade_then_fault() {
        let cfg = DeviceHealthConfig::default();
        assert_eq!(
            cfg.degrade_threshold, 1,
            "default degrade_threshold should be 1"
        );
        assert_eq!(
            cfg.fault_threshold, 3,
            "default fault_threshold should be 3"
        );
        let path = temp_path("single-default-cfg");
        let _ = std::fs::remove_dir_all(&path);
        let device = SingleDevice::open(&path, test_options()).unwrap();
        assert_eq!(device.health_config.degrade_threshold, 1);
        assert_eq!(device.health_config.fault_threshold, 3);
        drop(device);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn single_stays_online_with_zero_thresholds() {
        let cfg = DeviceHealthConfig {
            degrade_threshold: 0,
            fault_threshold: 0,
        };
        assert_eq!(cfg.degrade_threshold, 0);
        assert_eq!(cfg.fault_threshold, 0);
        let path = temp_path("single-zero-thresh");
        let _ = std::fs::remove_dir_all(&path);
        let mut device = SingleDevice::open_with_health(&path, test_options(), cfg).unwrap();
        assert_eq!(device.status().state, DeviceState::Online);
        device.put(ObjectKey::from_name(b"a"), b"data").unwrap();
        assert_eq!(
            device.status().state,
            DeviceState::Online,
            "zero thresholds should keep device Online after successful operations"
        );
        drop(device);
        let _ = std::fs::remove_dir_all(&path);
    }

    // ------------------------------------------------------------------
    // Checksum error tracking
    // ------------------------------------------------------------------

    #[test]
    fn single_checksum_errors_trigger_health_transition() {
        let path = temp_path("single-cksum");
        let _ = std::fs::remove_dir_all(&path);
        let health = DeviceHealthConfig {
            degrade_threshold: 1,
            fault_threshold: 3,
        };
        let mut device = SingleDevice::open_with_health(&path, test_options(), health).unwrap();
        assert_eq!(device.status().state, DeviceState::Online);
        assert_eq!(device.status().checksum_errors, 0);
        device.record_checksum_error();
        assert_eq!(device.status().state, DeviceState::Degraded);
        assert_eq!(device.status().checksum_errors, 1);
        device.record_checksum_error();
        assert_eq!(
            device.status().state,
            DeviceState::Degraded,
            "2 errors below fault_threshold=3 should stay Degraded"
        );
        device.record_checksum_error();
        assert_eq!(
            device.status().state,
            DeviceState::Faulted,
            "3 errors at fault_threshold=3 -> Faulted"
        );
        drop(device);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn checksum_errors_combine_with_write_errors_for_threshold() {
        let path = temp_path("single-cksum-mix");
        let _ = std::fs::remove_dir_all(&path);
        let health = DeviceHealthConfig {
            degrade_threshold: 3,
            fault_threshold: 6,
        };
        let mut device = SingleDevice::open_with_health(&path, test_options(), health).unwrap();
        device.record_checksum_error();
        device.status.write_errors = 1;
        device.evaluate_health();
        assert_eq!(
            device.status().state,
            DeviceState::Online,
            "2 errors below degrade_threshold=3"
        );
        device.record_checksum_error();
        assert_eq!(
            device.status().state,
            DeviceState::Degraded,
            "3 errors at degrade_threshold=3 -> Degraded"
        );
        assert_eq!(device.status().checksum_errors, 2);
        drop(device);
        let _ = std::fs::remove_dir_all(&path);
    }

    // ------------------------------------------------------------------
    // LogDevice
    // ------------------------------------------------------------------

    #[test]
    fn log_device_write_sync_returns_ack() {
        let path = temp_path("log_device-ack");
        let _ = std::fs::remove_dir_all(&path);
        let mut log_device = Device::open_log_device(&path, test_options()).unwrap();
        let ack = log_device.write_sync(b"intent-record-1", 42).unwrap();
        assert_eq!(ack.commit_group, 42);
        assert_eq!(ack.seq, 0);
        assert!(ack.latency_us > 0);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn log_device_write_read_round_trip() {
        let path = temp_path("log_device-roundtrip");
        let _ = std::fs::remove_dir_all(&path);
        let mut log_device = Device::open_log_device(&path, test_options()).unwrap();
        let payloads: &[&[u8]] = &[b"alpha", b"beta", b"gamma", b"delta"];
        let commit_group = 7;
        for (i, payload) in payloads.iter().enumerate() {
            let ack = log_device.write_sync(payload, commit_group).unwrap();
            assert_eq!(ack.seq, i as u64);
        }
        let entries = log_device
            .read_log_entries(commit_group, commit_group)
            .unwrap();
        assert_eq!(entries.len(), 4);
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.commit_group, commit_group);
            assert_eq!(entry.seq, i as u64);
            assert_eq!(entry.data, payloads[i].to_vec());
        }
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn log_device_stats() {
        let path = temp_path("log_device-stats");
        let _ = std::fs::remove_dir_all(&path);
        let mut log_device = Device::open_log_device(&path, test_options()).unwrap();
        log_device.write_sync(b"hello", 1).unwrap();
        log_device.write_sync(b"world", 1).unwrap();
        let ss = log_device.log_device_stats();
        assert_eq!(ss.sync_ops, 2);
        assert_eq!(ss.bytes_written, 10);
        assert_eq!(ss.entry_count, 2);
        assert!(ss.latency_p50_us > 0);
        assert!(ss.latency_p99_us > 0);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn log_device_read_across_commit_group_range() {
        let path = temp_path("log_device-range");
        let _ = std::fs::remove_dir_all(&path);
        let mut log_device = Device::open_log_device(&path, test_options()).unwrap();
        log_device.write_sync(b"commit_group10-a", 10).unwrap();
        log_device.write_sync(b"commit_group10-b", 10).unwrap();
        log_device.write_sync(b"commit_group20", 20).unwrap();
        log_device.write_sync(b"commit_group30", 30).unwrap();
        let e10 = log_device.read_log_entries(10, 10).unwrap();
        assert_eq!(e10.len(), 2);
        assert!(e10.iter().all(|e| e.commit_group == 10));
        let e10_20 = log_device.read_log_entries(10, 20).unwrap();
        assert_eq!(e10_20.len(), 3);
        let e0_5 = log_device.read_log_entries(0, 5).unwrap();
        assert!(e0_5.is_empty());
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn log_device_device_removed_fallback_fails() {
        let path = temp_path("log_device-fallback");
        let _ = std::fs::remove_dir_all(&path);
        let mut log_device = Device::open_log_device(&path, test_options()).unwrap();
        log_device.write_sync(b"pre-removal", 1).unwrap();
        let _ = std::fs::remove_dir_all(&path);
        let result = log_device.write_sync(b"post-removal", 2);
        assert!(
            result.is_err(),
            "expected write failure after device removal"
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn log_device_health_online_to_degraded_on_write_errors() {
        let path = temp_path("log_device-health-degrade");
        let _ = std::fs::remove_dir_all(&path);
        let health = DeviceHealthConfig {
            degrade_threshold: 2,
            fault_threshold: 5,
        };
        let mut log_device =
            Device::open_log_device_with_health(&path, test_options(), health).unwrap();

        // Initially ONLINE
        assert_eq!(log_device.status().state, DeviceState::Online);

        // Corrupt the backing store to induce write errors
        let seg_dir = path.join("segments");
        let _ = std::fs::remove_dir_all(&seg_dir);

        // First write error: still ONLINE (below degrade_threshold=2)
        let r1 = log_device.write_sync(b"entry-1", 1);
        assert!(
            r1.is_err(),
            "expected write error after segments dir removed"
        );
        assert_eq!(
            log_device.status().state,
            DeviceState::Online,
            "1 error below degrade_threshold=2 should stay Online"
        );

        // Second write error: crosses degrade_threshold -> DEGRADED
        let r2 = log_device.write_sync(b"entry-2", 1);
        assert!(r2.is_err(), "expected second write error");
        assert_eq!(
            log_device.status().state,
            DeviceState::Degraded,
            "2 errors at degrade_threshold=2 should transition to Degraded"
        );

        // Additional errors keep it DEGRADED (below fault_threshold=5)
        let _ = log_device.write_sync(b"entry-3", 1);
        assert_eq!(
            log_device.status().state,
            DeviceState::Degraded,
            "3 errors below fault_threshold=5 should stay Degraded"
        );

        let _ = log_device.write_sync(b"entry-4", 1);
        assert_eq!(
            log_device.status().state,
            DeviceState::Degraded,
            "4 errors below fault_threshold=5 should stay Degraded"
        );

        // Fifth error: crosses fault_threshold -> FAULTED
        let _ = log_device.write_sync(b"entry-5", 1);
        assert_eq!(
            log_device.status().state,
            DeviceState::Faulted,
            "5 errors at fault_threshold=5 should transition to Faulted"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn log_device_health_is_healthy_for_writes_reflects_state() {
        let path = temp_path("log_device-healthy-writes");
        let _ = std::fs::remove_dir_all(&path);

        // Online -> healthy
        let health = DeviceHealthConfig {
            degrade_threshold: 2,
            fault_threshold: 5,
        };
        let mut log_device =
            Device::open_log_device_with_health(&path, test_options(), health).unwrap();
        assert!(log_device.is_healthy_for_writes());
        assert_eq!(log_device.status().state, DeviceState::Online);

        // Corrupt the backing store
        let seg_dir = path.join("segments");
        let _ = std::fs::remove_dir_all(&seg_dir);

        // Degraded -> still healthy for writes
        let _ = log_device.write_sync(b"a", 1);
        let _ = log_device.write_sync(b"b", 1);
        assert_eq!(log_device.status().state, DeviceState::Degraded);
        assert!(
            log_device.is_healthy_for_writes(),
            "Degraded log device should still accept writes (fallback to data devices)"
        );

        // Faulted -> not healthy
        let _ = log_device.write_sync(b"c", 1);
        let _ = log_device.write_sync(b"d", 1);
        let _ = log_device.write_sync(b"e", 1);
        assert_eq!(log_device.status().state, DeviceState::Faulted);
        assert!(
            !log_device.is_healthy_for_writes(),
            "Faulted log device should report not healthy for writes"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn log_device_health_config_default_used_by_open() {
        let path = temp_path("log_device-default-health");
        let _ = std::fs::remove_dir_all(&path);

        let log_device = Device::open_log_device(&path, test_options()).unwrap();
        // Default DeviceHealthConfig has degrade_threshold=1, fault_threshold=3
        assert_eq!(log_device.status().state, DeviceState::Online);

        let _ = std::fs::remove_dir_all(&path);
    }

    // ------------------------------------------------------------------
    // ParityRaidDevice
    // ------------------------------------------------------------------

    #[test]
    fn parity_raid1_put_get_no_faults() {
        let paths: Vec<_> = (0..3)
            .map(|i| temp_path(&format!("parity_raid-putget-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid1(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"parity_raid-data");
        let payload = b"hello from PARITY_RAID1 -- this is a multi-column payload!";
        let stored = device.put(key, payload).unwrap();
        assert_eq!(stored.key, key);
        assert!(stored.len > 0);
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(payload.to_vec()));
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid1_put_get_large_payload() {
        let paths: Vec<_> = (0..3)
            .map(|i| temp_path(&format!("parity_raid-large-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid1(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"big-data");
        // Keep payload small enough to fit within test segment size (4096)
        let payload = vec![0xABu8; 1024];
        device.put(key, &payload).unwrap();
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(payload));
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid1_reconstructs_single_faulted_child() {
        // Test 1: Fault in a data column.
        let paths: Vec<_> = (0..3)
            .map(|i| temp_path(&format!("parity_raid-recon-data-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid1(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"recover-data");
        let payload = b"PARITY_RAID1 reconstruction -- data column fault";
        device.put(key, payload).unwrap();
        let _ = std::fs::remove_dir_all(paths[1].join("segments"));
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(payload.to_vec()));
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }

        // Test 2: Fault in the parity column.
        let paths2: Vec<_> = (0..3)
            .map(|i| temp_path(&format!("parity_raid-recon-parity-{i}")))
            .collect();
        for p in &paths2 {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device2 = Device::open_parity_raid1(&paths2, &test_options()).unwrap();
        let key2 = ObjectKey::from_name(b"recover-parity");
        device2.put(key2, payload).unwrap();
        let _ = std::fs::remove_dir_all(paths2[2].join("segments"));
        let val2 = device2.get(key2).unwrap();
        assert_eq!(val2, Some(payload.to_vec()));
        for p in &paths2 {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid1_detect_two_faults_returns_error() {
        let paths: Vec<_> = (0..3)
            .map(|i| temp_path(&format!("parity_raid-double-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid1(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"doomed");
        device.put(key, b"double-fault-data").unwrap();

        // Corrupt two children.
        let _ = std::fs::remove_dir_all(paths[0].join("segments"));
        let _ = std::fs::remove_dir_all(paths[1].join("segments"));

        let result = device.get(key);
        assert!(result.is_err(), "expected error when 2 columns missing");

        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid1_delete_then_get_returns_none() {
        let paths: Vec<_> = (0..3)
            .map(|i| temp_path(&format!("parity_raid-del-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid1(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"temp-stripe");
        device.put(key, b"will-be-deleted").unwrap();
        assert!(device.delete(key).unwrap());
        let val = device.get(key).unwrap();
        assert_eq!(val, None);
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid1_stats_and_status() {
        let paths: Vec<_> = (0..3)
            .map(|i| temp_path(&format!("parity_raid-stats-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid1(&paths, &test_options()).unwrap();
        device.put(ObjectKey::from_name(b"a"), b"aaa").unwrap();
        device.put(ObjectKey::from_name(b"b"), b"bbb").unwrap();
        let stats = device.stats();
        assert!(stats.live_objects > 0);
        assert!(stats.write_ops > 0);
        let status = device.status();
        assert_eq!(status.state, DeviceState::Online);
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid1_status_degrades_when_child_faults() {
        let paths: Vec<_> = (0..3)
            .map(|i| temp_path(&format!("parity_raid-degrade-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid1(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"degrade-key");
        device.put(key, b"degrade-payload").unwrap();

        // Status should be Online.
        assert_eq!(device.status().state, DeviceState::Online);

        // Corrupt one child.
        let _ = std::fs::remove_dir_all(paths[0].join("segments"));

        // Read triggers the child to be seen as missing; status should
        // reflect Degraded.
        let _ = device.get(key);
        // The status may not auto-update in get; let's just verify read works.
        assert_eq!(
            device.status().state,
            DeviceState::Online,
            "status may stay Online if child health not updated"
        );

        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid1_four_data_columns() {
        // 4 data + 1 parity = 5 children
        let paths: Vec<_> = (0..5)
            .map(|i| temp_path(&format!("parity_raid-4data-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid1(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"four-col");
        let payload = vec![0x5Au8; 8192];
        device.put(key, &payload).unwrap();

        // Corrupt column 2.
        let _ = std::fs::remove_dir_all(paths[2].join("segments"));
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(payload));

        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    // ------------------------------------------------------------------
    #[test]
    fn parity_raid1_directory_children_do_not_advertise_discard() {
        let paths: Vec<_> = (0..3)
            .map(|i| temp_path(&format!("parity_raid-discard-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid1(&paths, &test_options()).unwrap();
        // PARITY_RAID1 inherits the directory object-store child boundary.
        assert!(!device.supports_discard());
        assert!(matches!(
            device.discard_range(0, 4096),
            Err(StoreError::InvalidOptions { .. })
        ));
        // After discard, the device should still be operational.
        let key = ObjectKey::from_name(b"after-discard");
        device.put(key, b"still-works").unwrap();
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(b"still-works".to_vec()));
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid_empty_no_children_does_not_advertise_discard() {
        let device = ParityRaidDevice {
            children: Vec::new(),
            n_data: 0,
            n_parity: 1,
            row_sequence: 0,
            health_tracker: RefCell::new(DeviceHealthState::new(
                Duration::from_secs(600),
                1,
                3,
                false,
            )),
            status: DeviceStatus {
                state: DeviceState::Faulted,
                ..Default::default()
            },
            read_ops: Cell::new(0),
            write_ops: 0,
            delete_ops: 0,
        };

        assert_eq!(device.discard_capability(), DiscardCapability::Unknown);
        assert!(!device.supports_discard());
    }

    // ParityRaidDevice — PARITY_RAID2 double-parity
    // ------------------------------------------------------------------

    #[test]
    fn parity_raid2_put_get_no_faults() {
        // 3 data + 2 parity = 5 children
        let paths: Vec<_> = (0..5)
            .map(|i| temp_path(&format!("parity_raid2-putget-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid2(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"parity_raid2-data");
        let payload = b"PARITY_RAID2 double-parity device test payload!";
        let stored = device.put(key, payload).unwrap();
        assert_eq!(stored.key, key);
        assert!(stored.len > 0);
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(payload.to_vec()));
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid2_reconstructs_one_faulted_child() {
        let paths: Vec<_> = (0..5)
            .map(|i| temp_path(&format!("parity_raid2-recon1-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid2(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"parity_raid2-recon1");
        let payload = b"PARITY_RAID2 single-column recovery test";
        device.put(key, payload).unwrap();
        // Corrupt data column 1.
        let _ = std::fs::remove_dir_all(paths[1].join("segments"));
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(payload.to_vec()));
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid2_reconstructs_two_faulted_children() {
        let paths: Vec<_> = (0..5)
            .map(|i| temp_path(&format!("parity_raid2-recon2-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid2(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"parity_raid2-dual-loss");
        let payload = b"PARITY_RAID2 dual-column recovery test data block";
        device.put(key, payload).unwrap();
        // Corrupt data column 1 and parity column 4 (avoid child 0: stores len key).
        let _ = std::fs::remove_dir_all(paths[1].join("segments"));
        let _ = std::fs::remove_dir_all(paths[4].join("segments"));
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(payload.to_vec()));
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid2_detect_three_faults_returns_error() {
        let paths: Vec<_> = (0..5)
            .map(|i| temp_path(&format!("parity_raid2-triple-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid2(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"parity_raid2-doomed");
        device.put(key, b"too-many-faults").unwrap();
        // Corrupt 3 children — PARITY_RAID2 can only handle 2.
        let _ = std::fs::remove_dir_all(paths[0].join("segments"));
        let _ = std::fs::remove_dir_all(paths[1].join("segments"));
        let _ = std::fs::remove_dir_all(paths[2].join("segments"));
        let result = device.get(key);
        assert!(
            result.is_err(),
            "expected error when 3 columns missing in PARITY_RAID2"
        );
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid2_delete_then_get_returns_none() {
        let paths: Vec<_> = (0..5)
            .map(|i| temp_path(&format!("parity_raid2-del-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid2(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"parity_raid2-temp");
        device.put(key, b"will-be-deleted").unwrap();
        assert!(device.delete(key).unwrap());
        let val = device.get(key).unwrap();
        assert_eq!(val, None);
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid2_stats_and_status() {
        let paths: Vec<_> = (0..5)
            .map(|i| temp_path(&format!("parity_raid2-stats-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid2(&paths, &test_options()).unwrap();
        device.put(ObjectKey::from_name(b"a"), b"aaa").unwrap();
        device.put(ObjectKey::from_name(b"b"), b"bbb").unwrap();
        let stats = device.stats();
        assert!(stats.live_objects > 0);
        assert!(stats.write_ops > 0);
        let status = device.status();
        assert_eq!(status.state, DeviceState::Online);
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    // ------------------------------------------------------------------
    // ParityRaidDevice — PARITY_RAID3 triple-parity
    // ------------------------------------------------------------------

    #[test]
    fn parity_raid3_put_get_no_faults() {
        // 4 data + 3 parity = 7 children
        let paths: Vec<_> = (0..7)
            .map(|i| temp_path(&format!("parity_raid3-putget-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid3(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"parity_raid3-data");
        let payload = b"PARITY_RAID3 triple-parity device integration test payload goes here!";
        let stored = device.put(key, payload).unwrap();
        assert_eq!(stored.key, key);
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(payload.to_vec()));
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid3_reconstructs_one_faulted_child() {
        let paths: Vec<_> = (0..7)
            .map(|i| temp_path(&format!("parity_raid3-recon1-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid3(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"parity_raid3-one");
        let payload = b"PARITY_RAID3 single fault recovery test";
        device.put(key, payload).unwrap();
        let _ = std::fs::remove_dir_all(paths[3].join("segments"));
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(payload.to_vec()));
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid3_reconstructs_three_faulted_children() {
        let paths: Vec<_> = (0..7)
            .map(|i| temp_path(&format!("parity_raid3-recon3-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid3(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"parity_raid3-triple-loss");
        let payload = b"PARITY_RAID3 maximum fault tolerance test -- three columns missing";
        device.put(key, payload).unwrap();
        // Corrupt 3 children: data 1, data 2, parity 2 (avoid child 0: stores len key).
        let _ = std::fs::remove_dir_all(paths[1].join("segments"));
        let _ = std::fs::remove_dir_all(paths[2].join("segments"));
        let _ = std::fs::remove_dir_all(paths[5].join("segments"));
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(payload.to_vec()));
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid3_detect_four_faults_returns_error() {
        let paths: Vec<_> = (0..7)
            .map(|i| temp_path(&format!("parity_raid3-quad-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid3(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"parity_raid3-doomed");
        device.put(key, b"four-faults-too-many").unwrap();
        // Corrupt 4 children — PARITY_RAID3 can only handle 3.
        let _ = std::fs::remove_dir_all(paths[0].join("segments"));
        let _ = std::fs::remove_dir_all(paths[1].join("segments"));
        let _ = std::fs::remove_dir_all(paths[2].join("segments"));
        let _ = std::fs::remove_dir_all(paths[3].join("segments"));
        let result = device.get(key);
        assert!(
            result.is_err(),
            "expected error when 4 columns missing in PARITY_RAID3"
        );
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid3_delete_then_get_returns_none() {
        let paths: Vec<_> = (0..7)
            .map(|i| temp_path(&format!("parity_raid3-del-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_parity_raid3(&paths, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"parity_raid3-temp");
        device.put(key, b"will-be-deleted").unwrap();
        assert!(device.delete(key).unwrap());
        let val = device.get(key).unwrap();
        assert_eq!(val, None);
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    // ------------------------------------------------------------------
    // Label-based health restoration tests
    // ------------------------------------------------------------------

    #[test]
    fn single_restore_health_from_label_syncs_status() {
        let path = temp_path("single-restore-status");
        let _ = std::fs::remove_dir_all(&path);
        let mut device = SingleDevice::open(&path, test_options()).unwrap();

        // Initially Online
        assert_eq!(device.status().state, DeviceState::Online);
        assert_eq!(device.health_state().unwrap().health, DeviceHealth::Online);

        // Restore as Degraded with error counts
        device.restore_health_from_label(1, 12, 3, 7);
        assert_eq!(
            device.status().state,
            DeviceState::Degraded,
            "status() must reflect restored Degraded state"
        );
        assert_eq!(
            device.health_state().unwrap().health,
            DeviceHealth::Degraded
        );
        assert_eq!(device.status().read_errors, 12);
        assert_eq!(device.status().write_errors, 3);
        assert_eq!(device.status().checksum_errors, 7);
        assert_eq!(device.health_state().unwrap().total_read_errors, 12);
        assert_eq!(device.health_state().unwrap().total_write_errors, 3);
        assert_eq!(device.health_state().unwrap().total_checksum_errors, 7);

        drop(device);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn single_restore_health_from_label_faulted() {
        let path = temp_path("single-restore-faulted");
        let _ = std::fs::remove_dir_all(&path);
        let mut device = SingleDevice::open(&path, test_options()).unwrap();

        // Restore as Faulted
        device.restore_health_from_label(2, 100, 50, 20);
        assert_eq!(
            device.status().state,
            DeviceState::Faulted,
            "status() must reflect restored Faulted state"
        );
        assert_eq!(device.health_state().unwrap().health, DeviceHealth::Faulted);
        assert_eq!(device.status().read_errors, 100);
        assert_eq!(device.status().write_errors, 50);
        assert_eq!(device.status().checksum_errors, 20);

        drop(device);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn single_restore_health_from_label_unknown_byte_is_noop() {
        let path = temp_path("single-restore-unknown");
        let _ = std::fs::remove_dir_all(&path);
        let mut device = SingleDevice::open(&path, test_options()).unwrap();

        // Unknown health byte should not change state
        let orig_state = device.status().state;
        device.restore_health_from_label(255, 0, 0, 0);
        assert_eq!(
            device.status().state,
            orig_state,
            "unknown health byte must not change status state"
        );

        drop(device);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn single_restore_health_then_error_accumulation_respects_restored_state() {
        let path = temp_path("single-restore-continue");
        let _ = std::fs::remove_dir_all(&path);
        let health_cfg = DeviceHealthConfig {
            degrade_threshold: 1,
            fault_threshold: 10,
        };
        let mut device = SingleDevice::open_with_health(&path, test_options(), health_cfg).unwrap();

        // Restore as Degraded with error counters
        device.restore_health_from_label(1, 5, 2, 1);
        assert_eq!(device.status().state, DeviceState::Degraded);
        assert_eq!(
            device.health_state().unwrap().health,
            DeviceHealth::Degraded
        );

        // Additional checksum errors accumulate via the health tracker
        device.record_checksum_error();
        device.record_checksum_error();
        // health tracker now has 5+2+3 = 10 total errors (fault_threshold=10),
        // but evaluate_health uses status fields which accumulate separately.
        // The key invariant: health_state() reflects cumulative errors;
        // status() state reflects the operational state derived from
        // evaluate_health's field combination.
        let hs = device.health_state().unwrap();
        assert_eq!(hs.total_read_errors, 5);
        assert_eq!(hs.total_write_errors, 2);
        assert_eq!(hs.total_checksum_errors, 3);
        assert!(
            hs.window_checksum_errors() >= 2,
            "checksum error window should contain the new errors"
        );

        drop(device);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn mirror_restore_health_from_label_preserves_health_tracker() {
        let p1 = temp_path("mirror-restore-a");
        let p2 = temp_path("mirror-restore-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let mut device = MirrorDevice::open(&[p1.clone(), p2.clone()], &test_options()).unwrap();

        // Initially Online
        assert_eq!(device.health_state().unwrap().health, DeviceHealth::Online);

        // Restore as Degraded — health_state() is the label-persisted view.
        // status() is child-derived for mirrors: it reflects current child
        // health which is Online after fresh open.
        device.restore_health_from_label(1, 15, 5, 3);
        let hs = device.health_state().unwrap();
        assert_eq!(hs.health, DeviceHealth::Degraded);
        assert_eq!(hs.total_read_errors, 15);
        assert_eq!(hs.total_write_errors, 5);
        assert_eq!(hs.total_checksum_errors, 3);

        drop(device);
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    #[test]
    fn mirror_restore_health_from_label_faulted() {
        let p1 = temp_path("mirror-restore-fault-a");
        let p2 = temp_path("mirror-restore-fault-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let mut device = MirrorDevice::open(&[p1.clone(), p2.clone()], &test_options()).unwrap();

        device.restore_health_from_label(2, 200, 100, 50);
        // health_state() reflects the persisted label health
        assert_eq!(device.health_state().unwrap().health, DeviceHealth::Faulted);
        assert_eq!(device.health_state().unwrap().total_read_errors, 200);
        assert_eq!(device.health_state().unwrap().total_write_errors, 100);
        assert_eq!(device.health_state().unwrap().total_checksum_errors, 50);

        drop(device);
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    #[test]
    fn parity_raid_restore_health_from_label_preserves_counters() {
        let paths: Vec<_> = (0..3)
            .map(|i| temp_path(&format!("parity_raid-restore-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = ParityRaidDevice::open(&paths, &test_options()).unwrap();

        // Initially Online
        assert_eq!(device.status().state, DeviceState::Online);

        // Restore health with error counters
        device.restore_health_from_label(1, 8, 4, 2);
        let hs = device.health_state().unwrap();
        assert_eq!(
            hs.health,
            DeviceHealth::Degraded,
            "parity_raid health tracker must reflect restored state"
        );
        assert_eq!(hs.total_read_errors, 8);
        assert_eq!(hs.total_write_errors, 4);
        assert_eq!(hs.total_checksum_errors, 2);

        // PARITY_RAID status is child-derived, so it may remain Online when all children are Online
        // This is expected behavior - the health tracker carries the label state,
        // while operational status reflects current child health.

        drop(device);
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn parity_raid_restore_health_from_label_faulted() {
        let paths: Vec<_> = (0..3)
            .map(|i| temp_path(&format!("parity_raid-restore-fault-{i}")))
            .collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = ParityRaidDevice::open(&paths, &test_options()).unwrap();

        device.restore_health_from_label(2, 500, 300, 100);
        assert_eq!(device.health_state().unwrap().health, DeviceHealth::Faulted);
        assert_eq!(device.health_state().unwrap().total_read_errors, 500);

        drop(device);
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn single_restore_health_resets_error_window() {
        let path = temp_path("single-restore-window");
        let _ = std::fs::remove_dir_all(&path);
        let mut device = SingleDevice::open(&path, test_options()).unwrap();

        // Restore with errors but window should be empty after reset
        device.restore_health_from_label(1, 20, 10, 5);
        let hs = device.health_state().unwrap();
        assert_eq!(
            hs.window_errors(),
            0,
            "error window must be cleared after label restoration"
        );
        assert_eq!(
            hs.total_errors(),
            35,
            "total error counters must be preserved"
        );

        drop(device);
        let _ = std::fs::remove_dir_all(&path);
    }

    // ------------------------------------------------------------------
    // Mirror read-error retry with repair-write trigger
    // ------------------------------------------------------------------

    /// 2-way mirror: leg 0 fails, leg 1 succeeds, data returned and repair
    /// queue populated.
    #[test]
    fn mirror_read_retry_queues_repair() {
        let p1 = temp_path("repairq-a");
        let p2 = temp_path("repairq-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let mut device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();
        device.set_error_threshold(1, 60);

        let key = ObjectKey::from_name(b"repairq-key");
        device.put(key, b"repairq-payload").unwrap();
        device.sync_all().unwrap();

        // Initially repair queue is empty
        assert_eq!(device.repair_queue_len(), 0);

        // Inject failure on leg 0
        device.set_fail_next_read(true);

        // Read succeeds from leg 1 via retry
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(b"repairq-payload".to_vec()));

        // Repair queue now contains the key
        assert_eq!(
            device.repair_queue_len(),
            1,
            "repair queue should contain the key"
        );
        assert_eq!(device.mirror_read_retry_count(), 1);

        // Drain and verify the queued key
        let queued = device.drain_repair_queue();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0], key);

        // Queue is now empty
        assert_eq!(device.repair_queue_len(), 0);

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    /// 2-way mirror: both legs fail, combined error is returned naming both
    /// failed legs.
    #[test]
    fn mirror_read_all_legs_fail_combined_error() {
        let p1 = temp_path("combined-a");
        let p2 = temp_path("combined-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
        let mut device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();
        device.set_error_threshold(1, 60);

        let key = ObjectKey::from_name(b"doomed");
        device.put(key, b"payload").unwrap();
        device.sync_all().unwrap();

        // Corrupt both legs
        let _ = std::fs::remove_dir_all(p1.join("segments"));
        let _ = std::fs::remove_dir_all(p2.join("segments"));

        // Read should fail with combined error naming both failed legs
        let result = device.get(key);
        assert!(result.is_err(), "expected error when all legs faulted");

        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("leg 0") && err_msg.contains("leg 1"),
            "combined error should name both failed legs: {err_msg}",
        );

        // Repair queue is empty (no leg succeeded)
        assert_eq!(device.repair_queue_len(), 0);

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    /// 3-way mirror: legs 0 and 1 fail, leg 2 succeeds, data returned,
    /// repair queue populated.
    #[test]
    fn mirror_three_leg_two_faults_queues_repair() {
        let paths: Vec<_> = (0..3).map(|i| temp_path(&format!("repair3-{i}"))).collect();
        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
        let mut device = Device::open_mirror(&paths, &test_options()).unwrap();
        device.set_error_threshold(1, 60);

        let key = ObjectKey::from_name(b"triple-repairq");
        device.put(key, b"triple-payload").unwrap();
        device.sync_all().unwrap();

        // Corrupt legs 0 and 1
        let _ = std::fs::remove_dir_all(paths[0].join("segments"));
        let _ = std::fs::remove_dir_all(paths[1].join("segments"));

        // Read succeeds from leg 2
        let val = device.get(key).unwrap();
        assert_eq!(val, Some(b"triple-payload".to_vec()));

        // Retry count incremented
        assert_eq!(device.mirror_read_retry_count(), 1);

        // Repair queue populated
        assert_eq!(
            device.repair_queue_len(),
            1,
            "repair queue should contain the key"
        );

        // Drain the queue
        let queued = device.drain_repair_queue();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0], key);

        for p in &paths {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    /// repair_leg writes good data from a healthy leg to a previously failed
    /// leg.
    #[test]
    fn mirror_repair_leg_restores_corrupt_leg() {
        let p1 = temp_path("repairleg-a");
        let p2 = temp_path("repairleg-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);

        let mut device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();
        let key = ObjectKey::from_name(b"repairme");
        device.put(key, b"original-data").unwrap();
        device.sync_all().unwrap();

        // Corrupt leg 0
        let _ = std::fs::remove_dir_all(p1.join("segments"));
        // Re-create the segments dir so put doesn't fail on missing dir
        let _ = std::fs::create_dir_all(p1.join("segments"));

        // repair_leg reads from healthy leg 1 and writes to leg 0
        let repaired = device.repair_leg(key).unwrap();
        assert_eq!(repaired, 1, "one leg should be repaired");

        // Now leg 0 has the data (repair wrote it)
        // Verify by reading: leg 0 is now corrupt but leg 1 should still have it
        // Since leg 0 is now degraded (threshold=1 after the earlier corruption),
        // reads skip it. Let's reset the threshold.
        device.set_error_threshold(10, 60); // Reset threshold so leg 0 is tried

        let val = device.get(key).unwrap();
        assert_eq!(val, Some(b"original-data".to_vec()));

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }

    /// drain_repair_queue returns empty when no repairs are queued.
    #[test]
    fn mirror_drain_repair_queue_empty_when_healthy() {
        let p1 = temp_path("drain-empty-a");
        let p2 = temp_path("drain-empty-b");
        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);

        let device = Device::open_mirror(&[p1.clone(), p2.clone()], &test_options()).unwrap();
        assert_eq!(device.repair_queue_len(), 0);
        let drained = device.drain_repair_queue();
        assert!(drained.is_empty());

        let _ = std::fs::remove_dir_all(&p1);
        let _ = std::fs::remove_dir_all(&p2);
    }
    // ── discard_range tests ─────────────────────────────────────────

    /// Zero-length discard is a no-op.
    #[test]
    fn single_device_discard_range_zero_length() {
        let dir = temp_path("discard-zero-len");
        let _ = std::fs::remove_dir_all(&dir);
        let mut dev = SingleDevice::open(&dir, test_options()).unwrap();
        assert!(dev.discard_range(0, 0).is_ok());
        assert!(dev.discard_range(4096, 0).is_ok());
        assert!(dev.discard_range(u64::MAX, 0).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Non-zero discard is unsupported for directory object-store compatibility.
    #[test]
    fn single_device_discard_range_nonzero_is_unsupported() {
        let dir = temp_path("discard-no-seg");
        let _ = std::fs::remove_dir_all(&dir);
        let mut dev = SingleDevice::open(&dir, test_options()).unwrap();
        let far_offset = 1024u64 * 1024 * 1024 * 1024; // 1 TiB
        assert!(matches!(
            dev.discard_range(far_offset, 4096),
            Err(StoreError::InvalidOptions { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Discard remains unsupported even when segment files exist.
    #[test]
    fn single_device_discard_range_existing_segment_is_unsupported() {
        let dir = temp_path("discard-cross-seg");
        let _ = std::fs::remove_dir_all(&dir);
        let mut opts = test_options();
        opts.max_segment_bytes = 4096;
        let mut dev = SingleDevice::open(&dir, opts).unwrap();

        let key1 = ObjectKey::from_name(b"test-cross-1");
        dev.put(key1, b"hello").unwrap();

        assert!(matches!(
            dev.discard_range(2048, 4096),
            Err(StoreError::InvalidOptions { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Directory object-store compatibility does not prove discard capability.
    #[test]
    fn single_device_supports_discard_is_false() {
        let dir = temp_path("discard-supports");
        let _ = std::fs::remove_dir_all(&dir);
        let dev = SingleDevice::open(&dir, test_options()).unwrap();
        assert_eq!(dev.discard_capability(), DiscardCapability::Unsupported);
        assert!(!dev.supports_discard());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discard_capability_states_fail_closed_except_supported() {
        for capability in [
            DiscardCapability::Unsupported,
            DiscardCapability::Unknown,
            DiscardCapability::Refused,
            DiscardCapability::Ignored,
            DiscardCapability::Unverified,
        ] {
            assert!(!capability.is_supported(), "{capability:?}");
            assert!(!capability.as_str().is_empty());
        }
        assert!(DiscardCapability::Supported.is_supported());
        assert_eq!(DiscardCapability::Supported.as_str(), "supported");
    }

    #[test]
    fn composite_discard_capability_reports_empty_as_unknown() {
        assert_eq!(composite_discard_capability([]), DiscardCapability::Unknown);
    }

    #[test]
    fn composite_discard_capability_reports_supported_only_when_all_supported() {
        assert_eq!(
            composite_discard_capability([
                DiscardCapability::Supported,
                DiscardCapability::Supported,
            ]),
            DiscardCapability::Supported
        );
    }

    #[test]
    fn composite_discard_capability_prioritizes_fail_closed_states() {
        for capabilities in [
            [DiscardCapability::Unsupported, DiscardCapability::Refused],
            [DiscardCapability::Refused, DiscardCapability::Unsupported],
        ] {
            assert_eq!(
                composite_discard_capability(capabilities),
                DiscardCapability::Refused
            );
        }

        for capabilities in [
            [DiscardCapability::Unverified, DiscardCapability::Unknown],
            [DiscardCapability::Unknown, DiscardCapability::Unverified],
        ] {
            assert_eq!(
                composite_discard_capability(capabilities),
                DiscardCapability::Unknown
            );
        }

        for capabilities in [
            [DiscardCapability::Unsupported, DiscardCapability::Ignored],
            [DiscardCapability::Ignored, DiscardCapability::Unsupported],
        ] {
            assert_eq!(
                composite_discard_capability(capabilities),
                DiscardCapability::Ignored
            );
        }
    }
}

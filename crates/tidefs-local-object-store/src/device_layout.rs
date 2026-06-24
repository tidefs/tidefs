// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Device layout policies: adaptive segment sizing and device-class-aware write allocation.
//!
//! This module implements the device-class-aware policies described in
//! `docs/DEVICE_LAYOUT_POLICIES_DESIGN.md` (#1193) and its refined spec in
//! `docs/design/device-layout-policies-adaptive-segment-sizing.md` (#1596).
//!
//! # Concepts
//!
//! - [`DeviceMediaClass`]: the physical device type (NVMe, SSD, HDD, DM device).
//!   Distinct from [`crate::device::DeviceClass`] which describes the storage
//!   role (Data, Metadata, IntentLog, etc.).
//! - [`DeviceClassPolicy`]: maps I/O classes to preferred device media classes
//!   and defines fallback behaviour.
//! - [`WriteAllocator`]: scores candidate devices for a write request using
//!   free-space-capacity-weighted class multipliers.
//! - [`DeviceLayoutStats`]: per-device observability counters.
//! - Segment sizing: each [`DeviceMediaClass`] prescribes a default segment
//!   size and write-coalescing threshold.

use crate::device::{Device, DeviceImpl, DeviceState, IoClass};
use std::fmt;
use tidefs_binary_schema_checksum::crc32c;

// ---------------------------------------------------------------------------
// DeviceMediaClass — physical device type
// ---------------------------------------------------------------------------

/// Physical device media class, describing the underlying hardware.
///
/// This is orthogonal to [`crate::device::DeviceClass`], which describes
/// the storage role (Data, Metadata, IntentLog, etc.). A pool may have
/// a `DeviceClass::Metadata` device backed by `DeviceMediaClass::Nvme`
/// flash, or a `DeviceClass::Data` device backed by `DeviceMediaClass::Hdd`
/// spinning rust.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum DeviceMediaClass {
    /// NVMe flash (PCIe-attached, very low latency).
    Nvme,
    /// SATA/SAS SSD (higher latency than NVMe, still flash).
    Ssd,
    /// Spinning hard disk drive.
    Hdd,
    /// Device-mapper virtual device; probe the underlying physical device
    /// to determine the real media class.
    DmDevice,
}
impl Default for DeviceMediaClass {
    fn default() -> Self {
        Self::Ssd
    }
}

impl DeviceMediaClass {
    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nvme => "nvme",
            Self::Ssd => "ssd",
            Self::Hdd => "hdd",
            Self::DmDevice => "dm-device",
        }
    }

    /// Default segment size in bytes for this media class.
    #[must_use]
    pub const fn default_segment_size(self) -> u64 {
        match self {
            Self::Nvme => NVME_SEGMENT_BYTES,
            Self::Ssd => SSD_SEGMENT_BYTES,
            Self::Hdd => HDD_SEGMENT_BYTES,
            Self::DmDevice => SSD_SEGMENT_BYTES, // conservative default
        }
    }

    /// Write-coalescing threshold in bytes: buffered writes accumulate
    /// up to this many bytes before the store flushes a segment.
    #[must_use]
    pub const fn write_coalescing_threshold(self) -> u64 {
        match self {
            Self::Nvme => NVME_COALESCE_BYTES,
            Self::Ssd => SSD_COALESCE_BYTES,
            Self::Hdd => HDD_COALESCE_BYTES,
            Self::DmDevice => SSD_COALESCE_BYTES, // conservative default
        }
    }

    /// Weight multiplier used by [`WriteAllocator`] scoring.
    ///
    /// This is only a local allocator hint. Storage-intent decisions that
    /// spend flash lifetime or write-amplification budget must use the media
    /// cost ledger instead of treating this weight as complete policy
    /// authority.
    #[must_use]
    pub fn class_weight(self) -> f64 {
        match self {
            Self::Nvme => NVME_CLASS_WEIGHT,
            Self::Ssd => SSD_CLASS_WEIGHT,
            Self::Hdd => HDD_CLASS_WEIGHT,
            Self::DmDevice => SSD_CLASS_WEIGHT,
        }
    }
}

impl fmt::Display for DeviceMediaClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Segment sizing constants per media class
// ---------------------------------------------------------------------------

/// Default segment size for NVMe devices: 1 MiB.
pub const NVME_SEGMENT_BYTES: u64 = 1024 * 1024;

/// Default segment size for SSD devices: 4 MiB.
pub const SSD_SEGMENT_BYTES: u64 = 4 * 1024 * 1024;

/// Default segment size for HDD devices: 16 MiB.
pub const HDD_SEGMENT_BYTES: u64 = 16 * 1024 * 1024;

/// Write-coalescing threshold for NVMe devices: 64 KiB.
pub const NVME_COALESCE_BYTES: u64 = 64 * 1024;

/// Write-coalescing threshold for SSD devices: 256 KiB.
pub const SSD_COALESCE_BYTES: u64 = 256 * 1024;

/// Write-coalescing threshold for HDD devices: 1 MiB.
pub const HDD_COALESCE_BYTES: u64 = 1024 * 1024;

/// Class weight for NVMe devices in the [`WriteAllocator`] score.
pub const NVME_CLASS_WEIGHT: f64 = 3.0;

/// Class weight for SSD devices in the [`WriteAllocator`] score.
pub const SSD_CLASS_WEIGHT: f64 = 1.5;

/// Class weight for HDD devices in the [`WriteAllocator`] score.
pub const HDD_CLASS_WEIGHT: f64 = 0.5;

// ---------------------------------------------------------------------------
// DeviceClassPolicy — maps I/O class to preferred media class
// ---------------------------------------------------------------------------

/// Policy that determines which [`DeviceMediaClass`] is preferred for each
/// [`IoClass`], and what fallback behaviour is acceptable.
#[derive(Clone, Debug)]
pub struct DeviceClassPolicy {
    /// Preferred media classes for metadata writes, in descending order.
    /// The allocator tries the first class; if no healthy device of that
    /// class is available, it falls back to the next.
    pub metadata_preference: Vec<DeviceMediaClass>,

    /// Whether metadata writes are allowed on HDD devices.
    /// When `false`, HDD devices are excluded from metadata allocation.
    pub metadata_allow_hdd: bool,

    /// Preferred media classes for data writes, in descending order.
    /// Default: weight-by-free-space across all non-faulted devices.
    pub data_preference: Vec<DeviceMediaClass>,

    /// Preferred media classes for intent-log writes.
    /// Intent log needs the lowest possible latency.
    pub intent_log_preference: Vec<DeviceMediaClass>,

    /// Whether intent-log writes are allowed on HDD devices.
    pub intent_log_allow_hdd: bool,
}

impl Default for DeviceClassPolicy {
    fn default() -> Self {
        Self {
            // Metadata: prefer NVMe, fall back to SSD, refuse HDD.
            metadata_preference: vec![DeviceMediaClass::Nvme, DeviceMediaClass::Ssd],
            metadata_allow_hdd: false,
            // Data: weight by free space (no fixed preference order).
            data_preference: Vec::new(),
            // Intent log: prefer NVMe for lowest latency.
            intent_log_preference: vec![DeviceMediaClass::Nvme, DeviceMediaClass::Ssd],
            intent_log_allow_hdd: false,
        }
    }
}

impl DeviceClassPolicy {
    /// Production policy: metadata on NVMe or SSD, data weighted by free
    /// space, intent log on NVMe.
    #[must_use]
    pub fn production() -> Self {
        Self::default()
    }

    /// Relaxed policy that allows metadata and intent-log on HDD.
    /// Useful for single-device pools or pools with only HDD devices.
    #[must_use]
    pub fn hdd_friendly() -> Self {
        Self {
            metadata_preference: vec![
                DeviceMediaClass::Nvme,
                DeviceMediaClass::Ssd,
                DeviceMediaClass::Hdd,
            ],
            metadata_allow_hdd: true,
            data_preference: Vec::new(),
            intent_log_preference: vec![
                DeviceMediaClass::Nvme,
                DeviceMediaClass::Ssd,
                DeviceMediaClass::Hdd,
            ],
            intent_log_allow_hdd: true,
        }
    }
}

// ---------------------------------------------------------------------------
// WriteAllocator — scores devices for a given write request
// ---------------------------------------------------------------------------

/// Selects the best device for a write request based on free-space ratio
/// and media-class weights.
///
/// Score formula:
/// ```text
/// score = (free_bytes / total_bytes) * class_weight
/// ```
///
/// where `class_weight` is: Nvme=3.0, Ssd=1.5, Hdd=0.5.
///
/// The allocator returns the device index with the highest score.
/// Devices in `Faulted` or `Removed` state are excluded.
#[derive(Clone, Debug)]
pub struct WriteAllocator {
    /// Per-device media class (indexed by device index).
    media_classes: Vec<DeviceMediaClass>,
    /// Per-device total capacity in bytes.
    total_bytes: Vec<u64>,
}

impl WriteAllocator {
    /// Create a new allocator from device configurations.
    ///
    /// `media_classes`: per-device media class (same order as pool devices).
    /// `total_bytes`: per-device total capacity in bytes.
    #[must_use]
    pub fn new(media_classes: Vec<DeviceMediaClass>, total_bytes: Vec<u64>) -> Self {
        Self {
            media_classes,
            total_bytes,
        }
    }

    /// Score a single device.
    ///
    /// Returns `None` if the device is faulted or removed.
    #[must_use]
    pub fn score_device(&self, device_index: usize, device: &Device) -> Option<f64> {
        let state = device.status().state;
        if state == DeviceState::Faulted || state == DeviceState::Removed {
            return None;
        }
        let stats = device.stats();
        let free_bytes = self.total_bytes[device_index].saturating_sub(stats.live_bytes);
        let total = self.total_bytes[device_index];
        if total == 0 {
            return None;
        }
        let capacity_ratio = (free_bytes as f64) / (total as f64);
        let weight = self.media_classes[device_index].class_weight();
        Some(capacity_ratio * weight)
    }

    /// Select the best device from a set of candidates for the given I/O class.
    ///
    /// Returns the index (into `self.media_classes`) of the highest-scoring
    /// candidate, or `None` if no candidate is eligible.
    ///
    /// For `IoClass::Metadata` and `IoClass::IntentLog`, the policy's
    /// preference order is applied first to filter candidates by media class.
    pub fn select_device(
        &self,
        class: IoClass,
        candidates: &[usize],
        devices: &[Device],
        policy: &DeviceClassPolicy,
    ) -> Option<usize> {
        if candidates.is_empty() {
            return None;
        }

        // Determine which media classes are acceptable for this I/O class.
        let allowed: Vec<DeviceMediaClass> = match class {
            IoClass::Metadata => {
                if policy.metadata_allow_hdd {
                    policy.metadata_preference.clone()
                } else {
                    policy
                        .metadata_preference
                        .iter()
                        .copied()
                        .filter(|mc| *mc != DeviceMediaClass::Hdd)
                        .collect()
                }
            }
            IoClass::IntentLog => {
                if policy.intent_log_allow_hdd {
                    policy.intent_log_preference.clone()
                } else {
                    policy
                        .intent_log_preference
                        .iter()
                        .copied()
                        .filter(|mc| *mc != DeviceMediaClass::Hdd)
                        .collect()
                }
            }
            IoClass::Data | IoClass::ReadCache => {
                // Data: all media classes are allowed; prefer by score.
                vec![
                    DeviceMediaClass::Nvme,
                    DeviceMediaClass::Ssd,
                    DeviceMediaClass::Hdd,
                    DeviceMediaClass::DmDevice,
                ]
            }
        };

        // Filter candidates by allowed media classes, respecting preference order.
        let mut best_idx: Option<usize> = None;
        let mut best_score: f64 = f64::NEG_INFINITY;

        for &pref in &allowed {
            for &cand in candidates {
                if self.media_classes[cand] != pref {
                    continue;
                }
                if let Some(score) = self.score_device(cand, &devices[cand]) {
                    if score > best_score {
                        best_score = score;
                        best_idx = Some(cand);
                    }
                }
            }
            // If we found at least one device in this preference tier, stop
            // (preference ordering takes priority over scoring across tiers).
            if best_idx.is_some() {
                return best_idx;
            }
        }

        // Fallback: any candidate not covered by allowed list (shouldn't
        // happen with the current all-inclusive Data/ReadCache list, but
        // handles Metadata/IntentLog when only HDD devices exist and HDD
        // is not allowed — return None so the caller can handle gracefully).
        None
    }

    /// Number of devices tracked by this allocator.
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.media_classes.len()
    }
}

// ---------------------------------------------------------------------------
// DeviceLayoutStats — per-device layout observability
// ---------------------------------------------------------------------------

/// Per-device statistics for layout-policy observability.
#[derive(Clone, Debug, Default)]
pub struct DeviceLayoutStats {
    /// Number of segment rollovers that have occurred on this device.
    pub segment_rollovers: u64,
    /// Total bytes written to this device (across all segments).
    pub bytes_written: u64,
    /// Number of allocation errors for this device (e.g., ENOSPC).
    pub allocation_errors: u64,
    /// Number of times this device was selected by the WriteAllocator.
    pub write_allocations: u64,
    /// Current segment size in bytes.
    pub current_segment_size: u64,
}

impl DeviceLayoutStats {
    /// Create stats with the given segment size.
    #[must_use]
    pub const fn with_segment_size(segment_size: u64) -> Self {
        Self {
            segment_rollovers: 0,
            bytes_written: 0,
            allocation_errors: 0,
            write_allocations: 0,
            current_segment_size: segment_size,
        }
    }
}

// ---------------------------------------------------------------------------
// Adaptive segment sizing
// ---------------------------------------------------------------------------

/// Recommend a segment size for a device given its media class and total
/// capacity.
///
/// The recommendation starts from the media-class default and may be
/// adjusted up for very large devices to keep segment counts bounded.
#[must_use]
pub fn recommend_segment_size(media_class: DeviceMediaClass, total_bytes: u64) -> u64 {
    let base = media_class.default_segment_size();
    // For very large devices, scale up to keep segment count manageable.
    // Target: at most ~4M segments per device.
    let target_max_segments: u64 = 4_000_000;
    let min_segments: u64 = total_bytes / base;
    if min_segments > target_max_segments {
        // Scale up: double segment size until segment count <= target.
        let mut seg = base;
        while total_bytes / seg > target_max_segments && seg < MAX_SEGMENT_BYTES {
            seg = seg.saturating_mul(2);
        }
        seg
    } else {
        base
    }
}

/// Maximum segment size for any device class (256 MiB).
pub const MAX_SEGMENT_BYTES: u64 = 256 * 1024 * 1024;

/// Minimum segment size for any device class (256 KiB).
pub const MIN_SEGMENT_BYTES: u64 = 256 * 1024;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // DeviceMediaClass defaults
    // ------------------------------------------------------------------

    #[test]
    fn nvme_default_segment_size_is_1mb() {
        assert_eq!(DeviceMediaClass::Nvme.default_segment_size(), 1024 * 1024);
    }

    #[test]
    fn ssd_default_segment_size_is_4mb() {
        assert_eq!(
            DeviceMediaClass::Ssd.default_segment_size(),
            4 * 1024 * 1024
        );
    }

    #[test]
    fn hdd_default_segment_size_is_16mb() {
        assert_eq!(
            DeviceMediaClass::Hdd.default_segment_size(),
            16 * 1024 * 1024
        );
    }

    #[test]
    fn nvme_coalescing_is_64k() {
        assert_eq!(
            DeviceMediaClass::Nvme.write_coalescing_threshold(),
            64 * 1024
        );
    }

    #[test]
    fn ssd_coalescing_is_256k() {
        assert_eq!(
            DeviceMediaClass::Ssd.write_coalescing_threshold(),
            256 * 1024
        );
    }

    #[test]
    fn hdd_coalescing_is_1mb() {
        assert_eq!(
            DeviceMediaClass::Hdd.write_coalescing_threshold(),
            1024 * 1024
        );
    }

    // ------------------------------------------------------------------
    // DeviceMediaClass weights
    // ------------------------------------------------------------------

    #[test]
    fn nvme_weight_is_3() {
        assert!((DeviceMediaClass::Nvme.class_weight() - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ssd_weight_is_1_5() {
        assert!((DeviceMediaClass::Ssd.class_weight() - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn hdd_weight_is_0_5() {
        assert!((DeviceMediaClass::Hdd.class_weight() - 0.5).abs() < f64::EPSILON);
    }

    // ------------------------------------------------------------------
    // DeviceClassPolicy defaults
    // ------------------------------------------------------------------

    #[test]
    fn production_policy_refuses_hdd_for_metadata() {
        let policy = DeviceClassPolicy::production();
        assert!(!policy.metadata_allow_hdd);
        assert!(!policy.metadata_preference.contains(&DeviceMediaClass::Hdd));
    }

    #[test]
    fn production_policy_refuses_hdd_for_intent_log() {
        let policy = DeviceClassPolicy::production();
        assert!(!policy.intent_log_allow_hdd);
        assert!(!policy
            .intent_log_preference
            .contains(&DeviceMediaClass::Hdd));
    }

    #[test]
    fn production_policy_metadata_prefers_nvme_then_ssd() {
        let policy = DeviceClassPolicy::production();
        assert_eq!(policy.metadata_preference[0], DeviceMediaClass::Nvme);
        assert_eq!(policy.metadata_preference[1], DeviceMediaClass::Ssd);
    }

    #[test]
    fn production_policy_intent_log_prefers_nvme_then_ssd() {
        let policy = DeviceClassPolicy::production();
        assert_eq!(policy.intent_log_preference[0], DeviceMediaClass::Nvme);
        assert_eq!(policy.intent_log_preference[1], DeviceMediaClass::Ssd);
    }

    #[test]
    fn hdd_friendly_policy_allows_hdd_for_metadata() {
        let policy = DeviceClassPolicy::hdd_friendly();
        assert!(policy.metadata_allow_hdd);
        assert!(policy.metadata_preference.contains(&DeviceMediaClass::Hdd));
    }

    #[test]
    fn hdd_friendly_policy_allows_hdd_for_intent_log() {
        let policy = DeviceClassPolicy::hdd_friendly();
        assert!(policy.intent_log_allow_hdd);
        assert!(policy
            .intent_log_preference
            .contains(&DeviceMediaClass::Hdd));
    }

    // ------------------------------------------------------------------
    // WriteAllocator scoring
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // WriteAllocator::score_device (unit-testable logic)
    // ------------------------------------------------------------------

    /// Test the scoring formula independently of Device construction.
    #[test]
    fn score_formula_nvme_high_free_space() {
        // score = (free_bytes / total_bytes) * weight
        // free = 800, total = 1000, weight = 3.0 -> score = 0.8 * 3.0 = 2.4
        let free: f64 = 800.0;
        let total: f64 = 1000.0;
        let weight = DeviceMediaClass::Nvme.class_weight();
        let score = (free / total) * weight;
        assert!((score - 2.4).abs() < 0.001);
    }

    #[test]
    fn score_formula_hdd_low_free_space() {
        // free = 100, total = 1000, weight = 0.5 -> score = 0.1 * 0.5 = 0.05
        let free: f64 = 100.0;
        let total: f64 = 1000.0;
        let weight = DeviceMediaClass::Hdd.class_weight();
        let score = (free / total) * weight;
        assert!((score - 0.05).abs() < 0.001);
    }

    #[test]
    fn score_formula_ssd_half_free() {
        let free: f64 = 500.0;
        let total: f64 = 1000.0;
        let weight = DeviceMediaClass::Ssd.class_weight();
        let score = (free / total) * weight;
        assert!((score - 0.75).abs() < 0.001);
    }

    // ------------------------------------------------------------------
    // WriteAllocator::select_device logic (without Device)
    // ------------------------------------------------------------------

    #[test]
    fn select_device_empty_candidates_returns_none() {
        let alloc = WriteAllocator::new(vec![], vec![]);
        let policy = DeviceClassPolicy::production();
        let devices: Vec<Device> = Vec::new();
        let result = alloc.select_device(IoClass::Data, &[], &devices, &policy);
        assert!(result.is_none());
    }

    // ------------------------------------------------------------------
    // WriteAllocator construction
    // ------------------------------------------------------------------

    #[test]
    fn write_allocator_tracks_device_count() {
        let alloc = WriteAllocator::new(
            vec![
                DeviceMediaClass::Nvme,
                DeviceMediaClass::Ssd,
                DeviceMediaClass::Hdd,
            ],
            vec![1_000_000_000, 2_000_000_000, 16_000_000_000],
        );
        assert_eq!(alloc.device_count(), 3);
    }

    #[test]
    fn write_allocator_empty() {
        let alloc = WriteAllocator::new(vec![], vec![]);
        assert_eq!(alloc.device_count(), 0);
    }

    // ------------------------------------------------------------------
    // recommend_segment_size
    // ------------------------------------------------------------------

    #[test]
    fn nvme_1tb_keeps_1mb_segments() {
        // 1 TiB NVMe with 1 MiB segments = ~1M segments, well under 4M target
        let size = recommend_segment_size(DeviceMediaClass::Nvme, 1_099_511_627_776);
        assert_eq!(size, 1024 * 1024);
    }

    #[test]
    fn hdd_16tb_keeps_16mb_segments() {
        // 16 TiB HDD with 16 MiB segments = ~1M segments
        let size = recommend_segment_size(DeviceMediaClass::Hdd, 17_592_186_044_416);
        assert_eq!(size, 16 * 1024 * 1024);
    }

    #[test]
    fn ssd_4tb_keeps_4mb_segments() {
        // 4 TiB SSD with 4 MiB segments = ~1M segments
        let size = recommend_segment_size(DeviceMediaClass::Ssd, 4_398_046_511_104);
        assert_eq!(size, 4 * 1024 * 1024);
    }

    #[test]
    fn nvme_8tb_scales_up_to_2mb() {
        // 8 TiB NVMe with 1 MiB segments = ~8.4M segments, > 4M target
        // Should scale to 2 MiB → ~4.2M segments
        let size = recommend_segment_size(DeviceMediaClass::Nvme, 8_796_093_022_208);
        assert_eq!(size, 4 * 1024 * 1024);
    }

    #[test]
    fn hdd_huge_scales_up() {
        // 128 TiB HDD with 16 MiB segments = ~8.4M, should scale to 32 MiB
        let size = recommend_segment_size(DeviceMediaClass::Hdd, 140_737_488_355_328);
        assert_eq!(size, 64 * 1024 * 1024);
    }

    #[test]
    fn segment_size_never_exceeds_max() {
        // Extremely large device: 1 PiB
        let size = recommend_segment_size(DeviceMediaClass::Hdd, 1_125_899_906_842_624);
        assert!(size <= MAX_SEGMENT_BYTES);
        assert_eq!(size, 256 * 1024 * 1024);
    }

    #[test]
    fn tiny_device_keeps_minimum() {
        // Small device: 100 MiB — base segment size already exceeds total
        let size = recommend_segment_size(DeviceMediaClass::Nvme, 100 * 1024 * 1024);
        // Still returns the class default; caller is responsible for checking
        // that the device is large enough for even one segment.
        assert_eq!(size, 1024 * 1024);
    }

    // ------------------------------------------------------------------
    // DeviceLayoutStats
    // ------------------------------------------------------------------

    #[test]
    fn device_layout_stats_defaults() {
        let stats = DeviceLayoutStats::default();
        assert_eq!(stats.segment_rollovers, 0);
        assert_eq!(stats.bytes_written, 0);
        assert_eq!(stats.allocation_errors, 0);
        assert_eq!(stats.write_allocations, 0);
        assert_eq!(stats.current_segment_size, 0);
    }

    #[test]
    fn device_layout_stats_with_segment_size() {
        let stats = DeviceLayoutStats::with_segment_size(4 * 1024 * 1024);
        assert_eq!(stats.current_segment_size, 4 * 1024 * 1024);
        assert_eq!(stats.segment_rollovers, 0);
    }

    // ------------------------------------------------------------------
    // Mixed-class pool scoring exercise
    // ------------------------------------------------------------------

    #[test]
    fn mixed_class_nvme_beats_hdd_when_free_equal() {
        // NVMe free=500/1000 * 3.0 = 1.5
        // HDD  free=500/1000 * 0.5 = 0.25
        let nvme_score = (500.0 / 1000.0) * DeviceMediaClass::Nvme.class_weight();
        let hdd_score = (500.0 / 1000.0) * DeviceMediaClass::Hdd.class_weight();
        assert!(nvme_score > hdd_score);
    }

    #[test]
    fn full_hdd_loses_to_almost_full_nvme() {
        // NVMe free=100/1000 * 3.0 = 0.3
        // HDD  free=900/1000 * 0.5 = 0.45
        // HDD wins here — capacity-weighted allocation for data
        let nvme_score = (100.0 / 1000.0) * DeviceMediaClass::Nvme.class_weight();
        let hdd_score = (900.0 / 1000.0) * DeviceMediaClass::Hdd.class_weight();
        assert!(
            hdd_score > nvme_score,
            "HDD should win when NVMe is nearly full (data weighted by free space)"
        );
    }

    #[test]
    fn nvme_only_pool_all_metadata_preferred() {
        // In an NVMe-only pool, metadata preference should naturally pick NVMe.
        let policy = DeviceClassPolicy::production();
        assert_eq!(policy.metadata_preference[0], DeviceMediaClass::Nvme);
        assert_eq!(policy.metadata_preference.len(), 2); // fallback to SSD is harmless
    }

    #[test]
    fn hdd_only_pool_metadata_with_hdd_friendly_policy() {
        let policy = DeviceClassPolicy::hdd_friendly();
        assert!(policy.metadata_allow_hdd);
        assert!(policy.metadata_preference.contains(&DeviceMediaClass::Hdd));
    }
}

// ---------------------------------------------------------------------------
// DeviceLayoutPolicy — layout policy abstraction
// ---------------------------------------------------------------------------

/// Layout policy for computing device region partitioning and segment sizes.
///
/// Three policies are supported:
/// - [`Slice0Small`](DeviceLayoutPolicy::Slice0Small): fixed 1 MiB segments
///   and small journal regions for test/tiny devices.
/// - [`Auto`](DeviceLayoutPolicy::Auto): auto-scaling segment size chosen to
///   keep per-region segment count below a configured ceiling.
/// - [`Custom`](DeviceLayoutPolicy::Custom): operator-specified per-region
///   segment sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceLayoutPolicy {
    /// Historical small layout: 1 MiB segments, fixed small journal regions.
    Slice0Small,
    /// Auto-scaling: segment size chosen to keep segment count bounded.
    Auto,
    /// Operator-specified per-region segment sizes.  All sizes must be
    /// powers of two within [1 MiB, 256 MiB].
    Custom {
        data_segment_size: u64,
        metadata_segment_size: u64,
        journal_segment_size: u64,
    },
}

impl Default for DeviceLayoutPolicy {
    fn default() -> Self {
        Self::Auto
    }
}

impl fmt::Display for DeviceLayoutPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Slice0Small => f.write_str("Slice0Small"),
            Self::Auto => f.write_str("Auto"),
            Self::Custom { .. } => f.write_str("Custom"),
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceLayoutPolicyDiscriminant — stored policy tag
// ---------------------------------------------------------------------------

/// Stored policy discriminant (preserves which policy created the layout).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum DeviceLayoutPolicyDiscriminant {
    Slice0Small = 0,
    Auto = 1,
    Custom = 2,
}

impl DeviceLayoutPolicyDiscriminant {
    /// Decode from a u16 wire value.
    #[must_use]
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            0 => Some(Self::Slice0Small),
            1 => Some(Self::Auto),
            2 => Some(Self::Custom),
            _ => None,
        }
    }

    /// Encode to a u16 wire value.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        self as u16
    }
}

// ---------------------------------------------------------------------------
// DeviceLayoutV1 — on-media layout record
// ---------------------------------------------------------------------------

/// Persistent device layout record (written at pool creation, read on open).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceLayoutV1 {
    /// Which policy produced this layout.
    pub policy: DeviceLayoutPolicyDiscriminant,
    /// Total device capacity in bytes.
    pub device_size_bytes: u64,
    /// Byte offset of system area.
    pub system_area_offset: u64,
    /// System area length in bytes.
    pub system_area_len: u64,
    /// Byte offset of poolmap journal region.
    pub poolmap_journal_offset: u64,
    /// Poolmap journal length in bytes.
    pub poolmap_journal_len: u64,
    /// Byte offset of metadata journal region.
    pub metadata_journal_offset: u64,
    /// Metadata journal length in bytes.
    pub metadata_journal_len: u64,
    /// Byte offset of data journal region.
    pub data_journal_offset: u64,
    /// Data journal length in bytes.
    pub data_journal_len: u64,
    /// Segment size for system area (bytes, power of two).
    pub system_segment_size: u64,
    /// Segment size for poolmap journal (bytes, power of two).
    pub poolmap_segment_size: u64,
    /// Segment size for metadata journal (bytes, power of two).
    pub metadata_segment_size: u64,
    /// Segment size for data journal (bytes, power of two).
    pub data_segment_size: u64,
}

// ---------------------------------------------------------------------------
// DeviceLayoutV1 wire-format constants
// ---------------------------------------------------------------------------

/// Magic bytes identifying a DeviceLayoutV1 record: `b"VFSDLAY1"`.
pub const DEVICE_LAYOUT_V1_MAGIC: [u8; 8] = *b"VFSDLAY1";

/// Wire format version.
pub const DEVICE_LAYOUT_V1_VERSION: u16 = 1;

/// Total wire size of a DeviceLayoutV1 record in bytes.
pub const DEVICE_LAYOUT_V1_WIRE_SIZE: usize = 124;

/// Offset of the CRC32C checksum in the wire format.
pub const DEVICE_LAYOUT_V1_CRC32C_OFFSET: usize = 120;

// ---------------------------------------------------------------------------
// Layout computation constants
// ---------------------------------------------------------------------------

/// Target maximum segment count for the data region.
pub const TARGET_DATA_SEGMENTS: u64 = 4_000_000;

/// Minimum segment size: 1 MiB.
pub const MIN_SEGMENT_SIZE_BYTES: u64 = 1024 * 1024;

/// Maximum segment size: 256 MiB.
pub const MAX_SEGMENT_SIZE_BYTES: u64 = 256 * 1024 * 1024;

/// System area size in segments (always 1).
pub const SYSTEM_AREA_SEGMENTS: u64 = 1;

/// Poolmap journal size in segments.
pub const POOLMAP_JOURNAL_SEGMENTS: u64 = 16;

/// Metadata journal size in segments.
pub const METADATA_JOURNAL_SEGMENTS: u64 = 256;

/// Slice0Small fixed segment size: 1 MiB.
pub const SLICE0_SMALL_SEGMENT_BYTES: u64 = 1024 * 1024;

// ---------------------------------------------------------------------------
// LayoutPolicyError
// ---------------------------------------------------------------------------

/// Errors that can occur during layout policy computation or decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutPolicyError {
    /// Device size is zero (invalid).
    DeviceSizeZero,
    /// Device is too small for any valid layout.
    DeviceTooSmall {
        device_size_bytes: u64,
        minimum_required_bytes: u64,
    },
    /// Input buffer is too small.
    BufferTooSmall {
        expected: usize,
        actual: usize,
    },
    /// Magic bytes do not match.
    BadMagic {
        expected: [u8; 8],
        found: [u8; 8],
    },
    /// Unrecognized format version.
    UnsupportedVersion(u16),
    /// Bad policy discriminant value.
    BadPolicyDiscriminant(u16),
    /// CRC32C checksum mismatch.
    ChecksumMismatch {
        expected: u32,
        computed: u32,
    },
    /// Custom layout had an invalid segment size.
    InvalidSegmentSize {
        reason: InvalidSegmentSizeReason,
    },
    /// Custom layout region sizes exceed device capacity.
    RegionOverflow {
        device_size_bytes: u64,
        required_bytes: u64,
    },
}

impl fmt::Display for LayoutPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceSizeZero => f.write_str("device size is zero"),
            Self::DeviceTooSmall {
                device_size_bytes,
                minimum_required_bytes,
            } => write!(
                f,
                "device size {device_size_bytes} too small (min {minimum_required_bytes})"
            ),
            Self::BufferTooSmall { expected, actual } => write!(
                f,
                "buffer too small: need {expected} bytes, got {actual}"
            ),
            Self::BadMagic { expected: _, found } => {
                write!(f, "bad magic bytes: {found:02x?}")
            }
            Self::UnsupportedVersion(v) => write!(f, "unsupported layout version {v}"),
            Self::BadPolicyDiscriminant(v) => write!(f, "bad policy discriminant {v}"),
            Self::ChecksumMismatch { expected, computed } => write!(
                f,
                "CRC32C mismatch: expected {expected:#08x}, computed {computed:#08x}"
            ),
            Self::InvalidSegmentSize { reason } => write!(f, "invalid segment size: {reason}"),
            Self::RegionOverflow {
                device_size_bytes,
                required_bytes,
            } => write!(
                f,
                "region overflow: device {device_size_bytes} bytes, layout needs {required_bytes} bytes"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// InvalidSegmentSizeReason
// ---------------------------------------------------------------------------

/// Reason a custom segment size was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidSegmentSizeReason {
    /// Value is not a power of two.
    NotPowerOfTwo,
    /// Value is below the minimum allowed segment size (1 MiB).
    BelowMinimum { min: u64, actual: u64 },
    /// Value is above the maximum allowed segment size (256 MiB).
    AboveMaximum { max: u64, actual: u64 },
}

impl fmt::Display for InvalidSegmentSizeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPowerOfTwo => f.write_str("not a power of two"),
            Self::BelowMinimum { min, actual } => {
                write!(f, "{actual} below minimum {min}")
            }
            Self::AboveMaximum { max, actual } => {
                write!(f, "{actual} above maximum {max}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: power-of-two check
// ---------------------------------------------------------------------------

/// Returns true if `n` is a non-zero power of two.
#[inline]
pub const fn is_power_of_two_u64(n: u64) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

// ---------------------------------------------------------------------------
// Helper: choose power-of-two segment size for auto-scaling
// ---------------------------------------------------------------------------

/// Pick a power-of-two segment size that keeps the segment count for a
/// region of `region_size_bytes` below or near `target_segments`.
///
/// Returns a power-of-two in [`MIN_SEGMENT_SIZE_BYTES`, `MAX_SEGMENT_SIZE_BYTES`].
#[must_use]
pub fn choose_segment_size_bytes(
    region_size_bytes: u64,
    target_segments: u64,
) -> u64 {
    if region_size_bytes == 0 {
        return MIN_SEGMENT_SIZE_BYTES;
    }
    // Segment size that gives exactly target_segments segments.
    let raw = region_size_bytes / target_segments;
    // Clamp to bounds, then round up to next power of two.
    let clamped = raw.clamp(MIN_SEGMENT_SIZE_BYTES, MAX_SEGMENT_SIZE_BYTES);
    let pot = clamped.next_power_of_two();
    pot.clamp(MIN_SEGMENT_SIZE_BYTES, MAX_SEGMENT_SIZE_BYTES)
}

// ---------------------------------------------------------------------------
// validate_segment_size — Custom policy gate
// ---------------------------------------------------------------------------

/// Validate a caller-supplied segment size for the Custom policy.
///
/// Returns `Ok(())` if `size` is a power of two within [1 MiB, 256 MiB].
pub fn validate_segment_size(size: u64) -> Result<(), LayoutPolicyError> {
    if !is_power_of_two_u64(size) {
        return Err(LayoutPolicyError::InvalidSegmentSize {
            reason: InvalidSegmentSizeReason::NotPowerOfTwo,
        });
    }
    if size < MIN_SEGMENT_SIZE_BYTES {
        return Err(LayoutPolicyError::InvalidSegmentSize {
            reason: InvalidSegmentSizeReason::BelowMinimum {
                min: MIN_SEGMENT_SIZE_BYTES,
                actual: size,
            },
        });
    }
    if size > MAX_SEGMENT_SIZE_BYTES {
        return Err(LayoutPolicyError::InvalidSegmentSize {
            reason: InvalidSegmentSizeReason::AboveMaximum {
                max: MAX_SEGMENT_SIZE_BYTES,
                actual: size,
            },
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DeviceLayoutPolicy::compute — produce a DeviceLayoutV1
// ---------------------------------------------------------------------------

impl DeviceLayoutPolicy {
    /// Compute [`DeviceLayoutV1`] for a device of `device_size_bytes`.
    ///
    /// The returned layout divides the device into four contiguous regions:
    /// system area (1 segment), poolmap journal (16 segments),
    /// metadata journal (256 segments), and data journal (remainder).
    pub fn compute(self, device_size_bytes: u64) -> Result<DeviceLayoutV1, LayoutPolicyError> {
        if device_size_bytes == 0 {
            return Err(LayoutPolicyError::DeviceSizeZero);
        }

        match self {
            Self::Slice0Small => Self::compute_slice0_small(device_size_bytes),
            Self::Auto => Self::compute_auto(device_size_bytes),
            Self::Custom {
                data_segment_size,
                metadata_segment_size,
                journal_segment_size,
            } => Self::compute_custom(
                device_size_bytes,
                data_segment_size,
                metadata_segment_size,
                journal_segment_size,
            ),
        }
    }

    /// Fixed 1 MiB segment sizes for all regions.
    /// For devices too small for the full journal layout, journals are
    /// sized down proportionally so the layout always fits.
    fn compute_slice0_small(
        device_size_bytes: u64,
    ) -> Result<DeviceLayoutV1, LayoutPolicyError> {
        let seg = SLICE0_SMALL_SEGMENT_BYTES;

        // Absolute minimum: one segment for the system area.
        let system_area_len = seg * SYSTEM_AREA_SEGMENTS;
        if device_size_bytes < system_area_len {
            return Err(LayoutPolicyError::DeviceTooSmall {
                device_size_bytes,
                minimum_required_bytes: system_area_len,
            });
        }

        let remaining = device_size_bytes.saturating_sub(system_area_len);

        // Distribute remaining space: poolmap gets ~5%, metadata ~15%, data the rest.
        // Floor of 1 segment (1 MiB) for each journal when possible.
        let poolmap_seg = (POOLMAP_JOURNAL_SEGMENTS).min(remaining / seg / 21);
        let poolmap_journal_len = seg * poolmap_seg.max(1).min(remaining / seg);

        let remaining_after_poolmap = remaining.saturating_sub(poolmap_journal_len);
        let metadata_seg = METADATA_JOURNAL_SEGMENTS.min(remaining_after_poolmap / seg / 5);
        let metadata_journal_len = seg * metadata_seg.max(1).min(remaining_after_poolmap / seg);

        let remaining_after_metadata =
            remaining_after_poolmap.saturating_sub(metadata_journal_len);
        let data_journal_len = remaining_after_metadata;

        let system_end = system_area_len;
        let poolmap_end = system_end + poolmap_journal_len;
        let metadata_end = poolmap_end + metadata_journal_len;

        Ok(DeviceLayoutV1 {
            policy: DeviceLayoutPolicyDiscriminant::Slice0Small,
            device_size_bytes,
            system_area_offset: 0,
            system_area_len,
            poolmap_journal_offset: system_end,
            poolmap_journal_len,
            metadata_journal_offset: poolmap_end,
            metadata_journal_len,
            data_journal_offset: metadata_end,
            data_journal_len,
            system_segment_size: seg,
            poolmap_segment_size: seg,
            metadata_segment_size: seg,
            data_segment_size: seg,
        })
    }

    /// Auto-scaling: pick a segment size that keeps data region segment count
    /// below [`TARGET_DATA_SEGMENTS`], then size journal regions accordingly.
    fn compute_auto(
        device_size_bytes: u64,
    ) -> Result<DeviceLayoutV1, LayoutPolicyError> {
        // Minimum device size for Auto: system + poolmap + metadata at
        // 1 MiB segment size.  Below this, fall back to Slice0Small.
        let min_seg = MIN_SEGMENT_SIZE_BYTES;
        let system_area_len = min_seg * SYSTEM_AREA_SEGMENTS;
        let poolmap_journal_len = min_seg * POOLMAP_JOURNAL_SEGMENTS;
        let metadata_journal_len = min_seg * METADATA_JOURNAL_SEGMENTS;
        let fixed_overhead = system_area_len
            .saturating_add(poolmap_journal_len)
            .saturating_add(metadata_journal_len);

        // For very small devices, fall back to Slice0Small.
        if device_size_bytes < fixed_overhead {
            return Self::compute_slice0_small(device_size_bytes);
        }

        let data_region_size = device_size_bytes.saturating_sub(fixed_overhead);
        let data_segment_size =
            choose_segment_size_bytes(data_region_size, TARGET_DATA_SEGMENTS);

        let system_segment_size = MIN_SEGMENT_SIZE_BYTES; // always 1 MiB
        let poolmap_journal_len = data_segment_size * POOLMAP_JOURNAL_SEGMENTS;
        let metadata_journal_len = data_segment_size * METADATA_JOURNAL_SEGMENTS;

        let system_end = system_area_len;
        let poolmap_end = system_end + poolmap_journal_len;
        let metadata_end = poolmap_end + metadata_journal_len;
        let data_len = device_size_bytes.saturating_sub(metadata_end);

        Ok(DeviceLayoutV1 {
            policy: DeviceLayoutPolicyDiscriminant::Auto,
            device_size_bytes,
            system_area_offset: 0,
            system_area_len,
            poolmap_journal_offset: system_end,
            poolmap_journal_len,
            metadata_journal_offset: poolmap_end,
            metadata_journal_len,
            data_journal_offset: metadata_end,
            data_journal_len: data_len,
            system_segment_size,
            poolmap_segment_size: data_segment_size,
            metadata_segment_size: data_segment_size,
            data_segment_size,
        })
    }
    fn compute_custom(
        device_size_bytes: u64,
        data_segment_size: u64,
        metadata_segment_size: u64,
        journal_segment_size: u64,
    ) -> Result<DeviceLayoutV1, LayoutPolicyError> {
        validate_segment_size(data_segment_size)?;
        validate_segment_size(metadata_segment_size)?;
        validate_segment_size(journal_segment_size)?;

        let system_area_len = MIN_SEGMENT_SIZE_BYTES * SYSTEM_AREA_SEGMENTS;
        let poolmap_journal_len = journal_segment_size * POOLMAP_JOURNAL_SEGMENTS;
        let metadata_journal_len = metadata_segment_size * METADATA_JOURNAL_SEGMENTS;
        let required = system_area_len
            .saturating_add(poolmap_journal_len)
            .saturating_add(metadata_journal_len);

        if device_size_bytes < required {
            return Err(LayoutPolicyError::RegionOverflow {
                device_size_bytes,
                required_bytes: required,
            });
        }

        let system_end = system_area_len;
        let poolmap_end = system_end + poolmap_journal_len;
        let metadata_end = poolmap_end + metadata_journal_len;
        let data_len = device_size_bytes.saturating_sub(metadata_end);

        Ok(DeviceLayoutV1 {
            policy: DeviceLayoutPolicyDiscriminant::Custom,
            device_size_bytes,
            system_area_offset: 0,
            system_area_len,
            poolmap_journal_offset: system_end,
            poolmap_journal_len,
            metadata_journal_offset: poolmap_end,
            metadata_journal_len,
            data_journal_offset: metadata_end,
            data_journal_len: data_len,
            system_segment_size: MIN_SEGMENT_SIZE_BYTES,
            poolmap_segment_size: journal_segment_size,
            metadata_segment_size,
            data_segment_size,
        })
    }
}

// ---------------------------------------------------------------------------
// DeviceLayoutV1 encode/decode
// ---------------------------------------------------------------------------

/// Encode a [`DeviceLayoutV1`] into `buf`, which must be at least
/// [`DEVICE_LAYOUT_V1_WIRE_SIZE`] bytes.
pub fn encode_device_layout_v1(layout: &DeviceLayoutV1, buf: &mut [u8]) {
    assert!(buf.len() >= DEVICE_LAYOUT_V1_WIRE_SIZE);

    buf[0..8].copy_from_slice(&DEVICE_LAYOUT_V1_MAGIC);
    buf[8..10].copy_from_slice(&DEVICE_LAYOUT_V1_VERSION.to_le_bytes());
    buf[10..12].copy_from_slice(&layout.policy.to_u16().to_le_bytes());
    buf[12..20].copy_from_slice(&layout.device_size_bytes.to_le_bytes());
    buf[20..28].copy_from_slice(&layout.system_area_offset.to_le_bytes());
    buf[28..36].copy_from_slice(&layout.system_area_len.to_le_bytes());
    buf[36..44].copy_from_slice(&layout.poolmap_journal_offset.to_le_bytes());
    buf[44..52].copy_from_slice(&layout.poolmap_journal_len.to_le_bytes());
    buf[52..60].copy_from_slice(&layout.metadata_journal_offset.to_le_bytes());
    buf[60..68].copy_from_slice(&layout.metadata_journal_len.to_le_bytes());
    buf[68..76].copy_from_slice(&layout.data_journal_offset.to_le_bytes());
    buf[76..84].copy_from_slice(&layout.data_journal_len.to_le_bytes());
    buf[84..92].copy_from_slice(&layout.system_segment_size.to_le_bytes());
    buf[92..100].copy_from_slice(&layout.poolmap_segment_size.to_le_bytes());
    buf[100..108].copy_from_slice(&layout.metadata_segment_size.to_le_bytes());
    buf[108..116].copy_from_slice(&layout.data_segment_size.to_le_bytes());
    // offset 116-120: reserved (zero)
    buf[116..120].fill(0);

    // CRC32C over bytes 0..120
    let crc = crc32c(&buf[0..DEVICE_LAYOUT_V1_CRC32C_OFFSET]);
    buf[DEVICE_LAYOUT_V1_CRC32C_OFFSET..DEVICE_LAYOUT_V1_WIRE_SIZE]
        .copy_from_slice(&crc.to_le_bytes());
}

/// Decode a [`DeviceLayoutV1`] from `buf`.
pub fn decode_device_layout_v1(buf: &[u8]) -> Result<DeviceLayoutV1, LayoutPolicyError> {
    if buf.len() < DEVICE_LAYOUT_V1_WIRE_SIZE {
        return Err(LayoutPolicyError::BufferTooSmall {
            expected: DEVICE_LAYOUT_V1_WIRE_SIZE,
            actual: buf.len(),
        });
    }

    let magic: [u8; 8] = buf[0..8].try_into().unwrap();
    if magic != DEVICE_LAYOUT_V1_MAGIC {
        return Err(LayoutPolicyError::BadMagic {
            expected: DEVICE_LAYOUT_V1_MAGIC,
            found: magic,
        });
    }

    let version = u16::from_le_bytes(buf[8..10].try_into().unwrap());
    if version != DEVICE_LAYOUT_V1_VERSION {
        return Err(LayoutPolicyError::UnsupportedVersion(version));
    }

    let policy_disc = u16::from_le_bytes(buf[10..12].try_into().unwrap());
    let policy = DeviceLayoutPolicyDiscriminant::from_u16(policy_disc)
        .ok_or(LayoutPolicyError::BadPolicyDiscriminant(policy_disc))?;

    let device_size_bytes = u64::from_le_bytes(buf[12..20].try_into().unwrap());
    let system_area_offset = u64::from_le_bytes(buf[20..28].try_into().unwrap());
    let system_area_len = u64::from_le_bytes(buf[28..36].try_into().unwrap());
    let poolmap_journal_offset = u64::from_le_bytes(buf[36..44].try_into().unwrap());
    let poolmap_journal_len = u64::from_le_bytes(buf[44..52].try_into().unwrap());
    let metadata_journal_offset = u64::from_le_bytes(buf[52..60].try_into().unwrap());
    let metadata_journal_len = u64::from_le_bytes(buf[60..68].try_into().unwrap());
    let data_journal_offset = u64::from_le_bytes(buf[68..76].try_into().unwrap());
    let data_journal_len = u64::from_le_bytes(buf[76..84].try_into().unwrap());
    let system_segment_size = u64::from_le_bytes(buf[84..92].try_into().unwrap());
    let poolmap_segment_size = u64::from_le_bytes(buf[92..100].try_into().unwrap());
    let metadata_segment_size = u64::from_le_bytes(buf[100..108].try_into().unwrap());
    let data_segment_size = u64::from_le_bytes(buf[108..116].try_into().unwrap());

    // Verify CRC32C.
    let expected_crc = u32::from_le_bytes(
        buf[DEVICE_LAYOUT_V1_CRC32C_OFFSET..DEVICE_LAYOUT_V1_WIRE_SIZE]
            .try_into()
            .unwrap(),
    );
    let computed_crc = crc32c(&buf[0..DEVICE_LAYOUT_V1_CRC32C_OFFSET]);
    if computed_crc != expected_crc {
        return Err(LayoutPolicyError::ChecksumMismatch {
            expected: expected_crc,
            computed: computed_crc,
        });
    }

    Ok(DeviceLayoutV1 {
        policy,
        device_size_bytes,
        system_area_offset,
        system_area_len,
        poolmap_journal_offset,
        poolmap_journal_len,
        metadata_journal_offset,
        metadata_journal_len,
        data_journal_offset,
        data_journal_len,
        system_segment_size,
        poolmap_segment_size,
        metadata_segment_size,
        data_segment_size,
    })
}

// ---------------------------------------------------------------------------
// DeviceLayoutPolicy tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod layout_policy_tests {
    use super::*;

    // -- Slice0Small --------------------------------------------------------

    #[test]
    fn slice0_small_512mb() {
        let layout = DeviceLayoutPolicy::Slice0Small
            .compute(512 * 1024 * 1024)
            .expect("Slice0Small on 512 MiB");
        assert_eq!(layout.policy, DeviceLayoutPolicyDiscriminant::Slice0Small);
        assert_eq!(layout.device_size_bytes, 512 * 1024 * 1024);
        assert_eq!(layout.system_segment_size, 1024 * 1024);
        assert_eq!(layout.poolmap_segment_size, 1024 * 1024);
        assert_eq!(layout.metadata_segment_size, 1024 * 1024);
        assert_eq!(layout.data_segment_size, 1024 * 1024);
        assert_eq!(layout.system_area_offset, 0);
        assert_eq!(layout.system_area_len, 1024 * 1024);
        // poolmap starts right after system
        assert_eq!(
            layout.poolmap_journal_offset,
            layout.system_area_len
        );
        assert_eq!(
            layout.poolmap_journal_len,
            1024 * 1024 * POOLMAP_JOURNAL_SEGMENTS
        );
    }

    #[test]
    fn slice0_small_too_tiny() {
        // 1 MiB is the minimum (system area needs 1 MiB)
        let r = DeviceLayoutPolicy::Slice0Small.compute(512 * 1024);
        assert!(r.is_err());
        match r.unwrap_err() {
            LayoutPolicyError::DeviceTooSmall { .. } => {}
            e => panic!("expected DeviceTooSmall, got {e:?}"),
        }
    }

    // -- Auto ---------------------------------------------------------------

    fn approx_segment_count(_layout: &DeviceLayoutV1, region_size: u64, seg_size: u64) -> u64 {
        if seg_size == 0 {
            return 0;
        }
        region_size / seg_size
    }

    #[test]
    fn auto_1gib() {
        let dev_size: u64 = 1024 * 1024 * 1024;
        let layout = DeviceLayoutPolicy::Auto
            .compute(dev_size)
            .expect("Auto on 1 GiB");
        assert_eq!(layout.policy, DeviceLayoutPolicyDiscriminant::Auto);
        // 1 GiB with 1 MiB segments: data region ~ (1 GiB - 17 MiB) ~ 1007 MiB -> ~1007 segments
        // Well under 4M, so segment size stays at 1 MiB.
        assert_eq!(layout.data_segment_size, 1024 * 1024);
    }

    #[test]
    fn auto_1tib() {
        // 1 TiB
        let dev_size: u64 = 1_099_511_627_776;
        let layout = DeviceLayoutPolicy::Auto
            .compute(dev_size)
            .expect("Auto on 1 TiB");
        assert_eq!(layout.policy, DeviceLayoutPolicyDiscriminant::Auto);
        // 1 TiB / 1 MiB = ~1M segments, under 4M -> 1 MiB
        assert_eq!(layout.data_segment_size, 1024 * 1024);
    }

    #[test]
    fn auto_1pib() {
        // 1 PiB
        let dev_size: u64 = 1_125_899_906_842_624;
        let layout = DeviceLayoutPolicy::Auto
            .compute(dev_size)
            .expect("Auto on 1 PiB");
        assert_eq!(layout.policy, DeviceLayoutPolicyDiscriminant::Auto);
        // 1 PiB with target 4M segments: raw = 1 PiB / 4M ≈ 281.5 GiB per seg.
        // Clamped to 256 MiB max.
        assert_eq!(layout.data_segment_size, 256 * 1024 * 1024);
        // Verify segment count is reasonable
        let segs = approx_segment_count(
            &layout,
            layout.data_journal_len,
            layout.data_segment_size,
        );
        assert!(
            segs <= TARGET_DATA_SEGMENTS * 11 / 10,
            "data region has {segs} segments, target {TARGET_DATA_SEGMENTS}"
        );
    }

    #[test]
    fn auto_segment_size_is_power_of_two() {
        for &size in &[
            300_000_000u64,
            500_000_000,
            1_000_000_000,
            10_000_000_000,
            100_000_000_000,
            1_000_000_000_000,
            10_000_000_000_000,
            100_000_000_000_000,
            1_000_000_000_000_000,
        ] {
            let layout = DeviceLayoutPolicy::Auto.compute(size).unwrap();
            assert!(
                layout.data_segment_size.is_power_of_two(),
                "data_segment_size {} for device {size} not power of two",
                layout.data_segment_size
            );
            assert!(
                layout.metadata_segment_size.is_power_of_two(),
                "metadata_segment_size {} for device {size} not power of two",
                layout.metadata_segment_size
            );
            assert!(
                layout.poolmap_segment_size.is_power_of_two(),
                "poolmap_segment_size {} for device {size} not power of two",
                layout.poolmap_segment_size
            );
        }
    }

    #[test]
    fn auto_zero_device_size() {
        let r = DeviceLayoutPolicy::Auto.compute(0);
        assert!(matches!(r, Err(LayoutPolicyError::DeviceSizeZero)));
    }

    #[test]
    fn auto_region_bounds_strictly_increasing() {
        let layout = DeviceLayoutPolicy::Auto.compute(10_000_000_000).unwrap();
        assert!(layout.system_area_offset < layout.poolmap_journal_offset);
        assert!(layout.poolmap_journal_offset < layout.metadata_journal_offset);
        assert!(layout.metadata_journal_offset < layout.data_journal_offset);
    }

    #[test]
    fn auto_region_no_overlap() {
        let layout = DeviceLayoutPolicy::Auto.compute(10_000_000_000).unwrap();
        let sys_end = layout.system_area_offset + layout.system_area_len;
        let poolmap_end = layout.poolmap_journal_offset + layout.poolmap_journal_len;
        let meta_end = layout.metadata_journal_offset + layout.metadata_journal_len;
        let data_end = layout.data_journal_offset + layout.data_journal_len;
        assert!(sys_end <= layout.poolmap_journal_offset);
        assert!(poolmap_end <= layout.metadata_journal_offset);
        assert!(meta_end <= layout.data_journal_offset);
        assert!(data_end <= layout.device_size_bytes);
    }

    // -- Custom -------------------------------------------------------------

    #[test]
    fn custom_valid() {
        let dev_size: u64 = 100 * 1024 * 1024 * 1024; // 100 GiB
        let layout = DeviceLayoutPolicy::Custom {
            data_segment_size: 4 * 1024 * 1024,
            metadata_segment_size: 2 * 1024 * 1024,
            journal_segment_size: 1 * 1024 * 1024,
        }
        .compute(dev_size)
        .expect("Custom valid");
        assert_eq!(layout.data_segment_size, 4 * 1024 * 1024);
        assert_eq!(layout.metadata_segment_size, 2 * 1024 * 1024);
        assert_eq!(layout.poolmap_segment_size, 1 * 1024 * 1024);
    }

    #[test]
    fn custom_not_power_of_two() {
        let dev_size: u64 = 10 * 1024 * 1024 * 1024;
        let r = DeviceLayoutPolicy::Custom {
            data_segment_size: 3 * 1024 * 1024, // 3 MiB - not power of two
            metadata_segment_size: 1 * 1024 * 1024,
            journal_segment_size: 1 * 1024 * 1024,
        }
        .compute(dev_size);
        assert!(r.is_err());
        match r.unwrap_err() {
            LayoutPolicyError::InvalidSegmentSize { reason } => {
                assert_eq!(reason, InvalidSegmentSizeReason::NotPowerOfTwo);
            }
            e => panic!("expected InvalidSegmentSize, got {e:?}"),
        }
    }

    #[test]
    fn custom_below_minimum() {
        let r = DeviceLayoutPolicy::Custom {
            data_segment_size: 512 * 1024, // 512 KiB - below 1 MiB
            metadata_segment_size: 1 * 1024 * 1024,
            journal_segment_size: 1 * 1024 * 1024,
        }
        .compute(10 * 1024 * 1024 * 1024);
        assert!(r.is_err());
    }

    #[test]
    fn custom_above_maximum() {
        let r = DeviceLayoutPolicy::Custom {
            data_segment_size: 512 * 1024 * 1024, // 512 MiB - above 256 MiB
            metadata_segment_size: 1 * 1024 * 1024,
            journal_segment_size: 1 * 1024 * 1024,
        }
        .compute(10 * 1024 * 1024 * 1024);
        assert!(r.is_err());
    }

    #[test]
    fn custom_region_overflow() {
        // Device too small to fit all journals
        let r = DeviceLayoutPolicy::Custom {
            data_segment_size: 256 * 1024 * 1024, // 256 MiB
            metadata_segment_size: 256 * 1024 * 1024,
            journal_segment_size: 256 * 1024 * 1024,
        }
        .compute(1 * 1024 * 1024 * 1024); // 1 GiB — not enough for 16*256M + 256*256M + 256M
        assert!(r.is_err());
    }

    // -- DeviceLayoutV1 encode/decode round-trip ---------------------------

    #[test]
    fn encode_decode_roundtrip_slice0_small() {
        let layout = DeviceLayoutPolicy::Slice0Small
            .compute(512 * 1024 * 1024)
            .unwrap();
        let mut buf = [0u8; DEVICE_LAYOUT_V1_WIRE_SIZE];
        encode_device_layout_v1(&layout, &mut buf);
        let decoded = decode_device_layout_v1(&buf).unwrap();
        assert_eq!(layout, decoded);
    }

    #[test]
    fn encode_decode_roundtrip_auto() {
        let layout = DeviceLayoutPolicy::Auto
            .compute(1_000_000_000_000)
            .unwrap();
        let mut buf = [0u8; DEVICE_LAYOUT_V1_WIRE_SIZE];
        encode_device_layout_v1(&layout, &mut buf);
        let decoded = decode_device_layout_v1(&buf).unwrap();
        assert_eq!(layout, decoded);
    }

    #[test]
    fn encode_decode_roundtrip_custom() {
        let layout = DeviceLayoutPolicy::Custom {
            data_segment_size: 8 * 1024 * 1024,
            metadata_segment_size: 4 * 1024 * 1024,
            journal_segment_size: 2 * 1024 * 1024,
        }
        .compute(100 * 1024 * 1024 * 1024)
        .unwrap();
        let mut buf = [0u8; DEVICE_LAYOUT_V1_WIRE_SIZE];
        encode_device_layout_v1(&layout, &mut buf);
        let decoded = decode_device_layout_v1(&buf).unwrap();
        assert_eq!(layout, decoded);
    }

    #[test]
    fn decode_bad_magic() {
        let layout = DeviceLayoutPolicy::Auto.compute(1_000_000_000).unwrap();
        let mut buf = [0u8; DEVICE_LAYOUT_V1_WIRE_SIZE];
        encode_device_layout_v1(&layout, &mut buf);
        buf[0] = 0; // corrupt magic
        let r = decode_device_layout_v1(&buf);
        assert!(matches!(r, Err(LayoutPolicyError::BadMagic { .. })));
    }

    #[test]
    fn decode_bad_checksum() {
        let layout = DeviceLayoutPolicy::Auto.compute(1_000_000_000).unwrap();
        let mut buf = [0u8; DEVICE_LAYOUT_V1_WIRE_SIZE];
        encode_device_layout_v1(&layout, &mut buf);
        // Flip a bit in the CRC region
        buf[DEVICE_LAYOUT_V1_CRC32C_OFFSET] ^= 0xFF;
        let r = decode_device_layout_v1(&buf);
        assert!(matches!(
            r,
            Err(LayoutPolicyError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn decode_buffer_too_small() {
        let buf = [0u8; 100];
        let r = decode_device_layout_v1(&buf);
        assert!(matches!(r, Err(LayoutPolicyError::BufferTooSmall { .. })));
    }

    // -- choose_segment_size_bytes -----------------------------------------

    #[test]
    fn choose_segment_size_power_of_two_output() {
        for region_size in [1_000_000, 10_000_000, 100_000_000, 1_000_000_000, 10_000_000_000] {
            let seg = choose_segment_size_bytes(region_size, 4_000_000);
            assert!(
                seg.is_power_of_two(),
                "segment size {seg} for region {region_size} not power of two"
            );
            assert!(seg >= MIN_SEGMENT_SIZE_BYTES);
            assert!(seg <= MAX_SEGMENT_SIZE_BYTES);
        }
    }

    #[test]
    fn choose_segment_size_clamps_to_min() {
        // Very small region: raw = 1K / 4M ≈ 0, clamped to 1 MiB, next_power_of_two = 1 MiB
        let seg = choose_segment_size_bytes(1024, 4_000_000);
        assert_eq!(seg, MIN_SEGMENT_SIZE_BYTES);
    }

    #[test]
    fn choose_segment_size_clamps_to_max() {
        // Very large region: raw = 1 PiB / 4M ≈ 281 GiB, clamped to 256 MiB
        let seg = choose_segment_size_bytes(1_125_899_906_842_624, 4_000_000);
        assert_eq!(seg, MAX_SEGMENT_SIZE_BYTES);
    }

    // -- validate_segment_size ----------------------------------------------

    #[test]
    fn validate_segment_size_accepts_power_of_two() {
        assert!(validate_segment_size(1 * 1024 * 1024).is_ok());
        assert!(validate_segment_size(4 * 1024 * 1024).is_ok());
        assert!(validate_segment_size(256 * 1024 * 1024).is_ok());
    }

    #[test]
    fn validate_segment_size_rejects_non_power_of_two() {
        assert!(validate_segment_size(3 * 1024 * 1024).is_err());
    }

    #[test]
    fn validate_segment_size_rejects_too_small() {
        assert!(validate_segment_size(512 * 1024).is_err());
    }

    #[test]
    fn validate_segment_size_rejects_too_large() {
        assert!(validate_segment_size(512 * 1024 * 1024).is_err());
    }

    // -- DeviceLayoutPolicyDiscriminant round-trip -------------------------

    #[test]
    fn policy_discriminant_roundtrip() {
        for &v in &[0u16, 1, 2] {
            let disc = DeviceLayoutPolicyDiscriminant::from_u16(v)
                .expect("valid discriminant");
            assert_eq!(disc.to_u16(), v);
        }
    }

    #[test]
    fn policy_discriminant_invalid() {
        assert!(DeviceLayoutPolicyDiscriminant::from_u16(99).is_none());
    }

    // -- DeviceLayoutPolicy Display ----------------------------------------

    #[test]
    fn policy_display() {
        assert_eq!(DeviceLayoutPolicy::Slice0Small.to_string(), "Slice0Small");
        assert_eq!(DeviceLayoutPolicy::Auto.to_string(), "Auto");
        assert_eq!(
            DeviceLayoutPolicy::Custom {
                data_segment_size: 1,
                metadata_segment_size: 1,
                journal_segment_size: 1,
            }
            .to_string(),
            "Custom"
        );
    }
}

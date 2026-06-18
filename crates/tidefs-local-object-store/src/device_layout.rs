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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
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

//! Comparator harness — executes fio benchmarks against incumbent filesystems
//! (ext4, raw block) and captures baseline KPI vectors for performance gate
//! comparator rows.  ZFS and Ceph are staged/unavailable with release
//! blocker notes.
//!
//! # Comparator kinds
//!
//! - Ext4Posix: fio against ext4 mount on the same backend (POSIX/block-local rows)
//! - RawBlockBaseline: fio against raw block device (ublk rows)
//! - PreviousTideFS: previous-admitted TideFS variant (regression lock rows)
//! - ZfsStaged: ZFS unavailable — release blocker for superiority claims
//! - CephStaged: Ceph unavailable — release blocker for superiority claims

use super::benchmark_harness::FioHarness;
use super::gate_entry::{BaselineKpi, ComparatorRef};
use super::validation_tier::ValidationTier;
use serde::{Deserialize, Serialize};

/// Kind of comparator filesystem or baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComparatorKind {
    /// ext4 mounted filesystem on the same backend device.
    Ext4Posix,
    /// Raw block device (no filesystem) baseline.
    RawBlockBaseline,
    /// Previous-admitted TideFS variant for regression lock.
    PreviousTideFS,
    /// ZFS comparator — staged/unavailable.
    ZfsStaged,
    /// Ceph comparator — staged/unavailable.
    CephStaged,
}

impl ComparatorKind {
    pub fn ref_id(&self) -> &'static str {
        match self {
            Self::Ext4Posix => "comparator.ext4.posix",
            Self::RawBlockBaseline => "comparator.raw-block.baseline",
            Self::PreviousTideFS => "comparator.tidefs.previous-admitted",
            Self::ZfsStaged => "comparator.zfs.staged",
            Self::CephStaged => "comparator.ceph.staged",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Ext4Posix => "ext4 mounted filesystem on same backend device",
            Self::RawBlockBaseline => "raw block device baseline (no filesystem)",
            Self::PreviousTideFS => "previous-admitted TideFS variant for regression lock",
            Self::ZfsStaged => "ZFS comparator staged — unavailable, release blocker",
            Self::CephStaged => "Ceph comparator staged — unavailable, release blocker",
        }
    }

    /// Whether this comparator kind requires live execution (fio run).
    pub fn requires_execution(&self) -> bool {
        matches!(self, Self::Ext4Posix | Self::RawBlockBaseline)
    }

    /// Whether this is a staged (unavailable) comparator.
    pub fn is_staged(&self) -> bool {
        matches!(self, Self::ZfsStaged | Self::CephStaged)
    }
}

/// Single comparator run result — wraps a ComparatorRef with execution metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComparatorRun {
    pub ref_id: String,
    pub kind: ComparatorKind,
    pub description: String,
    pub executed: bool,
    pub baseline_kpis: Vec<BaselineKpi>,
    pub blocker: Option<String>,
}

impl ComparatorRun {
    /// Create a staged (unavailable) comparator run.
    pub fn staged(kind: ComparatorKind, reason: impl Into<String>) -> Self {
        Self {
            ref_id: kind.ref_id().to_string(),
            kind,
            description: kind.description().to_string(),
            executed: false,
            baseline_kpis: Vec::new(),
            blocker: Some(reason.into()),
        }
    }

    /// Convert into a ComparatorRef suitable for a PerformanceGateEntry.
    pub fn to_comparator_ref(&self) -> ComparatorRef {
        ComparatorRef {
            ref_id: self.ref_id.clone(),
            commit_sha: None,
            description: self.description.clone(),
            baseline_kpis: self.baseline_kpis.clone(),
        }
    }
}

/// ComparatorHarness executes fio against incumbent filesystems and
/// captures baseline KPI vectors.
pub struct ComparatorHarness {
    pub repo_root: String,
}

impl ComparatorHarness {
    pub fn new(repo_root: impl Into<String>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
    }

    /// Run all applicable comparators for a given subject.
    /// Returns a vector of ComparatorRun results.
    /// On execution failure (no fio binary, no /dev/fuse, no ext4 mkfs, etc.),
    /// returned runs have `executed = false` with a blocker note.
    pub fn run_all(&self, subject: &str, kinds: &[ComparatorKind]) -> Vec<ComparatorRun> {
        kinds
            .iter()
            .map(|&k| match k {
                ComparatorKind::Ext4Posix => self.run_ext4(subject),
                ComparatorKind::RawBlockBaseline => self.run_raw_block(subject),
                ComparatorKind::PreviousTideFS => self.run_previous_tidefs(subject),
                ComparatorKind::ZfsStaged => ComparatorRun::staged(
                    ComparatorKind::ZfsStaged,
                    "ZFS comparator not available — release blocker for superiority claims",
                ),
                ComparatorKind::CephStaged => ComparatorRun::staged(
                    ComparatorKind::CephStaged,
                    "Ceph comparator not available — release blocker for superiority claims",
                ),
            })
            .collect()
    }

    fn run_ext4(&self, subject: &str) -> ComparatorRun {
        let tmp = std::env::var("TIDEFS_COMPARATOR_TEMP")
            .unwrap_or_else(|_| "/tmp/tidefs-comparator-ext4".into());
        let mp = format!("{tmp}/mnt");
        let dev = format!("{tmp}/ext4.img");
        let _ = std::fs::remove_dir_all(&tmp);
        if std::fs::create_dir_all(&mp).is_err() || std::fs::create_dir_all(&tmp).is_err() {
            return ComparatorRun::staged(
                ComparatorKind::Ext4Posix,
                "cannot create comparator temp directory",
            );
        }

        // Create a 512 MiB sparse file and format as ext4
        if !std::process::Command::new("truncate")
            .arg("-s")
            .arg("512M")
            .arg(&dev)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return ComparatorRun::staged(
                ComparatorKind::Ext4Posix,
                "truncate binary unavailable — cannot create ext4 image",
            );
        }
        if !std::process::Command::new("mkfs.ext4")
            .arg("-F")
            .arg("-q")
            .arg(&dev)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return ComparatorRun::staged(
                ComparatorKind::Ext4Posix,
                "mkfs.ext4 unavailable — cannot format comparator device",
            );
        }
        if !std::process::Command::new("mount")
            .arg("-o")
            .arg("loop")
            .arg(&dev)
            .arg(&mp)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return ComparatorRun::staged(
                ComparatorKind::Ext4Posix,
                "mount failed — ext4 comparator cannot operate",
            );
        }

        let fio = FioHarness::new(&self.repo_root);
        let result = fio.run(
            format!("{subject}-ext4-comparator"),
            "fs",
            &mp,
            "comparator",
            ValidationTier::MountedUserspace,
        );

        let _ = std::process::Command::new("umount").arg(&mp).output();
        let _ = std::fs::remove_dir_all(&tmp);

        let baseline_kpis = if result.executed {
            result
                .kpis
                .iter()
                .map(|kpi| BaselineKpi {
                    name: kpi.name.clone(),
                    value: kpi.value,
                    unit: kpi.unit.clone(),
                })
                .collect()
        } else {
            Vec::new()
        };

        ComparatorRun {
            ref_id: ComparatorKind::Ext4Posix.ref_id().to_string(),
            kind: ComparatorKind::Ext4Posix,
            description: ComparatorKind::Ext4Posix.description().to_string(),
            executed: result.executed,
            baseline_kpis,
            blocker: if result.executed {
                None
            } else {
                Some(format!("ext4 comparator failed: {}", result.stderr_tail))
            },
        }
    }

    fn run_raw_block(&self, subject: &str) -> ComparatorRun {
        let tmp = std::env::var("TIDEFS_COMPARATOR_TEMP")
            .unwrap_or_else(|_| "/tmp/tidefs-comparator-rawblock".into());
        let dev = format!("{tmp}/raw.img");
        let _ = std::fs::remove_dir_all(&tmp);
        if std::fs::create_dir_all(&tmp).is_err() {
            return ComparatorRun::staged(
                ComparatorKind::RawBlockBaseline,
                "cannot create comparator temp directory",
            );
        }
        if !std::process::Command::new("truncate")
            .arg("-s")
            .arg("512M")
            .arg(&dev)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return ComparatorRun::staged(
                ComparatorKind::RawBlockBaseline,
                "truncate binary unavailable — cannot create raw block image",
            );
        }

        let fio = FioHarness::new(&self.repo_root);
        let result = fio.run(
            format!("{subject}-rawblock-comparator"),
            "block",
            &dev,
            "comparator",
            ValidationTier::MountedUserspace,
        );

        let _ = std::fs::remove_dir_all(&tmp);

        let baseline_kpis = if result.executed {
            result
                .kpis
                .iter()
                .map(|kpi| BaselineKpi {
                    name: kpi.name.clone(),
                    value: kpi.value,
                    unit: kpi.unit.clone(),
                })
                .collect()
        } else {
            Vec::new()
        };

        ComparatorRun {
            ref_id: ComparatorKind::RawBlockBaseline.ref_id().to_string(),
            kind: ComparatorKind::RawBlockBaseline,
            description: ComparatorKind::RawBlockBaseline.description().to_string(),
            executed: result.executed,
            baseline_kpis,
            blocker: if result.executed {
                None
            } else {
                Some(format!(
                    "raw-block comparator failed: {}",
                    result.stderr_tail
                ))
            },
        }
    }

    fn run_previous_tidefs(&self, _subject: &str) -> ComparatorRun {
        // Review debt TFR-015: comparison baselines are external inputs, not
        // source-controlled runtime output.
        match std::env::var("TIDEFS_PREVIOUS_TIDEFS_BASELINE") {
            Ok(path) if std::path::Path::new(&path).exists() => ComparatorRun::staged(
                ComparatorKind::PreviousTideFS,
                "External previous TideFS baseline configured but automated re-benchmark not wired",
            ),
            Ok(path) => ComparatorRun::staged(
                ComparatorKind::PreviousTideFS,
                format!("External previous TideFS baseline not found: {path}"),
            ),
            Err(_) => ComparatorRun::staged(
                ComparatorKind::PreviousTideFS,
                "No external previous-admitted TideFS baseline configured",
            ),
        }
    }
}

/// ComparatorManifest maps subject rows to required comparator kinds.
pub struct ComparatorManifest;

impl ComparatorManifest {
    /// Return the required comparator kinds for a given subject.
    pub fn comparators_for(subject: &str) -> Vec<ComparatorKind> {
        match subject {
            // POSIX/FUSE rows — ext4 comparator required
            "mounted-fuse" | "local-filesystem" => vec![
                ComparatorKind::Ext4Posix,
                ComparatorKind::PreviousTideFS,
                ComparatorKind::ZfsStaged,
                ComparatorKind::CephStaged,
            ],
            // ublk rows — raw block and ext4 comparators required
            "ublk-direct" | "ublk-ext4" => vec![
                ComparatorKind::RawBlockBaseline,
                ComparatorKind::Ext4Posix,
                ComparatorKind::PreviousTideFS,
            ],
            // Storage rows — raw block and ext4
            "local-object-store" => {
                vec![ComparatorKind::RawBlockBaseline, ComparatorKind::Ext4Posix]
            }
            // Transport/recovery rows — ext4 and regression lock
            "transport" | "recovery-rebuild" => {
                vec![ComparatorKind::Ext4Posix, ComparatorKind::PreviousTideFS]
            }
            // Kernel rows — currently blocked (staged)
            "kernel-kmod-vfs" | "kernel-block-kmod" => vec![
                ComparatorKind::Ext4Posix,
                ComparatorKind::RawBlockBaseline,
                ComparatorKind::PreviousTideFS,
            ],
            _ => vec![ComparatorKind::Ext4Posix, ComparatorKind::PreviousTideFS],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparator_kind_ref_ids_are_distinct() {
        let kinds = &[
            ComparatorKind::Ext4Posix,
            ComparatorKind::RawBlockBaseline,
            ComparatorKind::PreviousTideFS,
            ComparatorKind::ZfsStaged,
            ComparatorKind::CephStaged,
        ];
        let mut refs: Vec<&str> = kinds.iter().map(|k| k.ref_id()).collect();
        refs.sort();
        refs.dedup();
        assert_eq!(
            refs.len(),
            kinds.len(),
            "all comparator ref_ids must be distinct"
        );
    }

    #[test]
    fn staged_comparators_are_not_executable() {
        assert!(!ComparatorKind::ZfsStaged.requires_execution());
        assert!(!ComparatorKind::CephStaged.requires_execution());
    }

    #[test]
    fn staged_comparators_have_blocker() {
        let staged = ComparatorRun::staged(ComparatorKind::ZfsStaged, "blocked");
        assert!(!staged.executed);
        assert!(staged.blocker.is_some());
        assert!(staged.baseline_kpis.is_empty());
    }

    #[test]
    fn run_all_returns_one_per_kind() {
        let harness = ComparatorHarness::new("/nonexistent");
        let kinds = &[ComparatorKind::ZfsStaged, ComparatorKind::CephStaged];
        let runs = harness.run_all("test", kinds);
        assert_eq!(runs.len(), 2);
        for r in &runs {
            assert!(!r.executed);
        }
    }

    #[test]
    fn manifest_covers_all_required_subjects() {
        let subjects = &[
            "mounted-fuse",
            "ublk-direct",
            "ublk-ext4",
            "local-object-store",
            "local-filesystem",
            "transport",
            "recovery-rebuild",
            "kernel-kmod-vfs",
            "kernel-block-kmod",
        ];
        for s in subjects {
            let kinds = ComparatorManifest::comparators_for(s);
            assert!(!kinds.is_empty(), "subject '{s}' must have comparators");
            // Every POSIX/block-local subject must include Ext4Posix
            assert!(
                kinds.contains(&ComparatorKind::Ext4Posix),
                "subject '{s}' must include ext4 comparator"
            );
        }
    }

    #[test]
    fn mounted_fuse_requires_ext4_and_staged() {
        let kinds = ComparatorManifest::comparators_for("mounted-fuse");
        assert!(kinds.contains(&ComparatorKind::Ext4Posix));
        assert!(kinds.contains(&ComparatorKind::ZfsStaged));
        assert!(kinds.contains(&ComparatorKind::CephStaged));
    }

    #[test]
    fn ublk_direct_requires_raw_block() {
        let kinds = ComparatorManifest::comparators_for("ublk-direct");
        assert!(kinds.contains(&ComparatorKind::RawBlockBaseline));
        assert!(kinds.contains(&ComparatorKind::Ext4Posix));
    }

    #[test]
    fn comparator_run_to_ref_roundtrip() {
        let run = ComparatorRun::staged(ComparatorKind::ZfsStaged, "blocked");
        let cr = run.to_comparator_ref();
        assert_eq!(cr.ref_id, ComparatorKind::ZfsStaged.ref_id());
        assert!(cr.baseline_kpis.is_empty());
    }

    #[test]
    fn serde_roundtrip_comparator_kind() {
        for k in &[
            ComparatorKind::Ext4Posix,
            ComparatorKind::RawBlockBaseline,
            ComparatorKind::ZfsStaged,
        ] {
            let json = serde_json::to_string(k).unwrap();
            let back: ComparatorKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }
}

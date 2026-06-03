//! Workload signature enumeration and classification helpers.
//!
//! Defines the six canonical workload signatures that the sliding-window
//! classifier materializes. Each signature describes a distinct IO access
//! pattern that adaptive subsystems (prefetch, recordsize, ARC, scheduler)
//! can use to tune their behavior.

use core::fmt;
use core::str::FromStr;

/// Named workload signature classifying the dominant IO access pattern
/// observed over a sliding window.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum WorkloadSignature {
    /// Small random reads and writes with low fsync rate.
    /// Typical of OLTP databases and key-value stores.
    Oltp,
    /// Large sequential reads, read-heavy.
    /// Typical of OLAP/analytics queries and reporting.
    Olap,
    /// Large sequential writes, write-heavy.
    /// Typical of backup, ingest, and bulk-load jobs.
    Backup,
    /// Sequential reads of large files with very high sequential ratio.
    /// Typical of media streaming and content delivery.
    Media,
    /// Mixed random IO with elevated fsync rate.
    /// Typical of virtual machine disk images and databases with
    /// synchronous commit.
    Vm,
    /// Insufficient data or low confidence to classify.
    #[default]
    Unknown,
}

impl WorkloadSignature {
    /// All six variants in a fixed iteration order.
    pub const ALL: [WorkloadSignature; 6] = [
        WorkloadSignature::Oltp,
        WorkloadSignature::Olap,
        WorkloadSignature::Backup,
        WorkloadSignature::Media,
        WorkloadSignature::Vm,
        WorkloadSignature::Unknown,
    ];

    /// Human-readable name for the variant.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            WorkloadSignature::Oltp => "OLTP",
            WorkloadSignature::Olap => "OLAP",
            WorkloadSignature::Backup => "Backup",
            WorkloadSignature::Media => "Media",
            WorkloadSignature::Vm => "VM",
            WorkloadSignature::Unknown => "Unknown",
        }
    }

    /// Short description of the access pattern.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            WorkloadSignature::Oltp => "small random reads/writes with low fsync rate",
            WorkloadSignature::Olap => "large sequential reads, read-heavy",
            WorkloadSignature::Backup => "large sequential writes, write-heavy",
            WorkloadSignature::Media => "sequential reads of large files",
            WorkloadSignature::Vm => "mixed random IO with elevated fsync rate",
            WorkloadSignature::Unknown => "insufficient data or low confidence",
        }
    }
}

impl fmt::Display for WorkloadSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Error returned when parsing a [`WorkloadSignature`] from a string fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidWorkloadSignature;

impl fmt::Display for InvalidWorkloadSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid workload signature name")
    }
}

impl FromStr for WorkloadSignature {
    type Err = InvalidWorkloadSignature;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "OLTP" | "oltp" => Ok(WorkloadSignature::Oltp),
            "OLAP" | "olap" => Ok(WorkloadSignature::Olap),
            "Backup" | "backup" => Ok(WorkloadSignature::Backup),
            "Media" | "media" => Ok(WorkloadSignature::Media),
            "VM" | "vm" => Ok(WorkloadSignature::Vm),
            "Unknown" | "unknown" => Ok(WorkloadSignature::Unknown),
            _ => Err(InvalidWorkloadSignature),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_have_distinct_names() {
        let mut names: Vec<&str> = WorkloadSignature::ALL.iter().map(|s| s.name()).collect();
        let len_before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), len_before, "all names must be unique");
    }

    #[test]
    fn display_roundtrips_through_from_str() {
        for sig in WorkloadSignature::ALL {
            let s = sig.to_string();
            let parsed: WorkloadSignature = s.parse().expect("parse Display output");
            assert_eq!(parsed, sig, "roundtrip failed for {sig}");
        }
    }

    #[test]
    fn from_str_is_case_insensitive() {
        assert_eq!("oltp".parse(), Ok(WorkloadSignature::Oltp));
        assert_eq!("OLTP".parse(), Ok(WorkloadSignature::Oltp));
        assert_eq!("olap".parse(), Ok(WorkloadSignature::Olap));
        assert_eq!("vm".parse(), Ok(WorkloadSignature::Vm));
    }

    #[test]
    fn invalid_name_rejected() {
        assert!("".parse::<WorkloadSignature>().is_err());
        assert!("NOSUCH".parse::<WorkloadSignature>().is_err());
        assert!("oltpp".parse::<WorkloadSignature>().is_err());
    }

    #[test]
    fn descriptions_are_non_empty() {
        for sig in WorkloadSignature::ALL {
            assert!(!sig.description().is_empty(), "{sig} description empty");
        }
    }

    #[test]
    fn default_is_unknown() {
        assert_eq!(WorkloadSignature::default(), WorkloadSignature::Unknown);
    }
}

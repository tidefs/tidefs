#![forbid(unsafe_code)]

//! Claim ledger runtime: authority-tracked resource consumption.
//!
//! Design rule Rule 3: "Authority is scarce and explicit. Mutable heads,
//! projection roots, claim ledgers, reserve ledgers, witness sets, and
//! receipts are the scarce authority objects."
//!
//! This crate provides the runtime claim ledger that tracks every write
//! as a claim against a named budget domain, with claim admission gated
//! by the accompanying reserve ledger state.

use std::collections::BTreeMap;
use std::fmt;
use tidefs_types_claim_ledger_core::BudgetDomainId;
use tidefs_types_claim_ledger_core::ClaimId;
use tidefs_types_claim_ledger_core::StorageAuthorityToken;
use tidefs_types_vfs_core::InodeId;

mod integrity;
pub use integrity::{ClaimEncoding, ClaimIntegrity, EncodingError, IntegrityError};

mod receipt_chain;
pub use receipt_chain::{ValidationReceiptLedger, ValidationReceiptLedgerError};

// ---------------------------------------------------------------------------
// ClaimClass — what kind of consumption this claim represents
// ---------------------------------------------------------------------------

/// Classification of a claim's purpose for admission priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ClaimClass {
    /// Normal product writes (lowest priority under pressure).
    Product = 0,
    /// Rebuild writes after node loss (medium priority).
    Rebuild = 1,
    /// Anti-entropy scan and repair writes (medium priority).
    AntiEntropy = 2,
    /// Failover authority handoff writes (high priority).
    Failover = 3,
}

impl ClaimClass {
    pub const COUNT: usize = 4;

    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Product => "product",
            Self::Rebuild => "rebuild",
            Self::AntiEntropy => "anti_entropy",
            Self::Failover => "failover",
        }
    }

    /// Whether this claim class is a reserve-class write (not a product write).
    pub const fn is_reserve_class(self) -> bool {
        matches!(self, Self::Rebuild | Self::AntiEntropy | Self::Failover)
    }

    /// Admission priority: higher values are admitted under more pressure.
    pub const fn admission_priority(self) -> u8 {
        match self {
            Self::Product => 0,
            Self::AntiEntropy => 1,
            Self::Rebuild => 2,
            Self::Failover => 3,
        }
    }
}

impl fmt::Display for ClaimClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<u8> for ClaimClass {
    type Error = ClaimLedgerError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Product),
            1 => Ok(Self::Rebuild),
            2 => Ok(Self::AntiEntropy),
            3 => Ok(Self::Failover),
            _ => Err(ClaimLedgerError::InvalidClaimClass(v as u32)),
        }
    }
}

// ---------------------------------------------------------------------------
// ClaimantRef — who is making the claim
// ---------------------------------------------------------------------------

/// Identifies the claimant: a process, PID cohort, or service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimantRef {
    /// A specific process.
    Process { pid: u64, name: String },
    /// A PID cohort (group of processes).
    Cohort { cohort_id: u64, label: String },
    /// A named system service (e.g., "rebuild-planner").
    Service { service_name: String },
}

impl fmt::Display for ClaimantRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Process { pid, name } => write!(f, "process:{pid}({name})"),
            Self::Cohort { cohort_id, label } => write!(f, "cohort:{cohort_id}({label})"),
            Self::Service { service_name } => write!(f, "service:{service_name}"),
        }
    }
}

// ---------------------------------------------------------------------------
// LeaseDeadlineRecord — optional lease expiration for claim
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseDeadlineRecord {
    /// Absolute deadline (milliseconds since epoch).
    pub deadline_millis: u64,
    /// Claim is eligible for reclamation after this deadline.
    pub auto_reclaim: bool,
}

// ---------------------------------------------------------------------------
// ClaimEntryRecord — an individual claim entry in the ledger
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ClaimEntryRecord {
    /// Unique claim identifier.
    pub claim_id: ClaimId,
    /// Who is making the claim.
    pub claimant_ref: ClaimantRef,
    /// What kind of consumption this represents.
    pub claim_class: ClaimClass,
    /// Bytes requested (may exceed committed).
    pub claimed_bytes: u64,
    /// Bytes actually committed to durable storage.
    pub committed_bytes: u64,
    /// Target inode (if applicable).
    pub inode_id: Option<InodeId>,
    /// Fence that must be reached before this claim is durable.
    pub freshness_fence_ref: Option<u64>,
    /// Cryptographic receipt backing this claim.
    pub claim_receipt_ref: StorageAuthorityToken,
    /// Optional lease expiration.
    pub expiration_deadline: Option<LeaseDeadlineRecord>,
}

impl ClaimEntryRecord {
    pub fn new(
        claim_id: ClaimId,
        claimant_ref: ClaimantRef,
        claim_class: ClaimClass,
        claimed_bytes: u64,
    ) -> Self {
        Self {
            claim_id,
            claimant_ref,
            claim_class,
            claimed_bytes,
            committed_bytes: 0,
            inode_id: None,
            freshness_fence_ref: None,
            claim_receipt_ref: StorageAuthorityToken::ABSENT,
            expiration_deadline: None,
        }
    }

    /// Mark bytes as committed.
    pub fn commit_bytes(&mut self, bytes: u64) {
        self.committed_bytes = self.committed_bytes.saturating_add(bytes);
    }
}

// ---------------------------------------------------------------------------
// ClaimLedger — the authority-tracked claim ledger
// ---------------------------------------------------------------------------

/// Authority-tracked resource consumption ledger.
///
/// Every write must register a claim against a budget domain. The claim ledger
/// tracks all outstanding claims and enforces budget admission based on the
/// companion reserve ledger's pressure state.
#[derive(Clone, Debug)]
pub struct ClaimLedger {
    /// Unique ledger identifier.
    pub ledger_id: u64,
    /// Which budget domain this ledger belongs to.
    pub budget_domain_ref: BudgetDomainId,
    /// Total claimed bytes (all claims, committed or not).
    pub total_claimed_bytes: u64,
    /// Total committed bytes (durably stored).
    pub total_committed_bytes: u64,
    /// Individual claim entries.
    pub claim_entries: Vec<ClaimEntryRecord>,
    /// Receipt for this ledger's issuance.
    pub issuance_receipt_ref: StorageAuthorityToken,
}

impl ClaimLedger {
    /// Create a new claim ledger for a budget domain.
    pub fn new(ledger_id: u64, budget_domain_ref: BudgetDomainId) -> Self {
        Self {
            ledger_id,
            budget_domain_ref,
            total_claimed_bytes: 0,
            total_committed_bytes: 0,
            claim_entries: Vec::new(),
            issuance_receipt_ref: StorageAuthorityToken::ABSENT,
        }
    }

    /// Register a claim. Returns the claim_id on success.
    pub fn register_claim(
        &mut self,
        entry: ClaimEntryRecord,
        available_bytes: u64,
    ) -> Result<ClaimId, ClaimLedgerError> {
        if entry.claimed_bytes == 0 {
            return Err(ClaimLedgerError::ZeroByteClaim);
        }

        let after = self.total_claimed_bytes.saturating_add(entry.claimed_bytes);
        if after > available_bytes {
            return Err(ClaimLedgerError::BudgetExhausted {
                domain: self.budget_domain_ref.to_string(),
                requested: entry.claimed_bytes,
                available: available_bytes.saturating_sub(self.total_claimed_bytes),
            });
        }

        let claim_id = entry.claim_id;
        self.total_claimed_bytes = after;
        self.claim_entries.push(entry);
        Ok(claim_id)
    }

    /// Release a claim by its identifier. Returns the freed bytes.
    pub fn release_claim(&mut self, claim_id: ClaimId) -> u64 {
        let mut freed = 0_u64;
        self.claim_entries.retain(|e| {
            if e.claim_id == claim_id {
                freed = e.claimed_bytes;
                false
            } else {
                true
            }
        });
        self.total_claimed_bytes = self.total_claimed_bytes.saturating_sub(freed);
        freed
    }

    /// Release all claims for a given inode.
    pub fn release_claims_for_inode(&mut self, inode_id: InodeId) -> u64 {
        let mut freed = 0_u64;
        self.claim_entries.retain(|e| {
            if e.inode_id == Some(inode_id) {
                freed += e.claimed_bytes;
                false
            } else {
                true
            }
        });
        self.total_claimed_bytes = self.total_claimed_bytes.saturating_sub(freed);
        freed
    }

    /// Mark bytes as committed for a claim.
    pub fn commit_claim(&mut self, claim_id: ClaimId, bytes: u64) -> Result<(), ClaimLedgerError> {
        let entry = self
            .claim_entries
            .iter_mut()
            .find(|e| e.claim_id == claim_id)
            .ok_or(ClaimLedgerError::ClaimNotFound(claim_id))?;
        entry.commit_bytes(bytes);
        self.total_committed_bytes = self.total_committed_bytes.saturating_add(bytes);
        Ok(())
    }

    /// Count claims by class.
    pub fn count_by_class(&self) -> BTreeMap<ClaimClass, usize> {
        let mut counts = BTreeMap::new();
        for entry in &self.claim_entries {
            *counts.entry(entry.claim_class).or_insert(0) += 1;
        }
        counts
    }

    /// Sum claimed bytes by class.
    pub fn bytes_by_class(&self) -> BTreeMap<ClaimClass, u64> {
        let mut sums = BTreeMap::new();
        for entry in &self.claim_entries {
            *sums.entry(entry.claim_class).or_insert(0) += entry.claimed_bytes;
        }
        sums
    }

    /// Number of active claims.
    pub fn claim_count(&self) -> usize {
        self.claim_entries.len()
    }

    /// Iterate over all claim entries.
    pub fn iter(&self) -> impl Iterator<Item = &ClaimEntryRecord> {
        self.claim_entries.iter()
    }
}

impl fmt::Display for ClaimLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ClaimLedger {{")?;
        writeln!(f, "  ledger_id: {}", self.ledger_id)?;
        writeln!(f, "  budget_domain: {}", self.budget_domain_ref)?;
        writeln!(f, "  total_claimed_bytes: {}", self.total_claimed_bytes)?;
        writeln!(f, "  total_committed_bytes: {}", self.total_committed_bytes)?;
        writeln!(f, "  claim_count: {}", self.claim_count())?;
        writeln!(f, "}}")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ClaimLedgerReport — operator-queryable breakdown
// ---------------------------------------------------------------------------

/// Human- and machine-readable breakdown of claim ledger state.
#[derive(Clone, Debug)]
pub struct ClaimLedgerReport {
    pub ledger_id: u64,
    pub budget_domain: String,
    pub total_claimed_bytes: u64,
    pub total_committed_bytes: u64,
    pub claim_count: usize,
    pub bytes_by_class: BTreeMap<String, u64>,
    pub counts_by_class: BTreeMap<String, usize>,
}

impl ClaimLedger {
    /// Produce an operator-queryable report.
    pub fn report(&self) -> ClaimLedgerReport {
        let mut bytes_by_class = BTreeMap::new();
        let mut counts_by_class = BTreeMap::new();
        for entry in &self.claim_entries {
            let class_str = entry.claim_class.as_str().to_string();
            *bytes_by_class.entry(class_str.clone()).or_insert(0) += entry.claimed_bytes;
            *counts_by_class.entry(class_str).or_insert(0) += 1;
        }
        ClaimLedgerReport {
            ledger_id: self.ledger_id,
            budget_domain: self.budget_domain_ref.to_string(),
            total_claimed_bytes: self.total_claimed_bytes,
            total_committed_bytes: self.total_committed_bytes,
            claim_count: self.claim_count(),
            bytes_by_class,
            counts_by_class,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ClaimLedgerError {
    #[error("zero-byte claim rejected")]
    ZeroByteClaim,

    #[error(
        "budget exhausted for domain {domain}: requested {requested} bytes, {available} available"
    )]
    BudgetExhausted {
        domain: String,
        requested: u64,
        available: u64,
    },

    #[error("claim {0} not found")]
    ClaimNotFound(ClaimId),

    #[error("invalid claim class: {0}")]
    InvalidClaimClass(u32),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_domain() -> BudgetDomainId {
        BudgetDomainId::from_str("test_domain")
    }

    #[test]
    fn claim_ledger_register_and_release() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "write-worker".into(),
            },
            ClaimClass::Product,
            4096,
        );
        let claim_id = entry.claim_id;
        ledger.register_claim(entry, 1_000_000).unwrap();
        assert_eq!(ledger.claim_count(), 1);
        assert_eq!(ledger.total_claimed_bytes, 4096);

        let freed = ledger.release_claim(claim_id);
        assert_eq!(freed, 4096);
        assert_eq!(ledger.claim_count(), 0);
        assert_eq!(ledger.total_claimed_bytes, 0);
    }

    #[test]
    fn claim_ledger_budget_exhausted() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "write-worker".into(),
            },
            ClaimClass::Product,
            5000,
        );
        let result = ledger.register_claim(entry, 4096);
        assert!(result.is_err());
    }

    #[test]
    fn claim_ledger_release_for_inode() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let inode = InodeId::new(42);
        let mut entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            1000,
        );
        entry.inode_id = Some(inode);
        let _claim_id = entry.claim_id;
        ledger.register_claim(entry, 1_000_000).unwrap();

        let mut entry2 = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            2000,
        );
        entry2.inode_id = Some(inode);
        ledger.register_claim(entry2, 1_000_000).unwrap();

        assert_eq!(ledger.claim_count(), 2);
        let freed = ledger.release_claims_for_inode(inode);
        assert_eq!(freed, 3000);
        assert_eq!(ledger.claim_count(), 0);
    }

    #[test]
    fn claim_class_is_reserve_class() {
        assert!(!ClaimClass::Product.is_reserve_class());
        assert!(ClaimClass::Rebuild.is_reserve_class());
        assert!(ClaimClass::AntiEntropy.is_reserve_class());
        assert!(ClaimClass::Failover.is_reserve_class());
    }

    #[test]
    fn claim_class_roundtrip() {
        for v in 0_u8..4 {
            let parsed = ClaimClass::try_from(v).unwrap();
            assert_eq!(parsed.as_u8(), v);
        }
        assert!(ClaimClass::try_from(4).is_err());
    }

    #[test]
    fn claim_ledger_report() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Failover,
            8192,
        );
        ledger.register_claim(entry, 1_000_000).unwrap();

        let report = ledger.report();
        assert_eq!(report.claim_count, 1);
        assert_eq!(report.total_claimed_bytes, 8192);
        assert!(report.bytes_by_class.contains_key("failover"));
    }

    #[test]
    fn commit_claim_tracks_committed_bytes() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            4096,
        );
        let claim_id = entry.claim_id;
        ledger.register_claim(entry, 1_000_000).unwrap();
        assert_eq!(ledger.total_committed_bytes, 0);

        ledger.commit_claim(claim_id, 4096).unwrap();
        assert_eq!(ledger.total_committed_bytes, 4096);
    }

    #[test]
    fn claim_class_admission_priority_order() {
        assert!(
            ClaimClass::Product.admission_priority() < ClaimClass::Rebuild.admission_priority()
        );
        assert!(
            ClaimClass::Rebuild.admission_priority() < ClaimClass::Failover.admission_priority()
        );
    }

    // --- Error paths ---

    #[test]
    fn zero_byte_claim_rejected() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            0,
        );
        let result = ledger.register_claim(entry, 1_000_000);
        assert!(matches!(result, Err(ClaimLedgerError::ZeroByteClaim)));
    }

    #[test]
    fn commit_nonexistent_claim_errors() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let result = ledger.commit_claim(ClaimId::new(), 4096);
        assert!(matches!(result, Err(ClaimLedgerError::ClaimNotFound(_))));
    }

    #[test]
    fn invalid_claim_class_rejected() {
        assert!(ClaimClass::try_from(4).is_err());
        assert!(ClaimClass::try_from(255).is_err());
        // Verify error variant
        let err = ClaimClass::try_from(5).unwrap_err();
        assert!(matches!(err, ClaimLedgerError::InvalidClaimClass(5)));
    }

    #[test]
    fn claim_not_found_error_display() {
        let err = ClaimLedgerError::ClaimNotFound(ClaimId::new());
        let msg = err.to_string();
        assert!(msg.contains("not found"));
    }

    #[test]
    fn zero_byte_claim_error_display() {
        let err = ClaimLedgerError::ZeroByteClaim;
        assert_eq!(err.to_string(), "zero-byte claim rejected");
    }

    // --- Display impls ---

    #[test]
    fn claim_class_display() {
        assert_eq!(ClaimClass::Product.to_string(), "product");
        assert_eq!(ClaimClass::Rebuild.to_string(), "rebuild");
        assert_eq!(ClaimClass::AntiEntropy.to_string(), "anti_entropy");
        assert_eq!(ClaimClass::Failover.to_string(), "failover");
    }

    #[test]
    fn claim_class_as_str() {
        assert_eq!(ClaimClass::Product.as_str(), "product");
        assert_eq!(ClaimClass::Rebuild.as_str(), "rebuild");
        assert_eq!(ClaimClass::AntiEntropy.as_str(), "anti_entropy");
        assert_eq!(ClaimClass::Failover.as_str(), "failover");
    }

    #[test]
    fn claimant_ref_display() {
        let process = ClaimantRef::Process {
            pid: 1234,
            name: "worker".into(),
        };
        assert_eq!(process.to_string(), "process:1234(worker)");

        let cohort = ClaimantRef::Cohort {
            cohort_id: 7,
            label: "batch".into(),
        };
        assert_eq!(cohort.to_string(), "cohort:7(batch)");

        let service = ClaimantRef::Service {
            service_name: "rebuild-planner".into(),
        };
        assert_eq!(service.to_string(), "service:rebuild-planner");
    }

    #[test]
    fn claim_ledger_display() {
        let mut ledger = ClaimLedger::new(42, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            4096,
        );
        ledger.register_claim(entry, 1_000_000).unwrap();
        let output = ledger.to_string();
        assert!(output.contains("ledger_id: 42"));
        assert!(output.contains("total_claimed_bytes: 4096"));
        assert!(output.contains("claim_count: 1"));
    }

    // --- Multi-class operations ---

    #[test]
    fn multi_class_count_by_class() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        for class in [
            ClaimClass::Product,
            ClaimClass::Rebuild,
            ClaimClass::Product,
        ] {
            let entry = ClaimEntryRecord::new(
                ClaimId::new(),
                ClaimantRef::Service {
                    service_name: "test".into(),
                },
                class,
                100,
            );
            ledger.register_claim(entry, 1_000_000).unwrap();
        }
        let counts = ledger.count_by_class();
        assert_eq!(counts.get(&ClaimClass::Product), Some(&2));
        assert_eq!(counts.get(&ClaimClass::Rebuild), Some(&1));
        assert!(!counts.contains_key(&ClaimClass::AntiEntropy));
        assert!(!counts.contains_key(&ClaimClass::Failover));
    }

    #[test]
    fn multi_class_bytes_by_class() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry1 = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            500,
        );
        ledger.register_claim(entry1, 1_000_000).unwrap();
        let entry2 = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Failover,
            1500,
        );
        ledger.register_claim(entry2, 1_000_000).unwrap();

        let bytes = ledger.bytes_by_class();
        assert_eq!(bytes.get(&ClaimClass::Product), Some(&500));
        assert_eq!(bytes.get(&ClaimClass::Failover), Some(&1500));
    }

    // --- Release edge cases ---

    #[test]
    fn release_nonexistent_claim_returns_zero() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            4096,
        );
        let real_id = entry.claim_id;
        ledger.register_claim(entry, 1_000_000).unwrap();

        let freed = ledger.release_claim(ClaimId::new());
        assert_eq!(freed, 0);
        assert_eq!(ledger.claim_count(), 1);

        // Real claim still releasable
        let freed = ledger.release_claim(real_id);
        assert_eq!(freed, 4096);
    }

    #[test]
    fn release_claims_for_inode_no_matches() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            1000,
        );
        ledger.register_claim(entry, 1_000_000).unwrap();

        let freed = ledger.release_claims_for_inode(InodeId::new(99));
        assert_eq!(freed, 0);
        assert_eq!(ledger.claim_count(), 1);
    }

    // --- Commit edge cases ---

    #[test]
    fn partial_commit() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            4096,
        );
        let claim_id = entry.claim_id;
        ledger.register_claim(entry, 1_000_000).unwrap();

        // Commit only part of the claimed bytes
        ledger.commit_claim(claim_id, 2048).unwrap();
        assert_eq!(ledger.total_committed_bytes, 2048);

        // Commit the rest
        ledger.commit_claim(claim_id, 2048).unwrap();
        assert_eq!(ledger.total_committed_bytes, 4096);
    }

    #[test]
    fn commit_zero_bytes_is_noop() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            4096,
        );
        let claim_id = entry.claim_id;
        ledger.register_claim(entry, 1_000_000).unwrap();

        ledger.commit_claim(claim_id, 0).unwrap();
        assert_eq!(ledger.total_committed_bytes, 0);
    }

    // --- ClaimEntryRecord defaults ---

    #[test]
    fn claim_entry_record_new_defaults() {
        let claim_id = ClaimId::new();
        let entry = ClaimEntryRecord::new(
            claim_id,
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            4096,
        );
        assert_eq!(entry.claim_id, claim_id);
        assert_eq!(entry.claimed_bytes, 4096);
        assert_eq!(entry.committed_bytes, 0);
        assert_eq!(entry.inode_id, None);
        assert_eq!(entry.freshness_fence_ref, None);
        assert_eq!(entry.expiration_deadline, None);
        assert_eq!(entry.claim_class, ClaimClass::Product);
    }

    #[test]
    fn claim_entry_record_commit_bytes() {
        let mut entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            4096,
        );
        entry.commit_bytes(1024);
        assert_eq!(entry.committed_bytes, 1024);
        entry.commit_bytes(512);
        assert_eq!(entry.committed_bytes, 1536);
    }

    // --- LeaseDeadlineRecord ---

    #[test]
    fn lease_deadline_record_construction() {
        let lease = LeaseDeadlineRecord {
            deadline_millis: 1715300000000,
            auto_reclaim: true,
        };
        assert_eq!(lease.deadline_millis, 1715300000000);
        assert!(lease.auto_reclaim);
    }

    #[test]
    fn lease_deadline_record_auto_reclaim_false() {
        let lease = LeaseDeadlineRecord {
            deadline_millis: 0,
            auto_reclaim: false,
        };
        assert!(!lease.auto_reclaim);
    }

    // --- Iter and claim_count ---

    #[test]
    fn claim_ledger_iter_yields_all_entries() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let e1 = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "a".into(),
            },
            ClaimClass::Product,
            100,
        );
        let e2 = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "b".into(),
            },
            ClaimClass::Rebuild,
            200,
        );
        ledger.register_claim(e1, 1_000_000).unwrap();
        ledger.register_claim(e2, 1_000_000).unwrap();

        let entries: Vec<&ClaimEntryRecord> = ledger.iter().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(ledger.claim_count(), 2);
    }

    // --- Saturating arithmetic ---

    #[test]
    fn saturating_total_claimed_bytes() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            u64::MAX,
        );
        // Registering a u64::MAX claim with enough available budget
        let result = ledger.register_claim(entry, u64::MAX);
        assert!(result.is_ok());
        assert_eq!(ledger.total_claimed_bytes, u64::MAX);

        // Releasing it should saturate down to 0
        let freed = ledger.release_claim(result.unwrap());
        assert_eq!(freed, u64::MAX);
        assert_eq!(ledger.total_claimed_bytes, 0);
    }

    #[test]
    fn claim_class_count_constant() {
        assert_eq!(ClaimClass::COUNT, 4);
    }

    // ── Additional edge cases ────────────────────────────────────────

    #[test]
    fn error_budget_exhausted_exact_formatting() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            2000,
        );
        let err = ledger.register_claim(entry, 1500).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("budget exhausted"));
        assert!(msg.contains("test_domain"));
        assert!(msg.contains("2000"));
        assert!(msg.contains("1500"));
    }

    #[test]
    fn commit_saturating_at_u64_max() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            1,
        );
        let claim_id = entry.claim_id;
        ledger.register_claim(entry, 1_000_000).unwrap();
        // Saturate internally: committed_bytes uses saturating_add
        ledger.total_committed_bytes = u64::MAX;
        ledger.commit_claim(claim_id, 1).unwrap();
        assert_eq!(ledger.total_committed_bytes, u64::MAX);
    }

    #[test]
    fn release_saturating_subtract() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            500,
        );
        let claim_id = entry.claim_id;
        ledger.register_claim(entry, 1_000_000).unwrap();
        // Artificially set total below what will be released (saturating_sub guards)
        ledger.total_claimed_bytes = 100;
        let freed = ledger.release_claim(claim_id);
        assert_eq!(freed, 500);
        assert_eq!(ledger.total_claimed_bytes, 0); // saturates at 0
    }

    #[test]
    fn iter_empty_ledger_yields_nothing() {
        let ledger = ClaimLedger::new(1, test_domain());
        let entries: Vec<&ClaimEntryRecord> = ledger.iter().collect();
        assert!(entries.is_empty());
    }
}

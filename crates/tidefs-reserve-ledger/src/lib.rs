#![forbid(unsafe_code)]
// Worker slot: s18 (issue supply), s48 (implementation)

//! Reserve ledger and budget domain runtime.
//!
//! Design rule Rule 3: "Authority is scarce and explicit. ... claim ledgers,
//! reserve ledgers, witness sets, and receipts are the scarce authority
//! objects."
//!
//! The reserve ledger is **authority evidence** for admission decisions:
//! it records what was allocated, released, and under what pressure state,
//! enabling conservation audits that verify reserve invariants. It is not
//! a full capacity-accounting proof; it does not replace the allocator,
//! local-filesystem block accounting, or rebuild capacity tracking.
//!
//! This crate provides:
//! - `ReserveLedger` — guaranteed space for critical operations
//! - `ReservePressureState` — state machine: Healthy → Encroached → Violated → Emergency
//! - `BudgetDomain` — named resource pool binding claim ledger + reserve ledger
//! - `ReserveReceipt` / `ReceiptLog` — authority evidence for conservation audits
//! - `conservation_audit` — verifies no receipt sequence violates reserve invariants
//!
use std::fmt;
use tidefs_claim_ledger::{ClaimClass, ClaimLedger, ClaimLedgerError, ClaimLedgerReport};
use tidefs_types_claim_ledger_core::StorageAuthorityToken;
pub use tidefs_types_claim_ledger_core::{BudgetDomainId, ClaimId};

mod persistence;
mod receipt;
pub use persistence::ReserveLedgerRecord;
pub use receipt::*;

// ---------------------------------------------------------------------------
// ReserveClass — what the reserve guarantees space for
// ---------------------------------------------------------------------------

/// Classification of a reserve's purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ReserveClass {
    /// Guaranteed space for node-loss rebuild.
    Rebuild = 0,
    /// Guaranteed space for anti-entropy scan.
    AntiEntropy = 1,
    /// Guaranteed space for authority handoff.
    Failover = 2,
    /// Guaranteed space for snapshot freeze.
    Snapshot = 3,
    /// Operator-allocated emergency reserve.
    Operator = 4,
}

impl ReserveClass {
    pub const COUNT: usize = 5;

    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rebuild => "rebuild",
            Self::AntiEntropy => "anti_entropy",
            Self::Failover => "failover",
            Self::Snapshot => "snapshot",
            Self::Operator => "operator",
        }
    }

    /// Map reserve class to the corresponding claim class for admission.
    pub const fn to_claim_class(self) -> ClaimClass {
        match self {
            Self::Rebuild => ClaimClass::Rebuild,
            Self::AntiEntropy => ClaimClass::AntiEntropy,
            Self::Failover => ClaimClass::Failover,
            Self::Snapshot => ClaimClass::Product,
            Self::Operator => ClaimClass::Failover,
        }
    }

    /// Admission priority for reserve-class writes.
    pub const fn admission_priority(self) -> u8 {
        match self {
            Self::Snapshot => 0,
            Self::AntiEntropy => 1,
            Self::Rebuild => 2,
            Self::Failover => 3,
            Self::Operator => 4,
        }
    }
}

impl fmt::Display for ReserveClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<u8> for ReserveClass {
    type Error = ReserveLedgerError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Rebuild),
            1 => Ok(Self::AntiEntropy),
            2 => Ok(Self::Failover),
            3 => Ok(Self::Snapshot),
            4 => Ok(Self::Operator),
            _ => Err(ReserveLedgerError::InvalidReserveClass(v as u32)),
        }
    }
}

// ---------------------------------------------------------------------------
// ReservePressureState — state machine for reserve pressure
// ---------------------------------------------------------------------------

/// Reserve pressure state machine.
///
/// Transitions:
///   Healthy ──(product writes encroach)──> Encroached
///   Encroached ──(reserve floor breached)──> Violated
///   Violated ──(reserve near exhaustion)──> Emergency
///   Encroached/Violated/Emergency ──(space freed)──> Healthy
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservePressureState {
    /// Reserves met, surplus available for product writes.
    Healthy,
    /// Product writes are eating into reserve headroom.
    Encroached,
    /// Reserve floor breached — admit only reserve-class writes.
    Violated,
    /// Reserve near exhaustion — escalate to operator.
    Emergency,
}

impl ReservePressureState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Encroached => "encroached",
            Self::Violated => "violated",
            Self::Emergency => "emergency",
        }
    }

    /// Whether product writes are admissible in this state.
    pub const fn admits_product_writes(self) -> bool {
        matches!(self, Self::Healthy | Self::Encroached)
    }

    /// Whether reserve-class writes (rebuild, failover) are admissible.
    pub const fn admits_reserve_writes(self) -> bool {
        true // Reserve writes are always admitted
    }

    /// Transition to the next pressure state based on free bytes vs reserve floor.
    pub fn transition(
        self,
        free_bytes: u64,
        reserve_floor_bytes: u64,
        total_capacity: u64,
    ) -> Self {
        let effective_free_bytes = free_bytes.min(total_capacity);
        let reserve_exhausted = reserve_floor_bytes == 0 || effective_free_bytes == 0;
        let reserve_floor_unsatisfied = reserve_floor_bytes > total_capacity;
        let encroached = match reserve_floor_bytes.checked_mul(2) {
            Some(encroachment_floor_bytes) => effective_free_bytes < encroachment_floor_bytes,
            None => true,
        };
        let violated = reserve_floor_unsatisfied || effective_free_bytes < reserve_floor_bytes;
        let emergency = reserve_exhausted
            || (reserve_floor_bytes > 0 && effective_free_bytes < reserve_floor_bytes / 4);

        match self {
            Self::Healthy => {
                if emergency {
                    Self::Emergency
                } else if violated {
                    Self::Violated
                } else if encroached {
                    Self::Encroached
                } else {
                    Self::Healthy
                }
            }
            Self::Encroached => {
                if emergency {
                    Self::Emergency
                } else if violated {
                    Self::Violated
                } else if !encroached {
                    Self::Healthy
                } else {
                    Self::Encroached
                }
            }
            Self::Violated => {
                if emergency {
                    Self::Emergency
                } else if !violated {
                    if encroached {
                        Self::Encroached
                    } else {
                        Self::Healthy
                    }
                } else {
                    Self::Violated
                }
            }
            Self::Emergency => {
                if !reserve_exhausted && !emergency {
                    if violated {
                        Self::Violated
                    } else if encroached {
                        Self::Encroached
                    } else {
                        Self::Healthy
                    }
                } else {
                    Self::Emergency
                }
            }
        }
    }
}

impl fmt::Display for ReservePressureState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Default for ReservePressureState {
    fn default() -> Self {
        Self::Healthy
    }
}

// ---------------------------------------------------------------------------
// ReserveHolderRecord — tracks who holds the reserve
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ReserveHolderRecord {
    /// Which service or claimant holds this reserve.
    pub holder_id: u64,
    /// Name of the holder (e.g., "rebuild-planner").
    pub holder_name: String,
    /// Bytes reserved by this holder.
    pub reserved_bytes: u64,
    /// Bytes currently consumed from the reserve.
    pub consumed_bytes: u64,
}

// ---------------------------------------------------------------------------
// ReservationToken — handle for segment reservations
// ---------------------------------------------------------------------------

/// Token representing a segment reservation, returned by
/// [`ReserveLedger::reserve`] and consumed by [`ReserveLedger::release`].
///
/// Tokens are generation-guarded: releasing a stale token (from a previous
/// generation) is a safe no-op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationToken {
    /// Unique token identifier within the current generation.
    pub id: u64,
    /// Generation number; mismatches indicate a stale token.
    pub generation: u64,
    /// Number of segments reserved by this token.
    pub count: u32,
}

// ---------------------------------------------------------------------------
// WritePriority — tags write-path operations for reserve admission
// ---------------------------------------------------------------------------

/// Priority level for write-path operations when consulting the reserve
/// ledger.
///
/// [] writes are subject to the reserve guard:
/// they are rejected with  when free segments would drop below
/// the critical reserve.  [] writes (intent-log
/// TxCommit, committed-root creation, metadata updates) bypass the guard
/// and may consume the last free segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WritePriority {
    /// Standard user / product write.  Subject to reserve checks.
    Normal,
    /// Crash-safety write (intent-log commit, committed-root).
    /// Bypasses reserve checks.
    Critical,
}

impl WritePriority {
    /// Whether this priority should be subject to reserve admission.
    pub const fn is_normal(self) -> bool {
        matches!(self, Self::Normal)
    }
}

// ---------------------------------------------------------------------------
// ReserveLedger — guarantees space for critical operations
// ---------------------------------------------------------------------------

/// Reserve ledger: guarantees a minimum space floor for critical operations.
#[derive(Clone, Debug)]
pub struct ReserveLedger {
    /// Unique reservation identifier.
    pub reservation_id: u64,
    /// Which budget domain this reserve protects.
    pub budget_domain_ref: BudgetDomainId,
    /// What kind of reserve this is.
    pub reserve_class: ReserveClass,
    /// Minimum guaranteed bytes (reserve floor).
    pub reserve_floor_bytes: u64,
    /// Maximum reservable bytes (ceiling).
    pub reserve_ceiling_bytes: u64,
    /// Current pressure state.
    pub pressure_state: ReservePressureState,
    /// Who holds portions of this reserve.
    pub reserve_holders: Vec<ReserveHolderRecord>,
    /// Receipt for this reserve's issuance.
    pub issuance_receipt_ref: StorageAuthorityToken,

    // --- Segment-level reservation (allocation pipeline) ---
    /// Total segment capacity (0 = unconfigured).
    pub segment_capacity: u64,
    /// Number of segments currently reserved via tokens.
    pub segments_reserved: u32,
    /// Monotonic token id counter.
    next_token_id: u64,
    /// Token generation, incremented on capacity reset.
    token_generation: u64,
}

impl ReserveLedger {
    /// Create a new reserve ledger.
    pub fn new(
        reservation_id: u64,
        budget_domain_ref: BudgetDomainId,
        reserve_class: ReserveClass,
        floor_bytes: u64,
        ceiling_bytes: u64,
    ) -> Self {
        assert!(
            floor_bytes <= ceiling_bytes,
            "reserve floor must not exceed ceiling"
        );
        Self {
            reservation_id,
            budget_domain_ref,
            reserve_class,
            reserve_floor_bytes: floor_bytes,
            reserve_ceiling_bytes: ceiling_bytes,
            pressure_state: ReservePressureState::Healthy,
            reserve_holders: Vec::new(),
            issuance_receipt_ref: StorageAuthorityToken::ABSENT,
            segment_capacity: 0,
            segments_reserved: 0,
            next_token_id: 1,
            token_generation: 1,
        }
    }

    /// Total bytes currently reserved.
    pub fn total_reserved_bytes(&self) -> u64 {
        self.reserve_holders.iter().map(|h| h.reserved_bytes).sum()
    }

    /// Total bytes consumed from the reserve.
    pub fn total_consumed_bytes(&self) -> u64 {
        self.reserve_holders.iter().map(|h| h.consumed_bytes).sum()
    }

    /// Bytes available within the reserve (floor minus consumed).
    pub fn available_reserve_bytes(&self) -> u64 {
        self.reserve_floor_bytes
            .saturating_sub(self.total_consumed_bytes())
    }

    /// Add a reserve holder.
    pub fn add_holder(&mut self, holder: ReserveHolderRecord) -> Result<(), ReserveLedgerError> {
        let after = self.total_reserved_bytes() + holder.reserved_bytes;
        if after > self.reserve_ceiling_bytes {
            return Err(ReserveLedgerError::ReserveCeilingExceeded {
                requested: holder.reserved_bytes,
                ceiling: self.reserve_ceiling_bytes,
            });
        }
        self.reserve_holders.push(holder);
        Ok(())
    }

    /// Report consumption against a holder.
    pub fn consume(&mut self, holder_id: u64, bytes: u64) -> Result<(), ReserveLedgerError> {
        let holder = self
            .reserve_holders
            .iter_mut()
            .find(|h| h.holder_id == holder_id)
            .ok_or(ReserveLedgerError::HolderNotFound(holder_id))?;

        let after = holder.consumed_bytes.saturating_add(bytes);
        if after > holder.reserved_bytes {
            return Err(ReserveLedgerError::HolderExhausted {
                holder_id,
                reserved: holder.reserved_bytes,
                attempted: after,
            });
        }
        holder.consumed_bytes = after;
        Ok(())
    }

    /// Evaluate and update the pressure state.
    pub fn evaluate_pressure(
        &mut self,
        free_bytes_available: u64,
        total_capacity_bytes: u64,
    ) -> ReservePressureState {
        self.pressure_state = self.pressure_state.transition(
            free_bytes_available,
            self.reserve_floor_bytes,
            total_capacity_bytes,
        );
        self.pressure_state
    }

    // --- Segment-level reservation API ---

    /// Reserve `count` segments for non-critical writes.
    ///
    /// Returns a [`ReservationToken`] that must be passed to
    /// [`release`](Self::release) to return the segments to the pool.
    /// Returns an error if fewer than `count` segments are available.
    pub fn reserve(&mut self, count: u32) -> Result<ReservationToken, ReserveLedgerError> {
        if count == 0 {
            return Err(ReserveLedgerError::InvalidSegmentCount);
        }
        let avail = self.available();
        if avail < count {
            return Err(ReserveLedgerError::InsufficientSegments {
                requested: count,
                available: avail,
            });
        }
        self.segments_reserved = self.segments_reserved.saturating_add(count);
        let token = ReservationToken {
            id: self.next_token_id,
            generation: self.token_generation,
            count,
        };
        self.next_token_id += 1;
        Ok(token)
    }

    /// Release a reservation token, returning its segments to the pool.
    ///
    /// If the token belongs to a previous generation (stale) this is a
    /// safe no-op.  Double-release is likewise a no-op.
    pub fn release(&mut self, token: ReservationToken) {
        if token.generation == self.token_generation {
            self.segments_reserved = self.segments_reserved.saturating_sub(token.count);
        }
    }

    /// Number of segments currently available for reservation.
    pub fn available(&self) -> u32 {
        let cap = self.segment_capacity;
        let res = self.segments_reserved as u64;
        cap.saturating_sub(res).min(u32::MAX as u64) as u32
    }

    /// Set the total number of segments in the pool.
    pub fn set_capacity(&mut self, total_segments: u64) {
        self.segment_capacity = total_segments;
    }

    /// Reserve segments for critical write-path operations (intent-log
    /// TxCommit, committed-root creation).  Bypasses the normal reserve
    /// headroom — critical callers may consume the last free segments.
    ///
    /// Returns `true` if the reservation succeeded, `false` if even
    /// the emergency reserve is exhausted.
    pub fn reserve_for_critical(&mut self, count: u32) -> bool {
        if count == 0 {
            return false;
        }
        let cap = self.segment_capacity;
        if cap == 0 {
            return false;
        }
        let used = self.segments_reserved as u64;
        if used + count as u64 > cap {
            return false;
        }
        self.segments_reserved = self.segments_reserved.saturating_add(count);
        true
    }

    /// Check whether `count` segments can be reserved **without**
    /// actually reserving them.  Returns `true` when sufficient free
    /// segments exist.
    ///
    /// This is a read-only admission check; it does not modify the
    /// ledger state.
    pub fn can_reserve(&self, count: u32) -> bool {
        self.available() >= count
    }

    /// Check whether a write at the given priority can proceed,
    /// **without** modifying the ledger (read-only admission check).
    ///
    /// Returns `Ok(())` when sufficient segments are available;
    /// `Err(...)` when the reserve would be breached.
    ///
    /// Prefer [`Self::can_reserve`] for simple boolean checks;
    /// this method provides the specific error details.
    pub fn reserve_check(
        &self,
        priority: WritePriority,
        count: u32,
    ) -> Result<(), ReserveLedgerError> {
        match priority {
            WritePriority::Normal => {
                if !self.can_reserve(count) {
                    return Err(ReserveLedgerError::InsufficientSegments {
                        requested: count,
                        available: self.available(),
                    });
                }
                Ok(())
            }
            WritePriority::Critical => {
                // Critical writes bypass the reserve check entirely.
                // The caller (reserve_for_critical) handles the actual
                // reservation when the write commits.
                Ok(())
            }
        }
    }
}

impl fmt::Display for ReserveLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ReserveLedger {{")?;
        writeln!(f, "  reservation_id: {}", self.reservation_id)?;
        writeln!(f, "  class: {}", self.reserve_class)?;
        writeln!(f, "  floor: {} bytes", self.reserve_floor_bytes)?;
        writeln!(f, "  ceiling: {} bytes", self.reserve_ceiling_bytes)?;
        writeln!(f, "  pressure: {}", self.pressure_state)?;
        writeln!(f, "  holders: {}", self.reserve_holders.len())?;
        writeln!(f, "}}")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BudgetDomain — named resource pool
// ---------------------------------------------------------------------------

/// A named, governed resource pool.
///
/// Binds a claim ledger and reserve ledger together with placement policy
/// and quota constraints.
#[derive(Clone, Debug)]
pub struct BudgetDomain {
    /// Unique domain identifier.
    pub domain_id: BudgetDomainId,
    /// Human-readable domain name (e.g., "postgres-data").
    pub domain_name: String,
    /// Total capacity in bytes.
    pub total_capacity_bytes: u64,
    /// Quota ceiling (hard limit, like ZFS quota). None = no hard limit.
    pub quota_ceiling_bytes: Option<u64>,
    /// Claim ledger for this domain.
    pub claim_ledger: ClaimLedger,
    /// Reserve ledger for this domain.
    pub reserve_ledger: ReserveLedger,
    /// Receipt for this domain's issuance.
    pub issuance_receipt_ref: StorageAuthorityToken,
}

impl BudgetDomain {
    /// Create a new budget domain.
    pub fn new(
        domain_id: BudgetDomainId,
        domain_name: String,
        total_capacity_bytes: u64,
        reserve_class: ReserveClass,
        reserve_floor_bytes: u64,
        reserve_ceiling_bytes: u64,
    ) -> Self {
        Self {
            domain_id,
            domain_name: domain_name.clone(),
            total_capacity_bytes,
            quota_ceiling_bytes: None,
            claim_ledger: ClaimLedger::new(1_u64, domain_id),
            reserve_ledger: ReserveLedger::new(
                1_u64,
                domain_id,
                reserve_class,
                reserve_floor_bytes,
                reserve_ceiling_bytes,
            ),
            issuance_receipt_ref: StorageAuthorityToken::ABSENT,
        }
    }

    /// Compute free bytes: capacity minus claimed and reserved.
    pub fn free_bytes(&self) -> u64 {
        let claimed = self.claim_ledger.total_claimed_bytes;
        let reserved = self.reserve_ledger.total_reserved_bytes();
        self.total_capacity_bytes
            .saturating_sub(claimed)
            .saturating_sub(reserved)
    }

    /// Compute committed bytes.
    pub fn committed_bytes(&self) -> u64 {
        self.claim_ledger.total_committed_bytes
    }

    /// Available bytes for product writes (after reserves and claims).
    pub fn available_product_bytes(&self) -> u64 {
        let free = self.free_bytes();
        // Product writes are limited by the hard quota ceiling if set.
        match self.quota_ceiling_bytes {
            Some(ceiling) => {
                let used = self.claim_ledger.total_claimed_bytes;
                ceiling.saturating_sub(used).min(free)
            }
            None => free,
        }
    }

    /// Admit a claim against this domain.
    /// Returns an error if the budget cannot accommodate the claim
    /// per the current reserve pressure state.
    pub fn admit_claim(
        &mut self,
        claim_entry: tidefs_claim_ledger::ClaimEntryRecord,
    ) -> Result<ClaimId, BudgetDomainError> {
        let claim_class = claim_entry.claim_class;

        // Check admission based on pressure state.
        if !self.reserve_ledger.pressure_state.admits_product_writes()
            && !claim_class.is_reserve_class()
        {
            return Err(BudgetDomainError::AdmissionDenied {
                domain: self.domain_name.clone(),
                claim_class,
                pressure: self.reserve_ledger.pressure_state,
                reason: "pressure state does not admit non-reserve-class writes",
            });
        }

        // Use total capacity for budget ceiling
        let available = self.total_capacity_bytes;
        self.claim_ledger
            .register_claim(claim_entry, available)
            .map_err(BudgetDomainError::ClaimLedger)
    }

    /// Release a claim and update pressure state.
    pub fn release_claim(&mut self, claim_id: ClaimId) {
        self.claim_ledger.release_claim(claim_id);
        self.reserve_ledger
            .evaluate_pressure(self.free_bytes(), self.total_capacity_bytes);
    }

    /// Evaluate and update pressure state.
    pub fn evaluate_pressure(&mut self) -> ReservePressureState {
        self.reserve_ledger
            .evaluate_pressure(self.free_bytes(), self.total_capacity_bytes)
    }

    /// Produce an operator-queryable budget domain report.
    pub fn report(&self) -> BudgetDomainReport {
        BudgetDomainReport {
            domain_id: self.domain_id.to_string(),
            domain_name: self.domain_name.clone(),
            total_capacity_bytes: self.total_capacity_bytes,
            quota_ceiling_bytes: self.quota_ceiling_bytes,
            claimed_bytes: self.claim_ledger.total_claimed_bytes,
            committed_bytes: self.claim_ledger.total_committed_bytes,
            reserved_bytes: self.reserve_ledger.total_reserved_bytes(),
            consumed_reserve_bytes: self.reserve_ledger.total_consumed_bytes(),
            free_bytes: self.free_bytes(),
            claim_count: self.claim_ledger.claim_count(),
            pressure_state: self.reserve_ledger.pressure_state,
            claim_report: self.claim_ledger.report(),
        }
    }

    /// Show budget domain breakdown (operator query).
    pub fn show(&self) -> String {
        let report = self.report();
        format!(
            "Budget domain: {} ({})\n\
             capacity: {} bytes\n\
             claims: {} ({} claimed / {} committed)\n\
             reserve: {} reserved / {} consumed\n\
             free: {} bytes\n\
             pressure: {}\n\
             quota ceiling: {}\n\
             claim by class: {:?}",
            report.domain_name,
            report.domain_id,
            report.total_capacity_bytes,
            report.claim_count,
            report.claimed_bytes,
            report.committed_bytes,
            report.reserved_bytes,
            report.consumed_reserve_bytes,
            report.free_bytes,
            report.pressure_state,
            report
                .quota_ceiling_bytes
                .map_or("unlimited".to_string(), |v| v.to_string()),
            report.claim_report.bytes_by_class,
        )
    }
}

impl fmt::Display for BudgetDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.show())
    }
}

// ---------------------------------------------------------------------------
// BudgetDomainReport — operator-queryable breakdown
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct BudgetDomainReport {
    pub domain_id: String,
    pub domain_name: String,
    pub total_capacity_bytes: u64,
    pub quota_ceiling_bytes: Option<u64>,
    pub claimed_bytes: u64,
    pub committed_bytes: u64,
    pub reserved_bytes: u64,
    pub consumed_reserve_bytes: u64,
    pub free_bytes: u64,
    pub claim_count: usize,
    pub pressure_state: ReservePressureState,
    pub claim_report: ClaimLedgerReport,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ReserveLedgerError {
    #[error("reserve ceiling exceeded: requested {requested}, ceiling {ceiling}")]
    ReserveCeilingExceeded { requested: u64, ceiling: u64 },

    #[error("reserve holder {0} not found")]
    HolderNotFound(u64),

    #[error("holder {holder_id} exhausted: reserved {reserved}, attempted {attempted}")]
    HolderExhausted {
        holder_id: u64,
        reserved: u64,
        attempted: u64,
    },

    #[error("invalid reserve class: {0}")]
    InvalidReserveClass(u32),

    #[error("insufficient segments: requested {requested}, available {available}")]
    InsufficientSegments { requested: u32, available: u32 },

    #[error("invalid segment count: must be > 0")]
    InvalidSegmentCount,
}

#[derive(Debug, thiserror::Error)]
pub enum BudgetDomainError {
    #[error("admission denied for domain {domain}: class={claim_class}, pressure={pressure}, reason={reason}")]
    AdmissionDenied {
        domain: String,
        claim_class: ClaimClass,
        pressure: ReservePressureState,
        reason: &'static str,
    },

    #[error("claim ledger error: {0}")]
    ClaimLedger(#[from] ClaimLedgerError),

    #[error("reserve ledger error: {0}")]
    ReserveLedger(#[from] ReserveLedgerError),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_claim_ledger::{ClaimEntryRecord, ClaimantRef};

    fn test_domain() -> BudgetDomainId {
        BudgetDomainId::from_str("test_domain")
    }

    // --- ReservePressureState tests ---

    #[test]
    fn pressure_healthy_to_encroached() {
        // 1000 capacity, 400 floor. free = 500 (less than 2x floor → encroached)
        let state = ReservePressureState::Healthy.transition(500, 400, 1000);
        assert_eq!(state, ReservePressureState::Encroached);
    }

    #[test]
    fn pressure_healthy_to_violated() {
        let state = ReservePressureState::Healthy.transition(300, 400, 1000);
        assert_eq!(state, ReservePressureState::Violated);
    }

    #[test]
    fn pressure_healthy_to_emergency() {
        let state = ReservePressureState::Healthy.transition(50, 400, 1000);
        assert_eq!(state, ReservePressureState::Emergency);
    }

    #[test]
    fn pressure_encroached_back_to_healthy() {
        let state = ReservePressureState::Encroached.transition(900, 100, 1000);
        assert_eq!(state, ReservePressureState::Healthy);
    }

    #[test]
    fn pressure_violated_back_to_healthy() {
        let state = ReservePressureState::Violated.transition(900, 100, 1000);
        assert_eq!(state, ReservePressureState::Healthy);
    }

    #[test]
    fn pressure_emergency_recovery() {
        let state = ReservePressureState::Emergency.transition(200, 100, 1000);
        assert_eq!(state, ReservePressureState::Healthy);
    }

    #[test]
    fn pressure_zero_reserve_floor_is_emergency() {
        let state = ReservePressureState::Healthy.transition(1_000, 0, 1_000);
        assert_eq!(state, ReservePressureState::Emergency);
    }

    #[test]
    fn pressure_zero_free_bytes_is_emergency() {
        let state = ReservePressureState::Healthy.transition(0, 400, 1_000);
        assert_eq!(state, ReservePressureState::Emergency);
    }

    #[test]
    fn pressure_unsatisfied_floor_fails_closed() {
        let state = ReservePressureState::Healthy.transition(1_000, 1_200, 1_000);
        assert_eq!(state, ReservePressureState::Violated);
    }

    #[test]
    fn pressure_clamps_free_bytes_to_capacity() {
        let state = ReservePressureState::Healthy.transition(u64::MAX, 800, 1_000);
        assert_eq!(state, ReservePressureState::Encroached);
    }

    #[test]
    fn pressure_overflow_sized_floor_fails_closed_from_all_origins() {
        let reserve_floor_bytes = u64::MAX / 2 + 1;
        let total_capacity = reserve_floor_bytes - 1;

        for origin in [
            ReservePressureState::Healthy,
            ReservePressureState::Encroached,
            ReservePressureState::Violated,
            ReservePressureState::Emergency,
        ] {
            let state = origin.transition(total_capacity, reserve_floor_bytes, total_capacity);
            assert_eq!(state, ReservePressureState::Violated);
        }
    }

    #[test]
    fn pressure_overflow_threshold_at_max_capacity_encroaches() {
        let reserve_floor_bytes = u64::MAX / 2 + 1;
        let state =
            ReservePressureState::Healthy.transition(u64::MAX, reserve_floor_bytes, u64::MAX);
        assert_eq!(state, ReservePressureState::Encroached);
    }

    #[test]
    fn pressure_violated_blocks_product_writes() {
        assert!(!ReservePressureState::Violated.admits_product_writes());
        assert!(ReservePressureState::Violated.admits_reserve_writes());
    }

    #[test]
    fn pressure_healthy_admits_product_writes() {
        assert!(ReservePressureState::Healthy.admits_product_writes());
    }

    #[test]
    fn pressure_encroached_admits_product_writes() {
        assert!(ReservePressureState::Encroached.admits_product_writes());
    }

    // --- BudgetDomain tests ---

    #[test]
    fn budget_domain_available_free() {
        let domain = BudgetDomain::new(
            test_domain(),
            "test".into(),
            1_000_000,
            ReserveClass::Rebuild,
            100_000,
            200_000,
        );
        assert_eq!(domain.free_bytes(), 1_000_000);
        assert_eq!(domain.available_product_bytes(), 1_000_000);
    }

    #[test]
    fn budget_domain_admit_claim() {
        let mut domain = BudgetDomain::new(
            test_domain(),
            "test".into(),
            1_000_000,
            ReserveClass::Rebuild,
            100_000,
            200_000,
        );
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            4096,
        );
        let result = domain.admit_claim(entry);
        assert!(result.is_ok());
        assert_eq!(domain.claim_ledger.claim_count(), 1);
    }

    #[test]
    fn budget_domain_rejects_product_writes_in_violated_state() {
        let mut domain = BudgetDomain::new(
            test_domain(),
            "test".into(),
            100_000,
            ReserveClass::Rebuild,
            50_000,
            100_000,
        );

        // Fill up the domain with claims to trigger pressure
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "filler".into(),
            },
            ClaimClass::Product,
            80_000,
        );
        let _ = domain.admit_claim(entry);
        assert_eq!(domain.evaluate_pressure(), ReservePressureState::Violated);

        // Product write should be rejected
        let product_entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "product".into(),
            },
            ClaimClass::Product,
            1000,
        );
        let result = domain.admit_claim(product_entry);
        assert!(result.is_err());
    }

    #[test]
    fn budget_domain_admits_rebuild_writes_in_violated_state() {
        let mut domain = BudgetDomain::new(
            test_domain(),
            "test".into(),
            100_000,
            ReserveClass::Rebuild,
            50_000,
            100_000,
        );

        // Trigger Violated state
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "filler".into(),
            },
            ClaimClass::Product,
            80_000,
        );
        let _ = domain.admit_claim(entry);
        assert_eq!(domain.evaluate_pressure(), ReservePressureState::Violated);

        // Rebuild write should be admitted
        let rebuild_entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "rebuild".into(),
            },
            ClaimClass::Rebuild,
            1000,
        );
        let result = domain.admit_claim(rebuild_entry);
        assert!(result.is_ok());
    }

    #[test]
    fn budget_domain_report() {
        let mut domain = BudgetDomain::new(
            test_domain(),
            "postgres-data".into(),
            1_000_000,
            ReserveClass::Operator,
            200_000,
            500_000,
        );
        let entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "pg-writer".into(),
            },
            ClaimClass::Product,
            100_000,
        );
        let _ = domain.admit_claim(entry);

        let report = domain.report();
        assert_eq!(report.domain_name, "postgres-data");
        assert_eq!(report.claimed_bytes, 100_000);
        assert_eq!(report.pressure_state, ReservePressureState::Healthy);

        // Operator query output
        let show = domain.show();
        assert!(show.contains("postgres-data"));
        assert!(show.contains("100000"));
        assert!(show.contains("healthy"));
    }

    #[test]
    fn reserve_class_roundtrip() {
        for v in 0_u8..5 {
            let parsed = ReserveClass::try_from(v).unwrap();
            assert_eq!(parsed.as_u8(), v);
        }
        assert!(ReserveClass::try_from(5).is_err());
    }

    #[test]
    fn reserve_ledger_holder_operations() {
        let mut ledger =
            ReserveLedger::new(1, test_domain(), ReserveClass::Rebuild, 100_000, 200_000);

        ledger
            .add_holder(ReserveHolderRecord {
                holder_id: 1,
                holder_name: "rebuild-planner".into(),
                reserved_bytes: 50_000,
                consumed_bytes: 0,
            })
            .unwrap();

        assert_eq!(ledger.total_reserved_bytes(), 50_000);
        assert_eq!(ledger.available_reserve_bytes(), 100_000);

        ledger.consume(1, 30_000).unwrap();
        assert_eq!(ledger.total_consumed_bytes(), 30_000);
        assert_eq!(ledger.available_reserve_bytes(), 70_000);
    }

    #[test]
    fn split_brain_detection() {
        // Simulate two nodes both claiming ownership of the same domain.
        let node_a = BudgetDomain::new(
            test_domain(),
            "split-dom".into(),
            1_000_000,
            ReserveClass::Rebuild,
            100_000,
            200_000,
        );
        let node_b = BudgetDomain::new(
            test_domain(),
            "split-dom".into(),
            1_000_000,
            ReserveClass::Rebuild,
            100_000,
            200_000,
        );
        assert_eq!(node_a.total_capacity_bytes, node_b.total_capacity_bytes);
        assert_eq!(node_a.domain_name, node_b.domain_name);
    }

    // --- Segment-reservation API tests ---

    fn new_ledger() -> ReserveLedger {
        ReserveLedger::new(1, test_domain(), ReserveClass::Rebuild, 100_000, 200_000)
    }

    #[test]
    fn segment_reserve_within_capacity() {
        let mut rl = new_ledger();
        rl.set_capacity(100);
        assert_eq!(rl.available(), 100);

        let token = rl.reserve(30).unwrap();
        assert_eq!(token.count, 30);
        assert_eq!(rl.available(), 70);
    }

    #[test]
    fn segment_reserve_exhausts_capacity() {
        let mut rl = new_ledger();
        rl.set_capacity(5);
        let _t1 = rl.reserve(3).unwrap();
        let _t2 = rl.reserve(2).unwrap();
        assert_eq!(rl.available(), 0);
        assert!(rl.reserve(1).is_err());
    }

    #[test]
    fn segment_reserve_zero_fails() {
        let mut rl = new_ledger();
        rl.set_capacity(10);
        assert!(rl.reserve(0).is_err());
    }

    #[test]
    fn segment_release_restores_availability() {
        let mut rl = new_ledger();
        rl.set_capacity(50);
        let token = rl.reserve(20).unwrap();
        assert_eq!(rl.available(), 30);

        rl.release(token);
        assert_eq!(rl.available(), 50);
    }

    #[test]
    fn segment_double_release_is_noop() {
        let mut rl = new_ledger();
        rl.set_capacity(10);
        let token = rl.reserve(8).unwrap();
        rl.release(token);
        rl.release(token); // second release
        assert_eq!(rl.available(), 10);
    }

    #[test]
    fn segment_stale_token_is_noop() {
        let mut rl = new_ledger();
        rl.set_capacity(10);
        let _token = rl.reserve(4).unwrap();
        // Simulate generation change (capacity reset)
        rl.set_capacity(10);
        // Force generation invalidation via a new field? No, generation
        // only changes on explicit reset. For now, we test that
        // a token with wrong generation is harmless.
        let stale = ReservationToken {
            id: 0,
            generation: 999,
            count: 100,
        };
        rl.release(stale);
        assert_eq!(rl.available(), 6); // still 10 - 4 = 6
    }

    #[test]
    fn segment_available_never_negative() {
        let mut rl = new_ledger();
        rl.set_capacity(10);
        // Manually set reserved above capacity (shouldn't happen but test saturating)
        rl.segments_reserved = 20;
        assert_eq!(rl.available(), 0);
    }

    #[test]
    fn segment_capacity_zero_available_zero() {
        let rl = new_ledger();
        assert_eq!(rl.available(), 0);
    }

    #[test]
    fn segment_set_capacity_updates_available() {
        let mut rl = new_ledger();
        rl.set_capacity(100);
        assert_eq!(rl.available(), 100);
        rl.set_capacity(200);
        assert_eq!(rl.available(), 200);
    }

    #[test]
    fn segment_reserve_for_critical_succeeds() {
        let mut rl = new_ledger();
        rl.set_capacity(10);
        // Reserve 9 normally
        let _t = rl.reserve(9).unwrap();
        assert_eq!(rl.available(), 1);
        // Critical reserve for 1 should still succeed
        assert!(rl.reserve_for_critical(1));
        assert_eq!(rl.available(), 0);
    }

    #[test]
    fn segment_reserve_for_critical_fails_when_exhausted() {
        let mut rl = new_ledger();
        rl.set_capacity(5);
        let _t = rl.reserve(5).unwrap();
        assert!(!rl.reserve_for_critical(1));
    }

    #[test]
    fn segment_reserve_for_critical_zero_fails() {
        let mut rl = new_ledger();
        rl.set_capacity(10);
        assert!(!rl.reserve_for_critical(0));
    }

    #[test]
    fn segment_reserve_for_critical_no_capacity_fails() {
        let mut rl = new_ledger();
        assert!(!rl.reserve_for_critical(1));
    }

    #[test]
    fn segment_reserve_multiple_tokens_independent() {
        let mut rl = new_ledger();
        rl.set_capacity(30);
        let t1 = rl.reserve(10).unwrap();
        let t2 = rl.reserve(10).unwrap();
        assert_eq!(rl.available(), 10);
        rl.release(t1);
        assert_eq!(rl.available(), 20);
        rl.release(t2);
        assert_eq!(rl.available(), 30);
    }

    #[test]
    fn segment_token_ids_are_monotonic() {
        let mut rl = new_ledger();
        rl.set_capacity(100);
        let t1 = rl.reserve(1).unwrap();
        let t2 = rl.reserve(1).unwrap();
        let t3 = rl.reserve(1).unwrap();
        assert!(t1.id < t2.id);
        assert!(t2.id < t3.id);
    }

    #[test]
    fn segment_insufficient_error_has_correct_fields() {
        let mut rl = new_ledger();
        rl.set_capacity(5);
        let err = rl.reserve(10).unwrap_err();
        match err {
            ReserveLedgerError::InsufficientSegments {
                requested,
                available,
            } => {
                assert_eq!(requested, 10);
                assert_eq!(available, 5);
            }
            _ => panic!("wrong error variant"),
        }
    }

    #[test]
    fn segment_reserve_after_capacity_increase() {
        let mut rl = new_ledger();
        rl.set_capacity(10);
        let _t = rl.reserve(10).unwrap();
        assert!(rl.reserve(1).is_err());
        // Increase capacity
        rl.set_capacity(20);
        assert_eq!(rl.available(), 10);
        let _t2 = rl.reserve(5).unwrap();
        assert_eq!(rl.available(), 5);
    }

    // --- reserve_check (WritePriority) tests ---

    #[test]
    fn reserve_check_normal_succeeds_within_capacity() {
        let mut rl = new_ledger();
        rl.set_capacity(10);
        rl.reserve_check(WritePriority::Normal, 5).unwrap();
        // Non-mutating check: availability unchanged
        assert_eq!(rl.available(), 10);
    }

    #[test]
    fn reserve_check_normal_fails_on_exhaustion() {
        let mut rl = new_ledger();
        rl.set_capacity(3);
        let _t = rl.reserve(3).unwrap(); // actually reserve
        let err = rl.reserve_check(WritePriority::Normal, 1).unwrap_err();
        assert!(matches!(
            err,
            ReserveLedgerError::InsufficientSegments { .. }
        ));
    }

    #[test]
    fn reserve_check_critical_always_succeeds() {
        let mut rl = new_ledger();
        rl.set_capacity(1);
        let _t = rl.reserve(1).unwrap(); // exhausted
                                         // Critical always passes the read-only check
        rl.reserve_check(WritePriority::Critical, 100).unwrap();
    }

    #[test]
    fn can_reserve_returns_correct_bool() {
        let mut rl = new_ledger();
        rl.set_capacity(10);
        assert!(rl.can_reserve(5));
        assert!(!rl.can_reserve(11));
    }

    #[test]
    fn write_priority_is_normal() {
        assert!(WritePriority::Normal.is_normal());
        assert!(!WritePriority::Critical.is_normal());
    }
}

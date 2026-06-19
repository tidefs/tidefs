//! Reserve receipt conservation evidence.
//!
//! Receipts are the reserve ledger's authority evidence for admission
//! decisions. They record what was allocated, released, under what
//! pressure state, and at what validation tier. Conservation checks
//! verify that no receipt sequence violates reserve invariants:
//! underflow releases, over-admission, floor breaches without a
//! violated/emergency state, and product-write admission while violated.
//!
//! This module provides source-level evidence only. It does not gate
//! runtime admission or change allocator behavior; those decisions
//! belong to [`super::ReserveLedger`] and [`super::BudgetDomain`].

use super::{BudgetDomainId, ReserveClass, ReserveLedger, ReservePressureState};

// ---------------------------------------------------------------------------
// ValidationTier -- level of conservation enforcement
// ---------------------------------------------------------------------------

/// Validation tier for a receipt.
///
/// Authoritative receipts are suitable for hard conservation gates.
/// Informational receipts still participate in audits so malformed
/// evidence is reported instead of silently blessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationTier {
    /// Receipt is logged for informational purposes only.
    Informational = 0,
    /// Receipt is checked against hard conservation rules.
    Authoritative = 1,
}

impl ValidationTier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Authoritative => "authoritative",
        }
    }
}

impl std::fmt::Display for ValidationTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ReceiptOperation -- what the receipt records
// ---------------------------------------------------------------------------

/// Kind of receipt operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptOperation {
    /// Bytes were allocated from the reserve.
    Allocate,
    /// Bytes were released back to the reserve.
    Release,
}

impl ReceiptOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allocate => "allocate",
            Self::Release => "release",
        }
    }
}

impl std::fmt::Display for ReceiptOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ReserveReceipt -- single allocation or release record
// ---------------------------------------------------------------------------

/// A reserve receipt recording an allocation or release operation.
///
/// Each receipt captures the reserve class, budget domain, byte count,
/// operation kind, pressure state at time of recording, and validation
/// tier. Receipts form the authority evidence for reserve conservation
/// audits.
#[derive(Clone, Debug)]
pub struct ReserveReceipt {
    /// Monotonic receipt identifier.
    pub receipt_id: u64,
    /// Reserve class this receipt belongs to.
    pub reserve_class: ReserveClass,
    /// Budget domain this receipt operates within.
    pub budget_domain: BudgetDomainId,
    /// Bytes moved by this operation.
    pub bytes: u64,
    /// Whether this receipt records an allocation or release.
    pub operation: ReceiptOperation,
    /// Pressure state at time the receipt was recorded.
    pub pressure_state: ReservePressureState,
    /// Validation tier for this receipt.
    pub validation_tier: ValidationTier,
}

impl ReserveReceipt {
    /// Create a new allocation receipt.
    pub fn allocate(
        receipt_id: u64,
        reserve_class: ReserveClass,
        budget_domain: BudgetDomainId,
        bytes: u64,
        pressure_state: ReservePressureState,
        validation_tier: ValidationTier,
    ) -> Self {
        Self {
            receipt_id,
            reserve_class,
            budget_domain,
            bytes,
            operation: ReceiptOperation::Allocate,
            pressure_state,
            validation_tier,
        }
    }

    /// Create a new release receipt.
    pub fn release(
        receipt_id: u64,
        reserve_class: ReserveClass,
        budget_domain: BudgetDomainId,
        bytes: u64,
        pressure_state: ReservePressureState,
        validation_tier: ValidationTier,
    ) -> Self {
        Self {
            receipt_id,
            reserve_class,
            budget_domain,
            bytes,
            operation: ReceiptOperation::Release,
            pressure_state,
            validation_tier,
        }
    }
}

// ---------------------------------------------------------------------------
// ReceiptLog -- ordered collection of receipts with conservation audit
// ---------------------------------------------------------------------------

/// An ordered log of reserve receipts supporting conservation audits.
///
/// The log collects receipts and provides methods to audit them
/// against reserve invariants. It does not itself enforce admission
/// decisions; that remains the responsibility of the reserve ledger
/// and budget domain runtime.
#[derive(Clone, Debug, Default)]
pub struct ReceiptLog {
    receipts: Vec<ReserveReceipt>,
    next_id: u64,
}

impl ReceiptLog {
    /// Create an empty receipt log.
    pub fn new() -> Self {
        Self {
            receipts: Vec::new(),
            next_id: 1,
        }
    }

    /// Number of receipts in the log.
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// Return a slice of all receipts.
    pub fn receipts(&self) -> &[ReserveReceipt] {
        &self.receipts
    }

    /// Record an allocation and return its receipt.
    pub fn record_allocate(
        &mut self,
        reserve_class: ReserveClass,
        budget_domain: BudgetDomainId,
        bytes: u64,
        pressure_state: ReservePressureState,
        validation_tier: ValidationTier,
    ) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.receipts.push(ReserveReceipt::allocate(
            id,
            reserve_class,
            budget_domain,
            bytes,
            pressure_state,
            validation_tier,
        ));
        id
    }

    /// Record a release and return its receipt.
    pub fn record_release(
        &mut self,
        reserve_class: ReserveClass,
        budget_domain: BudgetDomainId,
        bytes: u64,
        pressure_state: ReservePressureState,
        validation_tier: ValidationTier,
    ) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.receipts.push(ReserveReceipt::release(
            id,
            reserve_class,
            budget_domain,
            bytes,
            pressure_state,
            validation_tier,
        ));
        id
    }

    /// Sum of admitted bytes (all Allocate receipts).
    pub fn total_admitted_bytes(&self) -> u64 {
        self.receipts
            .iter()
            .filter(|r| matches!(r.operation, ReceiptOperation::Allocate))
            .fold(0, |total, r| total.saturating_add(r.bytes))
    }

    /// Sum of released bytes (all Release receipts).
    pub fn total_released_bytes(&self) -> u64 {
        self.receipts
            .iter()
            .filter(|r| matches!(r.operation, ReceiptOperation::Release))
            .fold(0, |total, r| total.saturating_add(r.bytes))
    }

    /// Net admitted bytes (admitted minus released).
    pub fn net_admitted_bytes(&self) -> u64 {
        self.total_admitted_bytes()
            .saturating_sub(self.total_released_bytes())
    }

    /// Total admitted bytes for a specific (domain, class) pair.
    pub fn admitted_for(&self, budget_domain: &BudgetDomainId, reserve_class: ReserveClass) -> u64 {
        self.receipts
            .iter()
            .filter(|r| {
                matches!(r.operation, ReceiptOperation::Allocate)
                    && &r.budget_domain == budget_domain
                    && r.reserve_class == reserve_class
            })
            .fold(0, |total, r| total.saturating_add(r.bytes))
    }

    /// Total released bytes for a specific (domain, class) pair.
    pub fn released_for(&self, budget_domain: &BudgetDomainId, reserve_class: ReserveClass) -> u64 {
        self.receipts
            .iter()
            .filter(|r| {
                matches!(r.operation, ReceiptOperation::Release)
                    && &r.budget_domain == budget_domain
                    && r.reserve_class == reserve_class
            })
            .fold(0, |total, r| total.saturating_add(r.bytes))
    }

    /// Net admitted bytes for a specific (domain, class) pair.
    pub fn net_for(&self, budget_domain: &BudgetDomainId, reserve_class: ReserveClass) -> u64 {
        self.admitted_for(budget_domain, reserve_class)
            .saturating_sub(self.released_for(budget_domain, reserve_class))
    }
}

// ---------------------------------------------------------------------------
// ConservationViolation -- audit finding
// ---------------------------------------------------------------------------

/// Conservation violation discovered during receipt audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConservationViolation {
    /// Released more bytes than were allocated -- underflow.
    UnderflowRelease {
        allocated: u64,
        released: u64,
        budget_domain: String,
        reserve_class: String,
    },
    /// Admitted bytes exceed the reserve ceiling.
    OverAdmission {
        admitted: u64,
        ceiling: u64,
        budget_domain: String,
        reserve_class: String,
    },
    /// Reserve floor is breached but the pressure state recorded is
    /// neither Violated nor Emergency.
    FloorBreachWithoutViolation {
        free_bytes: u64,
        floor_bytes: u64,
        pressure_state: String,
        budget_domain: String,
    },
    /// Product-class writes were admitted while the reserve pressure
    /// state was Violated or Emergency.
    ProductWriteWhileViolated {
        budget_domain: String,
        pressure_state: String,
    },
    /// A release was recorded but no matching allocation exists
    /// (negative balance would result).
    ReleaseWithoutAllocation {
        budget_domain: String,
        reserve_class: String,
        released: u64,
        previously_admitted: u64,
    },
}

impl std::fmt::Display for ConservationViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnderflowRelease {
                allocated,
                released,
                budget_domain,
                reserve_class,
            } => write!(
                f,
                "underflow release in domain {budget_domain} class {reserve_class}: \
                 allocated {allocated}, released {released} (deficit {})",
                released.saturating_sub(*allocated)
            ),
            Self::OverAdmission {
                admitted,
                ceiling,
                budget_domain,
                reserve_class,
            } => write!(
                f,
                "over-admission in domain {budget_domain} class {reserve_class}: \
                 admitted {admitted} exceeds ceiling {ceiling}"
            ),
            Self::FloorBreachWithoutViolation {
                free_bytes,
                floor_bytes,
                pressure_state,
                budget_domain,
            } => write!(
                f,
                "floor breach without violation in domain {budget_domain}: \
                 free {free_bytes} < floor {floor_bytes}, state recorded as {pressure_state}"
            ),
            Self::ProductWriteWhileViolated {
                budget_domain,
                pressure_state,
            } => write!(
                f,
                "product write admitted while violated in domain {budget_domain}: \
                 state was {pressure_state}"
            ),
            Self::ReleaseWithoutAllocation {
                budget_domain,
                reserve_class,
                released,
                previously_admitted,
            } => write!(
                f,
                "release without matching allocation in domain {budget_domain} \
                 class {reserve_class}: released {released}, previously admitted \
                 {previously_admitted}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Conservation audit
// ---------------------------------------------------------------------------

/// Audit a receipt log against reserve conservation invariants.
///
/// Checks:
/// - Underflow releases (released > admitted per domain+class)
/// - Over-admission (peak outstanding admitted bytes > reserve ceiling)
/// - Floor breach without violated/emergency state
/// - Product-write admission while violated
///
/// Returns `Ok(())` if no violations are found, or all discovered
/// violations.
pub fn conservation_audit(
    receipts: &[ReserveReceipt],
    ledger: &ReserveLedger,
    free_bytes: u64,
) -> Result<(), Vec<ConservationViolation>> {
    let mut violations: Vec<ConservationViolation> = Vec::new();

    // Only audit receipts belonging to this ledger's budget domain
    let domain_receipts: Vec<&ReserveReceipt> = receipts
        .iter()
        .filter(|r| &r.budget_domain == &ledger.budget_domain_ref)
        .collect();

    // Collect unique (domain, class) pairs from receipts
    let mut pairs: Vec<(BudgetDomainId, ReserveClass)> = Vec::new();
    for r in &domain_receipts {
        let key = (r.budget_domain.clone(), r.reserve_class);
        if !pairs.contains(&key) {
            pairs.push(key);
        }
    }

    // Check underflow and over-admission per (domain, class) pair
    for (ref domain, class) in &pairs {
        let admitted: u64 = domain_receipts
            .iter()
            .filter(|r| {
                matches!(r.operation, ReceiptOperation::Allocate) && r.reserve_class == *class
            })
            .fold(0, |total, r| total.saturating_add(r.bytes));

        let released: u64 = domain_receipts
            .iter()
            .filter(|r| {
                matches!(r.operation, ReceiptOperation::Release) && r.reserve_class == *class
            })
            .fold(0, |total, r| total.saturating_add(r.bytes));

        // Underflow: released > admitted
        if released > admitted {
            violations.push(ConservationViolation::UnderflowRelease {
                allocated: admitted,
                released,
                budget_domain: domain.to_string(),
                reserve_class: class.as_str().to_string(),
            });
        }

        // Scan in order to catch release underflow and peak over-admission.
        let mut running_balance: u64 = 0;
        let mut over_admission_reported = false;
        for r in domain_receipts.iter().filter(|r| r.reserve_class == *class) {
            match r.operation {
                ReceiptOperation::Allocate => {
                    let next_balance = running_balance.checked_add(r.bytes);
                    running_balance = next_balance.unwrap_or(u64::MAX);
                    if !over_admission_reported
                        && (next_balance.is_none()
                            || running_balance > ledger.reserve_ceiling_bytes)
                    {
                        violations.push(ConservationViolation::OverAdmission {
                            admitted: running_balance,
                            ceiling: ledger.reserve_ceiling_bytes,
                            budget_domain: domain.to_string(),
                            reserve_class: class.as_str().to_string(),
                        });
                        over_admission_reported = true;
                    }
                }
                ReceiptOperation::Release => {
                    if r.bytes > running_balance {
                        violations.push(ConservationViolation::ReleaseWithoutAllocation {
                            budget_domain: domain.to_string(),
                            reserve_class: class.as_str().to_string(),
                            released: r.bytes,
                            previously_admitted: running_balance,
                        });
                        running_balance = 0;
                    } else {
                        running_balance = running_balance.saturating_sub(r.bytes);
                    }
                }
            }
        }
    }

    // Floor breach without violated/emergency: check each receipt's
    // pressure state against current free bytes and floor
    let floor = ledger.reserve_floor_bytes;
    if free_bytes < floor {
        // Check if any domain receipt recorded a non-violated state
        for r in &domain_receipts {
            if !matches!(
                r.pressure_state,
                ReservePressureState::Violated | ReservePressureState::Emergency
            ) {
                violations.push(ConservationViolation::FloorBreachWithoutViolation {
                    free_bytes,
                    floor_bytes: floor,
                    pressure_state: r.pressure_state.as_str().to_string(),
                    budget_domain: r.budget_domain.to_string(),
                });
                // Only report once per domain
                break;
            }
        }
    }

    // Product-write admission while violated: Snapshot reserve class
    // maps to ClaimClass::Product -- treat as product writes.
    for r in &domain_receipts {
        if matches!(r.operation, ReceiptOperation::Allocate)
            && matches!(
                r.pressure_state,
                ReservePressureState::Violated | ReservePressureState::Emergency
            )
            && r.reserve_class == ReserveClass::Snapshot
        {
            violations.push(ConservationViolation::ProductWriteWhileViolated {
                budget_domain: r.budget_domain.to_string(),
                pressure_state: r.pressure_state.as_str().to_string(),
            });
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReserveLedger;

    fn test_domain() -> BudgetDomainId {
        BudgetDomainId::from_str("test_domain")
    }

    fn test_ledger() -> ReserveLedger {
        ReserveLedger::new(1, test_domain(), ReserveClass::Rebuild, 100_000, 200_000)
    }

    fn test_ledger_snapshot() -> ReserveLedger {
        ReserveLedger::new(2, test_domain(), ReserveClass::Snapshot, 50_000, 100_000)
    }

    // --- ReceiptLog basics ---

    #[test]
    fn receipt_log_starts_empty() {
        let log = ReceiptLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert_eq!(log.total_admitted_bytes(), 0);
        assert_eq!(log.total_released_bytes(), 0);
    }

    #[test]
    fn receipt_log_records_allocate() {
        let mut log = ReceiptLog::new();
        let receipt_id = log.record_allocate(
            ReserveClass::Rebuild,
            test_domain(),
            50_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        assert_eq!(receipt_id, 1);
        let receipt = &log.receipts()[0];
        assert_eq!(receipt.bytes, 50_000);
        assert!(matches!(receipt.operation, ReceiptOperation::Allocate));
        assert_eq!(log.total_admitted_bytes(), 50_000);
        assert_eq!(log.total_released_bytes(), 0);
        assert_eq!(log.net_admitted_bytes(), 50_000);
    }

    #[test]
    fn receipt_log_records_release() {
        let mut log = ReceiptLog::new();
        log.record_allocate(
            ReserveClass::Failover,
            test_domain(),
            80_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_release(
            ReserveClass::Failover,
            test_domain(),
            30_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        assert_eq!(log.total_admitted_bytes(), 80_000);
        assert_eq!(log.total_released_bytes(), 30_000);
        assert_eq!(log.net_admitted_bytes(), 50_000);
    }

    #[test]
    fn receipt_log_totals_saturate_on_overflow() {
        let mut log = ReceiptLog::new();
        log.record_allocate(
            ReserveClass::Rebuild,
            test_domain(),
            u64::MAX,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_allocate(
            ReserveClass::Rebuild,
            test_domain(),
            1,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_release(
            ReserveClass::Rebuild,
            test_domain(),
            u64::MAX,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_release(
            ReserveClass::Rebuild,
            test_domain(),
            1,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );

        assert_eq!(log.total_admitted_bytes(), u64::MAX);
        assert_eq!(log.total_released_bytes(), u64::MAX);
        assert_eq!(log.net_admitted_bytes(), 0);
    }

    #[test]
    fn receipt_log_ids_are_monotonic() {
        let mut log = ReceiptLog::new();
        let id1 = log.record_allocate(
            ReserveClass::Rebuild,
            test_domain(),
            1,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        let id2 = log.record_allocate(
            ReserveClass::Rebuild,
            test_domain(),
            1,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        assert!(id1 < id2);
    }

    // --- Receipt domain/class filtering ---

    #[test]
    fn admitted_for_filters_correctly() {
        let mut log = ReceiptLog::new();
        let domain_a = BudgetDomainId::from_str("dom_a");
        let domain_b = BudgetDomainId::from_str("dom_b");

        log.record_allocate(
            ReserveClass::Rebuild,
            domain_a.clone(),
            10_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_allocate(
            ReserveClass::Rebuild,
            domain_b.clone(),
            20_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_allocate(
            ReserveClass::Failover,
            domain_a.clone(),
            5_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );

        assert_eq!(log.admitted_for(&domain_a, ReserveClass::Rebuild), 10_000);
        assert_eq!(log.admitted_for(&domain_b, ReserveClass::Rebuild), 20_000);
        assert_eq!(log.admitted_for(&domain_a, ReserveClass::Failover), 5_000);
    }

    #[test]
    fn released_for_filters_correctly() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();

        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            100_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_release(
            ReserveClass::Rebuild,
            domain.clone(),
            40_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );

        assert_eq!(log.released_for(&domain, ReserveClass::Rebuild), 40_000);
    }

    #[test]
    fn net_for_respects_saturation() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();

        log.record_release(
            ReserveClass::Rebuild,
            domain.clone(),
            100,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        assert_eq!(log.net_for(&domain, ReserveClass::Rebuild), 0);
    }

    // --- Conservation audit: healthy flow ---

    #[test]
    fn conservation_audit_passes_healthy_flow() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger();

        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            50_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_release(
            ReserveClass::Rebuild,
            domain.clone(),
            50_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );

        let result = conservation_audit(log.receipts(), &ledger, 500_000);
        assert!(result.is_ok(), "expected clean audit, got {:?}", result);
    }

    // --- Conservation audit: underflow release ---

    #[test]
    fn conservation_audit_rejects_underflow_release() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger();

        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            10_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_release(
            ReserveClass::Rebuild,
            domain.clone(),
            20_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );

        let result = conservation_audit(log.receipts(), &ledger, 500_000);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, ConservationViolation::UnderflowRelease { .. })),
            "expected UnderflowRelease violation, got {:?}",
            violations
        );
    }

    // --- Conservation audit: over-admission ---

    #[test]
    fn conservation_audit_rejects_over_admission() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger(); // ceiling = 200_000

        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            250_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );

        let result = conservation_audit(log.receipts(), &ledger, 500_000);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, ConservationViolation::OverAdmission { .. })),
            "expected OverAdmission violation, got {:?}",
            violations
        );
    }

    #[test]
    fn conservation_audit_allows_capacity_reuse_after_release() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger(); // ceiling = 200_000

        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            150_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_release(
            ReserveClass::Rebuild,
            domain.clone(),
            150_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            150_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );

        let result = conservation_audit(log.receipts(), &ledger, 500_000);
        assert!(result.is_ok(), "expected clean audit, got {:?}", result);
    }

    // --- Conservation audit: floor breach without violation ---

    #[test]
    fn conservation_audit_rejects_floor_breach_without_violation() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger(); // floor = 100_000

        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            50_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );

        // free_bytes (50_000) < floor (100_000) but receipts claim Healthy
        let result = conservation_audit(log.receipts(), &ledger, 50_000);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, ConservationViolation::FloorBreachWithoutViolation { .. })),
            "expected FloorBreachWithoutViolation, got {:?}",
            violations
        );
    }

    #[test]
    fn conservation_audit_allows_floor_breach_with_violated_state() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger(); // floor = 100_000

        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            50_000,
            ReservePressureState::Violated,
            ValidationTier::Authoritative,
        );

        let result = conservation_audit(log.receipts(), &ledger, 50_000);
        assert!(result.is_ok(), "expected clean audit, got {:?}", result);
    }

    #[test]
    fn conservation_audit_allows_floor_breach_with_emergency_state() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger(); // floor = 100_000

        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            50_000,
            ReservePressureState::Emergency,
            ValidationTier::Authoritative,
        );

        let result = conservation_audit(log.receipts(), &ledger, 10_000);
        assert!(result.is_ok(), "expected clean audit, got {:?}", result);
    }

    // --- Conservation audit: product write while violated ---

    #[test]
    fn conservation_audit_rejects_product_write_while_violated() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger_snapshot(); // Snapshot class

        log.record_allocate(
            ReserveClass::Snapshot,
            domain.clone(),
            10_000,
            ReservePressureState::Violated,
            ValidationTier::Authoritative,
        );

        let result = conservation_audit(log.receipts(), &ledger, 100_000);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, ConservationViolation::ProductWriteWhileViolated { .. })),
            "expected ProductWriteWhileViolated, got {:?}",
            violations
        );
    }

    #[test]
    fn conservation_audit_allows_product_write_while_healthy() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger_snapshot(); // Snapshot class

        log.record_allocate(
            ReserveClass::Snapshot,
            domain.clone(),
            10_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );

        let result = conservation_audit(log.receipts(), &ledger, 500_000);
        assert!(result.is_ok(), "expected clean audit, got {:?}", result);
    }

    // --- Conservation audit: release without allocation ---

    #[test]
    fn conservation_audit_rejects_release_without_allocation() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger();

        log.record_release(
            ReserveClass::Rebuild,
            domain.clone(),
            50_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );

        let result = conservation_audit(log.receipts(), &ledger, 500_000);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, ConservationViolation::ReleaseWithoutAllocation { .. })),
            "expected ReleaseWithoutAllocation, got {:?}",
            violations
        );
    }

    // --- Conservation audit: full pressure state lifecycle ---

    #[test]
    fn conservation_audit_passes_full_pressure_lifecycle() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger(); // floor = 100_000

        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            50_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_release(
            ReserveClass::Rebuild,
            domain.clone(),
            20_000,
            ReservePressureState::Encroached,
            ValidationTier::Authoritative,
        );
        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            10_000,
            ReservePressureState::Violated,
            ValidationTier::Authoritative,
        );
        log.record_release(
            ReserveClass::Rebuild,
            domain.clone(),
            40_000,
            ReservePressureState::Emergency,
            ValidationTier::Authoritative,
        );

        assert_eq!(log.net_admitted_bytes(), 0);

        let result = conservation_audit(log.receipts(), &ledger, 500_000);
        assert!(result.is_ok(), "expected clean audit, got {:?}", result);
    }

    // --- Conservation audit: invalid transitions ---

    #[test]
    fn conservation_audit_rejects_healthy_allocation_below_floor() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger(); // floor = 100_000

        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            10_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );

        let result = conservation_audit(log.receipts(), &ledger, 50_000);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, ConservationViolation::FloorBreachWithoutViolation { .. })),
            "expected FloorBreachWithoutViolation, got {:?}",
            violations
        );
    }

    #[test]
    fn conservation_audit_rejects_encroached_allocation_below_floor() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger(); // floor = 100_000

        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            10_000,
            ReservePressureState::Encroached,
            ValidationTier::Authoritative,
        );

        // free = 80_000 < floor = 100_000, state = Encroached (not Violated/Emergency)
        let result = conservation_audit(log.receipts(), &ledger, 80_000);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .iter()
            .any(|v| matches!(v, ConservationViolation::FloorBreachWithoutViolation { .. })));
    }

    // --- Validation tier ---

    #[test]
    fn informational_receipts_are_still_audited() {
        let mut log = ReceiptLog::new();
        let domain = test_domain();
        let ledger = test_ledger();

        log.record_allocate(
            ReserveClass::Rebuild,
            domain.clone(),
            10_000,
            ReservePressureState::Healthy,
            ValidationTier::Informational,
        );
        log.record_release(
            ReserveClass::Rebuild,
            domain.clone(),
            20_000,
            ReservePressureState::Healthy,
            ValidationTier::Informational,
        );

        let result = conservation_audit(log.receipts(), &ledger, 500_000);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .iter()
            .any(|v| matches!(v, ConservationViolation::UnderflowRelease { .. })));
    }

    // --- Multiple domains ---

    #[test]
    fn conservation_audit_handles_multiple_domains() {
        let mut log = ReceiptLog::new();
        let dom_a = BudgetDomainId::from_str("dom_a");
        let dom_b = BudgetDomainId::from_str("dom_b");
        let ledger_a = ReserveLedger::new(1, dom_a.clone(), ReserveClass::Rebuild, 50_000, 100_000);
        let ledger_b =
            ReserveLedger::new(2, dom_b.clone(), ReserveClass::Failover, 50_000, 100_000);

        log.record_allocate(
            ReserveClass::Rebuild,
            dom_a.clone(),
            30_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_release(
            ReserveClass::Rebuild,
            dom_a.clone(),
            30_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );

        log.record_allocate(
            ReserveClass::Failover,
            dom_b.clone(),
            10_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );
        log.record_release(
            ReserveClass::Failover,
            dom_b.clone(),
            20_000,
            ReservePressureState::Healthy,
            ValidationTier::Authoritative,
        );

        let r_a = conservation_audit(log.receipts(), &ledger_a, 500_000);
        assert!(r_a.is_ok(), "domain A should be clean, got {:?}", r_a);

        let r_b = conservation_audit(log.receipts(), &ledger_b, 500_000);
        assert!(r_b.is_err());
        assert!(r_b
            .unwrap_err()
            .iter()
            .any(|v| matches!(v, ConservationViolation::UnderflowRelease { .. })));
    }

    // --- Display impls ---

    #[test]
    fn validation_tier_display() {
        assert_eq!(ValidationTier::Authoritative.to_string(), "authoritative");
        assert_eq!(ValidationTier::Informational.to_string(), "informational");
    }

    #[test]
    fn receipt_operation_display() {
        assert_eq!(ReceiptOperation::Allocate.to_string(), "allocate");
        assert_eq!(ReceiptOperation::Release.to_string(), "release");
    }

    #[test]
    fn conservation_violation_display_non_empty() {
        let v = ConservationViolation::UnderflowRelease {
            allocated: 100,
            released: 200,
            budget_domain: "test".into(),
            reserve_class: "rebuild".into(),
        };
        let s = v.to_string();
        assert!(s.contains("test"));
        assert!(s.contains("rebuild"));
        assert!(s.contains("underflow"));
    }
}

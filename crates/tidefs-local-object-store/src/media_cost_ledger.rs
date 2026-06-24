// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Local flash media cost and wear accounting model.
//!
//! This module is the object-store side of the storage-intent media cost
//! ledger. It does not choose placement, relocation, or operator wording.
//! It records the local write-cost facts those later consumers need: who is
//! spending endurance, which write class caused it, what physical-write/WAF
//! evidence was available, which protected reserves were touched, and whether
//! the write should be refused instead of treating unknown media cost as free.

use crate::device_layout::DeviceMediaClass;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const DEFAULT_CONSERVATIVE_UNKNOWN_WAF_MULTIPLIER: u32 = 8;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MediaCostLedgerConfig {
    pub total_wear_budget_bytes: u64,
    pub conservative_unknown_waf_multiplier: u32,
    pub critical_reserves: CriticalWriteReserves,
}

impl MediaCostLedgerConfig {
    #[must_use]
    pub const fn new(total_wear_budget_bytes: u64) -> Self {
        Self {
            total_wear_budget_bytes,
            conservative_unknown_waf_multiplier: DEFAULT_CONSERVATIVE_UNKNOWN_WAF_MULTIPLIER,
            critical_reserves: CriticalWriteReserves::empty(),
        }
    }

    #[must_use]
    pub const fn with_critical_reserves(
        total_wear_budget_bytes: u64,
        critical_reserves: CriticalWriteReserves,
    ) -> Self {
        Self {
            total_wear_budget_bytes,
            conservative_unknown_waf_multiplier: DEFAULT_CONSERVATIVE_UNKNOWN_WAF_MULTIPLIER,
            critical_reserves,
        }
    }

    #[must_use]
    pub const fn effective_unknown_waf_multiplier(&self) -> u32 {
        if self.conservative_unknown_waf_multiplier == 0 {
            1
        } else {
            self.conservative_unknown_waf_multiplier
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CriticalWriteReserves {
    pub sync_intent_bytes: u64,
    pub repair_bytes: u64,
    pub evacuation_bytes: u64,
    pub policy_satisfaction_catch_up_bytes: u64,
}

impl CriticalWriteReserves {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            sync_intent_bytes: 0,
            repair_bytes: 0,
            evacuation_bytes: 0,
            policy_satisfaction_catch_up_bytes: 0,
        }
    }

    #[must_use]
    pub const fn total(self) -> u64 {
        self.sync_intent_bytes
            .saturating_add(self.repair_bytes)
            .saturating_add(self.evacuation_bytes)
            .saturating_add(self.policy_satisfaction_catch_up_bytes)
    }

    #[must_use]
    pub const fn floor_for(self, class: CriticalWriteReserveClass) -> u64 {
        match class {
            CriticalWriteReserveClass::SyncIntent => self.sync_intent_bytes,
            CriticalWriteReserveClass::Repair => self.repair_bytes,
            CriticalWriteReserveClass::Evacuation => self.evacuation_bytes,
            CriticalWriteReserveClass::PolicySatisfactionCatchUp => {
                self.policy_satisfaction_catch_up_bytes
            }
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum CriticalWriteReserveClass {
    SyncIntent,
    Repair,
    Evacuation,
    PolicySatisfactionCatchUp,
}

impl CriticalWriteReserveClass {
    pub const ALL: [Self; 4] = [
        Self::SyncIntent,
        Self::Repair,
        Self::Evacuation,
        Self::PolicySatisfactionCatchUp,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SyncIntent => "sync-intent",
            Self::Repair => "repair",
            Self::Evacuation => "evacuation",
            Self::PolicySatisfactionCatchUp => "policy-satisfaction-catch-up",
        }
    }
}

impl fmt::Display for CriticalWriteReserveClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum MediaWriteClass {
    ForegroundData,
    Metadata,
    SyncIntent,
    IntentLog,
    Repair,
    Evacuation,
    PolicySatisfactionCatchUp,
    Relocation,
    Compaction,
    Rebake,
    ReceiptRetirement,
    PreflightSimulation,
    DurableSignalSummary,
    DerivedViewEmission,
    PredictorCheckpoint,
    RetainedEvidenceMetadata,
    OperatorTelemetry,
    SpeculativePrefetch,
    CacheDeviceIndex,
    PersistentHotServingPromotion,
    FailedPromotionEvidence,
    DemotionBookkeeping,
    Unknown,
}

impl MediaWriteClass {
    #[must_use]
    pub const fn critical_reserve_class(self) -> Option<CriticalWriteReserveClass> {
        match self {
            Self::SyncIntent | Self::IntentLog => Some(CriticalWriteReserveClass::SyncIntent),
            Self::Repair => Some(CriticalWriteReserveClass::Repair),
            Self::Evacuation => Some(CriticalWriteReserveClass::Evacuation),
            Self::PolicySatisfactionCatchUp | Self::ReceiptRetirement => {
                Some(CriticalWriteReserveClass::PolicySatisfactionCatchUp)
            }
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_observability_write(self) -> bool {
        matches!(
            self,
            Self::DurableSignalSummary
                | Self::DerivedViewEmission
                | Self::PredictorCheckpoint
                | Self::RetainedEvidenceMetadata
                | Self::OperatorTelemetry
        )
    }
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum MediaRole {
    Data,
    Metadata,
    IntentLog,
    ReadCache,
    Special,
    Observability,
    Preflight,
    Relocation,
    Unknown,
}

#[derive(
    Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum DataShapeClass {
    Unknown,
    RawObject,
    MetadataRecord,
    SmallObject,
    LargeSequential,
    CompressedFrame,
    EncryptedEnvelope,
    ErasureCodedShard,
    RebakeSource,
    RebakeTarget,
    PredictorState,
    EvidenceRecord,
}

#[derive(
    Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum LayoutEvidenceClass {
    Unknown,
    LocalDefault,
    LayoutEvidenceRef(String),
    Fragmented,
    FreeRunAvailable,
    FreeRunScarce,
    PendingFreeSafe,
    PendingFreeUnsafe,
    EraseAligned,
    ZoneAligned,
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum RelocationReason {
    None,
    Defrag,
    Compaction,
    Rebake,
    Repair,
    Evacuation,
    Rebalance,
    GeoCatchUp,
    PrefetchPromotion,
    WearLeveling,
    PolicySatisfaction,
    Unknown,
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum AlignmentQuality {
    Unknown,
    EraseBlockAligned,
    ZoneAligned,
    PageAligned,
    Misaligned,
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum LocalityQuality {
    Unknown,
    ContiguousFreeRun,
    LocalFreeRun,
    Scattered,
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum PendingFreeSafety {
    Unknown,
    Safe,
    Unsafe,
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum MediaHealthState {
    Unknown,
    Healthy,
    Degraded,
    Failing,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MediaHealthSignal {
    pub state: MediaHealthState,
    pub error_count: u64,
    pub endurance_used_percent: Option<u8>,
    pub evidence_ref: Option<String>,
    pub stale: bool,
}

impl Default for MediaHealthSignal {
    fn default() -> Self {
        Self {
            state: MediaHealthState::Unknown,
            error_count: 0,
            endurance_used_percent: None,
            evidence_ref: None,
            stale: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum WafEvidence {
    KnownMediaBytes {
        media_bytes: u64,
        evidence_ref: Option<String>,
        stale: bool,
    },
    KnownRatio {
        numerator: u64,
        denominator: u64,
        evidence_ref: Option<String>,
        stale: bool,
    },
    ConservativeUnknown {
        reason: String,
    },
}

impl Default for WafEvidence {
    fn default() -> Self {
        Self::ConservativeUnknown {
            reason: "missing WAF evidence".to_string(),
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum MediaCostBasis {
    MeasuredPhysicalBytes,
    MeasuredWafRatio,
    ConservativeUnknownWaf,
}

#[derive(
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct MediaAttribution {
    pub dataset_ref: Option<String>,
    pub policy_class_ref: Option<String>,
    pub budget_owner_ref: Option<String>,
    pub tenant_ref: Option<String>,
    pub product_profile_ref: Option<String>,
    pub serving_trial_ref: Option<String>,
    pub relocation_class_ref: Option<String>,
    pub geo_catch_up_stream_ref: Option<String>,
}

impl MediaAttribution {
    #[must_use]
    pub fn unknown() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn dataset_policy(
        dataset_ref: impl Into<String>,
        policy_class_ref: impl Into<String>,
    ) -> Self {
        Self {
            dataset_ref: Some(dataset_ref.into()),
            policy_class_ref: Some(policy_class_ref.into()),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StorageIntentEvidenceRefs {
    pub retention_ref: Option<String>,
    pub action_execution_ref: Option<String>,
    pub measurement_attribution_ref: Option<String>,
    pub query_snapshot_ref: Option<String>,
    pub media_capability_ref: Option<String>,
    pub decision_frontier_ref: Option<String>,
    pub result_refusal_ref: Option<String>,
    pub isolation_ref: Option<String>,
    pub rollout_ref: Option<String>,
    pub layout_evidence_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PaybackConfidence {
    CallerProvided,
    MeasurementAttributed,
    ConservativeUnknown,
    ShadowOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PaybackEvidence {
    pub expected_avoided_future_media_bytes: u64,
    pub horizon_generations: u64,
    pub confidence: PaybackConfidence,
    pub evidence_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MediaCostIntent {
    pub logical_bytes: u64,
    pub write_class: MediaWriteClass,
    pub attribution: MediaAttribution,
    pub media_role: MediaRole,
    pub media_class: DeviceMediaClass,
    pub data_shape: DataShapeClass,
    pub layout_evidence: LayoutEvidenceClass,
    pub relocation_reason: RelocationReason,
    pub waf_evidence: WafEvidence,
    pub alignment: AlignmentQuality,
    pub locality: LocalityQuality,
    pub pending_free_safety: PendingFreeSafety,
    pub health: MediaHealthSignal,
    pub movement_subject_ref: Option<String>,
    pub payback: Option<PaybackEvidence>,
    pub evidence_refs: StorageIntentEvidenceRefs,
}

impl MediaCostIntent {
    #[must_use]
    pub fn new(
        logical_bytes: u64,
        write_class: MediaWriteClass,
        media_class: DeviceMediaClass,
    ) -> Self {
        Self {
            logical_bytes,
            write_class,
            attribution: MediaAttribution::unknown(),
            media_role: MediaRole::Unknown,
            media_class,
            data_shape: DataShapeClass::Unknown,
            layout_evidence: LayoutEvidenceClass::Unknown,
            relocation_reason: RelocationReason::None,
            waf_evidence: WafEvidence::default(),
            alignment: AlignmentQuality::Unknown,
            locality: LocalityQuality::Unknown,
            pending_free_safety: PendingFreeSafety::Unknown,
            health: MediaHealthSignal::default(),
            movement_subject_ref: None,
            payback: None,
            evidence_refs: StorageIntentEvidenceRefs::default(),
        }
    }

    #[must_use]
    pub fn with_attribution(mut self, attribution: MediaAttribution) -> Self {
        self.attribution = attribution;
        self
    }

    #[must_use]
    pub fn with_waf_evidence(mut self, waf_evidence: WafEvidence) -> Self {
        self.waf_evidence = waf_evidence;
        self
    }

    #[must_use]
    pub fn with_media_role(mut self, media_role: MediaRole) -> Self {
        self.media_role = media_role;
        self
    }

    #[must_use]
    pub fn with_relocation_reason(mut self, relocation_reason: RelocationReason) -> Self {
        self.relocation_reason = relocation_reason;
        self
    }

    #[must_use]
    pub fn with_movement_subject(mut self, subject_ref: impl Into<String>) -> Self {
        self.movement_subject_ref = Some(subject_ref.into());
        self
    }

    #[must_use]
    pub fn with_payback(mut self, payback: PaybackEvidence) -> Self {
        self.payback = Some(payback);
        self
    }
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum MediaCostRefusalReason {
    InvalidLogicalBytes,
    WearBudgetExceeded,
    CriticalReserveExceeded,
    ProtectedReserveWouldBeConsumed,
    UnknownReservation,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MediaCostRefusal {
    pub reason: MediaCostRefusalReason,
    pub write_class: MediaWriteClass,
    pub requested_logical_bytes: u64,
    pub estimated_media_bytes: u64,
    pub budget_remaining_bytes: u64,
    pub protected_reserve_remaining_bytes: u64,
    pub critical_reserve_class: Option<CriticalWriteReserveClass>,
    pub cost_basis: MediaCostBasis,
}

impl fmt::Display for MediaCostRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "media cost refused {:?}: write_class={:?} logical={} media={} remaining={} protected_remaining={}",
            self.reason,
            self.write_class,
            self.requested_logical_bytes,
            self.estimated_media_bytes,
            self.budget_remaining_bytes,
            self.protected_reserve_remaining_bytes
        )
    }
}

impl std::error::Error for MediaCostRefusal {}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct MediaReservationToken {
    pub id: u64,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MediaChargeReceipt {
    pub receipt_id: u64,
    pub reservation_id: Option<u64>,
    pub generation: u64,
    pub intent: MediaCostIntent,
    pub logical_bytes: u64,
    pub estimated_media_bytes: u64,
    pub cost_basis: MediaCostBasis,
    pub critical_reserve_class: Option<CriticalWriteReserveClass>,
    pub charged_from_critical_reserve: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MediaLedgerTotals {
    pub logical_bytes: u64,
    pub estimated_media_bytes: u64,
    pub charge_count: u64,
    pub conservative_unknown_media_bytes: u64,
}

impl MediaLedgerTotals {
    fn record(&mut self, estimate: CostEstimate) {
        self.logical_bytes = self.logical_bytes.saturating_add(estimate.logical_bytes);
        self.estimated_media_bytes = self
            .estimated_media_bytes
            .saturating_add(estimate.estimated_media_bytes);
        self.charge_count = self.charge_count.saturating_add(1);
        if estimate.cost_basis == MediaCostBasis::ConservativeUnknownWaf {
            self.conservative_unknown_media_bytes = self
                .conservative_unknown_media_bytes
                .saturating_add(estimate.estimated_media_bytes);
        }
    }
}

impl Default for MediaLedgerTotals {
    fn default() -> Self {
        Self {
            logical_bytes: 0,
            estimated_media_bytes: 0,
            charge_count: 0,
            conservative_unknown_media_bytes: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MovementDebtEntry {
    pub subject_ref: String,
    pub attribution: MediaAttribution,
    pub logical_bytes: u64,
    pub estimated_media_bytes: u64,
    pub relocation_reason: RelocationReason,
    pub created_generation: u64,
    pub last_updated_generation: u64,
    pub payback_horizon_generations: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PaybackEvidenceSnapshot {
    pub receipt_id: u64,
    pub attribution: MediaAttribution,
    pub relocation_reason: RelocationReason,
    pub expected_avoided_future_media_bytes: u64,
    pub horizon_generations: u64,
    pub confidence: PaybackConfidence,
    pub evidence_ref: Option<String>,
    pub charged_media_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CriticalReserveSnapshot {
    pub class: CriticalWriteReserveClass,
    pub floor_bytes: u64,
    pub active_reserved_bytes: u64,
    pub charged_bytes: u64,
    pub remaining_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MediaReservationSnapshot {
    pub token: MediaReservationToken,
    pub intent: MediaCostIntent,
    pub estimated_media_bytes: u64,
    pub cost_basis: MediaCostBasis,
    pub critical_reserve_class: Option<CriticalWriteReserveClass>,
    pub expires_at_generation: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MediaCostSnapshot {
    pub generation: u64,
    pub total_wear_budget_bytes: u64,
    pub charged_logical_bytes: u64,
    pub charged_media_bytes: u64,
    pub active_reserved_media_bytes: u64,
    pub remaining_budget_bytes: u64,
    pub protected_reserve_remaining_bytes: u64,
    pub totals_by_write_class: BTreeMap<MediaWriteClass, MediaLedgerTotals>,
    pub totals_by_attribution: BTreeMap<MediaAttribution, MediaLedgerTotals>,
    pub totals_by_media_role: BTreeMap<MediaRole, MediaLedgerTotals>,
    pub relocation_media_bytes_by_reason: BTreeMap<RelocationReason, u64>,
    pub critical_reserves: Vec<CriticalReserveSnapshot>,
    pub active_reservations: Vec<MediaReservationSnapshot>,
    pub movement_debt: Vec<MovementDebtEntry>,
    pub payback_evidence: Vec<PaybackEvidenceSnapshot>,
    pub refusals_by_reason: BTreeMap<MediaCostRefusalReason, u64>,
    pub released_reservations: u64,
    pub expired_reservations: u64,
    pub aborted_reservations: u64,
    pub retired_receipts: Vec<MediaChargeRetirement>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MediaChargeRetirement {
    pub receipt_id: u64,
    pub generation: u64,
    pub reason: MediaChargeRetirementReason,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum MediaChargeRetirementReason {
    SourceReceiptRetired,
    EvidenceCompacted,
    SupersededByReplacement,
    OperatorRetired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CostEstimate {
    logical_bytes: u64,
    estimated_media_bytes: u64,
    cost_basis: MediaCostBasis,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingMediaReservation {
    token: MediaReservationToken,
    intent: MediaCostIntent,
    estimate: CostEstimate,
    critical_reserve_class: Option<CriticalWriteReserveClass>,
    expires_at_generation: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct MediaCostLedger {
    config: MediaCostLedgerConfig,
    generation: u64,
    next_reservation_id: u64,
    next_receipt_id: u64,
    charged_logical_bytes: u64,
    charged_media_bytes: u64,
    active_reserved_media_bytes: u64,
    active_reservations: BTreeMap<u64, PendingMediaReservation>,
    critical_reserved_bytes: BTreeMap<CriticalWriteReserveClass, u64>,
    critical_charged_bytes: BTreeMap<CriticalWriteReserveClass, u64>,
    receipts: BTreeMap<u64, MediaChargeReceipt>,
    totals_by_write_class: BTreeMap<MediaWriteClass, MediaLedgerTotals>,
    totals_by_attribution: BTreeMap<MediaAttribution, MediaLedgerTotals>,
    totals_by_media_role: BTreeMap<MediaRole, MediaLedgerTotals>,
    relocation_media_bytes_by_reason: BTreeMap<RelocationReason, u64>,
    movement_debt: BTreeMap<String, MovementDebtEntry>,
    payback_evidence: Vec<PaybackEvidenceSnapshot>,
    refusals_by_reason: BTreeMap<MediaCostRefusalReason, u64>,
    released_reservations: u64,
    expired_reservations: u64,
    aborted_reservations: u64,
    retired_receipts: BTreeMap<u64, MediaChargeRetirement>,
}

impl MediaCostLedger {
    #[must_use]
    pub fn new(config: MediaCostLedgerConfig) -> Self {
        Self {
            config,
            generation: 0,
            next_reservation_id: 1,
            next_receipt_id: 1,
            charged_logical_bytes: 0,
            charged_media_bytes: 0,
            active_reserved_media_bytes: 0,
            active_reservations: BTreeMap::new(),
            critical_reserved_bytes: BTreeMap::new(),
            critical_charged_bytes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            totals_by_write_class: BTreeMap::new(),
            totals_by_attribution: BTreeMap::new(),
            totals_by_media_role: BTreeMap::new(),
            relocation_media_bytes_by_reason: BTreeMap::new(),
            movement_debt: BTreeMap::new(),
            payback_evidence: Vec::new(),
            refusals_by_reason: BTreeMap::new(),
            released_reservations: 0,
            expired_reservations: 0,
            aborted_reservations: 0,
            retired_receipts: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn config(&self) -> &MediaCostLedgerConfig {
        &self.config
    }

    pub fn reserve(
        &mut self,
        intent: MediaCostIntent,
        ttl_generations: Option<u64>,
    ) -> Result<MediaReservationToken, MediaCostRefusal> {
        let estimate = self.estimate_intent(&intent);
        let critical_reserve_class = intent.write_class.critical_reserve_class();
        self.admit(&intent, estimate, critical_reserve_class)?;

        self.generation = self.generation.saturating_add(1);
        let token = MediaReservationToken {
            id: self.next_reservation_id,
            generation: self.generation,
        };
        self.next_reservation_id = self.next_reservation_id.saturating_add(1);
        let expires_at_generation = ttl_generations.map(|ttl| self.generation.saturating_add(ttl));

        self.active_reserved_media_bytes = self
            .active_reserved_media_bytes
            .saturating_add(estimate.estimated_media_bytes);
        if let Some(class) = critical_reserve_class {
            let entry = self.critical_reserved_bytes.entry(class).or_default();
            *entry = entry.saturating_add(estimate.estimated_media_bytes);
        }

        let pending = PendingMediaReservation {
            token,
            intent,
            estimate,
            critical_reserve_class,
            expires_at_generation,
        };
        self.active_reservations.insert(token.id, pending);
        Ok(token)
    }

    pub fn charge(
        &mut self,
        intent: MediaCostIntent,
    ) -> Result<MediaChargeReceipt, MediaCostRefusal> {
        let estimate = self.estimate_intent(&intent);
        let critical_reserve_class = intent.write_class.critical_reserve_class();
        self.admit(&intent, estimate, critical_reserve_class)?;
        self.generation = self.generation.saturating_add(1);
        Ok(self.record_charge(None, intent, estimate, critical_reserve_class))
    }

    pub fn charge_reserved(
        &mut self,
        token: MediaReservationToken,
    ) -> Result<MediaChargeReceipt, MediaCostRefusal> {
        let Some(pending) = self.active_reservations.remove(&token.id) else {
            return Err(self.refusal_for_unknown_reservation());
        };
        if pending.token.generation != token.generation {
            self.active_reservations.insert(pending.token.id, pending);
            return Err(self.refusal_for_unknown_reservation());
        }

        self.active_reserved_media_bytes = self
            .active_reserved_media_bytes
            .saturating_sub(pending.estimate.estimated_media_bytes);
        if let Some(class) = pending.critical_reserve_class {
            let current = self
                .critical_reserved_bytes
                .get(&class)
                .copied()
                .unwrap_or(0);
            self.critical_reserved_bytes.insert(
                class,
                current.saturating_sub(pending.estimate.estimated_media_bytes),
            );
        }

        self.generation = self.generation.saturating_add(1);
        Ok(self.record_charge(
            Some(token.id),
            pending.intent,
            pending.estimate,
            pending.critical_reserve_class,
        ))
    }

    pub fn release(&mut self, token: MediaReservationToken) -> bool {
        self.drop_reservation(token, ReservationDropKind::Release)
    }

    pub fn expire(&mut self, token: MediaReservationToken) -> bool {
        self.drop_reservation(token, ReservationDropKind::Expire)
    }

    pub fn abort(&mut self, token: MediaReservationToken) -> bool {
        self.drop_reservation(token, ReservationDropKind::Abort)
    }

    pub fn retire_charge(&mut self, receipt_id: u64, reason: MediaChargeRetirementReason) -> bool {
        if !self.receipts.contains_key(&receipt_id)
            || self.retired_receipts.contains_key(&receipt_id)
        {
            return false;
        }
        self.generation = self.generation.saturating_add(1);
        self.retired_receipts.insert(
            receipt_id,
            MediaChargeRetirement {
                receipt_id,
                generation: self.generation,
                reason,
            },
        );
        true
    }

    pub fn retire_movement_debt(&mut self, subject_ref: &str) -> bool {
        self.movement_debt.remove(subject_ref).is_some()
    }

    pub fn expire_due_reservations(&mut self, generation: u64) -> Vec<MediaReservationToken> {
        let due: Vec<_> = self
            .active_reservations
            .values()
            .filter(|pending| {
                pending
                    .expires_at_generation
                    .is_some_and(|expires_at| expires_at <= generation)
            })
            .map(|pending| pending.token)
            .collect();
        for token in &due {
            self.expire(*token);
        }
        due
    }

    #[must_use]
    pub fn snapshot(&self) -> MediaCostSnapshot {
        let active_reservations = self
            .active_reservations
            .values()
            .map(|pending| MediaReservationSnapshot {
                token: pending.token,
                intent: pending.intent.clone(),
                estimated_media_bytes: pending.estimate.estimated_media_bytes,
                cost_basis: pending.estimate.cost_basis,
                critical_reserve_class: pending.critical_reserve_class,
                expires_at_generation: pending.expires_at_generation,
            })
            .collect();

        let critical_reserves = CriticalWriteReserveClass::ALL
            .iter()
            .copied()
            .map(|class| {
                let floor_bytes = self.config.critical_reserves.floor_for(class);
                let active_reserved_bytes = self
                    .critical_reserved_bytes
                    .get(&class)
                    .copied()
                    .unwrap_or(0);
                let charged_bytes = self
                    .critical_charged_bytes
                    .get(&class)
                    .copied()
                    .unwrap_or(0);
                CriticalReserveSnapshot {
                    class,
                    floor_bytes,
                    active_reserved_bytes,
                    charged_bytes,
                    remaining_bytes: floor_bytes
                        .saturating_sub(active_reserved_bytes.saturating_add(charged_bytes)),
                }
            })
            .collect();

        MediaCostSnapshot {
            generation: self.generation,
            total_wear_budget_bytes: self.config.total_wear_budget_bytes,
            charged_logical_bytes: self.charged_logical_bytes,
            charged_media_bytes: self.charged_media_bytes,
            active_reserved_media_bytes: self.active_reserved_media_bytes,
            remaining_budget_bytes: self.remaining_budget_bytes(),
            protected_reserve_remaining_bytes: self.protected_reserve_remaining_bytes(),
            totals_by_write_class: self.totals_by_write_class.clone(),
            totals_by_attribution: self.totals_by_attribution.clone(),
            totals_by_media_role: self.totals_by_media_role.clone(),
            relocation_media_bytes_by_reason: self.relocation_media_bytes_by_reason.clone(),
            critical_reserves,
            active_reservations,
            movement_debt: self.movement_debt.values().cloned().collect(),
            payback_evidence: self.payback_evidence.clone(),
            refusals_by_reason: self.refusals_by_reason.clone(),
            released_reservations: self.released_reservations,
            expired_reservations: self.expired_reservations,
            aborted_reservations: self.aborted_reservations,
            retired_receipts: self.retired_receipts.values().cloned().collect(),
        }
    }

    #[must_use]
    pub fn receipt(&self, receipt_id: u64) -> Option<&MediaChargeReceipt> {
        self.receipts.get(&receipt_id)
    }

    #[must_use]
    pub fn movement_debt(&self, subject_ref: &str) -> Option<&MovementDebtEntry> {
        self.movement_debt.get(subject_ref)
    }

    fn admit(
        &mut self,
        intent: &MediaCostIntent,
        estimate: CostEstimate,
        critical_reserve_class: Option<CriticalWriteReserveClass>,
    ) -> Result<(), MediaCostRefusal> {
        if estimate.logical_bytes == 0 {
            return Err(self.refusal(
                MediaCostRefusalReason::InvalidLogicalBytes,
                intent,
                estimate,
                critical_reserve_class,
            ));
        }

        if self.remaining_budget_bytes() < estimate.estimated_media_bytes {
            return Err(self.refusal(
                MediaCostRefusalReason::WearBudgetExceeded,
                intent,
                estimate,
                critical_reserve_class,
            ));
        }

        if let Some(class) = critical_reserve_class {
            if self.critical_reserve_remaining_bytes(class) < estimate.estimated_media_bytes {
                return Err(self.refusal(
                    MediaCostRefusalReason::CriticalReserveExceeded,
                    intent,
                    estimate,
                    critical_reserve_class,
                ));
            }
            return Ok(());
        }

        let remaining_after_request = self
            .remaining_budget_bytes()
            .saturating_sub(estimate.estimated_media_bytes);
        if remaining_after_request < self.protected_reserve_remaining_bytes() {
            return Err(self.refusal(
                MediaCostRefusalReason::ProtectedReserveWouldBeConsumed,
                intent,
                estimate,
                critical_reserve_class,
            ));
        }

        Ok(())
    }

    fn estimate_intent(&self, intent: &MediaCostIntent) -> CostEstimate {
        let multiplier = u64::from(self.config.effective_unknown_waf_multiplier());
        match &intent.waf_evidence {
            WafEvidence::KnownMediaBytes {
                media_bytes, stale, ..
            } if !stale => CostEstimate {
                logical_bytes: intent.logical_bytes,
                estimated_media_bytes: *media_bytes,
                cost_basis: MediaCostBasis::MeasuredPhysicalBytes,
            },
            WafEvidence::KnownRatio {
                numerator,
                denominator,
                stale,
                ..
            } if !stale && *denominator != 0 => CostEstimate {
                logical_bytes: intent.logical_bytes,
                estimated_media_bytes: mul_div_ceil(intent.logical_bytes, *numerator, *denominator),
                cost_basis: MediaCostBasis::MeasuredWafRatio,
            },
            _ => CostEstimate {
                logical_bytes: intent.logical_bytes,
                estimated_media_bytes: intent.logical_bytes.saturating_mul(multiplier),
                cost_basis: MediaCostBasis::ConservativeUnknownWaf,
            },
        }
    }

    fn record_charge(
        &mut self,
        reservation_id: Option<u64>,
        intent: MediaCostIntent,
        estimate: CostEstimate,
        critical_reserve_class: Option<CriticalWriteReserveClass>,
    ) -> MediaChargeReceipt {
        self.charged_logical_bytes = self
            .charged_logical_bytes
            .saturating_add(estimate.logical_bytes);
        self.charged_media_bytes = self
            .charged_media_bytes
            .saturating_add(estimate.estimated_media_bytes);

        if let Some(class) = critical_reserve_class {
            let entry = self.critical_charged_bytes.entry(class).or_default();
            *entry = entry.saturating_add(estimate.estimated_media_bytes);
        }

        self.totals_by_write_class
            .entry(intent.write_class)
            .or_default()
            .record(estimate);
        self.totals_by_attribution
            .entry(intent.attribution.clone())
            .or_default()
            .record(estimate);
        self.totals_by_media_role
            .entry(intent.media_role)
            .or_default()
            .record(estimate);

        if intent.relocation_reason != RelocationReason::None {
            let entry = self
                .relocation_media_bytes_by_reason
                .entry(intent.relocation_reason)
                .or_default();
            *entry = entry.saturating_add(estimate.estimated_media_bytes);
        }

        let receipt_id = self.next_receipt_id;
        self.next_receipt_id = self.next_receipt_id.saturating_add(1);
        self.record_movement_debt(receipt_id, &intent, estimate);

        let receipt = MediaChargeReceipt {
            receipt_id,
            reservation_id,
            generation: self.generation,
            intent,
            logical_bytes: estimate.logical_bytes,
            estimated_media_bytes: estimate.estimated_media_bytes,
            cost_basis: estimate.cost_basis,
            critical_reserve_class,
            charged_from_critical_reserve: critical_reserve_class.is_some(),
        };
        self.receipts.insert(receipt_id, receipt.clone());
        receipt
    }

    fn record_movement_debt(
        &mut self,
        receipt_id: u64,
        intent: &MediaCostIntent,
        estimate: CostEstimate,
    ) {
        if let Some(payback) = intent.payback.clone() {
            self.payback_evidence.push(PaybackEvidenceSnapshot {
                receipt_id,
                attribution: intent.attribution.clone(),
                relocation_reason: intent.relocation_reason,
                expected_avoided_future_media_bytes: payback.expected_avoided_future_media_bytes,
                horizon_generations: payback.horizon_generations,
                confidence: payback.confidence,
                evidence_ref: payback.evidence_ref,
                charged_media_bytes: estimate.estimated_media_bytes,
            });
        }

        let Some(subject_ref) = intent.movement_subject_ref.clone() else {
            return;
        };
        let entry = self
            .movement_debt
            .entry(subject_ref.clone())
            .or_insert_with(|| MovementDebtEntry {
                subject_ref: subject_ref.clone(),
                attribution: intent.attribution.clone(),
                logical_bytes: 0,
                estimated_media_bytes: 0,
                relocation_reason: intent.relocation_reason,
                created_generation: self.generation,
                last_updated_generation: self.generation,
                payback_horizon_generations: intent
                    .payback
                    .as_ref()
                    .map(|payback| payback.horizon_generations),
            });
        entry.logical_bytes = entry.logical_bytes.saturating_add(estimate.logical_bytes);
        entry.estimated_media_bytes = entry
            .estimated_media_bytes
            .saturating_add(estimate.estimated_media_bytes);
        entry.last_updated_generation = self.generation;
        if entry.payback_horizon_generations.is_none() {
            entry.payback_horizon_generations = intent
                .payback
                .as_ref()
                .map(|payback| payback.horizon_generations);
        }
    }

    fn drop_reservation(
        &mut self,
        token: MediaReservationToken,
        kind: ReservationDropKind,
    ) -> bool {
        let Some(pending) = self.active_reservations.get(&token.id) else {
            return false;
        };
        if pending.token.generation != token.generation {
            return false;
        }
        let pending = self
            .active_reservations
            .remove(&token.id)
            .expect("reservation checked above");
        self.active_reserved_media_bytes = self
            .active_reserved_media_bytes
            .saturating_sub(pending.estimate.estimated_media_bytes);
        if let Some(class) = pending.critical_reserve_class {
            let current = self
                .critical_reserved_bytes
                .get(&class)
                .copied()
                .unwrap_or(0);
            self.critical_reserved_bytes.insert(
                class,
                current.saturating_sub(pending.estimate.estimated_media_bytes),
            );
        }
        self.generation = self.generation.saturating_add(1);
        match kind {
            ReservationDropKind::Release => {
                self.released_reservations = self.released_reservations.saturating_add(1);
            }
            ReservationDropKind::Expire => {
                self.expired_reservations = self.expired_reservations.saturating_add(1);
            }
            ReservationDropKind::Abort => {
                self.aborted_reservations = self.aborted_reservations.saturating_add(1);
            }
        }
        true
    }

    fn refusal_for_unknown_reservation(&mut self) -> MediaCostRefusal {
        let estimate = CostEstimate {
            logical_bytes: 0,
            estimated_media_bytes: 0,
            cost_basis: MediaCostBasis::ConservativeUnknownWaf,
        };
        let intent = MediaCostIntent::new(0, MediaWriteClass::Unknown, DeviceMediaClass::Ssd);
        self.refusal(
            MediaCostRefusalReason::UnknownReservation,
            &intent,
            estimate,
            None,
        )
    }

    fn refusal(
        &mut self,
        reason: MediaCostRefusalReason,
        intent: &MediaCostIntent,
        estimate: CostEstimate,
        critical_reserve_class: Option<CriticalWriteReserveClass>,
    ) -> MediaCostRefusal {
        let entry = self.refusals_by_reason.entry(reason).or_default();
        *entry = entry.saturating_add(1);
        MediaCostRefusal {
            reason,
            write_class: intent.write_class,
            requested_logical_bytes: estimate.logical_bytes,
            estimated_media_bytes: estimate.estimated_media_bytes,
            budget_remaining_bytes: self.remaining_budget_bytes(),
            protected_reserve_remaining_bytes: self.protected_reserve_remaining_bytes(),
            critical_reserve_class,
            cost_basis: estimate.cost_basis,
        }
    }

    fn remaining_budget_bytes(&self) -> u64 {
        self.config
            .total_wear_budget_bytes
            .saturating_sub(self.charged_media_bytes)
            .saturating_sub(self.active_reserved_media_bytes)
    }

    fn critical_reserve_remaining_bytes(&self, class: CriticalWriteReserveClass) -> u64 {
        let floor = self.config.critical_reserves.floor_for(class);
        let active_reserved = self
            .critical_reserved_bytes
            .get(&class)
            .copied()
            .unwrap_or(0);
        let charged = self
            .critical_charged_bytes
            .get(&class)
            .copied()
            .unwrap_or(0);
        floor.saturating_sub(active_reserved.saturating_add(charged))
    }

    fn protected_reserve_remaining_bytes(&self) -> u64 {
        CriticalWriteReserveClass::ALL
            .iter()
            .copied()
            .map(|class| self.critical_reserve_remaining_bytes(class))
            .sum()
    }
}

#[derive(Clone, Copy, Debug)]
enum ReservationDropKind {
    Release,
    Expire,
    Abort,
}

fn mul_div_ceil(value: u64, numerator: u64, denominator: u64) -> u64 {
    if value == 0 || numerator == 0 {
        return 0;
    }
    let wide = u128::from(value).saturating_mul(u128::from(numerator));
    let quotient = wide / u128::from(denominator);
    let remainder = wide % u128::from(denominator);
    let rounded = if remainder == 0 {
        quotient
    } else {
        quotient.saturating_add(1)
    };
    u64::try_from(rounded).unwrap_or(u64::MAX)
}

#[must_use]
pub fn media_class_weight_is_allocator_hint_only(media_class: DeviceMediaClass) -> f64 {
    media_class.class_weight()
}

#[must_use]
pub fn charged_write_classes_include_observability() -> BTreeSet<MediaWriteClass> {
    [
        MediaWriteClass::DurableSignalSummary,
        MediaWriteClass::DerivedViewEmission,
        MediaWriteClass::PredictorCheckpoint,
        MediaWriteClass::RetainedEvidenceMetadata,
        MediaWriteClass::OperatorTelemetry,
    ]
    .into_iter()
    .collect()
}

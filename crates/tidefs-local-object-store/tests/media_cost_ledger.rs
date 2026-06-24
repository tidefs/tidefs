// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use tidefs_local_object_store::{
    charged_write_classes_include_observability, media_class_weight_is_allocator_hint_only,
    CriticalWriteReserveClass, CriticalWriteReserves, DeviceMediaClass, MediaAttribution,
    MediaChargeRetirementReason, MediaCostBasis, MediaCostIntent, MediaCostLedger,
    MediaCostLedgerConfig, MediaCostRefusalReason, MediaRole, MediaWriteClass, PaybackConfidence,
    PaybackEvidence, RelocationReason, WafEvidence,
};

fn known_media_bytes(media_bytes: u64) -> WafEvidence {
    WafEvidence::KnownMediaBytes {
        media_bytes,
        evidence_ref: Some("waf:test".to_string()),
        stale: false,
    }
}

fn ledger_with_reserves(total_wear_budget_bytes: u64) -> MediaCostLedger {
    let reserves = CriticalWriteReserves {
        sync_intent_bytes: 400,
        repair_bytes: 300,
        evacuation_bytes: 200,
        policy_satisfaction_catch_up_bytes: 100,
    };
    MediaCostLedger::new(MediaCostLedgerConfig::with_critical_reserves(
        total_wear_budget_bytes,
        reserves,
    ))
}

fn intent(logical_bytes: u64, write_class: MediaWriteClass, media_bytes: u64) -> MediaCostIntent {
    MediaCostIntent::new(logical_bytes, write_class, DeviceMediaClass::Nvme)
        .with_waf_evidence(known_media_bytes(media_bytes))
}

#[test]
fn reserve_charge_release_expire_retire_and_abort_paths_are_accounted() {
    let mut ledger = ledger_with_reserves(5_000);

    let release_token = ledger
        .reserve(intent(100, MediaWriteClass::ForegroundData, 100), None)
        .expect("foreground reserve");
    assert_eq!(ledger.snapshot().active_reserved_media_bytes, 100);
    assert!(ledger.release(release_token));

    let expire_token = ledger
        .reserve(intent(100, MediaWriteClass::Metadata, 75), Some(0))
        .expect("metadata reserve");
    let expired = ledger.expire_due_reservations(expire_token.generation);
    assert_eq!(expired, vec![expire_token]);

    let abort_token = ledger
        .reserve(intent(100, MediaWriteClass::Relocation, 80), None)
        .expect("relocation reserve");
    assert!(ledger.abort(abort_token));

    let sync_token = ledger
        .reserve(intent(128, MediaWriteClass::SyncIntent, 128), None)
        .expect("sync reserve");
    let receipt = ledger.charge_reserved(sync_token).expect("sync charge");
    assert_eq!(
        receipt.critical_reserve_class,
        Some(CriticalWriteReserveClass::SyncIntent)
    );
    assert!(receipt.charged_from_critical_reserve);
    assert!(ledger.retire_charge(
        receipt.receipt_id,
        MediaChargeRetirementReason::SourceReceiptRetired
    ));

    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.released_reservations, 1);
    assert_eq!(snapshot.expired_reservations, 1);
    assert_eq!(snapshot.aborted_reservations, 1);
    assert_eq!(snapshot.active_reserved_media_bytes, 0);
    assert_eq!(snapshot.charged_media_bytes, 128);
    assert_eq!(snapshot.retired_receipts.len(), 1);

    let sync_reserve = snapshot
        .critical_reserves
        .iter()
        .find(|reserve| reserve.class == CriticalWriteReserveClass::SyncIntent)
        .expect("sync reserve snapshot");
    assert_eq!(sync_reserve.charged_bytes, 128);
    assert_eq!(sync_reserve.remaining_bytes, 272);
}

#[test]
fn refuses_when_wear_budget_would_be_exceeded() {
    let mut ledger = MediaCostLedger::new(MediaCostLedgerConfig::new(100));

    let err = ledger
        .charge(intent(512, MediaWriteClass::ForegroundData, 200))
        .expect_err("charge should exceed wear budget");

    assert_eq!(err.reason, MediaCostRefusalReason::WearBudgetExceeded);
    assert_eq!(err.requested_logical_bytes, 512);
    assert_eq!(err.estimated_media_bytes, 200);
    assert_eq!(err.budget_remaining_bytes, 100);
    assert_eq!(
        ledger
            .snapshot()
            .refusals_by_reason
            .get(&MediaCostRefusalReason::WearBudgetExceeded),
        Some(&1)
    );
}

#[test]
fn unknown_and_stale_waf_are_conservative_not_zero() {
    let mut config = MediaCostLedgerConfig::new(1_000);
    config.conservative_unknown_waf_multiplier = 8;
    let mut ledger = MediaCostLedger::new(config);

    let unknown_receipt = ledger
        .charge(MediaCostIntent::new(
            10,
            MediaWriteClass::DurableSignalSummary,
            DeviceMediaClass::Ssd,
        ))
        .expect("unknown WAF signal charge");
    assert_eq!(
        unknown_receipt.cost_basis,
        MediaCostBasis::ConservativeUnknownWaf
    );
    assert_eq!(unknown_receipt.estimated_media_bytes, 80);

    let stale_receipt = ledger
        .charge(
            MediaCostIntent::new(5, MediaWriteClass::Metadata, DeviceMediaClass::Ssd)
                .with_waf_evidence(WafEvidence::KnownMediaBytes {
                    media_bytes: 5,
                    evidence_ref: Some("stale:physical-write".to_string()),
                    stale: true,
                }),
        )
        .expect("stale WAF charge");
    assert_eq!(stale_receipt.estimated_media_bytes, 40);
    assert_eq!(ledger.snapshot().charged_media_bytes, 120);
}

#[test]
fn movement_debt_persists_until_retired() {
    let mut ledger = MediaCostLedger::new(MediaCostLedgerConfig::new(2_000));

    let receipt = ledger
        .charge(
            intent(256, MediaWriteClass::Relocation, 300)
                .with_relocation_reason(RelocationReason::Compaction)
                .with_movement_subject("dataset-a/object-7"),
        )
        .expect("relocation charge");
    assert_eq!(receipt.estimated_media_bytes, 300);

    ledger
        .charge(intent(64, MediaWriteClass::ForegroundData, 64))
        .expect("unrelated charge");

    let debt = ledger
        .movement_debt("dataset-a/object-7")
        .expect("movement debt persists");
    assert_eq!(debt.estimated_media_bytes, 300);
    assert_eq!(debt.relocation_reason, RelocationReason::Compaction);

    assert!(ledger.retire_movement_debt("dataset-a/object-7"));
    assert!(ledger.movement_debt("dataset-a/object-7").is_none());
}

#[test]
fn per_dataset_and_policy_attribution_stays_visible() {
    let mut ledger = MediaCostLedger::new(MediaCostLedgerConfig::new(2_000));
    let dataset_a = MediaAttribution::dataset_policy("dataset-a", "policy-fast-sync");
    let dataset_b = MediaAttribution::dataset_policy("dataset-b", "policy-bulk");

    ledger
        .charge(
            intent(100, MediaWriteClass::ForegroundData, 100)
                .with_attribution(dataset_a.clone())
                .with_media_role(MediaRole::Data),
        )
        .expect("dataset a charge");
    ledger
        .charge(
            intent(200, MediaWriteClass::ForegroundData, 200)
                .with_attribution(dataset_b.clone())
                .with_media_role(MediaRole::Data),
        )
        .expect("dataset b charge");

    let snapshot = ledger.snapshot();
    assert_eq!(
        snapshot
            .totals_by_attribution
            .get(&dataset_a)
            .expect("dataset a totals")
            .estimated_media_bytes,
        100
    );
    assert_eq!(
        snapshot
            .totals_by_attribution
            .get(&dataset_b)
            .expect("dataset b totals")
            .estimated_media_bytes,
        200
    );
}

#[test]
fn foreground_sync_reserve_is_isolated_from_optimizer_work() {
    let mut ledger = ledger_with_reserves(1_000);

    let err = ledger
        .reserve(intent(700, MediaWriteClass::Compaction, 700), None)
        .expect_err("optimizer must not consume protected reserve");
    assert_eq!(
        err.reason,
        MediaCostRefusalReason::ProtectedReserveWouldBeConsumed
    );
    assert_eq!(err.protected_reserve_remaining_bytes, 1_000);

    let sync_receipt = ledger
        .charge(intent(300, MediaWriteClass::SyncIntent, 300))
        .expect("foreground sync uses sync reserve");
    assert_eq!(sync_receipt.estimated_media_bytes, 300);
    assert_eq!(
        sync_receipt.critical_reserve_class,
        Some(CriticalWriteReserveClass::SyncIntent)
    );

    let err = ledger
        .charge(intent(200, MediaWriteClass::SyncIntent, 200))
        .expect_err("sync reserve floor exceeded");
    assert_eq!(err.reason, MediaCostRefusalReason::CriticalReserveExceeded);
}

#[test]
fn payback_evidence_is_exposed_in_snapshots() {
    let mut ledger = MediaCostLedger::new(MediaCostLedgerConfig::new(2_000));

    let payback = PaybackEvidence {
        expected_avoided_future_media_bytes: 900,
        horizon_generations: 12,
        confidence: PaybackConfidence::CallerProvided,
        evidence_ref: Some("payback:relocation-plan-1".to_string()),
    };

    let receipt = ledger
        .charge(
            intent(256, MediaWriteClass::Relocation, 300)
                .with_relocation_reason(RelocationReason::Rebalance)
                .with_payback(payback),
        )
        .expect("payback charge");

    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.payback_evidence.len(), 1);
    let evidence = &snapshot.payback_evidence[0];
    assert_eq!(evidence.receipt_id, receipt.receipt_id);
    assert_eq!(evidence.expected_avoided_future_media_bytes, 900);
    assert_eq!(evidence.horizon_generations, 12);
    assert_eq!(evidence.charged_media_bytes, 300);
}

#[test]
fn observability_writes_are_charged_classes() {
    let mut config = MediaCostLedgerConfig::new(1_000);
    config.conservative_unknown_waf_multiplier = 4;
    let mut ledger = MediaCostLedger::new(config);

    let classes = charged_write_classes_include_observability();
    assert!(classes.contains(&MediaWriteClass::DurableSignalSummary));
    assert!(classes.contains(&MediaWriteClass::PredictorCheckpoint));

    let receipt = ledger
        .charge(MediaCostIntent::new(
            25,
            MediaWriteClass::PredictorCheckpoint,
            DeviceMediaClass::Nvme,
        ))
        .expect("predictor checkpoint charge");
    assert_eq!(receipt.estimated_media_bytes, 100);

    let snapshot = ledger.snapshot();
    assert_eq!(
        snapshot
            .totals_by_write_class
            .get(&MediaWriteClass::PredictorCheckpoint)
            .expect("predictor checkpoint totals")
            .conservative_unknown_media_bytes,
        100
    );

    assert_eq!(
        media_class_weight_is_allocator_hint_only(DeviceMediaClass::Nvme),
        DeviceMediaClass::Nvme.class_weight()
    );
}

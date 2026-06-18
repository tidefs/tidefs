// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_kernel_cutover_runtime::{
    teardown_proof_review_receipt, TeardownProofReviewError, TeardownProofReviewState,
    TeardownTokenState, TeardownWorkCase, KERNEL_TEARDOWN_NO_WORK_AFTER_CLAIM_ID,
    TEARDOWN_PROOF_SOURCE_ARTIFACT_SHA256, TEARDOWN_PROOF_VALIDATION_TIER,
};

#[test]
fn receipt_records_claim_scope_and_runtime_boundary() {
    let receipt = teardown_proof_review_receipt();

    assert_eq!(receipt.claim_id, KERNEL_TEARDOWN_NO_WORK_AFTER_CLAIM_ID);
    assert_eq!(receipt.evidence_class, "claims-gate-review");
    assert_eq!(receipt.source_artifact_digest_algorithm, "sha256");
    assert_eq!(
        receipt.source_artifact_digest,
        TEARDOWN_PROOF_SOURCE_ARTIFACT_SHA256
    );
    assert_eq!(receipt.validation_tier, TEARDOWN_PROOF_VALIDATION_TIER);
    assert!(receipt.source_model_evidence);
    assert!(!receipt.mounted_linux_runtime_evidence);
    assert!(receipt.evidence_boundary.contains("source/model"));
    assert!(receipt
        .evidence_boundary
        .contains("not mounted Linux runtime"));
    assert_eq!(
        receipt.token_states_covered,
        &[
            TeardownTokenState::Accepting,
            TeardownTokenState::Draining,
            TeardownTokenState::TornDown
        ]
    );
    assert!(receipt
        .forbidden_post_teardown_work_cases
        .contains(&TeardownWorkCase::DeferredWritebackEnqueue));
    assert!(receipt
        .missing_runtime_evidence
        .iter()
        .any(|item| item.contains("T5 mounted-kernel")));
    assert!(receipt
        .missing_runtime_evidence
        .iter()
        .any(|item| item.contains("T6 mounted kernel")));
}

#[test]
fn no_work_can_be_recorded_after_final_teardown() {
    let mut state = TeardownProofReviewState::new();
    let live_token = state.current_token();

    state
        .record_work(live_token, TeardownWorkCase::DeferredFlushEnqueue)
        .unwrap();
    state.begin_teardown().unwrap();
    state.complete_teardown().unwrap();

    let torn_down_token = state.current_token();
    let before = state.recorded_work_count();
    assert_eq!(
        state.record_work(torn_down_token, TeardownWorkCase::DeferredWritebackEnqueue),
        Err(TeardownProofReviewError::WorkRejectedAfterTeardown {
            token_state: TeardownTokenState::TornDown,
            work_case: TeardownWorkCase::DeferredWritebackEnqueue,
        })
    );
    assert_eq!(state.recorded_work_count(), before);
}

#[test]
fn stale_token_generations_are_rejected() {
    let mut state = TeardownProofReviewState::new();
    let stale_token = state.current_token();

    state.begin_teardown().unwrap();
    state.complete_teardown().unwrap();

    assert_eq!(
        state.record_work(stale_token, TeardownWorkCase::QueuedWorkStart),
        Err(TeardownProofReviewError::StaleTokenGeneration {
            expected: 1,
            actual: 0,
        })
    );
    assert_eq!(state.recorded_work_count(), 0);
}

#[test]
fn teardown_start_rejects_new_work_before_final_state() {
    let mut state = TeardownProofReviewState::new();
    let token = state.current_token();

    state.begin_teardown().unwrap();

    assert_eq!(
        state.record_work(token, TeardownWorkCase::TeardownCallbackNormalWork),
        Err(TeardownProofReviewError::WorkRejectedAfterTeardown {
            token_state: TeardownTokenState::Draining,
            work_case: TeardownWorkCase::TeardownCallbackNormalWork,
        })
    );
    assert_eq!(state.recorded_work_count(), 0);
}

#[test]
fn fixture_and_claim_registry_cite_review_receipt_without_validation() {
    let fixture = include_str!(
        "../../../validation/artifacts/kernel/teardown-no-work-after-claims-gate-review.toml"
    );
    let claims = include_str!("../../../validation/claims.toml");

    assert!(fixture.contains(KERNEL_TEARDOWN_NO_WORK_AFTER_CLAIM_ID));
    assert!(fixture.contains(TEARDOWN_PROOF_SOURCE_ARTIFACT_SHA256));
    assert!(fixture.contains(TEARDOWN_PROOF_VALIDATION_TIER));
    assert!(fixture.contains("mounted_linux_runtime_evidence = false"));
    assert!(fixture.contains("T5 mounted-kernel"));
    assert!(fixture.contains("T6 mounted kernel"));
    assert!(claims.contains("id = \"kernel.teardown.no_work_after.v1\""));
    assert!(claims.contains("status = \"blocked\""));
    assert!(claims
        .contains("validation/artifacts/kernel/teardown-no-work-after-claims-gate-review.toml"));
    assert!(!claims.contains("status = \"validated\"\nscope = \"kernel teardown"));
}

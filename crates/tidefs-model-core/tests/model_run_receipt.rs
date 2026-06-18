use tidefs_model_core::{
    ModelRunEvidenceScope, ModelRunReceipt, ModelRunReceiptValidationError, ModelRunValidationTier,
};
use tidefs_types_vfs_core::TIDE_CONTRACT_VERSION_V1;

fn valid_receipt() -> ModelRunReceipt {
    ModelRunReceipt::model_only(
        [
            "trace.rename_atomicity.v1",
            "local.vfs.write_fsync_crash.v1",
            "trace.rename_atomicity.v1",
        ],
        "tidefs-model-core 0.421.0",
        TIDE_CONTRACT_VERSION_V1,
        "sha256:9a7a7f4d1a9d0c18",
        "model-fingerprint:5df31a7b",
        ["write", "create", "sync", "read", "write"],
        "model replay is in-memory and carries no mounted runtime artifact",
    )
    .unwrap()
}

#[test]
fn model_run_receipt_serialization_is_deterministic() {
    let json = valid_receipt().to_canonical_json().unwrap();

    assert_eq!(
        json,
        r#"{
  "claim_ids": [
    "local.vfs.write_fsync_crash.v1",
    "trace.rename_atomicity.v1"
  ],
  "model_backend_version": "tidefs-model-core 0.421.0",
  "request_contract_version": 1,
  "input_digest": "sha256:9a7a7f4d1a9d0c18",
  "output_fingerprint": "model-fingerprint:5df31a7b",
  "operation_coverage": [
    "create",
    "read",
    "sync",
    "write"
  ],
  "validation_tier": "model",
  "evidence_scope": {
    "kind": "model-only",
    "reason": "model replay is in-memory and carries no mounted runtime artifact"
  }
}"#
    );
}

#[test]
fn receipt_validation_rejects_missing_claim_ids() {
    let mut receipt = valid_receipt();
    receipt.claim_ids.clear();

    assert_eq!(
        receipt.validate(),
        Err(ModelRunReceiptValidationError::MissingClaimIds)
    );
}

#[test]
fn receipt_validation_rejects_empty_claim_ids() {
    let mut receipt = valid_receipt();
    receipt.claim_ids.push(" ".to_string());

    assert_eq!(
        receipt.validate(),
        Err(ModelRunReceiptValidationError::EmptyClaimId)
    );
}

#[test]
fn receipt_validation_rejects_missing_input_digest() {
    let mut receipt = valid_receipt();
    receipt.input_digest.clear();

    assert_eq!(
        receipt.validate(),
        Err(ModelRunReceiptValidationError::MissingInputDigest)
    );
}

#[test]
fn receipt_validation_rejects_empty_operation_coverage() {
    let mut receipt = valid_receipt();
    receipt.operation_coverage.clear();

    assert_eq!(
        receipt.validate(),
        Err(ModelRunReceiptValidationError::EmptyOperationCoverage)
    );
}

#[test]
fn receipt_validation_rejects_unknown_operation_coverage() {
    let mut receipt = valid_receipt();
    receipt
        .operation_coverage
        .push("runtime-remount".to_string());

    assert_eq!(
        receipt.validate(),
        Err(ModelRunReceiptValidationError::UnknownOperationCoverage {
            operation: "runtime-remount".to_string()
        })
    );
}

#[test]
fn receipt_validation_rejects_runtime_tier_labels() {
    let mut receipt = valid_receipt();
    receipt.validation_tier = ModelRunValidationTier::RuntimeCrashOracle;

    assert_eq!(
        receipt.validate(),
        Err(ModelRunReceiptValidationError::RuntimeTierForModelReceipt {
            tier: ModelRunValidationTier::RuntimeCrashOracle
        })
    );
}

#[test]
fn receipt_validation_rejects_model_runtime_scope_confusion() {
    let mut receipt = valid_receipt();
    receipt.evidence_scope = ModelRunEvidenceScope::ModelAndRuntime;

    assert_eq!(
        receipt.validate(),
        Err(
            ModelRunReceiptValidationError::RuntimeScopeForModelReceipt {
                scope: tidefs_model_core::ModelRunEvidenceScopeKind::ModelAndRuntime
            }
        )
    );
}

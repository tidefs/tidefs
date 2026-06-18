//! Claim-scoped model run receipts.
//!
//! The receipt records deterministic model evidence only. It carries claim
//! references and model fingerprints without naming local runtime paths,
//! runtime artifacts, or claim status elevation.

use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};
use tidefs_types_vfs_core::ContractVersion;

/// Canonical operation names covered by `tidefs-model-core` receipts.
pub const MODEL_RUN_RECEIPT_KNOWN_OPERATIONS: &[&str] = &[
    "create", "getattr", "link", "mkdir", "read", "rename", "sync", "truncate", "unlink", "write",
];

/// Claim-scoped receipt for one pure model run.
///
/// The record is intentionally storage-free: callers provide digests,
/// fingerprints, claim ids, and operation coverage as portable strings. A
/// valid receipt is model-tier evidence only unless separate runtime artifacts
/// are paired elsewhere by the claim validation layer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelRunReceipt {
    pub claim_ids: Vec<String>,
    pub model_backend_version: String,
    pub request_contract_version: u16,
    pub input_digest: String,
    pub output_fingerprint: String,
    pub operation_coverage: Vec<String>,
    pub validation_tier: ModelRunValidationTier,
    pub evidence_scope: ModelRunEvidenceScope,
}

impl ModelRunReceipt {
    /// Build a canonical model-only receipt from caller-supplied metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ModelRunReceiptValidationError`] when any field would confuse
    /// model evidence with runtime evidence or when required coverage metadata
    /// is absent.
    pub fn model_only<C, O, Claim, Operation>(
        claim_ids: C,
        model_backend_version: impl Into<String>,
        request_contract_version: ContractVersion,
        input_digest: impl Into<String>,
        output_fingerprint: impl Into<String>,
        operation_coverage: O,
        model_tier_only_reason: impl Into<String>,
    ) -> Result<Self, ModelRunReceiptValidationError>
    where
        C: IntoIterator<Item = Claim>,
        O: IntoIterator<Item = Operation>,
        Claim: Into<String>,
        Operation: Into<String>,
    {
        let receipt = Self {
            claim_ids: claim_ids.into_iter().map(Into::into).collect(),
            model_backend_version: model_backend_version.into(),
            request_contract_version: request_contract_version.raw(),
            input_digest: input_digest.into(),
            output_fingerprint: output_fingerprint.into(),
            operation_coverage: operation_coverage.into_iter().map(Into::into).collect(),
            validation_tier: ModelRunValidationTier::Model,
            evidence_scope: ModelRunEvidenceScope::ModelOnly {
                reason: model_tier_only_reason.into(),
            },
        }
        .canonicalized();

        receipt.validate()?;
        Ok(receipt)
    }

    /// Return a stable copy with set-like fields sorted and deduplicated.
    #[must_use]
    pub fn canonicalized(&self) -> Self {
        let mut out = self.clone();
        normalize_string_set(&mut out.claim_ids);
        normalize_string_set(&mut out.operation_coverage);
        out.model_backend_version = out.model_backend_version.trim().to_string();
        out.input_digest = out.input_digest.trim().to_string();
        out.output_fingerprint = out.output_fingerprint.trim().to_string();
        if let ModelRunEvidenceScope::ModelOnly { reason } = &mut out.evidence_scope {
            *reason = reason.trim().to_string();
        }
        out
    }

    /// Validate the receipt without reading or resolving runtime storage.
    ///
    /// # Errors
    ///
    /// Rejects missing claims, missing digests, empty or unknown operation
    /// coverage, and any runtime-tier label on this pure model receipt.
    pub fn validate(&self) -> Result<(), ModelRunReceiptValidationError> {
        let receipt = self.canonicalized();

        if receipt.claim_ids.is_empty() {
            return Err(ModelRunReceiptValidationError::MissingClaimIds);
        }
        if receipt.claim_ids.iter().any(|claim_id| claim_id.is_empty()) {
            return Err(ModelRunReceiptValidationError::EmptyClaimId);
        }
        if receipt.model_backend_version.is_empty() {
            return Err(ModelRunReceiptValidationError::MissingModelBackendVersion);
        }
        if receipt.request_contract_version == 0 {
            return Err(ModelRunReceiptValidationError::MissingRequestContractVersion);
        }
        if receipt.input_digest.is_empty() {
            return Err(ModelRunReceiptValidationError::MissingInputDigest);
        }
        if receipt.output_fingerprint.is_empty() {
            return Err(ModelRunReceiptValidationError::MissingOutputFingerprint);
        }
        if receipt.operation_coverage.is_empty() {
            return Err(ModelRunReceiptValidationError::EmptyOperationCoverage);
        }
        for operation in &receipt.operation_coverage {
            if operation.is_empty() || !is_known_model_operation(operation) {
                return Err(ModelRunReceiptValidationError::UnknownOperationCoverage {
                    operation: operation.clone(),
                });
            }
        }

        if receipt.validation_tier != ModelRunValidationTier::Model {
            return Err(ModelRunReceiptValidationError::RuntimeTierForModelReceipt {
                tier: receipt.validation_tier,
            });
        }

        match &receipt.evidence_scope {
            ModelRunEvidenceScope::ModelOnly { reason } if reason.is_empty() => {
                Err(ModelRunReceiptValidationError::MissingModelOnlyReason)
            }
            ModelRunEvidenceScope::ModelOnly { .. } => Ok(()),
            scope => Err(
                ModelRunReceiptValidationError::RuntimeScopeForModelReceipt {
                    scope: scope.kind(),
                },
            ),
        }
    }

    /// Serialize a valid canonical receipt as stable pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns [`ModelRunReceiptSerializeError`] if validation fails or JSON
    /// serialization cannot complete.
    pub fn to_canonical_json(&self) -> Result<String, ModelRunReceiptSerializeError> {
        let receipt = self.canonicalized();
        receipt
            .validate()
            .map_err(ModelRunReceiptSerializeError::Invalid)?;
        serde_json::to_string_pretty(&receipt).map_err(ModelRunReceiptSerializeError::Json)
    }
}

/// Validation tier named by a model receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelRunValidationTier {
    Model,
    Runtime,
    RuntimeTraceOracle,
    RuntimeCrashOracle,
}

impl ModelRunValidationTier {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Runtime => "runtime",
            Self::RuntimeTraceOracle => "runtime-trace-oracle",
            Self::RuntimeCrashOracle => "runtime-crash-oracle",
        }
    }
}

impl fmt::Display for ModelRunValidationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Evidence scope declared by a model receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ModelRunEvidenceScope {
    ModelOnly { reason: String },
    RuntimeArtifact,
    ModelAndRuntime,
}

impl ModelRunEvidenceScope {
    #[must_use]
    pub const fn kind(&self) -> ModelRunEvidenceScopeKind {
        match self {
            Self::ModelOnly { .. } => ModelRunEvidenceScopeKind::ModelOnly,
            Self::RuntimeArtifact => ModelRunEvidenceScopeKind::RuntimeArtifact,
            Self::ModelAndRuntime => ModelRunEvidenceScopeKind::ModelAndRuntime,
        }
    }
}

/// Stable evidence-scope label for validation diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelRunEvidenceScopeKind {
    ModelOnly,
    RuntimeArtifact,
    ModelAndRuntime,
}

impl ModelRunEvidenceScopeKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelOnly => "model-only",
            Self::RuntimeArtifact => "runtime-artifact",
            Self::ModelAndRuntime => "model-and-runtime",
        }
    }
}

impl fmt::Display for ModelRunEvidenceScopeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Receipt validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelRunReceiptValidationError {
    MissingClaimIds,
    EmptyClaimId,
    MissingModelBackendVersion,
    MissingRequestContractVersion,
    MissingInputDigest,
    MissingOutputFingerprint,
    EmptyOperationCoverage,
    UnknownOperationCoverage { operation: String },
    RuntimeTierForModelReceipt { tier: ModelRunValidationTier },
    RuntimeScopeForModelReceipt { scope: ModelRunEvidenceScopeKind },
    MissingModelOnlyReason,
}

impl fmt::Display for ModelRunReceiptValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingClaimIds => f.write_str("model run receipt has no claim ids"),
            Self::EmptyClaimId => f.write_str("model run receipt has an empty claim id"),
            Self::MissingModelBackendVersion => {
                f.write_str("model run receipt is missing model backend version")
            }
            Self::MissingRequestContractVersion => {
                f.write_str("model run receipt is missing request contract version")
            }
            Self::MissingInputDigest => f.write_str("model run receipt is missing input digest"),
            Self::MissingOutputFingerprint => {
                f.write_str("model run receipt is missing output fingerprint")
            }
            Self::EmptyOperationCoverage => {
                f.write_str("model run receipt has no operation coverage")
            }
            Self::UnknownOperationCoverage { operation } => {
                write!(
                    f,
                    "model run receipt names unknown operation coverage `{operation}`"
                )
            }
            Self::RuntimeTierForModelReceipt { tier } => write!(
                f,
                "model run receipt cannot claim runtime validation tier `{tier}`"
            ),
            Self::RuntimeScopeForModelReceipt { scope } => {
                write!(f, "model run receipt cannot claim evidence scope `{scope}`")
            }
            Self::MissingModelOnlyReason => {
                f.write_str("model run receipt is missing its model-only evidence reason")
            }
        }
    }
}

impl Error for ModelRunReceiptValidationError {}

/// Canonical serialization failure.
#[derive(Debug)]
pub enum ModelRunReceiptSerializeError {
    Invalid(ModelRunReceiptValidationError),
    Json(serde_json::Error),
}

impl fmt::Display for ModelRunReceiptSerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => write!(f, "invalid model run receipt: {error}"),
            Self::Json(error) => write!(f, "serialize model run receipt: {error}"),
        }
    }
}

impl Error for ModelRunReceiptSerializeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invalid(error) => Some(error),
            Self::Json(error) => Some(error),
        }
    }
}

#[must_use]
pub fn is_known_model_operation(operation: &str) -> bool {
    MODEL_RUN_RECEIPT_KNOWN_OPERATIONS
        .binary_search(&operation)
        .is_ok()
}

fn normalize_string_set(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        *value = value.trim().to_string();
    }
    values.sort();
    values.dedup();
}

// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Claims-gate review helpers for kernel teardown source-model evidence.

pub const KERNEL_TEARDOWN_NO_WORK_AFTER_CLAIM_ID: &str = "kernel.teardown.no_work_after.v1";
pub const TEARDOWN_PROOF_SOURCE_ARTIFACT_PATH: &str =
    "validation/artifacts/kernel/teardown-race-proof-artifact.json";
pub const TEARDOWN_PROOF_SOURCE_ARTIFACT_SHA256: &str =
    "af34e9e782ff656690d84990b3f5cb339744e206c0f5c0702af012bfe8f1f6ed";
pub const TEARDOWN_PROOF_VALIDATION_TIER: &str = "T4 source/model claims-gate review";
pub const TEARDOWN_PROOF_EVIDENCE_BOUNDARY: &str =
    "source/model proof review only; not mounted Linux runtime evidence";

pub const TEARDOWN_PROOF_TOKEN_STATES_COVERED: &[TeardownTokenState] = &[
    TeardownTokenState::Accepting,
    TeardownTokenState::Draining,
    TeardownTokenState::TornDown,
];

pub const TEARDOWN_PROOF_FORBIDDEN_WORK_CASES: &[TeardownWorkCase] = &[
    TeardownWorkCase::DeferredWritebackEnqueue,
    TeardownWorkCase::DeferredFlushEnqueue,
    TeardownWorkCase::QueuedWorkStart,
    TeardownWorkCase::KernelCallbackBorrow,
    TeardownWorkCase::TeardownCallbackNormalWork,
];

pub const TEARDOWN_PROOF_MISSING_RUNTIME_EVIDENCE: &[&str] = &[
    "T5 mounted-kernel teardown stress with Linux workqueue and callback activity tracing",
    "T6 mounted kernel I/O teardown and recovery rows across the filesystem runtime",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TeardownTokenState {
    Accepting,
    Draining,
    TornDown,
}

impl TeardownTokenState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepting => "accepting",
            Self::Draining => "draining",
            Self::TornDown => "torn-down",
        }
    }

    #[must_use]
    pub const fn allows_new_work(self) -> bool {
        matches!(self, Self::Accepting)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TeardownWorkCase {
    DeferredWritebackEnqueue,
    DeferredFlushEnqueue,
    QueuedWorkStart,
    KernelCallbackBorrow,
    TeardownCallbackNormalWork,
}

impl TeardownWorkCase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeferredWritebackEnqueue => "deferred-writeback-enqueue",
            Self::DeferredFlushEnqueue => "deferred-flush-enqueue",
            Self::QueuedWorkStart => "queued-work-start",
            Self::KernelCallbackBorrow => "kernel-callback-borrow",
            Self::TeardownCallbackNormalWork => "teardown-callback-normal-work",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TeardownGenerationToken {
    generation: u64,
}

impl TeardownGenerationToken {
    #[must_use]
    pub const fn new(generation: u64) -> Self {
        Self { generation }
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TeardownRecordedWork {
    pub token_generation: u64,
    pub work_case: TeardownWorkCase,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeardownProofReviewState {
    token_state: TeardownTokenState,
    generation: u64,
    recorded_work: Vec<TeardownRecordedWork>,
}

impl TeardownProofReviewState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            token_state: TeardownTokenState::Accepting,
            generation: 0,
            recorded_work: Vec::new(),
        }
    }

    #[must_use]
    pub const fn token_state(&self) -> TeardownTokenState {
        self.token_state
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn current_token(&self) -> TeardownGenerationToken {
        TeardownGenerationToken::new(self.generation)
    }

    #[must_use]
    pub fn recorded_work(&self) -> &[TeardownRecordedWork] {
        &self.recorded_work
    }

    #[must_use]
    pub fn recorded_work_count(&self) -> usize {
        self.recorded_work.len()
    }

    pub fn record_work(
        &mut self,
        token: TeardownGenerationToken,
        work_case: TeardownWorkCase,
    ) -> Result<(), TeardownProofReviewError> {
        if token.generation != self.generation {
            return Err(TeardownProofReviewError::StaleTokenGeneration {
                expected: self.generation,
                actual: token.generation,
            });
        }
        if !self.token_state.allows_new_work() {
            return Err(TeardownProofReviewError::WorkRejectedAfterTeardown {
                token_state: self.token_state,
                work_case,
            });
        }

        self.recorded_work.push(TeardownRecordedWork {
            token_generation: token.generation,
            work_case,
        });
        Ok(())
    }

    pub fn begin_teardown(&mut self) -> Result<(), TeardownProofReviewError> {
        match self.token_state {
            TeardownTokenState::Accepting => {
                self.token_state = TeardownTokenState::Draining;
                Ok(())
            }
            TeardownTokenState::Draining => Err(TeardownProofReviewError::TeardownAlreadyDraining),
            TeardownTokenState::TornDown => Err(TeardownProofReviewError::TeardownAlreadyComplete),
        }
    }

    pub fn complete_teardown(&mut self) -> Result<(), TeardownProofReviewError> {
        match self.token_state {
            TeardownTokenState::Draining => {
                self.generation = self
                    .generation
                    .checked_add(1)
                    .ok_or(TeardownProofReviewError::TokenGenerationOverflow)?;
                self.token_state = TeardownTokenState::TornDown;
                Ok(())
            }
            TeardownTokenState::Accepting => Err(TeardownProofReviewError::TeardownNotDraining),
            TeardownTokenState::TornDown => Err(TeardownProofReviewError::TeardownAlreadyComplete),
        }
    }
}

impl Default for TeardownProofReviewState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TeardownProofReviewError {
    StaleTokenGeneration {
        expected: u64,
        actual: u64,
    },
    WorkRejectedAfterTeardown {
        token_state: TeardownTokenState,
        work_case: TeardownWorkCase,
    },
    TeardownAlreadyDraining,
    TeardownAlreadyComplete,
    TeardownNotDraining,
    TokenGenerationOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TeardownProofReviewReceipt {
    pub claim_id: &'static str,
    pub evidence_class: &'static str,
    pub source_artifact_path: &'static str,
    pub source_artifact_digest_algorithm: &'static str,
    pub source_artifact_digest: &'static str,
    pub validation_tier: &'static str,
    pub source_model_evidence: bool,
    pub mounted_linux_runtime_evidence: bool,
    pub evidence_boundary: &'static str,
    pub token_states_covered: &'static [TeardownTokenState],
    pub forbidden_post_teardown_work_cases: &'static [TeardownWorkCase],
    pub missing_runtime_evidence: &'static [&'static str],
}

#[must_use]
pub const fn teardown_proof_review_receipt() -> TeardownProofReviewReceipt {
    TeardownProofReviewReceipt {
        claim_id: KERNEL_TEARDOWN_NO_WORK_AFTER_CLAIM_ID,
        evidence_class: "claims-gate-review",
        source_artifact_path: TEARDOWN_PROOF_SOURCE_ARTIFACT_PATH,
        source_artifact_digest_algorithm: "sha256",
        source_artifact_digest: TEARDOWN_PROOF_SOURCE_ARTIFACT_SHA256,
        validation_tier: TEARDOWN_PROOF_VALIDATION_TIER,
        source_model_evidence: true,
        mounted_linux_runtime_evidence: false,
        evidence_boundary: TEARDOWN_PROOF_EVIDENCE_BOUNDARY,
        token_states_covered: TEARDOWN_PROOF_TOKEN_STATES_COVERED,
        forbidden_post_teardown_work_cases: TEARDOWN_PROOF_FORBIDDEN_WORK_CASES,
        missing_runtime_evidence: TEARDOWN_PROOF_MISSING_RUNTIME_EVIDENCE,
    }
}

//! BLAKE3-verified kernel cutover validation harness.
//! Domain: tidefs-kernel-cutover-validation-v1
//!
//! Exercises the full cutover lifecycle with deterministic state digests:
//! - Pre-cutover state snapshot
//! - Userspace-to-kernel transition with BLAKE3-256 digest chain
//! - Post-cutover state verification
//! - Rollback symmetry with state restoration validation
//! - Error-injection paths (mid-transition failure, partial state recovery)
//! - Concurrent operation isolation
//! - Committed-root chain integrity across the cutover boundary

use tidefs_kernel_cutover_runtime::{
    AlwaysAdmitGate, AlwaysRefuseGate, CutoverExecutor, CutoverFenceKind, CutoverFenceToken,
    CutoverGateResult, CutoverRuntimeError, CutoverState, CutoverStep, CutoverTransition,
    FenceManager, KernelMode, RollbackPlan, StepOutcome,
};

const DOMAIN: &str = "tidefs-kernel-cutover-validation-v1";

// ---- State digest helpers ----

/// Compute a domain-separated BLAKE3-256 digest of a CutoverState.
fn state_digest(state: &CutoverState) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DOMAIN);
    h.update(&[state.current_mode as u8]);
    if let Some(tm) = state.target_mode {
        h.update(&[1u8]);
        h.update(&[tm as u8]);
    } else {
        h.update(&[0u8]);
    }
    if let Some(step) = state.current_step {
        h.update(&[1u8]);
        h.update(&[step as u8]);
    } else {
        h.update(&[0u8]);
    }
    if let Some(ref plan) = state.rollback_plan {
        h.update(&[1u8]);
        h.update(&[plan.restore_mode as u8]);
        h.update(&[plan.preserve_validation as u8]);
        h.update(&[plan.reopen_admission as u8]);
    } else {
        h.update(&[0u8]);
    }
    if let Some(token) = state.held_fence {
        h.update(&[1u8]);
        h.update(&token.0);
    } else {
        h.update(&[0u8]);
    }
    h.finalize().into()
}

/// Domain-separated digest of a CutoverTransition.
fn transition_digest(t: CutoverTransition) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DOMAIN);
    h.update(b"transition");
    h.update(&[t.from as u8, t.to as u8]);
    h.finalize().into()
}

/// Domain-separated digest of a FenceManager (captures held state).
fn fence_manager_digest(fm: &FenceManager) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DOMAIN);
    h.update(b"fence-manager");
    h.update(&[fm.has_fence() as u8]);
    if let Some(kind) = fm.held_kind() {
        h.update(&[kind as u8]);
    }
    h.finalize().into()
}

/// Full executor digest: combines state + fence manager digests.
fn executor_digest<G: tidefs_kernel_cutover_runtime::CutoverGateEvaluator>(
    ex: &CutoverExecutor<G>,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DOMAIN);
    h.update(b"executor");
    h.update(&state_digest(ex.state()));
    h.update(&fence_manager_digest(ex.fence_manager()));
    h.finalize().into()
}

/// Digest of a step sequence: each step's ordinal fed in order.
fn step_chain_digest(steps: &[CutoverStep]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DOMAIN);
    h.update(b"step-chain");
    for s in steps {
        h.update(&[*s as u8]);
    }
    h.finalize().into()
}

// ---- Snapshot determinism tests ----

#[test]
fn snapshot_determinism_same_state() {
    let s1 = CutoverState::idle_at(KernelMode::Userspace);
    let s2 = CutoverState::idle_at(KernelMode::Userspace);
    assert_eq!(state_digest(&s1), state_digest(&s2));
}

#[test]
fn snapshot_uniqueness_different_mode() {
    let s1 = CutoverState::idle_at(KernelMode::Userspace);
    let s2 = CutoverState::idle_at(KernelMode::MixedPosixRead);
    assert_ne!(state_digest(&s1), state_digest(&s2));
}

#[test]
fn snapshot_uniqueness_in_progress() {
    let mut s = CutoverState::idle_at(KernelMode::Userspace);
    let idle_digest = state_digest(&s);
    s.target_mode = Some(KernelMode::MixedPosixRead);
    s.current_step = Some(CutoverStep::Intent);
    let in_progress_digest = state_digest(&s);
    assert_ne!(idle_digest, in_progress_digest);
}

#[test]
fn snapshot_uniqueness_with_rollback_plan() {
    let mut s = CutoverState::idle_at(KernelMode::Userspace);
    let no_plan = state_digest(&s);
    s.rollback_plan = Some(RollbackPlan::new(KernelMode::Userspace));
    let with_plan = state_digest(&s);
    assert_ne!(no_plan, with_plan);
}

#[test]
fn domain_separation_produces_different_digests() {
    let s = CutoverState::idle_at(KernelMode::Userspace);
    let d1 = state_digest(&s);
    let mut h = blake3::Hasher::new_derive_key("other-domain-v1");
    h.update(&[s.current_mode as u8]);
    h.update(&[0u8; 4]);
    let d2: [u8; 32] = h.finalize().into();
    assert_ne!(d1, d2);
}

// ---- Full transition lifecycle tests ----

#[test]
fn full_cutover_userspace_to_mixed_posix_read_deterministic() {
    let pre_state = CutoverState::idle_at(KernelMode::Userspace);
    let pre_digest = state_digest(&pre_state);

    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();

    assert_eq!(
        ex.advance(),
        Ok(StepOutcome::Advanced(CutoverStep::PreflightSnapshot))
    );
    assert_eq!(
        ex.advance(),
        Ok(StepOutcome::Advanced(CutoverStep::DryRunGate))
    );
    assert_eq!(
        ex.advance(),
        Ok(StepOutcome::Advanced(CutoverStep::StageFencePrepare))
    );
    assert_eq!(
        ex.advance(),
        Ok(StepOutcome::Advanced(CutoverStep::CommitTransition))
    );
    assert_eq!(
        ex.advance(),
        Ok(StepOutcome::Advanced(CutoverStep::VerifyTruth))
    );
    assert_eq!(
        ex.advance(),
        Ok(StepOutcome::Advanced(CutoverStep::CloseOrReenter))
    );
    assert_eq!(
        ex.advance(),
        Ok(StepOutcome::Completed {
            final_mode: KernelMode::MixedPosixRead
        })
    );

    let post_state = ex.state();
    assert_eq!(post_state.current_mode, KernelMode::MixedPosixRead);
    assert!(post_state.is_complete());
    assert_ne!(pre_digest, state_digest(post_state));
}

#[test]
fn full_cutover_mixed_posix_read_to_mixed_full_client() {
    let mut ex = CutoverExecutor::new(KernelMode::MixedPosixRead, AlwaysAdmitGate);
    let pre_digest = executor_digest(&ex);

    ex.begin_cutover(KernelMode::MixedFullClient).unwrap();
    for _ in 0..7 {
        ex.advance().unwrap();
    }

    assert_eq!(ex.state().current_mode, KernelMode::MixedFullClient);
    assert!(ex.state().is_complete());
    assert_ne!(pre_digest, executor_digest(&ex));
}

#[test]
fn full_cutover_mixed_full_client_to_full_kernel() {
    let mut ex = CutoverExecutor::new(KernelMode::MixedFullClient, AlwaysAdmitGate);
    let pre_digest = executor_digest(&ex);

    ex.begin_cutover(KernelMode::FullKernel).unwrap();
    for _ in 0..7 {
        ex.advance().unwrap();
    }

    assert_eq!(ex.state().current_mode, KernelMode::FullKernel);
    assert!(ex.state().is_complete());
    assert_ne!(pre_digest, executor_digest(&ex));
}

#[test]
fn cutover_chain_all_four_modes_forward() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);

    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    for _ in 0..7 {
        ex.advance().unwrap();
    }
    assert_eq!(ex.state().current_mode, KernelMode::MixedPosixRead);

    ex.begin_cutover(KernelMode::MixedFullClient).unwrap();
    for _ in 0..7 {
        ex.advance().unwrap();
    }
    assert_eq!(ex.state().current_mode, KernelMode::MixedFullClient);

    ex.begin_cutover(KernelMode::FullKernel).unwrap();
    for _ in 0..7 {
        ex.advance().unwrap();
    }
    assert_eq!(ex.state().current_mode, KernelMode::FullKernel);
    assert!(ex.state().is_complete());
}

#[test]
fn cutover_chain_all_four_modes_rollback() {
    let mut ex = CutoverExecutor::new(KernelMode::FullKernel, AlwaysAdmitGate);

    ex.begin_cutover(KernelMode::MixedFullClient).unwrap();
    for _ in 0..7 {
        ex.advance().unwrap();
    }
    assert_eq!(ex.state().current_mode, KernelMode::MixedFullClient);

    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    for _ in 0..7 {
        ex.advance().unwrap();
    }
    assert_eq!(ex.state().current_mode, KernelMode::MixedPosixRead);

    ex.begin_cutover(KernelMode::Userspace).unwrap();
    for _ in 0..7 {
        ex.advance().unwrap();
    }
    assert_eq!(ex.state().current_mode, KernelMode::Userspace);
}

#[test]
fn intermediate_state_digests_form_chain() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    let mut chain: Vec<[u8; 32]> = Vec::new();

    chain.push(state_digest(ex.state()));

    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    chain.push(state_digest(ex.state()));

    for _ in 0..7 {
        ex.advance().unwrap();
        chain.push(state_digest(ex.state()));
    }

    assert_eq!(chain.len(), 9);

    for w in chain.windows(2) {
        assert_ne!(w[0], w[1], "adjacent chain digests must differ");
    }

    assert_ne!(chain[0], chain[chain.len() - 1]);

    // Replay determinism
    let mut ex2 = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    assert_eq!(state_digest(ex2.state()), chain[0]);

    ex2.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    assert_eq!(state_digest(ex2.state()), chain[1]);

    for i in 0..7 {
        ex2.advance().unwrap();
        assert_eq!(
            state_digest(ex2.state()),
            chain[i + 2],
            "chain digest mismatch at position {i}"
        );
    }
}

// ---- Rollback & recovery tests ----

#[test]
fn rollback_at_preflight_snapshot_restores_state() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);

    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    ex.advance().unwrap();

    let receipt = ex.execute_rollback().unwrap();
    assert_eq!(receipt.restored_mode, KernelMode::Userspace);
    assert!(receipt.validation_preserved);
    assert!(receipt.admission_reopened);
    assert!(ex.state().is_idle());
    assert_eq!(
        state_digest(ex.state()),
        state_digest(&CutoverState::idle_at(KernelMode::Userspace))
    );
}

#[test]
fn rollback_at_stage_fence_restores_and_releases_fence() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);

    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    for _ in 0..4 {
        ex.advance().unwrap();
    }

    assert!(ex.fence_manager().has_fence());

    let receipt = ex.execute_rollback().unwrap();
    assert_eq!(receipt.restored_mode, KernelMode::Userspace);
    assert!(!ex.fence_manager().has_fence());
    assert!(ex.state().is_idle());
}

#[test]
fn rollback_at_verify_truth_restores_and_releases_fence() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);

    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    for _ in 0..6 {
        ex.advance().unwrap();
    }

    assert_eq!(ex.state().current_mode, KernelMode::MixedPosixRead);
    assert!(ex.fence_manager().has_fence());

    let receipt = ex.execute_rollback().unwrap();
    assert_eq!(receipt.restored_mode, KernelMode::Userspace);
    assert!(!ex.fence_manager().has_fence());
    assert!(ex.state().is_idle());
}

#[test]
fn rollback_symmetry_forward_back_forward() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    for _ in 0..7 {
        ex.advance().unwrap();
    }
    assert_eq!(ex.state().current_mode, KernelMode::MixedPosixRead);

    ex.begin_cutover(KernelMode::Userspace).unwrap();
    for _ in 0..7 {
        ex.advance().unwrap();
    }
    assert_eq!(ex.state().current_mode, KernelMode::Userspace);

    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    for _ in 0..7 {
        ex.advance().unwrap();
    }
    assert_eq!(ex.state().current_mode, KernelMode::MixedPosixRead);
}

#[test]
fn rollback_with_custom_plan_preserves_settings() {
    let mut ex = CutoverExecutor::new(KernelMode::FullKernel, AlwaysAdmitGate);
    ex.set_rollback_plan(RollbackPlan {
        restore_mode: KernelMode::Userspace,
        preserve_validation: false,
        reopen_admission: false,
    });

    ex.begin_cutover(KernelMode::MixedFullClient).unwrap();
    ex.advance().unwrap();

    let receipt = ex.execute_rollback().unwrap();
    assert_eq!(receipt.restored_mode, KernelMode::Userspace);
    assert!(!receipt.validation_preserved);
    assert!(!receipt.admission_reopened);
}

#[test]
fn rollback_without_active_cutover_errors() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    assert_eq!(
        ex.execute_rollback(),
        Err(CutoverRuntimeError::NoActiveCutover)
    );
}

// ---- Error injection tests ----

#[test]
fn gate_refusal_preserves_pre_cutover_state() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysRefuseGate);
    let pre_digest = state_digest(ex.state());

    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    ex.advance().unwrap();
    ex.advance().unwrap();
    assert_eq!(
        ex.advance(),
        Ok(StepOutcome::GateRefused(CutoverGateResult::Refused))
    );

    assert!(ex.state().is_in_progress());
    assert_eq!(ex.state().current_step, Some(CutoverStep::DryRunGate));

    ex.execute_rollback().unwrap();
    assert_eq!(state_digest(ex.state()), pre_digest);
}

#[test]
fn gate_blocked_and_quarantine_results() {
    for result in &[
        CutoverGateResult::Blocked,
        CutoverGateResult::Refused,
        CutoverGateResult::OverrideRequired,
        CutoverGateResult::QuarantineRequired,
    ] {
        assert!(!result.is_admissible());
    }
}

#[test]
fn double_begin_cutover_errors() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    assert_eq!(
        ex.begin_cutover(KernelMode::MixedFullClient),
        Err(CutoverRuntimeError::CutoverAlreadyInProgress)
    );
}

#[test]
fn illegal_transition_skip_modes() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    assert_eq!(
        ex.begin_cutover(KernelMode::FullKernel),
        Err(CutoverRuntimeError::IllegalTransition {
            from: KernelMode::Userspace,
            to: KernelMode::FullKernel,
        })
    );
}

#[test]
fn illegal_transition_non_adjacent() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    assert_eq!(
        ex.begin_cutover(KernelMode::MixedFullClient),
        Err(CutoverRuntimeError::IllegalTransition {
            from: KernelMode::Userspace,
            to: KernelMode::MixedFullClient,
        })
    );
}

#[test]
fn advance_without_active_cutover_errors() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    assert_eq!(ex.advance(), Err(CutoverRuntimeError::NoActiveCutover));
}

#[test]
fn fence_double_acquire_errors() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    for _ in 0..4 {
        ex.advance().unwrap();
    }
    assert!(ex.fence_manager().has_fence());
    assert_eq!(
        ex.fence_manager_mut().acquire(CutoverFenceKind::Quiesce),
        Err(CutoverRuntimeError::FenceAlreadyHeld)
    );
}

#[test]
fn fence_kind_mismatch_on_release() {
    let mut fm = FenceManager::new();
    fm.acquire(CutoverFenceKind::Stage).unwrap();
    assert_eq!(
        fm.release(CutoverFenceKind::Commit),
        Err(CutoverRuntimeError::FenceKindMismatch {
            expected: CutoverFenceKind::Commit,
            held: CutoverFenceKind::Stage,
        })
    );
}

// ---- Concurrent isolation tests ----

#[test]
fn independent_executors_dont_interfere() {
    let mut ex1 = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    let mut ex2 = CutoverExecutor::new(KernelMode::MixedPosixRead, AlwaysAdmitGate);

    let ex1_pre = executor_digest(&ex1);
    let ex2_pre = executor_digest(&ex2);
    assert_ne!(ex1_pre, ex2_pre);

    ex1.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    ex1.advance().unwrap();

    assert_eq!(executor_digest(&ex2), ex2_pre);

    ex2.begin_cutover(KernelMode::MixedFullClient).unwrap();
    for _ in 0..7 {
        ex2.advance().unwrap();
    }
    assert_eq!(ex2.state().current_mode, KernelMode::MixedFullClient);

    assert!(ex1.state().is_in_progress());
    assert_eq!(
        ex1.state().current_step,
        Some(CutoverStep::PreflightSnapshot)
    );
}

#[test]
fn concurrent_full_cutover_digest_isolation() {
    let mut ex_a = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    let mut ex_b = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);

    assert_eq!(executor_digest(&ex_a), executor_digest(&ex_b));

    ex_a.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    for _ in 0..7 {
        ex_a.advance().unwrap();
    }

    ex_b.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    for _ in 0..7 {
        ex_b.advance().unwrap();
    }

    assert_eq!(ex_a.state().current_mode, KernelMode::MixedPosixRead);
    assert_eq!(ex_b.state().current_mode, KernelMode::MixedPosixRead);
    assert_eq!(state_digest(ex_a.state()), state_digest(ex_b.state()));
}

// ---- Committed-root chain integrity tests ----

#[test]
fn committed_root_chain_forward_deterministic() {
    let run1 = {
        let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
        let mut chain: Vec<([u8; 32], CutoverStep)> = Vec::new();

        ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
        for _ in 0..7 {
            let step = ex.state().current_step.unwrap();
            chain.push((state_digest(ex.state()), step));
            ex.advance().unwrap();
        }
        chain
    };

    let run2 = {
        let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
        let mut chain: Vec<([u8; 32], CutoverStep)> = Vec::new();

        ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
        for _ in 0..7 {
            let step = ex.state().current_step.unwrap();
            chain.push((state_digest(ex.state()), step));
            ex.advance().unwrap();
        }
        chain
    };

    assert_eq!(run1.len(), run2.len());
    for i in 0..run1.len() {
        assert_eq!(run1[i], run2[i], "chain divergence at position {i}");
    }
}

#[test]
fn committed_root_chain_rollback_preserves_validation() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    let pre_digest = state_digest(ex.state());

    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    for _ in 0..3 {
        ex.advance().unwrap();
    }

    let at_gate_digest = state_digest(ex.state());
    assert_ne!(pre_digest, at_gate_digest);

    ex.execute_rollback().unwrap();
    assert_eq!(state_digest(ex.state()), pre_digest);
}

#[test]
fn chain_digest_verification_after_partial_rollback() {
    let final_digest_clean = {
        let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
        ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
        for _ in 0..7 {
            ex.advance().unwrap();
        }
        state_digest(ex.state())
    };

    let final_digest_after_rollback = {
        let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
        ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
        for _ in 0..3 {
            ex.advance().unwrap();
        }
        ex.execute_rollback().unwrap();

        ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
        for _ in 0..7 {
            ex.advance().unwrap();
        }
        state_digest(ex.state())
    };

    assert_eq!(final_digest_clean, final_digest_after_rollback);
}

// ---- Fence manager state digest tests ----

#[test]
fn fence_manager_digest_changes_with_acquisition() {
    let mut fm = FenceManager::new();
    let empty_digest = fence_manager_digest(&fm);

    fm.acquire(CutoverFenceKind::Quiesce).unwrap();
    let held_digest = fence_manager_digest(&fm);
    assert_ne!(empty_digest, held_digest);

    fm.release(CutoverFenceKind::Quiesce).unwrap();
    let released_digest = fence_manager_digest(&fm);
    assert_ne!(released_digest, held_digest);
    // Nonce is internal and not hashed; released state matches empty
    assert_eq!(empty_digest, released_digest);
}

#[test]
fn fence_manager_different_kinds_different_digests() {
    let mut fm_q = FenceManager::new();
    fm_q.acquire(CutoverFenceKind::Quiesce).unwrap();
    let quiesce_digest = fence_manager_digest(&fm_q);

    let mut fm_s = FenceManager::new();
    fm_s.acquire(CutoverFenceKind::Stage).unwrap();
    let stage_digest = fence_manager_digest(&fm_s);

    assert_ne!(quiesce_digest, stage_digest);
}

// ---- Transition digest tests ----

#[test]
fn transition_digest_deterministic() {
    let t1 = CutoverTransition::new(KernelMode::Userspace, KernelMode::MixedPosixRead);
    let t2 = CutoverTransition::new(KernelMode::Userspace, KernelMode::MixedPosixRead);
    assert_eq!(transition_digest(t1), transition_digest(t2));
}

#[test]
fn transition_digest_different_directions() {
    let forward = CutoverTransition::new(KernelMode::Userspace, KernelMode::MixedPosixRead);
    let backward = CutoverTransition::new(KernelMode::MixedPosixRead, KernelMode::Userspace);
    assert_ne!(transition_digest(forward), transition_digest(backward));
}

// ---- Step chain tests ----

#[test]
fn step_chain_full_sequence_deterministic() {
    let steps: Vec<CutoverStep> = vec![
        CutoverStep::Intent,
        CutoverStep::PreflightSnapshot,
        CutoverStep::DryRunGate,
        CutoverStep::StageFencePrepare,
        CutoverStep::CommitTransition,
        CutoverStep::VerifyTruth,
        CutoverStep::CloseOrReenter,
    ];
    let d1 = step_chain_digest(&steps);
    let d2 = step_chain_digest(&steps);
    assert_eq!(d1, d2);
}

#[test]
fn step_chain_truncated_differs_from_full() {
    let full: Vec<CutoverStep> = vec![
        CutoverStep::Intent,
        CutoverStep::PreflightSnapshot,
        CutoverStep::DryRunGate,
        CutoverStep::StageFencePrepare,
        CutoverStep::CommitTransition,
        CutoverStep::VerifyTruth,
        CutoverStep::CloseOrReenter,
    ];
    let partial: Vec<CutoverStep> = vec![
        CutoverStep::Intent,
        CutoverStep::PreflightSnapshot,
        CutoverStep::DryRunGate,
    ];
    assert_ne!(step_chain_digest(&full), step_chain_digest(&partial));
}

// ---- CutoverFenceToken digest tests ----

#[test]
fn fence_token_affects_state_digest() {
    let mut s = CutoverState::idle_at(KernelMode::Userspace);
    let no_token = state_digest(&s);

    s.held_fence = Some(CutoverFenceToken::from_u128_le(42));
    let with_token = state_digest(&s);
    assert_ne!(no_token, with_token);

    s.held_fence = Some(CutoverFenceToken::from_u128_le(99));
    let other_token = state_digest(&s);
    assert_ne!(with_token, other_token);
}

// ---- RollbackReceipt validation test ----

#[test]
fn rollback_receipt_validation_fields() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    ex.set_rollback_plan(RollbackPlan {
        restore_mode: KernelMode::Userspace,
        preserve_validation: true,
        reopen_admission: false,
    });

    ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
    ex.advance().unwrap();

    let receipt = ex.execute_rollback().unwrap();
    assert_eq!(receipt.restored_mode, KernelMode::Userspace);
    assert!(receipt.validation_preserved);
    assert!(!receipt.admission_reopened);
}

// ---- Executor completeness after full cycle ----

#[test]
fn full_roundtrip_userspace_to_kernel_and_back() {
    let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
    let start_digest = state_digest(ex.state());

    for target in &[
        KernelMode::MixedPosixRead,
        KernelMode::MixedFullClient,
        KernelMode::FullKernel,
    ] {
        ex.begin_cutover(*target).unwrap();
        for _ in 0..7 {
            ex.advance().unwrap();
        }
    }
    assert_eq!(ex.state().current_mode, KernelMode::FullKernel);
    let kernel_digest = state_digest(ex.state());
    assert_ne!(start_digest, kernel_digest);

    for target in &[
        KernelMode::MixedFullClient,
        KernelMode::MixedPosixRead,
        KernelMode::Userspace,
    ] {
        ex.begin_cutover(*target).unwrap();
        for _ in 0..7 {
            ex.advance().unwrap();
        }
    }
    assert_eq!(ex.state().current_mode, KernelMode::Userspace);
    assert!(ex.state().is_complete());
}

//! Userspace kernel-cutover runtime: state-machine executor, fence manager,
//! dry-run gate evaluator, and rollback engine. d2 domain (userspace std).

mod types;
pub use crate::types::{
    CutoverFenceKind, CutoverFenceToken, CutoverGateResult, CutoverState, CutoverStep,
    CutoverTransition, KernelMode, RollbackPlan, RollbackReceipt,
};

#[derive(Debug)]
pub struct FenceManager {
    next_nonce: u128,
    held: Option<(CutoverFenceKind, CutoverFenceToken)>,
}
impl FenceManager {
    pub fn new() -> Self {
        Self {
            next_nonce: 1,
            held: None,
        }
    }
    fn generate_token(&mut self) -> CutoverFenceToken {
        let t = CutoverFenceToken::from_u128_le(self.next_nonce);
        self.next_nonce = self.next_nonce.wrapping_add(1);
        t
    }
    pub fn acquire(
        &mut self,
        kind: CutoverFenceKind,
    ) -> Result<CutoverFenceToken, CutoverRuntimeError> {
        if self.held.is_some() {
            return Err(CutoverRuntimeError::FenceAlreadyHeld);
        }
        let token = self.generate_token();
        self.held = Some((kind, token));
        Ok(token)
    }
    pub fn release(
        &mut self,
        expected_kind: CutoverFenceKind,
    ) -> Result<CutoverFenceToken, CutoverRuntimeError> {
        match self.held.take() {
            Some((kind, token)) if kind == expected_kind => Ok(token),
            Some((kind, _)) => Err(CutoverRuntimeError::FenceKindMismatch {
                expected: expected_kind,
                held: kind,
            }),
            None => Err(CutoverRuntimeError::NoFenceHeld),
        }
    }
    pub fn has_fence(&self) -> bool {
        self.held.is_some()
    }
    pub fn held_kind(&self) -> Option<CutoverFenceKind> {
        self.held.map(|(k, _)| k)
    }
}
impl Default for FenceManager {
    fn default() -> Self {
        Self::new()
    }
}

pub trait CutoverGateEvaluator {
    fn evaluate(&self, transition: CutoverTransition) -> CutoverGateResult;
}
#[derive(Debug, Default)]
pub struct AlwaysAdmitGate;
impl CutoverGateEvaluator for AlwaysAdmitGate {
    fn evaluate(&self, _: CutoverTransition) -> CutoverGateResult {
        CutoverGateResult::Admissible
    }
}
#[derive(Debug, Default)]
pub struct AlwaysRefuseGate;
impl CutoverGateEvaluator for AlwaysRefuseGate {
    fn evaluate(&self, _: CutoverTransition) -> CutoverGateResult {
        CutoverGateResult::Refused
    }
}

#[derive(Debug)]
pub struct CutoverExecutor<G: CutoverGateEvaluator = AlwaysRefuseGate> {
    state: CutoverState,
    fence_manager: FenceManager,
    gate_evaluator: G,
}
impl<G: CutoverGateEvaluator> CutoverExecutor<G> {
    pub fn new(initial_mode: KernelMode, gate_evaluator: G) -> Self {
        Self {
            state: CutoverState::idle_at(initial_mode),
            fence_manager: FenceManager::new(),
            gate_evaluator,
        }
    }
    pub fn state(&self) -> &CutoverState {
        &self.state
    }
    pub fn fence_manager(&self) -> &FenceManager {
        &self.fence_manager
    }
    pub fn fence_manager_mut(&mut self) -> &mut FenceManager {
        &mut self.fence_manager
    }
    pub fn begin_cutover(&mut self, target: KernelMode) -> Result<(), CutoverRuntimeError> {
        if self.state.is_in_progress() {
            return Err(CutoverRuntimeError::CutoverAlreadyInProgress);
        }
        let t = CutoverTransition::new(self.state.current_mode, target);
        if !t.is_legal() {
            return Err(CutoverRuntimeError::IllegalTransition {
                from: self.state.current_mode,
                to: target,
            });
        }
        self.state.target_mode = Some(target);
        self.state.current_step = Some(CutoverStep::Intent);
        Ok(())
    }
    pub fn advance(&mut self) -> Result<StepOutcome, CutoverRuntimeError> {
        let current = self
            .state
            .current_step
            .ok_or(CutoverRuntimeError::NoActiveCutover)?;
        match current {
            CutoverStep::Intent => {
                self.state.current_step = Some(CutoverStep::PreflightSnapshot);
                Ok(StepOutcome::Advanced(CutoverStep::PreflightSnapshot))
            }
            CutoverStep::PreflightSnapshot => {
                self.state.current_step = Some(CutoverStep::DryRunGate);
                Ok(StepOutcome::Advanced(CutoverStep::DryRunGate))
            }
            CutoverStep::DryRunGate => {
                let target = self
                    .state
                    .target_mode
                    .ok_or(CutoverRuntimeError::NoActiveCutover)?;
                let result = self
                    .gate_evaluator
                    .evaluate(CutoverTransition::new(self.state.current_mode, target));
                if result.is_admissible() {
                    self.state.current_step = Some(CutoverStep::StageFencePrepare);
                    Ok(StepOutcome::Advanced(CutoverStep::StageFencePrepare))
                } else {
                    Ok(StepOutcome::GateRefused(result))
                }
            }
            CutoverStep::StageFencePrepare => {
                let token = self.fence_manager.acquire(CutoverFenceKind::Quiesce)?;
                self.state.held_fence = Some(token);
                self.state.current_step = Some(CutoverStep::CommitTransition);
                Ok(StepOutcome::Advanced(CutoverStep::CommitTransition))
            }
            CutoverStep::CommitTransition => {
                let _st = self.fence_manager.release(CutoverFenceKind::Quiesce)?;
                let target = self
                    .state
                    .target_mode
                    .ok_or(CutoverRuntimeError::NoActiveCutover)?;
                if self.state.rollback_plan.is_none() {
                    self.state.rollback_plan = Some(RollbackPlan::new(self.state.current_mode));
                }
                let ct = self.fence_manager.acquire(CutoverFenceKind::Stage)?;
                self.state.held_fence = Some(ct);
                self.state.current_mode = target;
                self.state.current_step = Some(CutoverStep::VerifyTruth);
                Ok(StepOutcome::Advanced(CutoverStep::VerifyTruth))
            }
            CutoverStep::VerifyTruth => {
                let _st = self.fence_manager.release(CutoverFenceKind::Stage)?;
                let vt = self.fence_manager.acquire(CutoverFenceKind::Commit)?;
                self.state.held_fence = Some(vt);
                self.state.current_step = Some(CutoverStep::CloseOrReenter);
                Ok(StepOutcome::Advanced(CutoverStep::CloseOrReenter))
            }
            CutoverStep::CloseOrReenter => {
                let _ct = self.fence_manager.release(CutoverFenceKind::Commit)?;
                self.state.held_fence = None;
                self.state.target_mode = None;
                self.state.current_step = Some(CutoverStep::CloseOrReenter);
                Ok(StepOutcome::Completed {
                    final_mode: self.state.current_mode,
                })
            }
        }
    }
    pub fn execute_rollback(&mut self) -> Result<RollbackReceipt, CutoverRuntimeError> {
        if !self.state.is_in_progress() {
            return Err(CutoverRuntimeError::NoActiveCutover);
        }
        let rm = self
            .state
            .rollback_plan
            .as_ref()
            .map(|p| p.restore_mode)
            .unwrap_or(KernelMode::Userspace);
        let ep = self
            .state
            .rollback_plan
            .as_ref()
            .map(|p| p.preserve_validation)
            .unwrap_or(true);
        let ar = self
            .state
            .rollback_plan
            .as_ref()
            .map(|p| p.reopen_admission)
            .unwrap_or(true);
        if let Some(kind) = self.fence_manager.held_kind() {
            self.fence_manager.release(kind)?;
        }
        self.state.held_fence = None;
        self.state.current_mode = rm;
        self.state.target_mode = None;
        self.state.current_step = None;
        self.state.rollback_plan = None;
        Ok(RollbackReceipt::new(rm, ep, ar))
    }
    pub fn set_rollback_plan(&mut self, plan: RollbackPlan) {
        self.state.rollback_plan = Some(plan);
    }
    pub fn set_gate_evaluator(&mut self, evaluator: G) {
        self.gate_evaluator = evaluator;
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum StepOutcome {
    Advanced(CutoverStep),
    GateRefused(CutoverGateResult),
    Completed { final_mode: KernelMode },
}
#[derive(Debug, Eq, PartialEq)]
pub enum CutoverRuntimeError {
    NoActiveCutover,
    CutoverAlreadyInProgress,
    IllegalTransition {
        from: KernelMode,
        to: KernelMode,
    },
    FenceAlreadyHeld,
    NoFenceHeld,
    FenceKindMismatch {
        expected: CutoverFenceKind,
        held: CutoverFenceKind,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fence_acq_rel() {
        let mut fm = FenceManager::new();
        fm.acquire(CutoverFenceKind::Quiesce).unwrap();
        assert!(fm.has_fence());
        fm.release(CutoverFenceKind::Quiesce).unwrap();
        assert!(!fm.has_fence());
    }
    #[test]
    fn fence_nested() {
        let mut fm = FenceManager::new();
        fm.acquire(CutoverFenceKind::Stage).unwrap();
        assert_eq!(
            fm.acquire(CutoverFenceKind::Commit),
            Err(CutoverRuntimeError::FenceAlreadyHeld)
        );
    }
    #[test]
    fn fence_no_acq() {
        assert_eq!(
            FenceManager::new().release(CutoverFenceKind::Quiesce),
            Err(CutoverRuntimeError::NoFenceHeld)
        );
    }
    #[test]
    fn fence_mismatch() {
        let mut fm = FenceManager::new();
        fm.acquire(CutoverFenceKind::Quiesce).unwrap();
        assert_eq!(
            fm.release(CutoverFenceKind::Stage),
            Err(CutoverRuntimeError::FenceKindMismatch {
                expected: CutoverFenceKind::Stage,
                held: CutoverFenceKind::Quiesce
            })
        );
    }
    #[test]
    fn ex_idle() {
        assert!(CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate)
            .state()
            .is_idle());
    }
    #[test]
    fn begin_legal() {
        let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
        ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
        assert!(ex.state().is_in_progress());
    }
    #[test]
    fn begin_illegal() {
        let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
        assert_eq!(
            ex.begin_cutover(KernelMode::FullKernel),
            Err(CutoverRuntimeError::IllegalTransition {
                from: KernelMode::Userspace,
                to: KernelMode::FullKernel
            })
        );
    }
    #[test]
    fn full_cutover() {
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
    }
    #[test]
    fn gate_refusal() {
        let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysRefuseGate);
        ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
        ex.advance().unwrap();
        ex.advance().unwrap();
        assert_eq!(
            ex.advance(),
            Ok(StepOutcome::GateRefused(CutoverGateResult::Refused))
        );
    }
    #[test]
    fn rollback() {
        let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
        ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
        ex.advance().unwrap();
        let r = ex.execute_rollback().unwrap();
        assert_eq!(r.restored_mode, KernelMode::Userspace);
        assert!(ex.state().is_idle());
    }
    #[test]
    fn rollback_fence() {
        let mut ex = CutoverExecutor::new(KernelMode::Userspace, AlwaysAdmitGate);
        ex.begin_cutover(KernelMode::MixedPosixRead).unwrap();
        for _ in 0..4 {
            ex.advance().unwrap();
        }
        assert!(ex.fence_manager().has_fence());
        ex.execute_rollback().unwrap();
        assert!(!ex.fence_manager().has_fence());
    }
    #[test]
    fn rollback_wo() {
        assert_eq!(
            CutoverExecutor::<AlwaysAdmitGate>::new(KernelMode::Userspace, AlwaysAdmitGate)
                .execute_rollback(),
            Err(CutoverRuntimeError::NoActiveCutover)
        );
    }
    #[test]
    fn adv_wo() {
        assert_eq!(
            CutoverExecutor::<AlwaysAdmitGate>::new(KernelMode::Userspace, AlwaysAdmitGate)
                .advance(),
            Err(CutoverRuntimeError::NoActiveCutover)
        );
    }
    #[test]
    fn admit() {
        assert_eq!(
            AlwaysAdmitGate.evaluate(CutoverTransition::new(
                KernelMode::Userspace,
                KernelMode::MixedPosixRead
            )),
            CutoverGateResult::Admissible
        );
    }
    #[test]
    fn refuse() {
        assert_eq!(
            AlwaysRefuseGate.evaluate(CutoverTransition::new(
                KernelMode::Userspace,
                KernelMode::MixedPosixRead
            )),
            CutoverGateResult::Refused
        );
    }
}

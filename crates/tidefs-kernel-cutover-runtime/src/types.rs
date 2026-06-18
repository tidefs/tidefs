// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Portable kernel cutover mode, fence, and rollback state-machine types.
//! d0 boundary domain -- formerly `tidefs-types-kernel-cutover-core`.
//! Consolidated into the runtime crate per #5726 since it has a single consumer.

use std::convert::TryFrom;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum KernelMode {
    Userspace = 0,
    MixedPosixRead = 1,
    MixedFullClient = 2,
    FullKernel = 3,
}

impl KernelMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Userspace => "mode.kernel_cutover.userspace.m0",
            Self::MixedPosixRead => "mode.kernel_cutover.mixed_posix_read.m1",
            Self::MixedFullClient => "mode.kernel_cutover.mixed_full_client.m2",
            Self::FullKernel => "mode.kernel_cutover.full_kernel.m3",
        }
    }

    #[must_use]
    pub const fn is_kernel_active(self) -> bool {
        matches!(
            self,
            Self::MixedPosixRead | Self::MixedFullClient | Self::FullKernel
        )
    }

    #[must_use]
    pub const fn allows_kernel_block(self) -> bool {
        matches!(self, Self::MixedFullClient | Self::FullKernel)
    }

    #[must_use]
    pub const fn allows_kernel_policy_authority(self) -> bool {
        matches!(self, Self::FullKernel)
    }
}

impl Default for KernelMode {
    fn default() -> Self {
        Self::Userspace
    }
}

impl TryFrom<u8> for KernelMode {
    type Error = KernelCutoverDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Userspace),
            1 => Ok(Self::MixedPosixRead),
            2 => Ok(Self::MixedFullClient),
            3 => Ok(Self::FullKernel),
            _ => Err(KernelCutoverDecodeError::InvalidKernelMode(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelCutoverDecodeError {
    InvalidKernelMode(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CutoverFenceKind {
    Quiesce = 0,
    Stage = 1,
    Commit = 2,
    Rollback = 3,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct CutoverFenceToken(pub [u8; 16]);

impl CutoverFenceToken {
    pub const ZERO: Self = Self([0_u8; 16]);

    #[must_use]
    pub const fn from_u128_le(v: u128) -> Self {
        Self(v.to_le_bytes())
    }

    #[must_use]
    pub const fn as_u128_le(self) -> u128 {
        u128::from_le_bytes(self.0)
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        let mut i = 0;
        while i < 16 {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CutoverGateResult {
    Admissible = 0,
    Blocked = 1,
    Refused = 2,
    OverrideRequired = 3,
    QuarantineRequired = 4,
}

impl CutoverGateResult {
    #[must_use]
    pub const fn is_admissible(self) -> bool {
        matches!(self, Self::Admissible)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CutoverStep {
    Intent = 0,
    PreflightSnapshot = 1,
    DryRunGate = 2,
    StageFencePrepare = 3,
    CommitTransition = 4,
    VerifyTruth = 5,
    CloseOrReenter = 6,
}

impl CutoverStep {
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Intent => Some(Self::PreflightSnapshot),
            Self::PreflightSnapshot => Some(Self::DryRunGate),
            Self::DryRunGate => Some(Self::StageFencePrepare),
            Self::StageFencePrepare => Some(Self::CommitTransition),
            Self::CommitTransition => Some(Self::VerifyTruth),
            Self::VerifyTruth => Some(Self::CloseOrReenter),
            Self::CloseOrReenter => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CutoverTransition {
    pub from: KernelMode,
    pub to: KernelMode,
}

impl CutoverTransition {
    #[must_use]
    pub const fn new(from: KernelMode, to: KernelMode) -> Self {
        Self { from, to }
    }

    #[must_use]
    pub const fn is_forward(self) -> bool {
        (self.to as u8) > (self.from as u8)
    }

    #[must_use]
    pub const fn is_rollback(self) -> bool {
        (self.to as u8) < (self.from as u8)
    }

    #[must_use]
    pub const fn is_legal(self) -> bool {
        if self.is_forward() {
            (self.to as u8) == (self.from as u8) + 1
        } else if self.is_rollback() {
            self.to as u8 == 0 || (self.to as u8) == (self.from as u8) - 1
        } else {
            true
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackPlan {
    pub restore_mode: KernelMode,
    pub preserve_validation: bool,
    pub reopen_admission: bool,
}

impl RollbackPlan {
    #[must_use]
    pub const fn new(restore_mode: KernelMode) -> Self {
        Self {
            restore_mode,
            preserve_validation: true,
            reopen_admission: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackReceipt {
    pub restored_mode: KernelMode,
    pub validation_preserved: bool,
    pub admission_reopened: bool,
}

impl RollbackReceipt {
    #[must_use]
    pub const fn new(
        restored_mode: KernelMode,
        validation_preserved: bool,
        admission_reopened: bool,
    ) -> Self {
        Self {
            restored_mode,
            validation_preserved,
            admission_reopened,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutoverState {
    pub current_mode: KernelMode,
    pub target_mode: Option<KernelMode>,
    pub current_step: Option<CutoverStep>,
    pub rollback_plan: Option<RollbackPlan>,
    pub held_fence: Option<CutoverFenceToken>,
}

impl CutoverState {
    #[must_use]
    pub const fn idle_at(mode: KernelMode) -> Self {
        Self {
            current_mode: mode,
            target_mode: None,
            current_step: None,
            rollback_plan: None,
            held_fence: None,
        }
    }

    #[must_use]
    pub const fn is_idle(&self) -> bool {
        self.target_mode.is_none() && self.current_step.is_none()
    }

    #[must_use]
    pub const fn is_in_progress(&self) -> bool {
        self.target_mode.is_some()
    }

    #[must_use]
    pub const fn requires_explicit_rollback(&self) -> bool {
        matches!(
            self.current_step,
            Some(CutoverStep::StageFencePrepare)
                | Some(CutoverStep::CommitTransition)
                | Some(CutoverStep::VerifyTruth)
        )
    }

    pub fn is_complete(&self) -> bool {
        self.current_step == Some(CutoverStep::CloseOrReenter) && self.target_mode.is_none()
    }
}

impl Default for CutoverState {
    fn default() -> Self {
        Self::idle_at(KernelMode::Userspace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_default() {
        assert_eq!(KernelMode::default(), KernelMode::Userspace);
    }

    #[test]
    fn mode_ordering() {
        assert!(KernelMode::Userspace < KernelMode::MixedPosixRead);
    }

    #[test]
    fn mode_active() {
        assert!(!KernelMode::Userspace.is_kernel_active());
        assert!(KernelMode::MixedPosixRead.is_kernel_active());
    }

    #[test]
    fn mode_block() {
        assert!(!KernelMode::Userspace.allows_kernel_block());
        assert!(KernelMode::FullKernel.allows_kernel_block());
    }

    #[test]
    fn mode_decode() {
        assert_eq!(KernelMode::try_from(0), Ok(KernelMode::Userspace));
        assert!(KernelMode::try_from(4).is_err());
    }

    #[test]
    fn fence_roundtrip() {
        let t = CutoverFenceToken::from_u128_le(0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0_u128);
        assert!(!t.is_zero());
        assert_eq!(
            t.as_u128_le(),
            0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0_u128
        );
    }

    #[test]
    fn fence_zero() {
        assert!(CutoverFenceToken::ZERO.is_zero());
    }

    #[test]
    fn gate() {
        assert!(CutoverGateResult::Admissible.is_admissible());
        assert!(!CutoverGateResult::Refused.is_admissible());
    }

    #[test]
    fn step_sequence() {
        let mut s = Some(CutoverStep::Intent);
        let mut c = 0;
        while let Some(st) = s {
            c += 1;
            s = st.next();
        }
        assert_eq!(c, 7);
    }

    #[test]
    fn step_terminal() {
        assert_eq!(CutoverStep::CloseOrReenter.next(), None);
    }

    #[test]
    fn trans_forward() {
        assert!(
            CutoverTransition::new(KernelMode::Userspace, KernelMode::MixedPosixRead).is_legal()
        );
    }

    #[test]
    fn trans_illegal() {
        assert!(!CutoverTransition::new(KernelMode::Userspace, KernelMode::FullKernel).is_legal());
    }

    #[test]
    fn rollback_userspace() {
        assert!(CutoverTransition::new(KernelMode::FullKernel, KernelMode::Userspace).is_legal());
    }

    #[test]
    fn rollback_step() {
        assert!(
            CutoverTransition::new(KernelMode::FullKernel, KernelMode::MixedFullClient).is_legal()
        );
    }

    #[test]
    fn noop() {
        assert!(CutoverTransition::new(KernelMode::Userspace, KernelMode::Userspace).is_legal());
    }

    #[test]
    fn direction() {
        assert!(
            CutoverTransition::new(KernelMode::Userspace, KernelMode::MixedPosixRead).is_forward()
        );
        assert!(
            CutoverTransition::new(KernelMode::MixedPosixRead, KernelMode::Userspace).is_rollback()
        );
    }

    #[test]
    fn plan() {
        let p = RollbackPlan::new(KernelMode::Userspace);
        assert!(p.preserve_validation);
    }

    #[test]
    fn receipt() {
        let r = RollbackReceipt::new(KernelMode::Userspace, true, false);
        assert!(r.validation_preserved);
        assert!(!r.admission_reopened);
    }

    #[test]
    fn state_idle() {
        assert!(CutoverState::default().is_idle());
    }

    #[test]
    fn state_progress() {
        let mut s = CutoverState::idle_at(KernelMode::Userspace);
        s.target_mode = Some(KernelMode::MixedPosixRead);
        assert!(s.is_in_progress());
    }

    #[test]
    fn state_complete() {
        let mut s = CutoverState::idle_at(KernelMode::MixedPosixRead);
        s.current_step = Some(CutoverStep::CloseOrReenter);
        assert!(s.is_complete());
    }

    #[test]
    fn state_rollback() {
        let mut s = CutoverState::idle_at(KernelMode::Userspace);
        s.current_step = Some(CutoverStep::StageFencePrepare);
        assert!(s.requires_explicit_rollback());
        s.current_step = Some(CutoverStep::Intent);
        assert!(!s.requires_explicit_rollback());
    }
}

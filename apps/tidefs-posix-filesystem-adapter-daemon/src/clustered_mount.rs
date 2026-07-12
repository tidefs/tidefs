// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Clustered POSIX mount admission boundary.
//!
//! This module provides the committed mount identity and authority snapshot
//! that a clustered POSIX mount must obtain before it can construct or use
//! a cluster [`LockServiceHandle`] for lock forwarding.
//!
//! The local `mount_vfs` path does not construct
//! [`ClusteredPosixMountRuntime`], use MEMBERSHIP, or open LOCK transport.
//! It continues to open [`LocalFileSystem`] and keep advisory locks
//! in-process via [`DaemonLockDispatch`].
//!
//! [`LockServiceHandle`]: tidefs_lock_service::LockServiceHandle
//! [`LocalFileSystem`]: tidefs_local_filesystem::LocalFileSystem
//! [`DaemonLockDispatch`]: crate::lock_dispatch::DaemonLockDispatch

use tidefs_lock_service::{DatasetMountIdentity, EpochId, MemberId};

/// Error returned when clustered POSIX mount admission fails.
///
/// Every variant causes the admission to fail closed: the mount is not
/// allowed to serve clustered lock requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusteredPosixMountAdmissionError {
    /// The supplied [`DatasetMountIdentity`] has no committed dataset or mount
    /// identity (`dataset_id == 0 || mount_id == 0`).
    MissingIdentity,
    /// The mount identity has a committed epoch of zero.
    UncommittedEpoch,
    /// The current authority [`EpochId`] is zero.
    MissingCurrentEpoch,
    /// The current authority epoch is behind the committed mount identity.
    StaleAuthorityEpoch,
    /// The current LOCK/lease authority term is zero.
    MissingAuthorityTerm,
    /// The current LOCK leader or routed authority endpoint is zero.
    MissingLockAuthorityEndpoint,
    /// The admission/session binding generation is zero.
    MissingAdmissionGeneration,
}

impl ClusteredPosixMountAdmissionError {
    /// Stable diagnostic label for the refusal reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingIdentity => "missing_mount_identity",
            Self::UncommittedEpoch => "uncommitted_epoch",
            Self::MissingCurrentEpoch => "missing_current_epoch",
            Self::StaleAuthorityEpoch => "stale_authority_epoch",
            Self::MissingAuthorityTerm => "missing_authority_term",
            Self::MissingLockAuthorityEndpoint => "missing_lock_authority_endpoint",
            Self::MissingAdmissionGeneration => "missing_admission_generation",
        }
    }
}

/// Current clustered LOCK authority evidence for a mounted POSIX runtime.
///
/// The clustered mount boundary receives this snapshot from the current
/// membership, lease, and LOCK authority sources used by clustered requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClusteredPosixAuthoritySnapshot {
    /// Current membership epoch for the mounted clustered dataset.
    pub current_epoch: EpochId,
    /// Current LOCK/lease authority term for the mounted clustered dataset.
    pub current_term: u64,
    /// Current LOCK leader or equivalent routed authority endpoint.
    pub lock_leader: MemberId,
    /// Admission/session binding generation proving the cached identity still
    /// belongs to this mounted clustered dataset.
    pub admission_generation: u64,
}

/// Clustered POSIX mounted boundary admitted with committed identity and
/// current authority evidence.
///
/// This type is the clustered POSIX LOCK admission boundary. Lock-forwarding
/// code consumes this runtime to construct an identity-bound
/// `LockServiceHandle` and LOCK transport, while local POSIX stays on
/// in-process lock dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClusteredPosixMountRuntime {
    mount_identity: DatasetMountIdentity,
    authority: ClusteredPosixAuthoritySnapshot,
}

impl ClusteredPosixMountRuntime {
    /// Admit a clustered POSIX mount after cluster admission and lease
    /// bootstrap produce committed identity and current authority evidence.
    ///
    /// The boundary fails closed when any required fact is missing, zero, or
    /// stale relative to the committed mount identity.
    pub fn open_committed_mount(
        mount_identity: DatasetMountIdentity,
        authority: ClusteredPosixAuthoritySnapshot,
    ) -> Result<Self, ClusteredPosixMountAdmissionError> {
        if mount_identity.dataset_id == 0 || mount_identity.mount_id == 0 {
            return Err(ClusteredPosixMountAdmissionError::MissingIdentity);
        }
        if mount_identity.committed_epoch == 0 {
            return Err(ClusteredPosixMountAdmissionError::UncommittedEpoch);
        }
        if authority.current_epoch.0 == 0 {
            return Err(ClusteredPosixMountAdmissionError::MissingCurrentEpoch);
        }
        if mount_identity.committed_epoch > authority.current_epoch.0 {
            return Err(ClusteredPosixMountAdmissionError::StaleAuthorityEpoch);
        }
        if authority.current_term == 0 {
            return Err(ClusteredPosixMountAdmissionError::MissingAuthorityTerm);
        }
        if authority.lock_leader.0 == 0 {
            return Err(ClusteredPosixMountAdmissionError::MissingLockAuthorityEndpoint);
        }
        if authority.admission_generation == 0 {
            return Err(ClusteredPosixMountAdmissionError::MissingAdmissionGeneration);
        }

        Ok(Self {
            mount_identity,
            authority,
        })
    }

    /// Committed identity admitted for this clustered POSIX mount.
    #[must_use]
    pub const fn mount_identity(&self) -> DatasetMountIdentity {
        self.mount_identity
    }

    /// Current authority snapshot admitted for this clustered POSIX mount.
    #[must_use]
    pub const fn authority(&self) -> ClusteredPosixAuthoritySnapshot {
        self.authority
    }

    /// Current membership epoch supplied by the clustered authority.
    #[must_use]
    pub const fn current_epoch(&self) -> EpochId {
        self.authority.current_epoch
    }

    /// Current LOCK/lease authority term supplied by the clustered authority.
    #[must_use]
    pub const fn current_term(&self) -> u64 {
        self.authority.current_term
    }

    /// Current LOCK leader or equivalent routed authority endpoint.
    #[must_use]
    pub const fn lock_leader(&self) -> MemberId {
        self.authority.lock_leader
    }

    /// Admission/session binding generation for the mounted dataset identity.
    #[must_use]
    pub const fn admission_generation(&self) -> u64 {
        self.authority.admission_generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(dataset_id: u64, mount_id: u64, committed_epoch: u64) -> DatasetMountIdentity {
        DatasetMountIdentity::new(dataset_id, mount_id, committed_epoch)
    }

    fn authority(
        current_epoch: u64,
        current_term: u64,
        lock_leader: u64,
        admission_generation: u64,
    ) -> ClusteredPosixAuthoritySnapshot {
        ClusteredPosixAuthoritySnapshot {
            current_epoch: EpochId::new(current_epoch),
            current_term,
            lock_leader: MemberId::new(lock_leader),
            admission_generation,
        }
    }

    #[test]
    fn admits_valid_committed_mount_runtime() {
        let runtime = ClusteredPosixMountRuntime::open_committed_mount(
            identity(1, 2, 5),
            authority(5, 7, 3, 11),
        )
        .unwrap();

        assert_eq!(runtime.mount_identity(), identity(1, 2, 5));
        assert_eq!(runtime.current_epoch(), EpochId::new(5));
        assert_eq!(runtime.current_term(), 7);
        assert_eq!(runtime.lock_leader(), MemberId::new(3));
        assert_eq!(runtime.admission_generation(), 11);
    }

    #[test]
    fn admits_identity_committed_in_prior_epoch() {
        let runtime = ClusteredPosixMountRuntime::open_committed_mount(
            identity(1, 2, 3),
            authority(7, 7, 3, 11),
        )
        .unwrap();

        assert_eq!(runtime.current_epoch(), EpochId::new(7));
    }

    #[test]
    fn refuses_zero_dataset_id() {
        let err = ClusteredPosixMountRuntime::open_committed_mount(
            identity(0, 2, 5),
            authority(5, 7, 3, 11),
        )
        .unwrap_err();

        assert_eq!(err, ClusteredPosixMountAdmissionError::MissingIdentity);
    }

    #[test]
    fn refuses_zero_mount_id() {
        let err = ClusteredPosixMountRuntime::open_committed_mount(
            identity(1, 0, 5),
            authority(5, 7, 3, 11),
        )
        .unwrap_err();

        assert_eq!(err, ClusteredPosixMountAdmissionError::MissingIdentity);
    }

    #[test]
    fn refuses_uncommitted_epoch() {
        let err = ClusteredPosixMountRuntime::open_committed_mount(
            identity(1, 2, 0),
            authority(5, 7, 3, 11),
        )
        .unwrap_err();

        assert_eq!(err, ClusteredPosixMountAdmissionError::UncommittedEpoch);
    }

    #[test]
    fn refuses_zero_current_epoch() {
        let err = ClusteredPosixMountRuntime::open_committed_mount(
            identity(1, 2, 5),
            authority(0, 7, 3, 11),
        )
        .unwrap_err();

        assert_eq!(err, ClusteredPosixMountAdmissionError::MissingCurrentEpoch);
    }

    #[test]
    fn refuses_stale_authority_epoch() {
        let err = ClusteredPosixMountRuntime::open_committed_mount(
            identity(1, 2, 10),
            authority(5, 7, 3, 11),
        )
        .unwrap_err();

        assert_eq!(err, ClusteredPosixMountAdmissionError::StaleAuthorityEpoch);
    }

    #[test]
    fn refuses_zero_authority_term() {
        let err = ClusteredPosixMountRuntime::open_committed_mount(
            identity(1, 2, 5),
            authority(5, 0, 3, 11),
        )
        .unwrap_err();

        assert_eq!(err, ClusteredPosixMountAdmissionError::MissingAuthorityTerm);
    }

    #[test]
    fn refuses_zero_lock_authority_endpoint() {
        let err = ClusteredPosixMountRuntime::open_committed_mount(
            identity(1, 2, 5),
            authority(5, 7, 0, 11),
        )
        .unwrap_err();

        assert_eq!(
            err,
            ClusteredPosixMountAdmissionError::MissingLockAuthorityEndpoint
        );
    }

    #[test]
    fn refuses_zero_admission_generation() {
        let err = ClusteredPosixMountRuntime::open_committed_mount(
            identity(1, 2, 5),
            authority(5, 7, 3, 0),
        )
        .unwrap_err();

        assert_eq!(
            err,
            ClusteredPosixMountAdmissionError::MissingAdmissionGeneration
        );
    }

    #[test]
    fn as_str_returns_stable_labels() {
        assert_eq!(
            ClusteredPosixMountAdmissionError::MissingIdentity.as_str(),
            "missing_mount_identity"
        );
        assert_eq!(
            ClusteredPosixMountAdmissionError::UncommittedEpoch.as_str(),
            "uncommitted_epoch"
        );
        assert_eq!(
            ClusteredPosixMountAdmissionError::MissingCurrentEpoch.as_str(),
            "missing_current_epoch"
        );
        assert_eq!(
            ClusteredPosixMountAdmissionError::StaleAuthorityEpoch.as_str(),
            "stale_authority_epoch"
        );
        assert_eq!(
            ClusteredPosixMountAdmissionError::MissingAuthorityTerm.as_str(),
            "missing_authority_term"
        );
        assert_eq!(
            ClusteredPosixMountAdmissionError::MissingLockAuthorityEndpoint.as_str(),
            "missing_lock_authority_endpoint"
        );
        assert_eq!(
            ClusteredPosixMountAdmissionError::MissingAdmissionGeneration.as_str(),
            "missing_admission_generation"
        );
    }
}

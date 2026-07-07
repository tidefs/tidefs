// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Source-backed evidence records for pool import/export and device topology.

/// Pool or topology action represented by lifecycle evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolLifecycleAction {
    Scan,
    Import,
    Export,
    Reopen,
    AddDevice,
    RemoveDevice,
    ReplaceDevice,
    FailClosed,
}

impl PoolLifecycleAction {
    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Import => "import",
            Self::Export => "export",
            Self::Reopen => "reopen",
            Self::AddDevice => "add-device",
            Self::RemoveDevice => "remove-device",
            Self::ReplaceDevice => "replace-device",
            Self::FailClosed => "fail-closed",
        }
    }
}

/// Whether the represented lifecycle action executed or was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolLifecycleOutcome {
    Executed,
    Refused,
}

impl PoolLifecycleOutcome {
    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::Executed => "executed",
            Self::Refused => "refused",
        }
    }
}

/// Compact evidence row for claim review of local pool lifecycle transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolLifecycleEvidence {
    pub action: PoolLifecycleAction,
    pub outcome: PoolLifecycleOutcome,
    pub pool_guid: Option<[u8; 16]>,
    pub pool_name: Option<String>,
    pub device_count: usize,
    pub expected_device_count: usize,
    pub capacity_bytes: u64,
    pub topology_generation: u64,
    pub commit_group: u64,
    pub topology_complete: bool,
    pub owner_authorized: bool,
    pub reason: String,
}

/// Shared context used by lifecycle evidence constructors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolLifecycleContext {
    pub pool_guid: Option<[u8; 16]>,
    pub pool_name: Option<String>,
    pub device_count: usize,
    pub expected_device_count: usize,
    pub capacity_bytes: u64,
    pub topology_generation: u64,
    pub commit_group: u64,
}

impl PoolLifecycleEvidence {
    #[must_use]
    pub fn executed(action: PoolLifecycleAction, context: PoolLifecycleContext) -> Self {
        Self {
            action,
            outcome: PoolLifecycleOutcome::Executed,
            topology_complete: context.device_count >= context.expected_device_count,
            owner_authorized: true,
            pool_guid: context.pool_guid,
            pool_name: context.pool_name,
            device_count: context.device_count,
            expected_device_count: context.expected_device_count,
            capacity_bytes: context.capacity_bytes,
            topology_generation: context.topology_generation,
            commit_group: context.commit_group,
            reason: "action executed with complete owner/topology evidence".to_string(),
        }
    }

    #[must_use]
    pub fn refused(
        action: PoolLifecycleAction,
        context: PoolLifecycleContext,
        reason: impl Into<String>,
    ) -> Self {
        Self::refused_with_authority(action, context, false, false, reason)
    }

    #[must_use]
    pub fn refused_with_authority(
        action: PoolLifecycleAction,
        context: PoolLifecycleContext,
        topology_complete: bool,
        owner_authorized: bool,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            action,
            outcome: PoolLifecycleOutcome::Refused,
            topology_complete,
            owner_authorized,
            pool_guid: context.pool_guid,
            pool_name: context.pool_name,
            device_count: context.device_count,
            expected_device_count: context.expected_device_count,
            capacity_bytes: context.capacity_bytes,
            topology_generation: context.topology_generation,
            commit_group: context.commit_group,
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn is_fail_closed(&self) -> bool {
        self.outcome == PoolLifecycleOutcome::Refused
            && (!self.topology_complete || !self.owner_authorized)
    }

    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "action={} outcome={} devices={}/{} capacity_bytes={} topology_generation={} commit_group={} topology_complete={} owner_authorized={} reason={}",
            self.action.stable_id(),
            self.outcome.stable_id(),
            self.device_count,
            self.expected_device_count,
            self.capacity_bytes,
            self.topology_generation,
            self.commit_group,
            self.topology_complete,
            self.owner_authorized,
            self.reason
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> PoolLifecycleContext {
        PoolLifecycleContext {
            pool_guid: Some([0x44; 16]),
            pool_name: Some("life".to_string()),
            device_count: 2,
            expected_device_count: 2,
            capacity_bytes: 4096,
            topology_generation: 7,
            commit_group: 11,
        }
    }

    #[test]
    fn executed_evidence_records_authorized_complete_action() {
        let evidence = PoolLifecycleEvidence::executed(PoolLifecycleAction::Import, context());

        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Executed);
        assert!(evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(!evidence.is_fail_closed());
        assert!(evidence.summary().contains("action=import"));
    }

    #[test]
    fn refused_evidence_is_fail_closed_without_complete_authority() {
        let evidence = PoolLifecycleEvidence::refused(
            PoolLifecycleAction::Import,
            context(),
            "missing owner token",
        );

        assert_eq!(evidence.action, PoolLifecycleAction::Import);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert!(!evidence.topology_complete);
        assert!(!evidence.owner_authorized);
        assert!(evidence.is_fail_closed());
        assert!(evidence.summary().contains("action=import"));
        assert!(evidence.summary().contains("missing owner token"));
    }
}

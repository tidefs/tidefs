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
    pub fail_closed: bool,
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

impl PoolLifecycleContext {
    #[must_use]
    pub fn topology_complete(&self) -> bool {
        self.pool_guid.is_some_and(|guid| guid != [0u8; 16])
            && self
                .pool_name
                .as_deref()
                .is_some_and(|name| !name.trim().is_empty())
            && self.expected_device_count > 0
            && self.device_count == self.expected_device_count
            && self.capacity_bytes > 0
            && self.topology_generation > 0
    }
}

impl PoolLifecycleEvidence {
    #[must_use]
    pub fn executed(action: PoolLifecycleAction, context: PoolLifecycleContext) -> Self {
        if !context.topology_complete() {
            return Self::refused_with_authority(
                action,
                context,
                false,
                true,
                "topology evidence incomplete",
            );
        }

        Self {
            action,
            outcome: PoolLifecycleOutcome::Executed,
            topology_complete: true,
            owner_authorized: true,
            fail_closed: false,
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
        let fail_closed =
            action == PoolLifecycleAction::FailClosed || !topology_complete || !owner_authorized;
        Self::refused_with_fail_closed(
            action,
            context,
            topology_complete,
            owner_authorized,
            fail_closed,
            reason,
        )
    }

    #[must_use]
    pub fn refused_fail_closed_with_authority(
        action: PoolLifecycleAction,
        context: PoolLifecycleContext,
        topology_complete: bool,
        owner_authorized: bool,
        reason: impl Into<String>,
    ) -> Self {
        Self::refused_with_fail_closed(
            action,
            context,
            topology_complete,
            owner_authorized,
            true,
            reason,
        )
    }

    fn refused_with_fail_closed(
        action: PoolLifecycleAction,
        context: PoolLifecycleContext,
        topology_complete: bool,
        owner_authorized: bool,
        fail_closed: bool,
        reason: impl Into<String>,
    ) -> Self {
        let topology_complete = topology_complete && context.topology_complete();
        let fail_closed = fail_closed || !topology_complete || !owner_authorized;
        let reason = reason.into();
        let reason = if reason.trim().is_empty() {
            "lifecycle evidence refused".to_string()
        } else {
            reason
        };

        Self {
            action,
            outcome: PoolLifecycleOutcome::Refused,
            topology_complete,
            owner_authorized,
            fail_closed,
            pool_guid: context.pool_guid,
            pool_name: context.pool_name,
            device_count: context.device_count,
            expected_device_count: context.expected_device_count,
            capacity_bytes: context.capacity_bytes,
            topology_generation: context.topology_generation,
            commit_group: context.commit_group,
            reason,
        }
    }

    #[must_use]
    pub fn is_fail_closed(&self) -> bool {
        self.outcome == PoolLifecycleOutcome::Refused && self.fail_closed
    }

    #[must_use]
    pub fn summary(&self) -> String {
        let pool_guid = self
            .pool_guid
            .map(|guid| {
                let mut rendered = String::with_capacity(32);
                for byte in guid {
                    use std::fmt::Write as _;
                    let _ = write!(&mut rendered, "{byte:02x}");
                }
                rendered
            })
            .unwrap_or_else(|| "none".to_string());
        let pool_name = self.pool_name.as_deref().unwrap_or("none");

        format!(
            "action={} outcome={} pool_guid={} pool_name={} devices={}/{} capacity_bytes={} topology_generation={} commit_group={} topology_complete={} owner_authorized={} fail_closed={} reason={}",
            self.action.stable_id(),
            self.outcome.stable_id(),
            pool_guid,
            pool_name,
            self.device_count,
            self.expected_device_count,
            self.capacity_bytes,
            self.topology_generation,
            self.commit_group,
            self.topology_complete,
            self.owner_authorized,
            self.fail_closed,
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
        assert!(!evidence.fail_closed);
        assert!(!evidence.is_fail_closed());
        assert!(evidence.summary().contains("action=import"));
        assert!(evidence
            .summary()
            .contains("pool_guid=44444444444444444444444444444444"));
        assert!(evidence.summary().contains("pool_name=life"));
    }

    #[test]
    fn executed_evidence_refuses_incomplete_topology() {
        let mut incomplete = context();
        incomplete.device_count = 1;

        let evidence = PoolLifecycleEvidence::executed(PoolLifecycleAction::Import, incomplete);

        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
        assert!(evidence.summary().contains("outcome=refused"));
    }

    #[test]
    fn executed_evidence_refuses_topology_without_pool_guid() {
        let mut missing_guid = context();
        missing_guid.pool_guid = None;

        let evidence = PoolLifecycleEvidence::executed(PoolLifecycleAction::Import, missing_guid);

        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.pool_guid, None);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
    }

    #[test]
    fn executed_evidence_refuses_topology_with_nil_pool_guid() {
        let mut nil_guid = context();
        nil_guid.pool_guid = Some([0u8; 16]);

        let evidence = PoolLifecycleEvidence::executed(PoolLifecycleAction::Import, nil_guid);

        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.pool_guid, Some([0u8; 16]));
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
    }

    #[test]
    fn executed_evidence_refuses_topology_without_pool_name() {
        let mut missing_name = context();
        missing_name.pool_name = Some("   ".to_string());

        let evidence = PoolLifecycleEvidence::executed(PoolLifecycleAction::Import, missing_name);

        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.pool_name, Some("   ".to_string()));
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
    }

    #[test]
    fn executed_evidence_refuses_surplus_topology() {
        let mut surplus = context();
        surplus.device_count = 3;
        surplus.expected_device_count = 2;

        let evidence = PoolLifecycleEvidence::executed(PoolLifecycleAction::Import, surplus);

        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
    }

    #[test]
    fn executed_evidence_refuses_empty_topology() {
        let mut empty = context();
        empty.device_count = 0;
        empty.expected_device_count = 0;
        empty.capacity_bytes = 0;

        let evidence = PoolLifecycleEvidence::executed(PoolLifecycleAction::Import, empty);

        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.device_count, 0);
        assert_eq!(evidence.expected_device_count, 0);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
    }

    #[test]
    fn executed_evidence_refuses_topology_without_capacity() {
        let mut missing_capacity = context();
        missing_capacity.capacity_bytes = 0;

        let evidence =
            PoolLifecycleEvidence::executed(PoolLifecycleAction::Import, missing_capacity);

        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.device_count, 2);
        assert_eq!(evidence.expected_device_count, 2);
        assert_eq!(evidence.capacity_bytes, 0);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
    }

    #[test]
    fn executed_evidence_refuses_topology_without_generation() {
        let mut missing_generation = context();
        missing_generation.topology_generation = 0;

        let evidence =
            PoolLifecycleEvidence::executed(PoolLifecycleAction::Import, missing_generation);

        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.device_count, 2);
        assert_eq!(evidence.expected_device_count, 2);
        assert_eq!(evidence.capacity_bytes, 4096);
        assert_eq!(evidence.topology_generation, 0);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
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
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert!(evidence.summary().contains("action=import"));
        assert!(evidence.summary().contains("missing owner token"));
    }

    #[test]
    fn refused_evidence_cannot_overstate_incomplete_context() {
        let mut incomplete = context();
        incomplete.capacity_bytes = 0;

        let evidence = PoolLifecycleEvidence::refused_with_authority(
            PoolLifecycleAction::Export,
            incomplete,
            true,
            true,
            "export not completed",
        );

        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.capacity_bytes, 0);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
    }

    #[test]
    fn refused_evidence_records_non_empty_reason() {
        let evidence =
            PoolLifecycleEvidence::refused(PoolLifecycleAction::Import, context(), "   ");

        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.reason, "lifecycle evidence refused");
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert!(evidence
            .summary()
            .contains("reason=lifecycle evidence refused"));
    }

    #[test]
    fn refused_fail_closed_evidence_preserves_requested_action() {
        let evidence = PoolLifecycleEvidence::refused_fail_closed_with_authority(
            PoolLifecycleAction::Export,
            context(),
            true,
            true,
            "unsupported lifecycle action",
        );

        assert_eq!(evidence.action, PoolLifecycleAction::Export);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert!(evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert!(evidence.summary().contains("action=export"));
        assert!(evidence.summary().contains("fail_closed=true"));
    }

    #[test]
    fn explicit_refused_fail_closed_action_is_fail_closed() {
        let evidence = PoolLifecycleEvidence::refused_with_authority(
            PoolLifecycleAction::FailClosed,
            context(),
            true,
            true,
            "unsupported lifecycle action",
        );

        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert!(evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert!(evidence.summary().contains("action=fail-closed"));
    }
}

// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Operator truth-view carrier boundary for CLI status surfaces.

use tidefs_types_vfs_core::{
    TruthViewCutClass, TruthViewExactnessClass, TruthViewFreshnessClass, TruthViewProvenanceClass,
    TruthViewSourceClass,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperatorTruthEvidenceState {
    LiveWithinBudget,
    Stale,
    DeterministicNonLive,
    Refused,
}

impl OperatorTruthEvidenceState {
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::LiveWithinBudget => "live-within-budget",
            Self::Stale => "stale",
            Self::DeterministicNonLive => "deterministic-non-live",
            Self::Refused => "refused",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OperatorTruthCarrier {
    pub(crate) command: &'static str,
    pub(crate) operation: &'static str,
    pub(crate) pool_name: String,
    pub(crate) evidence_state: OperatorTruthEvidenceState,
    pub(crate) source: TruthViewSourceClass,
    pub(crate) cut: TruthViewCutClass,
    pub(crate) provenance: TruthViewProvenanceClass,
    pub(crate) exactness: TruthViewExactnessClass,
    pub(crate) freshness: TruthViewFreshnessClass,
    pub(crate) refusal: Option<&'static str>,
}

impl OperatorTruthCarrier {
    #[must_use]
    pub(crate) fn live_route(
        command: &'static str,
        operation: &'static str,
        pool_name: &str,
    ) -> Self {
        Self {
            command,
            operation,
            pool_name: pool_name.to_string(),
            evidence_state: OperatorTruthEvidenceState::LiveWithinBudget,
            source: TruthViewSourceClass::RuntimeMirror,
            cut: TruthViewCutClass::LiveWindow,
            provenance: TruthViewProvenanceClass::LiveMirror,
            exactness: TruthViewExactnessClass::SourceBoundProjection,
            freshness: TruthViewFreshnessClass::LiveWithinBudget,
            refusal: None,
        }
    }

    #[must_use]
    pub(crate) fn no_live_refusal(
        command: &'static str,
        operation: &'static str,
        pool_name: &str,
    ) -> Self {
        Self {
            command,
            operation,
            pool_name: pool_name.to_string(),
            evidence_state: OperatorTruthEvidenceState::Refused,
            source: TruthViewSourceClass::RuntimeMirror,
            cut: TruthViewCutClass::LiveWindow,
            provenance: TruthViewProvenanceClass::LiveMirror,
            exactness: TruthViewExactnessClass::DegradedOrPartial,
            freshness: TruthViewFreshnessClass::Refused,
            refusal: Some("no reachable live owner; cached local metadata is non-authoritative"),
        }
    }

    #[must_use]
    pub(crate) fn stale_non_live(
        command: &'static str,
        operation: &'static str,
        pool_name: &str,
    ) -> Self {
        Self {
            command,
            operation,
            pool_name: pool_name.to_string(),
            evidence_state: OperatorTruthEvidenceState::Stale,
            source: TruthViewSourceClass::RunbookState,
            cut: TruthViewCutClass::ArchiveRecall,
            provenance: TruthViewProvenanceClass::ManifestRecall,
            exactness: TruthViewExactnessClass::DegradedOrPartial,
            freshness: TruthViewFreshnessClass::Stale,
            refusal: Some("status evidence is stale and is not live operator truth"),
        }
    }

    #[must_use]
    pub(crate) fn deterministic_non_live(
        command: &'static str,
        operation: &'static str,
        pool_name: &str,
    ) -> Self {
        Self {
            command,
            operation,
            pool_name: pool_name.to_string(),
            evidence_state: OperatorTruthEvidenceState::DeterministicNonLive,
            source: TruthViewSourceClass::SemanticTrace,
            cut: TruthViewCutClass::TraceReplay,
            provenance: TruthViewProvenanceClass::SemanticTrace,
            exactness: TruthViewExactnessClass::SourceBoundProjection,
            freshness: TruthViewFreshnessClass::DeterministicNonLive,
            refusal: Some("deterministic replay/demo evidence is not live operator truth"),
        }
    }

    #[must_use]
    pub(crate) fn live_route_attempt_line(&self) -> String {
        format!(
            "operator truth carrier: attempting live route for tidefsctl {} {} pool '{}' with evidence {} and freshness {}",
            self.command,
            self.operation,
            self.pool_name,
            self.evidence_state.as_str(),
            self.freshness.as_str()
        )
    }

    #[must_use]
    pub(crate) fn json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "command": self.command,
            "operation": self.operation,
            "pool_name": self.pool_name,
            "evidence_state": self.evidence_state.as_str(),
            "supported_evidence_states": [
                OperatorTruthEvidenceState::LiveWithinBudget.as_str(),
                OperatorTruthEvidenceState::Stale.as_str(),
                OperatorTruthEvidenceState::DeterministicNonLive.as_str(),
                OperatorTruthEvidenceState::Refused.as_str(),
            ],
            "source": self.source.as_str(),
            "cut": self.cut.as_str(),
            "provenance": self.provenance.as_str(),
            "exactness": self.exactness.as_str(),
            "freshness": self.freshness.as_str(),
            "refusal": self.refusal,
        })
    }

    #[must_use]
    pub(crate) fn operator_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!(
                "operator truth carrier: tidefsctl {} {} pool '{}'",
                self.command, self.operation, self.pool_name
            ),
            format!("  evidence:   {}", self.evidence_state.as_str()),
            format!(
                "  states:     {}, {}, {}, {}",
                OperatorTruthEvidenceState::LiveWithinBudget.as_str(),
                OperatorTruthEvidenceState::Stale.as_str(),
                OperatorTruthEvidenceState::DeterministicNonLive.as_str(),
                OperatorTruthEvidenceState::Refused.as_str()
            ),
            format!("  source:     {}", self.source.as_str()),
            format!("  cut:        {}", self.cut.as_str()),
            format!("  provenance: {}", self.provenance.as_str()),
            format!("  exactness:  {}", self.exactness.as_str()),
            format!("  freshness:  {}", self.freshness.as_str()),
        ];
        if let Some(refusal) = self.refusal {
            lines.push(format!("  refusal:    {refusal}"));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_carrier_uses_runtime_mirror_freshness() {
        let carrier = OperatorTruthCarrier::live_route("cluster", "status", "alpha");

        assert_eq!(
            carrier.evidence_state,
            OperatorTruthEvidenceState::LiveWithinBudget
        );
        assert_eq!(carrier.source, TruthViewSourceClass::RuntimeMirror);
        assert_eq!(carrier.freshness, TruthViewFreshnessClass::LiveWithinBudget);
        assert_eq!(carrier.refusal, None);
    }

    #[test]
    fn live_route_attempt_line_exposes_truth_state() {
        let carrier = OperatorTruthCarrier::live_route("cluster", "status", "alpha");

        assert_eq!(
            carrier.live_route_attempt_line(),
            "operator truth carrier: attempting live route for tidefsctl cluster status pool 'alpha' with evidence live-within-budget and freshness fresh.truth_view.live_within_budget.f0"
        );
    }

    #[test]
    fn refusal_carrier_is_operator_readable_by_default() {
        let carrier = OperatorTruthCarrier::no_live_refusal("device", "status", "alpha");
        let lines = carrier.operator_lines();

        assert!(lines
            .iter()
            .any(|line| line.contains("evidence:   refused")));
        assert!(lines
            .iter()
            .any(|line| line.contains("fresh.truth_view.refused.f4")));
        assert!(lines.iter().any(|line| line.contains("refusal:")));
        assert!(!lines.join("\n").trim_start().starts_with('{'));
    }

    #[test]
    fn json_carrier_exposes_machine_fields_when_requested() {
        let carrier = OperatorTruthCarrier::no_live_refusal("device", "status", "alpha");
        let json = carrier.json_value();

        assert_eq!(json["evidence_state"], "refused");
        assert_eq!(json["source"], "source.truth_view.runtime_mirror.a2");
        assert_eq!(json["cut"], "cut.truth_view.live_window.c0");
        assert_eq!(json["provenance"], "prov.truth_view.live_mirror.p4");
        assert_eq!(json["exactness"], "exact.truth_view.degraded_or_partial.e3");
        assert_eq!(json["freshness"], "fresh.truth_view.refused.f4");
    }

    #[test]
    fn carrier_boundary_names_stale_and_deterministic_non_live() {
        let stale = OperatorTruthCarrier::stale_non_live("cluster", "status", "alpha");
        let deterministic =
            OperatorTruthCarrier::deterministic_non_live("cluster", "status", "alpha");

        assert_eq!(stale.evidence_state, OperatorTruthEvidenceState::Stale);
        assert_eq!(stale.freshness, TruthViewFreshnessClass::Stale);
        assert_eq!(
            deterministic.evidence_state,
            OperatorTruthEvidenceState::DeterministicNonLive
        );
        assert_eq!(
            deterministic.freshness,
            TruthViewFreshnessClass::DeterministicNonLive
        );
    }
}

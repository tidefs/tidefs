// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Operator truth-view carrier boundary for CLI status surfaces.

use tidefs_types_vfs_core::{
    ControlPlaneRouteClass, ResponseRegistryAnswerKind, TruthViewAudienceClass, TruthViewCutClass,
    TruthViewDistributedOperatorSignalClass, TruthViewDistributedOperatorStatusClass,
    TruthViewDistributedOperatorSurfaceRecord, TruthViewExactnessClass, TruthViewFreshnessClass,
    TruthViewProvenanceClass, TruthViewSourceClass, TruthViewSurfaceClass,
    TruthViewTruthBundleRecord,
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
    pub(crate) const fn distributed_status_class(&self) -> TruthViewDistributedOperatorStatusClass {
        match self.evidence_state {
            OperatorTruthEvidenceState::LiveWithinBudget => {
                TruthViewDistributedOperatorStatusClass::Nominal
            }
            OperatorTruthEvidenceState::Stale
            | OperatorTruthEvidenceState::DeterministicNonLive => {
                TruthViewDistributedOperatorStatusClass::Degraded
            }
            OperatorTruthEvidenceState::Refused => TruthViewDistributedOperatorStatusClass::Blocked,
        }
    }

    #[must_use]
    pub(crate) fn distributed_surface_record(&self) -> TruthViewDistributedOperatorSurfaceRecord {
        let signal = TruthViewDistributedOperatorSignalClass::Health;
        TruthViewDistributedOperatorSurfaceRecord {
            live_view_class: signal.required_live_view().as_u32(),
            signal_class: signal.as_u32(),
            status_class: self.distributed_status_class().as_u32(),
            source_class: self.source.as_u32(),
            cut_class: self.cut.as_u32(),
            provenance_class: self.provenance.as_u32(),
            exactness_class: self.exactness.as_u32(),
            freshness_class: self.freshness.as_u32(),
            ..TruthViewDistributedOperatorSurfaceRecord::default()
        }
    }

    #[must_use]
    pub(crate) fn truth_bundle_record(&self) -> TruthViewTruthBundleRecord {
        TruthViewTruthBundleRecord {
            route_class: ControlPlaneRouteClass::TruthSurface.as_u32(),
            surface_class: TruthViewSurfaceClass::SystemOverview.as_u32(),
            cut_class: self.cut.as_u32(),
            source_class: self.source.as_u32(),
            provenance_class: self.provenance.as_u32(),
            audience_class: TruthViewAudienceClass::OperatorSummary.as_u32(),
            answer_kind: if self.refusal.is_some() {
                ResponseRegistryAnswerKind::Refusal.as_u32()
            } else {
                ResponseRegistryAnswerKind::Bundle.as_u32()
            },
            ..TruthViewTruthBundleRecord::default()
        }
    }

    #[must_use]
    pub(crate) fn json_value(&self) -> serde_json::Value {
        let distributed_surface_record = self.distributed_surface_record();
        let truth_bundle_record = self.truth_bundle_record();

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
            "distributed_surface_record": {
                "live_view": distributed_surface_record.live_view().expect("operator truth live-view class is fixed").as_str(),
                "signal": distributed_surface_record.signal().expect("operator truth signal class is fixed").as_str(),
                "status": distributed_surface_record.status().expect("operator truth status class is fixed").as_str(),
                "source": distributed_surface_record.source().expect("operator truth source class comes from typed carrier").as_str(),
                "cut": distributed_surface_record.cut().expect("operator truth cut class comes from typed carrier").as_str(),
                "provenance": distributed_surface_record.provenance().expect("operator truth provenance class comes from typed carrier").as_str(),
                "exactness": distributed_surface_record.exactness().expect("operator truth exactness class comes from typed carrier").as_str(),
                "freshness": distributed_surface_record.freshness().expect("operator truth freshness class comes from typed carrier").as_str(),
            },
            "truth_bundle_record": {
                "route": truth_bundle_record.route().expect("operator truth route class is fixed").as_str(),
                "surface": truth_bundle_record.surface().expect("operator truth surface class is fixed").as_str(),
                "cut": truth_bundle_record.cut().expect("operator truth cut class comes from typed carrier").as_str(),
                "source": truth_bundle_record.source().expect("operator truth source class comes from typed carrier").as_str(),
                "provenance": truth_bundle_record.provenance().expect("operator truth provenance class comes from typed carrier").as_str(),
                "audience": truth_bundle_record.audience().expect("operator truth audience class is fixed").as_str(),
                "answer_kind": truth_bundle_record.answer_kind().expect("operator truth answer kind is fixed").as_str(),
            },
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
    fn live_carrier_projects_to_typed_truth_view_records() {
        let carrier = OperatorTruthCarrier::live_route("cluster", "status", "alpha");

        let surface = carrier.distributed_surface_record();
        assert_eq!(
            surface.live_view().unwrap(),
            TruthViewDistributedOperatorSignalClass::Health.required_live_view()
        );
        assert_eq!(
            surface.signal().unwrap(),
            TruthViewDistributedOperatorSignalClass::Health
        );
        assert_eq!(
            surface.status().unwrap(),
            TruthViewDistributedOperatorStatusClass::Nominal
        );
        assert_eq!(surface.source().unwrap(), carrier.source);
        assert_eq!(surface.cut().unwrap(), carrier.cut);
        assert_eq!(surface.provenance().unwrap(), carrier.provenance);
        assert_eq!(surface.exactness().unwrap(), carrier.exactness);
        assert_eq!(surface.freshness().unwrap(), carrier.freshness);

        let bundle = carrier.truth_bundle_record();
        assert_eq!(
            bundle.route().unwrap(),
            ControlPlaneRouteClass::TruthSurface
        );
        assert_eq!(
            bundle.surface().unwrap(),
            TruthViewSurfaceClass::SystemOverview
        );
        assert_eq!(bundle.source().unwrap(), carrier.source);
        assert_eq!(bundle.cut().unwrap(), carrier.cut);
        assert_eq!(bundle.provenance().unwrap(), carrier.provenance);
        assert_eq!(
            bundle.audience().unwrap(),
            TruthViewAudienceClass::OperatorSummary
        );
        assert_eq!(
            bundle.answer_kind().unwrap(),
            ResponseRegistryAnswerKind::Bundle
        );
    }

    #[test]
    fn refusal_projects_to_blocked_refusal_records() {
        let carrier = OperatorTruthCarrier::no_live_refusal("device", "status", "alpha");

        let surface = carrier.distributed_surface_record();
        assert_eq!(
            surface.status().unwrap(),
            TruthViewDistributedOperatorStatusClass::Blocked
        );
        assert_eq!(
            surface.freshness().unwrap(),
            TruthViewFreshnessClass::Refused
        );

        let bundle = carrier.truth_bundle_record();
        assert_eq!(
            bundle.answer_kind().unwrap(),
            ResponseRegistryAnswerKind::Refusal
        );
        assert_eq!(
            bundle.source().unwrap(),
            TruthViewSourceClass::RuntimeMirror
        );
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
        assert_eq!(
            stale.distributed_surface_record().status().unwrap(),
            TruthViewDistributedOperatorStatusClass::Degraded
        );
        assert_eq!(
            deterministic.distributed_surface_record().status().unwrap(),
            TruthViewDistributedOperatorStatusClass::Degraded
        );
    }
}

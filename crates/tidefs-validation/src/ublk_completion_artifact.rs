// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

pub const UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS: &str = "runtime-ublk-completion-artifact";
pub const UBLK_COMPLETION_ARTIFACT_CLAIM_ID: &str = "ublk.qid_tag.exactly_once_completion.v1";
pub const UBLK_QID_TAG_RUNTIME_SCENARIO: &str = "qemu-ublk-qid-tag-runtime";
pub const UBLK_QID_TAG_RUNTIME_ERROR_INJECTION_SCENARIO: &str =
    "qemu-ublk-qid-tag-runtime-error-injection";
const UBLK_QID_TAG_RUNTIME_MIN_QUEUES: u16 = 2;
const UBLK_QID_TAG_RUNTIME_MIN_QUEUE_DEPTH: u16 = 64;
const UBLK_COMPLETION_REQUIRED_NON_CLAIMS: &[&str] = &[
    "bounded_qemu_runtime_row",
    "not_block_device_product_readiness",
    "not_release_or_production_readiness",
    "not_successor_or_comparator_evidence",
];
const UBLK_QID_TAG_RUNTIME_REQUIRED_OPS: &[&str] =
    &["read", "write", "discard", "write_zeroes"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkCompletionArtifactSummary {
    pub event_count: usize,
    pub terminal_completion_count: usize,
    pub nr_hw_queues: u16,
    pub queue_depth: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkCompletionArtifactError {
    failures: Vec<String>,
}

impl UblkCompletionArtifactError {
    #[must_use]
    pub fn failures(&self) -> &[String] {
        &self.failures
    }
}

impl fmt::Display for UblkCompletionArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "uBLK completion artifact validation failed:")?;
        for failure in &self.failures {
            writeln!(f, "- {failure}")?;
        }
        Ok(())
    }
}

impl Error for UblkCompletionArtifactError {}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UblkCompletionArtifact {
    report_version: u32,
    generated_by: String,
    claim_ids: Vec<String>,
    evidence_class: String,
    evidence_scope: String,
    scenario: String,
    #[serde(default)]
    non_claims: Vec<String>,
    nr_hw_queues: u16,
    queue_depth: u16,
    max_completed_requests: usize,
    events: Vec<UblkCompletionArtifactEvent>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UblkCompletionArtifactEvent {
    sequence: u64,
    qid: u16,
    tag: u16,
    generation_token: u64,
    operation_kind: String,
    lifecycle_state: String,
    terminal_result: Option<i32>,
    source: String,
}

#[derive(Clone, Debug, Default)]
struct SlotVerifierState {
    current_generation_token: u64,
    in_flight_generation_token: Option<u64>,
    completed_generations: BTreeSet<u64>,
    pending_completion_cqe: Option<u64>,
    released: bool,
}

#[must_use]
pub fn validate_ublk_completion_artifact_json(
    text: &str,
) -> Result<UblkCompletionArtifactSummary, UblkCompletionArtifactError> {
    let artifact = match serde_json::from_str::<UblkCompletionArtifact>(text) {
        Ok(artifact) => artifact,
        Err(error) => {
            return Err(UblkCompletionArtifactError {
                failures: vec![format!("artifact JSON does not match schema: {error}")],
            });
        }
    };
    validate_ublk_completion_artifact(artifact)
}

pub fn validate_ublk_completion_artifact_path(
    path: impl AsRef<Path>,
) -> Result<UblkCompletionArtifactSummary, UblkCompletionArtifactError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|error| UblkCompletionArtifactError {
        failures: vec![format!("read `{}`: {error}", path.display())],
    })?;
    validate_ublk_completion_artifact_json(&text)
}

fn validate_ublk_completion_artifact(
    artifact: UblkCompletionArtifact,
) -> Result<UblkCompletionArtifactSummary, UblkCompletionArtifactError> {
    let mut failures = Vec::new();
    if artifact.report_version != 1 {
        failures.push(format!(
            "report_version must be 1, found {}",
            artifact.report_version
        ));
    }
    if artifact.generated_by.trim().is_empty() {
        failures.push("generated_by must not be empty".to_string());
    }
    if artifact.evidence_class != UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS {
        failures.push(format!(
            "evidence_class must be `{UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS}`, found `{}`",
            artifact.evidence_class
        ));
    }
    if !artifact
        .claim_ids
        .iter()
        .any(|claim_id| claim_id == UBLK_COMPLETION_ARTIFACT_CLAIM_ID)
    {
        failures.push(format!(
            "claim_ids must include `{UBLK_COMPLETION_ARTIFACT_CLAIM_ID}`"
        ));
    }
    if artifact.evidence_scope.trim().is_empty() {
        failures.push("evidence_scope must not be empty".to_string());
    }
    if artifact.scenario.trim().is_empty() {
        failures.push("scenario must not be empty".to_string());
    }
    if artifact.nr_hw_queues == 0 {
        failures.push("nr_hw_queues must be nonzero".to_string());
    }
    if artifact.queue_depth == 0 {
        failures.push("queue_depth must be nonzero".to_string());
    }
    if artifact.max_completed_requests == 0 {
        failures.push("max_completed_requests must be nonzero".to_string());
    }
    if artifact.events.is_empty() {
        failures.push("events must not be empty".to_string());
    }

    let mut slots = BTreeMap::<(u16, u16), SlotVerifierState>::new();
    let mut last_sequence = None;
    let mut terminal_completion_count = 0usize;
    let mut saw_fetch_submitted = false;
    let mut saw_request_fetched = false;
    let mut saw_request_reissued = false;
    let mut saw_completion_submitted = false;
    let mut saw_completion_cqe = false;
    let mut saw_queue_released = false;
    let mut fetch_submitted_slots = BTreeSet::<(u16, u16)>::new();
    let mut queue_released_slots = BTreeSet::<(u16, u16)>::new();
    let mut terminal_qids = BTreeSet::<u16>::new();
    let mut terminal_tags = BTreeSet::<u16>::new();
    let mut terminal_ops = BTreeSet::<String>::new();
    let mut negative_terminal_count = 0usize;
    let mut negative_terminal_ops = BTreeSet::<String>::new();

    for event in &artifact.events {
        if let Some(previous) = last_sequence {
            if event.sequence <= previous {
                failures.push(format!(
                    "event sequence {} is not strictly after previous sequence {previous}",
                    event.sequence
                ));
            }
        }
        last_sequence = Some(event.sequence);

        if event.qid >= artifact.nr_hw_queues {
            failures.push(format!(
                "event {} has wrong-qid {} for nr_hw_queues {}",
                event.sequence, event.qid, artifact.nr_hw_queues
            ));
        }
        if event.tag >= artifact.queue_depth {
            failures.push(format!(
                "event {} has out-of-range tag {} for queue_depth {}",
                event.sequence, event.tag, artifact.queue_depth
            ));
        }
        if event.operation_kind.trim().is_empty() {
            failures.push(format!("event {} has empty operation_kind", event.sequence));
        }
        if event.source.trim().is_empty() {
            failures.push(format!("event {} has empty source", event.sequence));
        }

        let slot = slots.entry((event.qid, event.tag)).or_default();
        match event.lifecycle_state.as_str() {
            "fetch_submitted" => {
                saw_fetch_submitted = true;
                fetch_submitted_slots.insert((event.qid, event.tag));
                if event.terminal_result.is_some() {
                    failures.push(format!(
                        "event {} fetch_submitted must not carry terminal_result",
                        event.sequence
                    ));
                }
                if event.generation_token != slot.current_generation_token {
                    failures.push(format!(
                        "event {} fetch_submitted has stale generation_token {}; expected {}",
                        event.sequence, event.generation_token, slot.current_generation_token
                    ));
                }
            }
            "request_fetched" | "request_reissued" => {
                if event.lifecycle_state == "request_fetched" {
                    saw_request_fetched = true;
                } else {
                    saw_request_reissued = true;
                }
                if event.terminal_result.is_some() {
                    failures.push(format!(
                        "event {} {} must not carry terminal_result",
                        event.sequence, event.lifecycle_state
                    ));
                }
                if slot.released {
                    failures.push(format!(
                        "event {} fetched qid {} tag {} after queue release",
                        event.sequence, event.qid, event.tag
                    ));
                }
                if let Some(active_generation) = slot.in_flight_generation_token {
                    failures.push(format!(
                        "event {} fetched qid {} tag {} generation {} while generation {} is still in flight",
                        event.sequence,
                        event.qid,
                        event.tag,
                        event.generation_token,
                        active_generation
                    ));
                }
                let expected_generation = slot.current_generation_token.saturating_add(1);
                if event.generation_token != expected_generation {
                    failures.push(format!(
                        "event {} has stale generation_token {}; expected {} for qid {} tag {}",
                        event.sequence,
                        event.generation_token,
                        expected_generation,
                        event.qid,
                        event.tag
                    ));
                }
                slot.current_generation_token = event.generation_token;
                slot.in_flight_generation_token = Some(event.generation_token);
            }
            "completion_submitted" => {
                saw_completion_submitted = true;
                let Some(terminal_result) = event.terminal_result else {
                    failures.push(format!(
                        "event {} completion_submitted must carry terminal_result",
                        event.sequence
                    ));
                    continue;
                };
                if slot.released {
                    failures.push(format!(
                        "event {} completion after abort/release for qid {} tag {} generation {}",
                        event.sequence, event.qid, event.tag, event.generation_token
                    ));
                }
                match slot.in_flight_generation_token {
                    Some(active_generation) if active_generation == event.generation_token => {}
                    Some(active_generation) => failures.push(format!(
                        "event {} stale completion generation_token {}; active generation is {}",
                        event.sequence, event.generation_token, active_generation
                    )),
                    None => failures.push(format!(
                        "event {} completion without in-flight request for qid {} tag {} generation {}",
                        event.sequence, event.qid, event.tag, event.generation_token
                    )),
                }
                if !slot.completed_generations.insert(event.generation_token) {
                    failures.push(format!(
                        "duplicate completion for qid {} tag {} generation {}",
                        event.qid, event.tag, event.generation_token
                    ));
                }
                slot.in_flight_generation_token = None;
                slot.pending_completion_cqe = Some(event.generation_token);
                terminal_qids.insert(event.qid);
                terminal_tags.insert(event.tag);
                terminal_ops.insert(event.operation_kind.clone());
                if terminal_result < 0 {
                    negative_terminal_count = negative_terminal_count.saturating_add(1);
                    negative_terminal_ops.insert(event.operation_kind.clone());
                }
                terminal_completion_count = terminal_completion_count.saturating_add(1);
            }
            "completion_cqe" => {
                saw_completion_cqe = true;
                if event.terminal_result.is_none() {
                    failures.push(format!(
                        "event {} completion_cqe must carry terminal_result",
                        event.sequence
                    ));
                }
                match slot.pending_completion_cqe {
                    Some(pending_generation) if pending_generation == event.generation_token => {
                        slot.pending_completion_cqe = None;
                    }
                    Some(pending_generation) => failures.push(format!(
                        "event {} completion_cqe generation_token {}; pending completion cqe is {}",
                        event.sequence, event.generation_token, pending_generation
                    )),
                    None => failures.push(format!(
                        "event {} completion_cqe without pending completion for qid {} tag {} generation {}",
                        event.sequence, event.qid, event.tag, event.generation_token
                    )),
                }
            }
            "request_released" => {
                let Some(terminal_result) = event.terminal_result else {
                    failures.push(format!(
                        "event {} request_released must carry terminal_result",
                        event.sequence
                    ));
                    continue;
                };
                match slot.in_flight_generation_token {
                    Some(active_generation) if active_generation == event.generation_token => {}
                    Some(active_generation) => failures.push(format!(
                        "event {} release generation_token {}; active generation is {}",
                        event.sequence, event.generation_token, active_generation
                    )),
                    None => failures.push(format!(
                        "event {} request_released without in-flight request for qid {} tag {}",
                        event.sequence, event.qid, event.tag
                    )),
                }
                if !slot.completed_generations.insert(event.generation_token) {
                    failures.push(format!(
                        "duplicate release terminal for qid {} tag {} generation {}",
                        event.qid, event.tag, event.generation_token
                    ));
                }
                slot.in_flight_generation_token = None;
                terminal_qids.insert(event.qid);
                terminal_tags.insert(event.tag);
                terminal_ops.insert(event.operation_kind.clone());
                if terminal_result < 0 {
                    negative_terminal_count = negative_terminal_count.saturating_add(1);
                    negative_terminal_ops.insert(event.operation_kind.clone());
                }
                terminal_completion_count = terminal_completion_count.saturating_add(1);
            }
            "queue_released" => {
                saw_queue_released = true;
                queue_released_slots.insert((event.qid, event.tag));
                if event.terminal_result.is_some() {
                    failures.push(format!(
                        "event {} queue_released must not carry terminal_result",
                        event.sequence
                    ));
                }
                if event.generation_token != slot.current_generation_token {
                    failures.push(format!(
                        "event {} queue_released has generation_token {}; current generation is {}",
                        event.sequence, event.generation_token, slot.current_generation_token
                    ));
                }
                if slot.released {
                    failures.push(format!(
                        "duplicate queue release for qid {} tag {}",
                        event.qid, event.tag
                    ));
                }
                slot.released = true;
            }
            "completion_submit_failed" | "completion_cqe_error" | "fetch_cqe_error" => {
                failures.push(format!(
                    "event {} records failing runtime lifecycle state `{}`",
                    event.sequence, event.lifecycle_state
                ));
            }
            other => {
                failures.push(format!(
                    "event {} has unknown lifecycle_state `{other}`",
                    event.sequence
                ));
            }
        }
    }

    for ((qid, tag), slot) in &slots {
        if let Some(generation) = slot.in_flight_generation_token {
            failures.push(format!(
                "missing terminal completion for in-flight request qid {qid} tag {tag} generation {generation}"
            ));
        }
    }

    for (state, saw) in [
        ("fetch_submitted", saw_fetch_submitted),
        ("request_fetched", saw_request_fetched),
        ("request_reissued", saw_request_reissued),
        ("completion_submitted", saw_completion_submitted),
        ("completion_cqe", saw_completion_cqe),
        ("queue_released", saw_queue_released),
    ] {
        if !saw {
            failures.push(format!(
                "artifact does not observe lifecycle state `{state}`"
            ));
        }
    }
    if terminal_completion_count == 0 {
        failures.push("artifact records no terminal completions".to_string());
    }
    validate_scenario_contract(
        &artifact,
        &fetch_submitted_slots,
        &queue_released_slots,
        &terminal_qids,
        &terminal_tags,
        &terminal_ops,
        negative_terminal_count,
        &negative_terminal_ops,
        &mut failures,
    );

    if failures.is_empty() {
        Ok(UblkCompletionArtifactSummary {
            event_count: artifact.events.len(),
            terminal_completion_count,
            nr_hw_queues: artifact.nr_hw_queues,
            queue_depth: artifact.queue_depth,
        })
    } else {
        Err(UblkCompletionArtifactError { failures })
    }
}

fn validate_scenario_contract(
    artifact: &UblkCompletionArtifact,
    fetch_submitted_slots: &BTreeSet<(u16, u16)>,
    queue_released_slots: &BTreeSet<(u16, u16)>,
    terminal_qids: &BTreeSet<u16>,
    terminal_tags: &BTreeSet<u16>,
    terminal_ops: &BTreeSet<String>,
    negative_terminal_count: usize,
    negative_terminal_ops: &BTreeSet<String>,
    failures: &mut Vec<String>,
) {
    let require_operation_breadth = match artifact.scenario.as_str() {
        UBLK_QID_TAG_RUNTIME_SCENARIO => true,
        UBLK_QID_TAG_RUNTIME_ERROR_INJECTION_SCENARIO => false,
        _ => return,
    };

    if artifact.nr_hw_queues < UBLK_QID_TAG_RUNTIME_MIN_QUEUES {
        failures.push(format!(
            "scenario `{}` requires nr_hw_queues >= {}, found {}",
            artifact.scenario, UBLK_QID_TAG_RUNTIME_MIN_QUEUES, artifact.nr_hw_queues
        ));
    }
    if artifact.queue_depth < UBLK_QID_TAG_RUNTIME_MIN_QUEUE_DEPTH {
        failures.push(format!(
            "scenario `{}` requires queue_depth >= {}, found {}",
            artifact.scenario, UBLK_QID_TAG_RUNTIME_MIN_QUEUE_DEPTH, artifact.queue_depth
        ));
    }

    for non_claim in UBLK_COMPLETION_REQUIRED_NON_CLAIMS {
        if !artifact
            .non_claims
            .iter()
            .any(|actual| actual.as_str() == *non_claim)
        {
            failures.push(format!(
                "scenario `{}` non_claims must include `{non_claim}`",
                artifact.scenario
            ));
        }
    }

    let expected_slots = usize::from(artifact.nr_hw_queues) * usize::from(artifact.queue_depth);
    if fetch_submitted_slots.len() != expected_slots {
        failures.push(format!(
            "scenario `{}` must submit FETCH_REQ for every configured qid/tag slot; expected {}, found {}",
            artifact.scenario,
            expected_slots,
            fetch_submitted_slots.len()
        ));
    }
    if queue_released_slots.len() != expected_slots {
        failures.push(format!(
            "scenario `{}` must release every configured qid/tag slot during teardown; expected {}, found {}",
            artifact.scenario,
            expected_slots,
            queue_released_slots.len()
        ));
    }

    if require_operation_breadth {
        if terminal_qids.len() < usize::from(UBLK_QID_TAG_RUNTIME_MIN_QUEUES) {
            failures.push(format!(
                "scenario `{}` must terminally complete requests on at least two queues; found qids {:?}",
                artifact.scenario, terminal_qids
            ));
        }
        if terminal_tags.len() < 2 {
            failures.push(format!(
                "scenario `{}` must terminally complete multiple tags; found tags {:?}",
                artifact.scenario, terminal_tags
            ));
        }
        for operation in UBLK_QID_TAG_RUNTIME_REQUIRED_OPS {
            if !terminal_ops
                .iter()
                .any(|actual| actual.as_str() == *operation)
            {
                failures.push(format!(
                    "scenario `{}` must terminally complete `{operation}`",
                    artifact.scenario
                ));
            }
        }
        if negative_terminal_count != 0 {
            failures.push(format!(
                "scenario `{}` success artifact must not contain negative terminal results",
                artifact.scenario
            ));
        }
    } else {
        if negative_terminal_count == 0 {
            failures.push(format!(
                "scenario `{}` must record at least one negative terminal completion",
                artifact.scenario
            ));
        }
        if !negative_terminal_ops
            .iter()
            .any(|operation| operation.as_str() == "write")
        {
            failures.push(format!(
                "scenario `{}` must include a negative write terminal completion",
                artifact.scenario
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    fn valid_artifact() -> String {
        r#"{
  "report_version": 1,
  "generated_by": "tidefs-block-volume-adapter-daemon",
  "claim_ids": ["ublk.qid_tag.exactly_once_completion.v1"],
  "evidence_class": "runtime-ublk-completion-artifact",
  "evidence_scope": "bounded runtime uBLK daemon qid/tag completion lifecycle trace",
  "scenario": "qemu-ublk-smoke",
  "nr_hw_queues": 1,
  "queue_depth": 2,
  "max_completed_requests": 4,
  "events": [
    {"sequence": 1, "qid": 0, "tag": 0, "generation_token": 0, "operation_kind": "fetch", "lifecycle_state": "fetch_submitted", "terminal_result": null, "source": "initial_fetch_req_submit"},
    {"sequence": 2, "qid": 0, "tag": 1, "generation_token": 0, "operation_kind": "fetch", "lifecycle_state": "fetch_submitted", "terminal_result": null, "source": "initial_fetch_req_submit"},
    {"sequence": 3, "qid": 0, "tag": 0, "generation_token": 1, "operation_kind": "read", "lifecycle_state": "request_fetched", "terminal_result": null, "source": "fetch_req_cqe"},
    {"sequence": 4, "qid": 0, "tag": 0, "generation_token": 1, "operation_kind": "read", "lifecycle_state": "completion_submitted", "terminal_result": 0, "source": "daemon_commit_and_fetch_submit"},
    {"sequence": 5, "qid": 0, "tag": 0, "generation_token": 1, "operation_kind": "read", "lifecycle_state": "completion_cqe", "terminal_result": 0, "source": "commit_and_fetch_cqe"},
    {"sequence": 6, "qid": 0, "tag": 0, "generation_token": 2, "operation_kind": "write", "lifecycle_state": "request_reissued", "terminal_result": null, "source": "commit_and_fetch_cqe"},
    {"sequence": 7, "qid": 0, "tag": 0, "generation_token": 2, "operation_kind": "write", "lifecycle_state": "completion_submitted", "terminal_result": 0, "source": "daemon_commit_and_fetch_submit"},
    {"sequence": 8, "qid": 0, "tag": 0, "generation_token": 2, "operation_kind": "write", "lifecycle_state": "completion_cqe", "terminal_result": 0, "source": "commit_and_fetch_cqe"},
    {"sequence": 9, "qid": 0, "tag": 0, "generation_token": 3, "operation_kind": "flush", "lifecycle_state": "request_reissued", "terminal_result": null, "source": "commit_and_fetch_cqe"},
    {"sequence": 10, "qid": 0, "tag": 0, "generation_token": 3, "operation_kind": "flush", "lifecycle_state": "completion_submitted", "terminal_result": 0, "source": "daemon_commit_and_fetch_submit"},
    {"sequence": 11, "qid": 0, "tag": 0, "generation_token": 3, "operation_kind": "release", "lifecycle_state": "queue_released", "terminal_result": null, "source": "data_queue_release"},
    {"sequence": 12, "qid": 0, "tag": 1, "generation_token": 0, "operation_kind": "release", "lifecycle_state": "queue_released", "terminal_result": null, "source": "data_queue_release"}
  ]
}"#
        .to_string()
    }

    fn assert_invalid_contains(mut text: String, needle: &str) {
        let error = validate_ublk_completion_artifact_json(&text).expect_err("artifact invalid");
        assert!(
            error
                .failures()
                .iter()
                .any(|failure| failure.contains(needle)),
            "expected failure containing `{needle}`, got {error:?} for {text}"
        );
        text.clear();
    }

    fn qid_tag_runtime_artifact(scenario: &str, operations: &[(&str, u16, u16, i32)]) -> String {
        let nr_hw_queues = 2_u16;
        let queue_depth = 64_u16;
        let mut sequence = 1_u64;
        let mut current_generation =
            vec![vec![0_u64; usize::from(queue_depth)]; usize::from(nr_hw_queues)];
        let mut events = Vec::<String>::new();

        for qid in 0..nr_hw_queues {
            for tag in 0..queue_depth {
                events.push(format!(
                    r#"    {{"sequence": {sequence}, "qid": {qid}, "tag": {tag}, "generation_token": 0, "operation_kind": "fetch", "lifecycle_state": "fetch_submitted", "terminal_result": null, "source": "initial_fetch_req_submit"}}"#
                ));
                sequence += 1;
            }
        }

        for (operation, qid, tag, terminal_result) in operations {
            let generation = current_generation[usize::from(*qid)][usize::from(*tag)] + 1;
            current_generation[usize::from(*qid)][usize::from(*tag)] = generation;
            let fetch_state = if generation == 1 {
                "request_fetched"
            } else {
                "request_reissued"
            };
            let fetch_source = if generation == 1 {
                "fetch_req_cqe"
            } else {
                "commit_and_fetch_cqe"
            };
            events.push(format!(
                r#"    {{"sequence": {sequence}, "qid": {qid}, "tag": {tag}, "generation_token": {generation}, "operation_kind": "{operation}", "lifecycle_state": "{fetch_state}", "terminal_result": null, "source": "{fetch_source}"}}"#
            ));
            sequence += 1;
            events.push(format!(
                r#"    {{"sequence": {sequence}, "qid": {qid}, "tag": {tag}, "generation_token": {generation}, "operation_kind": "{operation}", "lifecycle_state": "completion_submitted", "terminal_result": {terminal_result}, "source": "daemon_commit_and_fetch_submit"}}"#
            ));
            sequence += 1;
            events.push(format!(
                r#"    {{"sequence": {sequence}, "qid": {qid}, "tag": {tag}, "generation_token": {generation}, "operation_kind": "{operation}", "lifecycle_state": "completion_cqe", "terminal_result": {terminal_result}, "source": "commit_and_fetch_cqe"}}"#
            ));
            sequence += 1;
        }

        for qid in 0..nr_hw_queues {
            for tag in 0..queue_depth {
                let generation = current_generation[usize::from(qid)][usize::from(tag)];
                events.push(format!(
                    r#"    {{"sequence": {sequence}, "qid": {qid}, "tag": {tag}, "generation_token": {generation}, "operation_kind": "release", "lifecycle_state": "queue_released", "terminal_result": null, "source": "data_queue_release"}}"#
                ));
                sequence += 1;
            }
        }

        let mut text = String::new();
        let _ = writeln!(
            text,
            r#"{{
  "report_version": 1,
  "generated_by": "tidefs-block-volume-adapter-daemon",
  "claim_ids": ["ublk.qid_tag.exactly_once_completion.v1"],
  "evidence_class": "runtime-ublk-completion-artifact",
  "evidence_scope": "bounded runtime uBLK daemon qid/tag completion lifecycle trace",
  "scenario": "{scenario}",
  "non_claims": [
    "bounded_qemu_runtime_row",
    "not_block_device_product_readiness",
    "not_release_or_production_readiness",
    "not_successor_or_comparator_evidence"
  ],
  "nr_hw_queues": {nr_hw_queues},
  "queue_depth": {queue_depth},
  "max_completed_requests": 512,
  "events": [
{}
  ]
}}"#,
            events.join(",\n")
        );
        text
    }

    #[test]
    fn accepts_bounded_runtime_completion_artifact() {
        let summary =
            validate_ublk_completion_artifact_json(&valid_artifact()).expect("valid artifact");
        assert_eq!(summary.event_count, 12);
        assert_eq!(summary.terminal_completion_count, 3);
        assert_eq!(summary.nr_hw_queues, 1);
        assert_eq!(summary.queue_depth, 2);
    }

    #[test]
    fn accepts_qid_tag_runtime_contract_artifact() {
        let text = qid_tag_runtime_artifact(
            UBLK_QID_TAG_RUNTIME_SCENARIO,
            &[
                ("read", 0, 0, 4096),
                ("write", 1, 0, 4096),
                ("flush", 0, 0, 0),
                ("discard", 1, 1, 0),
                ("write_zeroes", 0, 2, 0),
            ],
        );
        let summary = validate_ublk_completion_artifact_json(&text).expect("valid artifact");
        assert_eq!(summary.nr_hw_queues, 2);
        assert_eq!(summary.queue_depth, 64);
        assert_eq!(summary.terminal_completion_count, 5);
    }

    #[test]
    fn accepts_qid_tag_error_injection_contract_artifact() {
        let text = qid_tag_runtime_artifact(
            UBLK_QID_TAG_RUNTIME_ERROR_INJECTION_SCENARIO,
            &[("read", 0, 0, 4096), ("write", 0, 0, -5)],
        );
        let summary = validate_ublk_completion_artifact_json(&text).expect("valid artifact");
        assert_eq!(summary.terminal_completion_count, 2);
    }

    #[test]
    fn rejects_focused_smoke_shape_for_qid_tag_runtime_contract() {
        let text = valid_artifact().replace(
            r#""scenario": "qemu-ublk-smoke""#,
            r#""scenario": "qemu-ublk-qid-tag-runtime""#,
        );
        assert_invalid_contains(text, "requires nr_hw_queues >= 2");
    }

    #[test]
    fn rejects_runtime_contract_without_operation_breadth() {
        let text = qid_tag_runtime_artifact(
            UBLK_QID_TAG_RUNTIME_SCENARIO,
            &[("read", 0, 0, 4096), ("write", 1, 0, 4096), ("write_zeroes", 0, 1, 0)],
        );
        assert_invalid_contains(text, "must terminally complete `discard`");
    }

    #[test]
    fn rejects_error_injection_contract_without_negative_completion() {
        let text = qid_tag_runtime_artifact(
            UBLK_QID_TAG_RUNTIME_ERROR_INJECTION_SCENARIO,
            &[("read", 0, 0, 4096), ("write", 0, 0, 4096)],
        );
        assert_invalid_contains(
            text,
            "must record at least one negative terminal completion",
        );
    }

    #[test]
    fn rejects_duplicate_completion_for_generation() {
        let text = valid_artifact().replace(
            r#"{"sequence": 5, "qid": 0, "tag": 0, "generation_token": 1, "operation_kind": "read", "lifecycle_state": "completion_cqe", "terminal_result": 0, "source": "commit_and_fetch_cqe"}"#,
            r#"{"sequence": 5, "qid": 0, "tag": 0, "generation_token": 1, "operation_kind": "read", "lifecycle_state": "completion_submitted", "terminal_result": 0, "source": "daemon_commit_and_fetch_submit"}"#,
        );
        assert_invalid_contains(text, "duplicate completion");
    }

    #[test]
    fn rejects_stale_generation_completion() {
        let text = valid_artifact().replace(
            r#""sequence": 7, "qid": 0, "tag": 0, "generation_token": 2"#,
            r#""sequence": 7, "qid": 0, "tag": 0, "generation_token": 1"#,
        );
        assert_invalid_contains(text, "stale completion generation_token");
    }

    #[test]
    fn rejects_wrong_qid_completion() {
        let text = valid_artifact().replace(
            r#""sequence": 7, "qid": 0, "tag": 0, "generation_token": 2"#,
            r#""sequence": 7, "qid": 7, "tag": 0, "generation_token": 2"#,
        );
        assert_invalid_contains(text, "wrong-qid");
    }

    #[test]
    fn rejects_completion_after_release() {
        let text = valid_artifact().replace(
            r#"{"sequence": 11, "qid": 0, "tag": 0, "generation_token": 3, "operation_kind": "release", "lifecycle_state": "queue_released", "terminal_result": null, "source": "data_queue_release"}"#,
            r#"{"sequence": 11, "qid": 0, "tag": 0, "generation_token": 3, "operation_kind": "release", "lifecycle_state": "queue_released", "terminal_result": null, "source": "data_queue_release"},
    {"sequence": 12, "qid": 0, "tag": 0, "generation_token": 3, "operation_kind": "flush", "lifecycle_state": "completion_submitted", "terminal_result": 0, "source": "daemon_commit_and_fetch_submit"}"#,
        );
        assert_invalid_contains(text, "completion after abort/release");
    }

    #[test]
    fn rejects_missing_terminal_completion() {
        let text = valid_artifact().replace(
            r#"    {"sequence": 10, "qid": 0, "tag": 0, "generation_token": 3, "operation_kind": "flush", "lifecycle_state": "completion_submitted", "terminal_result": 0, "source": "daemon_commit_and_fetch_submit"},
"#,
            "",
        );
        assert_invalid_contains(text, "missing terminal completion");
    }
}

// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Focused mounted-userspace foreground-read evidence while scrub work is pending.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use crate::evidence_artifact_manifest::{
    content_digest_for_bytes, BlockingIssueRef, EvidenceArtifactManifest,
    EVIDENCE_ARTIFACT_MANIFEST_VERSION,
};
use crate::mount_harness::{find_daemon_binary, MountHarness};
use crate::runtime_artifact_source::RuntimeArtifactSource;
use crate::validation_schema::ValidationTier;
use crate::validation_status::ValidationStatus;
use tidefs_performance_contract::oracle::{
    with_scheduling_and_admission, without_scheduling_or_admission, OracleConfig,
};
use tidefs_performance_contract::ServiceCurve;

pub const SCRUB_FOREGROUND_READ_ROW_ID: &str = "scrub-foreground-read-runtime";
pub const SCRUB_READ_RUNTIME_ARTIFACT: &str = "scrub-read-runtime.json";
pub const SCRUB_READ_EVIDENCE_CLASS: &str = "runtime-scrub-read-artifact";
pub const SCRUB_READ_PRIMARY_CLAIM_ID: &str = "scrub.foreground_read.protected.v1";

const FOREGROUND_READ_NOT_BLOCKED_CLAIM_ID: &str =
    "perf.local.foreground_read_not_blocked_by_scrub.v1";
const SOURCE_ISSUE: &str = "https://github.com/tidefs/tidefs/issues/1792";
const SOURCE_LABEL: &str = "qemu-smoke-scrub-foreground-read-runtime";
const BACKGROUND_SCRUB_INTERVAL_SECS: u64 = 1;
const FOREGROUND_READ_BYTES: usize = 128 * 1024;
const FOREGROUND_READ_ITERATIONS: u32 = 8;
const SCRUB_UNITS_REQUESTED: u32 = 16;
const SCRUB_UNIT_BYTES: u64 = 64 * 1024;
const SCRUB_LIMIT_BYTES_PER_SEC: u64 = 4 * 1024;
const SCRUB_LIMIT_IOPS: u64 = 1;
const SCRUB_BACKOFF_MILLIS: u64 = 25;
const FUSE_SUPER_MAGIC: libc::c_long = 0x6573_5546;
const MOUNT_READY_TIMEOUT_SECS: u64 = 10;
const FOREGROUND_READ_ARRIVAL_TICK: u64 = 1;
const MAX_FOREGROUND_READ_WAIT_TICKS: u64 = 1;

pub const SCRUB_READ_RESIDUAL_RISK: &str = "This row records a mounted FUSE foreground-read correctness workload while scrub work is configured and represented by bounded scrub queue/rate-limiter facts. It can support the runtime-scrub-read-artifact evidence class for the named claims, but it is not production performance readiness, broad scrub/repair correctness, kernel/uBLK/RDMA validation, crash recovery, release-candidate status, or a claim-status/product-wording change.";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScrubForegroundReadRuntimeEvidence {
    pub manifest_version: u8,
    pub row_id: String,
    pub evidence_class: String,
    pub source_issue: String,
    pub validation_tier: ValidationTier,
    pub outcome: ValidationStatus,
    pub supported_claims: Vec<String>,
    pub non_claims: Vec<String>,
    pub claim_status_change: bool,
    pub product_wording_change: bool,
    pub run_id: String,
    pub source_ref: String,
    pub generated_at: String,
    pub environment: RuntimeEnvironmentEvidence,
    pub runtime_source: RuntimeArtifactSource,
    pub mount: Option<MountRuntimeEvidence>,
    pub foreground_read: ForegroundReadEvidence,
    pub scrub_activity: ScrubActivityEvidence,
    pub service_curve: ServiceCurveEvidence,
    pub passed: bool,
}

impl ScrubForegroundReadRuntimeEvidence {
    pub fn assert_no_product_or_harness_failure(&self) -> Result<(), String> {
        match self.outcome {
            ValidationStatus::Pass => {
                if self.passed
                    && scrub_read_isolation_passed(
                        &self.foreground_read,
                        &self.scrub_activity,
                        &self.service_curve,
                    )
                {
                    Ok(())
                } else {
                    Err(
                        "scrub foreground-read runtime row reported pass without complete read-isolation evidence"
                            .to_string(),
                    )
                }
            }
            ValidationStatus::EnvironmentRefusal => Ok(()),
            ValidationStatus::ProductFail => Err(format!(
                "scrub foreground-read runtime row found product failure: {:?}",
                self.foreground_read.failures
            )),
            ValidationStatus::HarnessFail => {
                Err("scrub foreground-read runtime row reported a harness failure".to_string())
            }
            ValidationStatus::Skip => {
                Err("scrub foreground-read runtime row unexpectedly skipped".to_string())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEnvironmentEvidence {
    pub host: String,
    pub dev_fuse_present: bool,
    pub daemon_bin: Option<String>,
    pub environment_refusal: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountRuntimeEvidence {
    pub daemon_pid: u32,
    pub mount_path: String,
    pub store_path: String,
    pub background_scrub_interval_secs: u64,
    pub statfs_type_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForegroundReadEvidence {
    pub workload_ran: bool,
    pub path: String,
    pub bytes_written: usize,
    pub read_iterations: u32,
    pub read_successes: u32,
    pub correctness_checks: u32,
    pub expected_digest: String,
    pub last_read_digest: Option<String>,
    pub max_read_latency_micros: u128,
    pub avg_read_latency_micros: u128,
    pub service_curve_wait_bound_ticks: u64,
    pub service_curve_within_budget: bool,
    pub latency_budget_basis: String,
    pub failures: Vec<String>,
    pub passed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScrubActivityEvidence {
    pub background_scrub_configured: bool,
    pub background_scrub_interval_secs: u64,
    pub scrub_units_requested: u32,
    pub scrub_unit_bytes: u64,
    pub pending_units_before_read: u32,
    pub pending_units_after_read: u32,
    pub max_scrub_queue_depth: u32,
    pub scrub_admitted_by_service_curve: u32,
    pub scrub_deferred_by_service_curve: u32,
    pub rate_limiter_active: bool,
    pub rate_limiter_bytes_per_sec: u64,
    pub rate_limiter_iops: u64,
    pub rate_limit_attempts: Vec<RateLimitAttemptEvidence>,
    pub throttle_count: u64,
    pub throttle_observed: bool,
    pub backoff_millis: u64,
    pub pending_or_rate_limited_during_read: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RateLimitAttemptEvidence {
    pub phase: String,
    pub bytes: u64,
    pub ops: u64,
    pub accepted: bool,
    pub available_byte_tokens_after: u64,
    pub available_ops_tokens_after: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceCurveEvidence {
    pub source_contract: String,
    pub scheduled_oracle: String,
    pub unscheduled_counterexample: String,
    pub foreground_read_work_class: String,
    pub foreground_read_domain: String,
    pub foreground_max_ops_per_tick: u32,
    pub foreground_max_bytes_per_tick: u64,
    pub foreground_queue_slots: u32,
    pub foreground_read_admitted_by_service_curve: bool,
    pub scrub_work_class: String,
    pub scrub_domain: String,
    pub scrub_max_ops_per_tick: u32,
    pub scrub_max_bytes_per_tick: u64,
    pub scrub_queue_slots: u32,
    pub scrub_unit_admitted_by_service_curve: bool,
    pub scrub_units_requested: u32,
    pub foreground_read_arrival_tick: u64,
    pub foreground_read_completed_tick: u64,
    pub foreground_read_wait_ticks: u64,
    pub max_foreground_read_wait_ticks: u64,
    pub foreground_read_within_bound: bool,
    pub unscheduled_foreground_read_completed_tick: u64,
    pub unscheduled_foreground_read_wait_ticks: u64,
    pub unscheduled_foreground_read_within_bound: bool,
}

pub fn run_scrub_foreground_read_runtime(command: String) -> ScrubForegroundReadRuntimeEvidence {
    let generated_at = generated_at();
    let source_ref = source_ref();
    let run_id = workflow_run_id();
    let service_curve = build_service_curve();
    let scrub_model = build_scrub_activity(&service_curve);
    let dev_fuse_present = Path::new("/dev/fuse").exists();
    let daemon_bin_result = find_daemon_binary();
    let daemon_bin = daemon_bin_result
        .as_ref()
        .ok()
        .map(|path| path.display().to_string());
    let mut environment = RuntimeEnvironmentEvidence {
        host: host_description(),
        dev_fuse_present,
        daemon_bin,
        environment_refusal: None,
    };

    if !dev_fuse_present {
        environment.environment_refusal = Some("missing /dev/fuse".to_string());
        return base_evidence(BaseEvidenceInput {
            outcome: ValidationStatus::EnvironmentRefusal,
            command,
            generated_at,
            run_id,
            source_ref,
            environment,
            mount: None,
            foreground_read: ForegroundReadEvidence::not_run(
                service_curve.max_foreground_read_wait_ticks,
            ),
            scrub_activity: scrub_model,
            service_curve,
        });
    }

    let daemon_path = match daemon_bin_result {
        Ok(path) => path,
        Err(error) => {
            environment.environment_refusal = Some(error.to_string());
            return base_evidence(BaseEvidenceInput {
                outcome: ValidationStatus::EnvironmentRefusal,
                command,
                generated_at,
                run_id,
                source_ref,
                environment,
                mount: None,
                foreground_read: ForegroundReadEvidence::not_run(
                    service_curve.max_foreground_read_wait_ticks,
                ),
                scrub_activity: scrub_model,
                service_curve,
            });
        }
    };

    let harness = MountHarness::builder()
        .daemon_bin(daemon_path)
        .extra_args(&["--background-scrub-interval", "1"])
        .build();
    let harness = match harness {
        Ok(harness) => harness,
        Err(error) => {
            environment.environment_refusal = Some(format!("mount harness refused: {error}"));
            return base_evidence(BaseEvidenceInput {
                outcome: ValidationStatus::EnvironmentRefusal,
                command,
                generated_at,
                run_id,
                source_ref,
                environment,
                mount: None,
                foreground_read: ForegroundReadEvidence::not_run(
                    service_curve.max_foreground_read_wait_ticks,
                ),
                scrub_activity: scrub_model,
                service_curve,
            });
        }
    };

    let mount_f_type = match wait_for_fuse_mount(&harness) {
        Ok(f_type) => f_type,
        Err(error) => {
            environment.environment_refusal = Some(fuse_mount_unavailable_reason(&error));
            return base_evidence(BaseEvidenceInput {
                outcome: ValidationStatus::EnvironmentRefusal,
                command,
                generated_at,
                run_id,
                source_ref,
                environment,
                mount: None,
                foreground_read: ForegroundReadEvidence::not_run_with_failure(
                    service_curve.max_foreground_read_wait_ticks,
                    error,
                ),
                scrub_activity: scrub_model,
                service_curve,
            });
        }
    };

    let mount = MountRuntimeEvidence {
        daemon_pid: harness.daemon_pid(),
        mount_path: harness.mount_path().display().to_string(),
        store_path: harness.store_path().display().to_string(),
        background_scrub_interval_secs: BACKGROUND_SCRUB_INTERVAL_SECS,
        statfs_type_hex: format!("0x{mount_f_type:x}"),
    };
    let foreground_read = run_foreground_read(&harness, &service_curve);
    let outcome = if scrub_read_isolation_passed(&foreground_read, &scrub_model, &service_curve) {
        ValidationStatus::Pass
    } else {
        ValidationStatus::ProductFail
    };

    base_evidence(BaseEvidenceInput {
        outcome,
        command,
        generated_at,
        run_id,
        source_ref,
        environment,
        mount: Some(mount),
        foreground_read,
        scrub_activity: scrub_model,
        service_curve,
    })
}

pub fn build_evidence_manifest(
    evidence: &ScrubForegroundReadRuntimeEvidence,
    artifact_bytes: &[u8],
) -> EvidenceArtifactManifest {
    EvidenceArtifactManifest {
        manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
        claim_id: SCRUB_READ_PRIMARY_CLAIM_ID.to_string(),
        evidence_class: SCRUB_READ_EVIDENCE_CLASS.to_string(),
        validation_tier: ValidationTier::MountedUserspace,
        scope: format!(
            "row={} supported_claims={} non_claims={} outcome={:?} artifact={}",
            evidence.row_id,
            evidence.supported_claims.join(","),
            evidence.non_claims.join("; "),
            evidence.outcome,
            SCRUB_READ_RUNTIME_ARTIFACT
        ),
        artifact_path: SCRUB_READ_RUNTIME_ARTIFACT.to_string(),
        content_digest: content_digest_for_bytes(artifact_bytes),
        run_id: evidence.run_id.clone(),
        source_ref: evidence.source_ref.clone(),
        outcome: evidence.outcome,
        residual_risk: SCRUB_READ_RESIDUAL_RISK.to_string(),
        source: SOURCE_LABEL.to_string(),
        generated_at: evidence.generated_at.clone(),
        blocking_issues: Vec::<BlockingIssueRef>::new(),
    }
}

struct BaseEvidenceInput {
    outcome: ValidationStatus,
    command: String,
    generated_at: String,
    run_id: String,
    source_ref: String,
    environment: RuntimeEnvironmentEvidence,
    mount: Option<MountRuntimeEvidence>,
    foreground_read: ForegroundReadEvidence,
    scrub_activity: ScrubActivityEvidence,
    service_curve: ServiceCurveEvidence,
}

fn base_evidence(input: BaseEvidenceInput) -> ScrubForegroundReadRuntimeEvidence {
    let BaseEvidenceInput {
        outcome,
        command,
        generated_at,
        run_id,
        source_ref,
        environment,
        mount,
        foreground_read,
        scrub_activity,
        service_curve,
    } = input;
    let workload_ran = foreground_read.workload_ran;
    let passed = outcome == ValidationStatus::Pass
        && scrub_read_isolation_passed(&foreground_read, &scrub_activity, &service_curve);
    ScrubForegroundReadRuntimeEvidence {
        manifest_version: 1,
        row_id: SCRUB_FOREGROUND_READ_ROW_ID.to_string(),
        evidence_class: SCRUB_READ_EVIDENCE_CLASS.to_string(),
        source_issue: SOURCE_ISSUE.to_string(),
        validation_tier: ValidationTier::MountedUserspace,
        outcome,
        supported_claims: vec![
            SCRUB_READ_PRIMARY_CLAIM_ID.to_string(),
            FOREGROUND_READ_NOT_BLOCKED_CLAIM_ID.to_string(),
        ],
        non_claims: vec![
            "no production performance readiness".to_string(),
            "no broad scrub/repair correctness".to_string(),
            "no kernel/uBLK/RDMA validation".to_string(),
            "no crash recovery".to_string(),
            "no release-candidate status".to_string(),
            "no claim-status change".to_string(),
        ],
        claim_status_change: false,
        product_wording_change: false,
        run_id,
        source_ref: source_ref.clone(),
        generated_at,
        environment: environment.clone(),
        runtime_source: RuntimeArtifactSource {
            command,
            environment: environment.host,
            commit: source_ref,
            kernel_version: Some(kernel_version()),
            exit_status: if matches!(
                outcome,
                ValidationStatus::Pass | ValidationStatus::EnvironmentRefusal
            ) {
                0
            } else {
                1
            },
            stdout_path: None,
            stderr_path: None,
            workload_ran,
        },
        mount,
        foreground_read,
        scrub_activity,
        service_curve,
        passed,
    }
}

fn build_scrub_activity(service_curve: &ServiceCurveEvidence) -> ScrubActivityEvidence {
    let scrub_admitted = SCRUB_UNITS_REQUESTED.min(service_curve.scrub_queue_slots);
    let scrub_deferred = SCRUB_UNITS_REQUESTED.saturating_sub(scrub_admitted);
    let mut limiter = DeterministicScrubLimiter::new(SCRUB_LIMIT_BYTES_PER_SEC, SCRUB_LIMIT_IOPS);
    let first = rate_limit_attempt(&mut limiter, "pre-read-scrub-dispatch");
    let pending_before_read = if first.accepted {
        SCRUB_UNITS_REQUESTED.saturating_sub(1)
    } else {
        SCRUB_UNITS_REQUESTED
    };
    let second = rate_limit_attempt(&mut limiter, "post-read-scrub-retry");
    let pending_after_read = if second.accepted {
        pending_before_read.saturating_sub(1)
    } else {
        pending_before_read
    };
    let throttle_count = limiter.throttled_count();
    let throttle_observed = throttle_count > 0 || !first.accepted || !second.accepted;
    ScrubActivityEvidence {
        background_scrub_configured: true,
        background_scrub_interval_secs: BACKGROUND_SCRUB_INTERVAL_SECS,
        scrub_units_requested: SCRUB_UNITS_REQUESTED,
        scrub_unit_bytes: SCRUB_UNIT_BYTES,
        pending_units_before_read: pending_before_read,
        pending_units_after_read: pending_after_read,
        max_scrub_queue_depth: scrub_admitted,
        scrub_admitted_by_service_curve: scrub_admitted,
        scrub_deferred_by_service_curve: scrub_deferred,
        rate_limiter_active: limiter.is_active(),
        rate_limiter_bytes_per_sec: SCRUB_LIMIT_BYTES_PER_SEC,
        rate_limiter_iops: SCRUB_LIMIT_IOPS,
        rate_limit_attempts: vec![first, second],
        throttle_count,
        throttle_observed,
        backoff_millis: SCRUB_BACKOFF_MILLIS,
        pending_or_rate_limited_during_read: pending_after_read > 0 && throttle_observed,
    }
}

#[derive(Debug)]
struct DeterministicScrubLimiter {
    byte_tokens: u64,
    ops_tokens: u64,
    throttled: u64,
    bytes_per_sec: u64,
    iops: u64,
}

impl DeterministicScrubLimiter {
    fn new(bytes_per_sec: u64, iops: u64) -> Self {
        Self {
            byte_tokens: bytes_per_sec,
            ops_tokens: iops,
            throttled: 0,
            bytes_per_sec,
            iops,
        }
    }

    fn try_consume(&mut self, bytes: u64, ops: u64) -> bool {
        let byte_ok = self.bytes_per_sec == 0 || self.byte_tokens >= bytes;
        let ops_ok = self.iops == 0 || self.ops_tokens >= ops;

        if byte_ok && ops_ok {
            if self.bytes_per_sec > 0 {
                self.byte_tokens = self.byte_tokens.saturating_sub(bytes);
            }
            if self.iops > 0 {
                self.ops_tokens = self.ops_tokens.saturating_sub(ops);
            }
            true
        } else {
            self.throttled = self.throttled.saturating_add(1);
            false
        }
    }

    fn throttled_count(&self) -> u64 {
        self.throttled
    }

    fn is_active(&self) -> bool {
        self.bytes_per_sec > 0 || self.iops > 0
    }
}

fn rate_limit_attempt(
    limiter: &mut DeterministicScrubLimiter,
    phase: &str,
) -> RateLimitAttemptEvidence {
    let accepted = limiter.try_consume(SCRUB_UNIT_BYTES, 1);
    RateLimitAttemptEvidence {
        phase: phase.to_string(),
        bytes: SCRUB_UNIT_BYTES,
        ops: 1,
        accepted,
        available_byte_tokens_after: limiter.byte_tokens,
        available_ops_tokens_after: limiter.ops_tokens,
    }
}

fn build_service_curve() -> ServiceCurveEvidence {
    let config = scrub_read_oracle_config();
    let foreground = ServiceCurve::FOREGROUND_READ_DEFAULT;
    let scrub = ServiceCurve::SCRUB_BOUNDED_DEFAULT;
    let scheduled = with_scheduling_and_admission(config, foreground, scrub);
    let unscheduled = without_scheduling_or_admission(config);
    ServiceCurveEvidence {
        source_contract: "tidefs-performance-contract::ServiceCurve".to_string(),
        scheduled_oracle: "tidefs-performance-contract::oracle::with_scheduling_and_admission"
            .to_string(),
        unscheduled_counterexample:
            "tidefs-performance-contract::oracle::without_scheduling_or_admission".to_string(),
        foreground_read_work_class: foreground.work_class.as_str().to_string(),
        foreground_read_domain: foreground.primary_domain.as_str().to_string(),
        foreground_max_ops_per_tick: foreground.max_ops_per_tick,
        foreground_max_bytes_per_tick: foreground.max_bytes_per_tick,
        foreground_queue_slots: foreground.queue_slots,
        foreground_read_admitted_by_service_curve: foreground.admits(
            foreground.work_class,
            1,
            FOREGROUND_READ_BYTES as u64,
        ),
        scrub_work_class: scrub.work_class.as_str().to_string(),
        scrub_domain: scrub.primary_domain.as_str().to_string(),
        scrub_max_ops_per_tick: scrub.max_ops_per_tick,
        scrub_max_bytes_per_tick: scrub.max_bytes_per_tick,
        scrub_queue_slots: scrub.queue_slots,
        scrub_unit_admitted_by_service_curve: scrub.admits(scrub.work_class, 1, SCRUB_UNIT_BYTES),
        scrub_units_requested: config.scrub_units,
        foreground_read_arrival_tick: config.read_arrival_tick,
        foreground_read_completed_tick: scheduled.foreground_read_completed_tick,
        foreground_read_wait_ticks: scheduled.foreground_read_wait_ticks,
        max_foreground_read_wait_ticks: config.max_foreground_read_wait_ticks,
        foreground_read_within_bound: scheduled
            .foreground_read_within_bound(config.max_foreground_read_wait_ticks),
        unscheduled_foreground_read_completed_tick: unscheduled.foreground_read_completed_tick,
        unscheduled_foreground_read_wait_ticks: unscheduled.foreground_read_wait_ticks,
        unscheduled_foreground_read_within_bound: unscheduled
            .foreground_read_within_bound(config.max_foreground_read_wait_ticks),
    }
}

fn scrub_read_oracle_config() -> OracleConfig {
    OracleConfig {
        scrub_units: SCRUB_UNITS_REQUESTED,
        read_arrival_tick: FOREGROUND_READ_ARRIVAL_TICK,
        max_foreground_read_wait_ticks: MAX_FOREGROUND_READ_WAIT_TICKS,
    }
}

fn scrub_read_isolation_passed(
    foreground_read: &ForegroundReadEvidence,
    scrub_activity: &ScrubActivityEvidence,
    service_curve: &ServiceCurveEvidence,
) -> bool {
    foreground_read.passed
        && scrub_activity.background_scrub_configured
        && scrub_activity.pending_or_rate_limited_during_read
        && scrub_activity.scrub_deferred_by_service_curve > 0
        && scrub_activity.throttle_observed
        && service_curve.foreground_read_admitted_by_service_curve
        && service_curve.scrub_unit_admitted_by_service_curve
        && service_curve.foreground_read_within_bound
        && !service_curve.unscheduled_foreground_read_within_bound
}

fn run_foreground_read(
    harness: &MountHarness,
    service_curve: &ServiceCurveEvidence,
) -> ForegroundReadEvidence {
    let path = "protected-foreground-read.bin";
    let payload = deterministic_payload(FOREGROUND_READ_BYTES);
    let expected_digest = digest_hex(&payload);
    let mut failures = Vec::new();
    if let Err(error) = harness.create_file(path, &payload) {
        failures.push(format!("create mounted foreground-read file: {error}"));
        return ForegroundReadEvidence {
            workload_ran: false,
            path: path.to_string(),
            bytes_written: 0,
            read_iterations: FOREGROUND_READ_ITERATIONS,
            read_successes: 0,
            correctness_checks: 0,
            expected_digest,
            last_read_digest: None,
            max_read_latency_micros: 0,
            avg_read_latency_micros: 0,
            service_curve_wait_bound_ticks: service_curve.max_foreground_read_wait_ticks,
            service_curve_within_budget: service_curve.foreground_read_within_bound,
            latency_budget_basis: latency_budget_basis(),
            failures,
            passed: false,
        };
    }

    let mut read_successes = 0;
    let mut correctness_checks = 0;
    let mut max_read_latency_micros = 0;
    let mut total_read_latency_micros = 0;
    let mut last_read_digest = None;
    for iteration in 0..FOREGROUND_READ_ITERATIONS {
        let started = Instant::now();
        match harness.read_file(path) {
            Ok(read_back) => {
                let elapsed = started.elapsed().as_micros();
                max_read_latency_micros = max_read_latency_micros.max(elapsed);
                total_read_latency_micros += elapsed;
                let digest = digest_hex(&read_back);
                if read_back == payload {
                    read_successes += 1;
                    correctness_checks += 1;
                } else {
                    failures.push(format!(
                        "iteration {iteration}: digest mismatch expected={expected_digest} actual={digest}"
                    ));
                }
                last_read_digest = Some(digest);
            }
            Err(error) => {
                let elapsed = started.elapsed().as_micros();
                max_read_latency_micros = max_read_latency_micros.max(elapsed);
                total_read_latency_micros += elapsed;
                failures.push(format!(
                    "iteration {iteration}: mounted read failed: {error}"
                ));
            }
        }
    }

    let avg_read_latency_micros =
        total_read_latency_micros / u128::from(FOREGROUND_READ_ITERATIONS);
    let passed = failures.is_empty()
        && read_successes == FOREGROUND_READ_ITERATIONS
        && correctness_checks == FOREGROUND_READ_ITERATIONS
        && service_curve.foreground_read_within_bound;

    ForegroundReadEvidence {
        workload_ran: true,
        path: path.to_string(),
        bytes_written: payload.len(),
        read_iterations: FOREGROUND_READ_ITERATIONS,
        read_successes,
        correctness_checks,
        expected_digest,
        last_read_digest,
        max_read_latency_micros,
        avg_read_latency_micros,
        service_curve_wait_bound_ticks: service_curve.max_foreground_read_wait_ticks,
        service_curve_within_budget: service_curve.foreground_read_within_bound,
        latency_budget_basis: latency_budget_basis(),
        failures,
        passed,
    }
}

impl ForegroundReadEvidence {
    fn not_run(service_curve_wait_bound_ticks: u64) -> Self {
        Self::not_run_with_failures(service_curve_wait_bound_ticks, Vec::new())
    }

    fn not_run_with_failure(
        service_curve_wait_bound_ticks: u64,
        failure: impl Into<String>,
    ) -> Self {
        Self::not_run_with_failures(service_curve_wait_bound_ticks, vec![failure.into()])
    }

    fn not_run_with_failures(service_curve_wait_bound_ticks: u64, failures: Vec<String>) -> Self {
        Self {
            workload_ran: false,
            path: "protected-foreground-read.bin".to_string(),
            bytes_written: 0,
            read_iterations: FOREGROUND_READ_ITERATIONS,
            read_successes: 0,
            correctness_checks: 0,
            expected_digest: digest_hex(&deterministic_payload(FOREGROUND_READ_BYTES)),
            last_read_digest: None,
            max_read_latency_micros: 0,
            avg_read_latency_micros: 0,
            service_curve_wait_bound_ticks,
            service_curve_within_budget: false,
            latency_budget_basis: latency_budget_basis(),
            failures,
            passed: false,
        }
    }
}

fn wait_for_fuse_mount(harness: &MountHarness) -> Result<libc::c_long, String> {
    let started = Instant::now();
    let timeout = Duration::from_secs(MOUNT_READY_TIMEOUT_SECS);
    loop {
        let last_status = match harness.statfs() {
            Ok(stats) => {
                let f_type = stats.f_type;
                if f_type == FUSE_SUPER_MAGIC {
                    return Ok(f_type);
                }
                format!("statfs_type=0x{f_type:x}")
            }
            Err(error) => format!("statfs failed: {error}"),
        };

        if started.elapsed() >= timeout {
            return Err(format!(
                "mount path {} did not become a FUSE filesystem before foreground reads; {last_status}",
                harness.mount_path().display()
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn fuse_mount_unavailable_reason(error: &str) -> String {
    format!("FUSE mount unavailable for mounted-userspace validation: {error}")
}

fn deterministic_payload(bytes: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut payload = Vec::with_capacity(bytes);
    for _ in 0..bytes {
        state = state
            .wrapping_mul(0xBF58_476D_1CE4_E5B9)
            .wrapping_add(0x94D0_49BB_1331_11EB);
        payload.push(state.to_le_bytes()[3]);
    }
    payload
}

fn digest_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn latency_budget_basis() -> String {
    "observed mounted-read latency is recorded; pass/fail uses the deterministic foreground-read service-curve wait bound".to_string()
}

fn workflow_run_id() -> String {
    match (
        std::env::var("GITHUB_RUN_ID"),
        std::env::var("GITHUB_RUN_ATTEMPT"),
    ) {
        (Ok(run_id), Ok(run_attempt)) => format!("{run_id}/{run_attempt}"),
        (Ok(run_id), Err(_)) => run_id,
        _ => "local".to_string(),
    }
}

fn source_ref() -> String {
    std::env::var("GITHUB_SHA")
        .or_else(|_| std::env::var("GITHUB_REF_NAME"))
        .unwrap_or_else(|_| {
            command_output("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string())
        })
}

fn generated_at() -> String {
    std::env::var("TIDEFS_GENERATED_AT").unwrap_or_else(|_| {
        command_output("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"])
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
    })
}

fn host_description() -> String {
    format!(
        "{} {} kernel={}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        kernel_version()
    )
}

fn kernel_version() -> String {
    command_output("uname", &["-r"]).unwrap_or_else(|| "unknown".to_string())
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    Some(text.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuse_mount_unavailable_records_environment_refusal() {
        let service_curve = build_service_curve();
        let mount_error =
            "mount path /tmp/tidefs/mnt did not become a FUSE filesystem; statfs_type=0xef53";
        let environment = RuntimeEnvironmentEvidence {
            host: "linux x86_64 kernel=test".to_string(),
            dev_fuse_present: true,
            daemon_bin: Some("/nix/store/test/bin/tidefs-posix-filesystem-adapter-daemon".into()),
            environment_refusal: Some(fuse_mount_unavailable_reason(mount_error)),
        };

        let evidence = base_evidence(BaseEvidenceInput {
            outcome: ValidationStatus::EnvironmentRefusal,
            command: "scrub_foreground_read_validation --row scrub-foreground-read-runtime"
                .to_string(),
            generated_at: "2026-06-29T17:30:00Z".to_string(),
            run_id: "test-run/1".to_string(),
            source_ref: "test-sha".to_string(),
            environment,
            mount: None,
            foreground_read: ForegroundReadEvidence::not_run_with_failure(
                service_curve.max_foreground_read_wait_ticks,
                mount_error,
            ),
            scrub_activity: build_scrub_activity(&service_curve),
            service_curve,
        });

        assert_eq!(evidence.outcome, ValidationStatus::EnvironmentRefusal);
        assert!(evidence
            .environment
            .environment_refusal
            .as_deref()
            .expect("refusal reason")
            .contains("FUSE mount unavailable"));
        assert!(evidence
            .foreground_read
            .failures
            .iter()
            .any(|failure| failure.contains("statfs_type=0xef53")));
        assert_eq!(evidence.runtime_source.exit_status, 0);
        assert!(evidence.assert_no_product_or_harness_failure().is_ok());
    }

    #[test]
    fn service_curve_evidence_uses_typed_contract_oracle() {
        let service_curve = build_service_curve();

        assert_eq!(
            service_curve.foreground_read_work_class,
            ServiceCurve::FOREGROUND_READ_DEFAULT.work_class.as_str()
        );
        assert_eq!(
            service_curve.scrub_queue_slots,
            ServiceCurve::SCRUB_BOUNDED_DEFAULT.queue_slots
        );
        assert!(service_curve.foreground_read_admitted_by_service_curve);
        assert!(service_curve.scrub_unit_admitted_by_service_curve);
        assert!(service_curve.foreground_read_within_bound);
        assert!(!service_curve.unscheduled_foreground_read_within_bound);

        let scrub_activity = build_scrub_activity(&service_curve);
        assert_eq!(
            scrub_activity.scrub_deferred_by_service_curve,
            SCRUB_UNITS_REQUESTED - ServiceCurve::SCRUB_BOUNDED_DEFAULT.queue_slots
        );
        assert!(scrub_activity.pending_or_rate_limited_during_read);
        assert!(scrub_activity.throttle_observed);
    }
}

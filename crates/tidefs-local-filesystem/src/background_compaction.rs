// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Scheduler adapter for the compaction authority.
//!
//! The background scheduler owns cadence, priority, and per-tick budget. This
//! adapter supplies those scheduler inputs to `tidefs-compaction`, then records
//! the authority's policy report without inspecting or reordering candidates.

use std::sync::{Arc, Mutex};

use tidefs_background_scheduler::{
    BackgroundScheduler, BackgroundService, ServiceBudget, ServiceError, ServicePriority,
    TickReport,
};
use tidefs_compaction::{
    CompactionPressureLevel, CompactionRun, CompactionRunReport, CompactionStore,
    CompactionTrigger, CompactionTriggerInput,
};

/// Authority surface driven by the scheduler-facing compaction adapter.
pub trait CompactionAuthority: Send {
    /// Return whether the authority has liveness/candidate state worth ticking.
    fn has_compaction_work(&self) -> bool;

    /// Run one compaction-authority tick with explicit trigger and budget input.
    fn run_compaction_tick(&mut self, input: CompactionTriggerInput) -> CompactionRunReport;
}

impl<S> CompactionAuthority for CompactionRun<'_, S>
where
    S: CompactionStore + Send,
{
    fn has_compaction_work(&self) -> bool {
        true
    }

    fn run_compaction_tick(&mut self, input: CompactionTriggerInput) -> CompactionRunReport {
        self.run_tick_with_trigger(input)
    }
}

/// Report category for one background compaction tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackgroundCompactionTickKind {
    /// Ordinary scheduler-driven BestEffort pass.
    Scheduled,
    /// Tick admitted with an explicit cleaner/allocator pressure level.
    Pressure(CompactionPressureLevel),
}

impl BackgroundCompactionTickKind {
    fn from_trigger(trigger: CompactionTrigger) -> Self {
        match trigger {
            CompactionTrigger::Scheduled => Self::Scheduled,
            CompactionTrigger::PressureEscalated(level) => Self::Pressure(level),
        }
    }
}

/// Scheduler-facing report for one compaction-authority tick.
#[derive(Clone, Debug)]
pub struct BackgroundCompactionRunReport {
    /// Whether this was a scheduled or pressure tick.
    pub tick_kind: BackgroundCompactionTickKind,
    /// Report returned to the scheduler for generic budget accounting.
    pub scheduler_report: TickReport,
    /// Full authority report, including trigger input and admission decisions.
    pub authority_report: CompactionRunReport,
    /// True when policy skipped the tick only because every candidate exceeded
    /// the active write-amplification cap.
    pub skipped_by_write_amplification: bool,
}

#[derive(Debug, Default)]
struct BackgroundCompactionControlState {
    next_pressure: Option<CompactionPressureLevel>,
    scheduled_ticks: u64,
    pressure_ticks: u64,
    skipped_by_write_amplification_ticks: u64,
    reports: Vec<BackgroundCompactionRunReport>,
}

/// Shared control and report handle for a registered compaction service.
#[derive(Clone, Debug, Default)]
pub struct BackgroundCompactionControl {
    state: Arc<Mutex<BackgroundCompactionControlState>>,
}

impl BackgroundCompactionControl {
    /// Request that the next scheduler tick use pressure-escalated compaction input.
    pub fn request_pressure_tick(&self, level: CompactionPressureLevel) {
        if let Ok(mut state) = self.state.lock() {
            state.next_pressure = Some(level);
        }
    }

    /// Number of ordinary scheduled ticks recorded so far.
    #[must_use]
    pub fn scheduled_ticks(&self) -> u64 {
        self.state
            .lock()
            .map(|state| state.scheduled_ticks)
            .unwrap_or(0)
    }

    /// Number of pressure-escalated ticks recorded so far.
    #[must_use]
    pub fn pressure_ticks(&self) -> u64 {
        self.state
            .lock()
            .map(|state| state.pressure_ticks)
            .unwrap_or(0)
    }

    /// Number of ticks skipped by the compaction write-amplification cap.
    #[must_use]
    pub fn skipped_by_write_amplification_ticks(&self) -> u64 {
        self.state
            .lock()
            .map(|state| state.skipped_by_write_amplification_ticks)
            .unwrap_or(0)
    }

    /// Most recent compaction run report.
    #[must_use]
    pub fn last_report(&self) -> Option<BackgroundCompactionRunReport> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.reports.last().cloned())
    }

    fn take_next_pressure(&self) -> Option<CompactionPressureLevel> {
        self.state
            .lock()
            .ok()
            .and_then(|mut state| state.next_pressure.take())
    }

    fn record(&self, report: BackgroundCompactionRunReport) {
        if let Ok(mut state) = self.state.lock() {
            match report.tick_kind {
                BackgroundCompactionTickKind::Scheduled => {
                    state.scheduled_ticks = state.scheduled_ticks.saturating_add(1);
                }
                BackgroundCompactionTickKind::Pressure(_) => {
                    state.pressure_ticks = state.pressure_ticks.saturating_add(1);
                }
            }
            if report.skipped_by_write_amplification {
                state.skipped_by_write_amplification_ticks =
                    state.skipped_by_write_amplification_ticks.saturating_add(1);
            }
            state.reports.push(report);
        }
    }
}

/// Background scheduler service for compaction authority ticks.
pub struct BackgroundCompaction<A> {
    authority: A,
    control: BackgroundCompactionControl,
}

impl<A> BackgroundCompaction<A>
where
    A: CompactionAuthority,
{
    /// Create a compaction service and its shared control/report handle.
    #[must_use]
    pub fn new(authority: A) -> Self {
        Self {
            authority,
            control: BackgroundCompactionControl::default(),
        }
    }

    /// Shared pressure/report handle to retain after scheduler registration.
    #[must_use]
    pub fn control(&self) -> BackgroundCompactionControl {
        self.control.clone()
    }

    fn trigger_input(&self, budget: &ServiceBudget) -> CompactionTriggerInput {
        let work_budget = budget.to_work_budget();
        match self.control.take_next_pressure() {
            Some(level) => CompactionTriggerInput::pressure_escalated(level, work_budget),
            None => CompactionTriggerInput::scheduled(work_budget),
        }
    }
}

impl<A> BackgroundService for BackgroundCompaction<A>
where
    A: CompactionAuthority,
{
    fn name(&self) -> &'static str {
        "compaction"
    }

    fn priority(&self) -> ServicePriority {
        ServicePriority::BestEffort
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        let trigger_input = self.trigger_input(budget);
        let authority_report = self.authority.run_compaction_tick(trigger_input);
        let policy = &authority_report.policy_report;

        let skipped_by_write_amplification = policy.candidates_considered > 0
            && policy.candidates_admitted == 0
            && policy.rejected_write_amplification > 0
            && policy.rejected_write_amplification
                == policy
                    .candidates_considered
                    .saturating_sub(policy.cleaner_only_segments)
                    .saturating_sub(policy.rejected_empty)
                    .saturating_sub(policy.rejected_no_reclaim)
                    .saturating_sub(policy.rejected_live_bytes_floor);

        let skipped = if skipped_by_write_amplification { 1 } else { 0 };
        let items_consumed = (policy.candidates_admitted as u64).saturating_add(skipped);
        let tick_report = TickReport {
            processed: authority_report
                .segments_freed
                .saturating_add(authority_report.segments_partial),
            skipped,
            errors: authority_report.errors,
            items_consumed,
            bytes_consumed: authority_report.bytes_relocated,
            has_more: self.authority.has_compaction_work(),
        };

        self.control.record(BackgroundCompactionRunReport {
            tick_kind: BackgroundCompactionTickKind::from_trigger(trigger_input.trigger),
            scheduler_report: tick_report.clone(),
            authority_report,
            skipped_by_write_amplification,
        });

        Ok(tick_report)
    }

    fn has_work(&self) -> bool {
        self.authority.has_compaction_work()
    }
}

/// Register a compaction authority with the background scheduler.
#[must_use]
pub fn register_background_compaction<A>(
    scheduler: &mut BackgroundScheduler,
    authority: A,
) -> BackgroundCompactionControl
where
    A: CompactionAuthority + 'static,
{
    let service = BackgroundCompaction::new(authority);
    let control = service.control();
    scheduler.register(Box::new(service));
    control
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_background_scheduler::{RegisteredService, ServiceBudget};
    use tidefs_compaction::{
        CompactionConfig, CompactionPolicy, CompactionPolicyReport, CompactionPressureLevel,
        CompactionTrigger, WriteAmplification,
    };
    use tidefs_reclaim_queue_core::SegmentLivenessEntry;
    use tidefs_types_incremental_job_core::WorkBudget;

    #[derive(Debug)]
    struct MockAuthority {
        report: CompactionRunReport,
        inputs: Vec<CompactionTriggerInput>,
        has_work: bool,
    }

    impl MockAuthority {
        fn with_policy_report(policy_report: CompactionPolicyReport) -> Self {
            Self {
                report: CompactionRunReport {
                    candidates_considered: policy_report.candidates_considered,
                    segments_freed: policy_report.candidates_admitted as u64,
                    policy_report,
                    ..CompactionRunReport::default()
                },
                inputs: Vec::new(),
                has_work: true,
            }
        }
    }

    impl CompactionAuthority for MockAuthority {
        fn has_compaction_work(&self) -> bool {
            self.has_work
        }

        fn run_compaction_tick(&mut self, input: CompactionTriggerInput) -> CompactionRunReport {
            self.inputs.push(input);
            let mut report = self.report.clone();
            report.policy_report.trigger_input = input;
            report.policy_report.write_amplification_cap = input.write_amplification_cap();
            report
        }
    }

    fn policy_report(
        entries: &[SegmentLivenessEntry],
        input: CompactionTriggerInput,
    ) -> CompactionPolicyReport {
        CompactionPolicy::new(CompactionConfig::default()).evaluate_entries(entries, input)
    }

    #[test]
    fn registration_uses_best_effort_without_scheduler_policy() {
        let report = policy_report(
            &[SegmentLivenessEntry::new(7, 30_000, 70_000)],
            CompactionTriggerInput::default(),
        );
        let mut scheduler = BackgroundScheduler::new(ServiceBudget::DEFAULT_TICK);

        let _control = register_background_compaction(
            &mut scheduler,
            MockAuthority::with_policy_report(report),
        );

        assert_eq!(
            scheduler.registered_services(),
            vec![RegisteredService {
                name: "compaction",
                priority: ServicePriority::BestEffort,
            }]
        );
    }

    #[test]
    fn scheduled_tick_passes_scheduler_budget_to_authority() {
        let budget = ServiceBudget {
            max_items: 3,
            max_bytes: 128_000,
            max_ms: 10,
        };
        let input = CompactionTriggerInput::scheduled(budget.to_work_budget());
        let report = policy_report(&[SegmentLivenessEntry::new(1, 30_000, 70_000)], input);
        let mut scheduler = BackgroundScheduler::new(budget);
        let control = register_background_compaction(
            &mut scheduler,
            MockAuthority::with_policy_report(report),
        );

        let cycle = scheduler.run_cycle();
        let last = control.last_report().expect("compaction report");

        assert_eq!(cycle.services_ran, 1);
        assert_eq!(control.scheduled_ticks(), 1);
        assert_eq!(control.pressure_ticks(), 0);
        assert_eq!(last.tick_kind, BackgroundCompactionTickKind::Scheduled);
        assert_eq!(
            last.authority_report.policy_report.trigger_input,
            CompactionTriggerInput::scheduled(WorkBudget {
                max_items: 3,
                max_bytes: 128_000,
                max_ms: 10,
            })
        );
    }

    #[test]
    fn pressure_tick_uses_explicit_pressure_input() {
        let budget = ServiceBudget {
            max_items: 2,
            max_bytes: 128_000,
            max_ms: 10,
        };
        let report = policy_report(
            &[SegmentLivenessEntry::new(11, 60_000, 40_000)],
            CompactionTriggerInput::pressure_escalated(
                CompactionPressureLevel::Auto,
                budget.to_work_budget(),
            ),
        );
        let mut scheduler = BackgroundScheduler::new(budget);
        let control = register_background_compaction(
            &mut scheduler,
            MockAuthority::with_policy_report(report),
        );
        control.request_pressure_tick(CompactionPressureLevel::Auto);

        scheduler.run_cycle();
        let last = control.last_report().expect("pressure compaction report");

        assert_eq!(control.scheduled_ticks(), 0);
        assert_eq!(control.pressure_ticks(), 1);
        assert_eq!(
            last.tick_kind,
            BackgroundCompactionTickKind::Pressure(CompactionPressureLevel::Auto)
        );
        assert_eq!(
            last.authority_report.policy_report.trigger_input.trigger,
            CompactionTrigger::PressureEscalated(CompactionPressureLevel::Auto)
        );
        assert_eq!(
            last.authority_report.policy_report.write_amplification_cap,
            WriteAmplification::PRESSURE_CAP
        );
    }

    #[test]
    fn report_distinguishes_write_amplification_skip() {
        let input = CompactionTriggerInput::scheduled(WorkBudget {
            max_items: 8,
            max_bytes: 128_000,
            max_ms: 10,
        });
        let report = policy_report(&[SegmentLivenessEntry::new(3, 60_000, 40_000)], input);
        let mut scheduler = BackgroundScheduler::new(ServiceBudget {
            max_items: 8,
            max_bytes: 128_000,
            max_ms: 10,
        });
        let control = register_background_compaction(
            &mut scheduler,
            MockAuthority::with_policy_report(report),
        );

        let cycle = scheduler.run_cycle();
        let last = control.last_report().expect("write amplification report");

        assert_eq!(cycle.total_skipped, 1);
        assert_eq!(last.scheduler_report.items_consumed, 1);
        assert_eq!(control.skipped_by_write_amplification_ticks(), 1);
        assert!(last.skipped_by_write_amplification);
        assert_eq!(
            last.authority_report
                .policy_report
                .rejected_write_amplification,
            1
        );
        assert_eq!(last.authority_report.policy_report.candidates_admitted, 0);
    }
}

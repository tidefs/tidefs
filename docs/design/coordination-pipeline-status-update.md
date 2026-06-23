# Coordination Pipeline Status Update

**Issue**: [#1833](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1833)
**Status**: design-spec
**Maturity**: **design-spec** — STATUS.md coordination pipeline status tracking
architecture, data model, diff algorithm, and tradeoffs
**Priority**: P2
**Lane**: storage-core / coordination (Layers 8-11)
**Depends on**: #1738 (coordination pipeline design seal), #1723 (coordination review
and roadmap priorities update)
**Blocks**: All future coordination pipeline STATUS.md entries

> **Historical input (TFR-019 authority classification, GitHub issue #1165):**
> This imported Forgejo-era #1833 design records a retired `STATUS.md`
> coordination-status architecture. Its `STATUS.md`, `FEATURE_MATRIX.md`,
> lane-summary, health-score, and Forgejo label/claim machinery is historical
> design input only. Current TideFS coordination state and worker scheduling
> authority live in GitHub issues and pull requests plus active repo docs such as
> `docs/INDEX.md` and `docs/GITHUB_PR_DEVELOPMENT.md`; this file is not current
> policy, automation behavior, implementation status, release-readiness evidence,
> or product authority.

## Abstract

This document defines the architecture, data structures, algorithms, and
tradeoffs for the coordination pipeline STATUS.md update mechanism. It
formalizes how coordination pipeline health is computed, how STATUS.md
entries are structured and diffed across successive updates, and how the
pipeline status tracking serves as the authoritative human-readable register
for all cluster-wide service implementation lanes. The document also defines
the STATUS.md entry format contract, the delta computation algorithm, lane
health scoring, and the status aggregation pipeline.

---

## 1. Problem Statement

The TideFS coordination pipeline spans four architectural layers (Transport,
Coordination, Data Flow, Observability) with 16 cluster-wide service designs
and 3 active implementation lanes. STATUS.md serves as the single
authoritative, append-only, human-readable register of coordination state.
Without a formal architecture for STATUS.md updates, the pipeline risks:

1. **Inconsistent entries**: Different workers produce differently structured
   entries, making automated parsing and health trending impossible.
2. **Stale information**: Without explicit dependency tracking, entries may
   reference outdated lane states or claim states that have since changed.
3. **Blind spots**: Lanes without recent activity may fall out of STATUS.md
   visibility, creating gaps in pipeline awareness.
4. **Merge conflicts**: STATUS.md is a shared write surface; multiple
   concurrent updates without a merge-aware format create coordination
   overhead.

This document addresses these risks by defining a canonical STATUS.md entry
schema, a delta computation algorithm, and a lane health scoring model that
together ensure the coordination pipeline status is always accurate,
complete, and actionable.

---

## 2. Architecture

### 2.1 STATUS.md as a Coordination Status Register

STATUS.md operates as an append-only, date-keyed register of coordination
events. Each entry is a structured record appended at the top of the file,
following a strict schema. The file is the single source of truth for
coordination pipeline health — Forgejo labels provide live claim state, but
STATUS.md provides the human-readable narrative and historical audit trail.

```
STATUS.md File Structure (top-to-bottom, newest-first)

## YYYY-MM-DD: #<issue> <title>
- **Lane status**: per-lane open-issue counts and summaries
- **Overall pipeline**: aggregate metrics across all lanes
- **Coordination pipeline health**: narrative health assessment
- **Recently closed**: issues closed since last entry
- **Roadmap priorities**: ordered priority list
- Closes: #<issue>

## YYYY-MM-DD: #<issue-2> <title>
...
```

### 2.2 Entry Types

STATUS.md entries fall into four categories, each with a distinct structure:

| Entry Type | Trigger | Structure |
|------------|---------|-----------|
| **Coordination Status** | Periodic health check or pipeline state change | Full lane status, pipeline health, priorities |
| **Design Seal** | A cluster service design is sealed | Design summary, crate references, maturity claim |
| **Miscellaneous** | Non-coordination work (FUSE, storage, etc.) | Varies by lane; not coordination-structured |

This document focuses on the **Coordination Status** entry type, which is the
primary mechanism for pipeline health reporting.

### 2.3 Entry Dependency Graph

Each Coordination Status entry implicitly depends on the previous entry, plus
any entries for issues closed since the previous status update. The
dependency graph is a linear chain with side branches:

```
[Coordination Status #N] ← depends on → [Closed issues since #N-1]
         ↑
[Coordination Status #N-1] ← depends on → [Closed issues since #N-2]
         ↑
       ...
```

The entry at the top of STATUS.md is always the most recent and represents
the current authoritative state.

### 2.4 Integration with Forgejo

STATUS.md entries are derived from Forgejo state (issue labels, claim
status, lane assignments) but are not a substitute. The relationship:

| Data Source | Authoritative For | Update Cadence |
|-------------|-------------------|----------------|
| Forgejo labels | Live claim state, issue maturity | Real-time |
| STATUS.md | Human-readable pipeline narrative | On coordination status entry |
| FEATURE_MATRIX.md | Capability maturity matrix | On maturity state change |

The coordination worker queries Forgejo at entry-generation time, computes
deltas from the previous STATUS.md entry, and writes the new entry.

---

## 3. Data Structures

### 3.1 LaneStatus

The core data structure representing the state of a single coordination lane.

```rust
/// Status of a single coordination pipeline lane.
#[derive(Debug, Clone)]
pub struct LaneStatus {
    /// Lane identifier.
    pub lane: LaneId,

    /// Total open issues in this lane.
    pub open_count: u16,

    /// Count by claim state.
    pub ready: u16,
    pub claimed: u16,
    pub needs_review: u16,
    pub blocked: u16,
    pub deferred_unlabeled: u16,

    /// Individual issue summaries (up to 5 most salient).
    pub salient_issues: Vec<IssueSummary>,

    /// Whether any issue in this lane touches a serial write surface.
    pub serial_surface_contention: bool,
}

/// Summary of a single issue within a lane.
#[derive(Debug, Clone)]
pub struct IssueSummary {
    /// Forgejo issue number.
    pub number: u32,

    /// Short descriptive tag (e.g., "OW-302").
    pub tag: Option<String>,

    /// One-line description.
    pub title: String,

    /// Current claim state label.
    pub claim_state: ClaimState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimState {
    Ready,
    Claimed,
    NeedsReview,
    Blocked,
    Deferred,
}
```

### 3.2 PipelineHealth

Aggregate health assessment across all coordination lanes.

```rust
/// Aggregate coordination pipeline health.
#[derive(Debug, Clone)]
pub struct PipelineHealth {
    /// Total open issues across all lanes.
    pub total_open: u16,

    /// Breakdown by lane.
    pub lanes: Vec<LaneStatus>,

    /// Count of codex:ready issues (available work).
    pub available_work: u16,

    /// Count of codex:claimed issues (active work).
    pub active_work: u16,

    /// Count of codex:needs-review issues.
    pub in_review: u16,

    /// Count of codex:blocked issues.
    pub blocked: u16,

    /// Whether the design phase is complete for all services.
    pub design_phase_complete: bool,

    /// Number of services with active implementation.
    pub active_implementation_lanes: u8,

    /// Number of services deferred to wire-up issues.
    pub deferred_services: u8,

    /// Narrative health assessment (1-2 sentences).
    pub narrative: String,

    /// Whether any new blocked work or design gaps emerged.
    pub new_blocked_work: bool,

    /// Whether any new design gaps emerged.
    pub new_design_gaps: bool,
}
```

### 3.3 StatusDiff

Delta between two successive Coordination Status entries, used to generate
the narrative summary and detect significant changes.

```rust
/// Delta between two Coordination Status entries.
#[derive(Debug, Clone)]
pub struct StatusDiff {
    /// Issues closed since the previous entry.
    pub closed_issues: Vec<ClosedIssue>,

    /// Issues opened since the previous entry.
    pub opened_issues: Vec<IssueSummary>,

    /// Lanes whose open count changed.
    pub changed_lanes: Vec<LaneDelta>,

    /// Overall pipeline metrics delta.
    pub pipeline_delta: PipelineDelta,

    /// Whether the narrative health assessment changed materially.
    pub narrative_changed: bool,
}

#[derive(Debug, Clone)]
pub struct LaneDelta {
    pub lane: LaneId,
    pub previous_open: u16,
    pub current_open: u16,
    pub previous_claimed: u16,
    pub current_claimed: u16,
}

#[derive(Debug, Clone)]
pub struct PipelineDelta {
    pub previous_total: u16,
    pub current_total: u16,
    pub previous_active: u16,
    pub current_active: u16,
    pub previous_available: u16,
    pub current_available: u16,
}

#[derive(Debug, Clone)]
pub struct ClosedIssue {
    pub number: u32,
    pub title: String,
    pub closed_between: (u32, u32), // (previous_entry_issue, current_entry_issue)
}
```

### 3.4 Lane Health Score

Per-lane health scoring for prioritization and risk detection.

```rust
/// Health score for a single coordination lane.
/// Range 0.0 (critical failure) to 1.0 (perfect health).
#[derive(Debug, Clone, Copy)]
pub struct LaneHealthScore(f64);

impl LaneHealthScore {
    /// Compute health score from lane status.
    pub fn compute(status: &LaneStatus) -> Self {
        // Weights sum to 1.0
        const BLOCKED_PENALTY_WEIGHT: f64 = 0.30;
        const STALENESS_WEIGHT: f64 = 0.25;
        const CLAIM_BALANCE_WEIGHT: f64 = 0.20;
        const PROGRESS_WEIGHT: f64 = 0.15;
        const CONTENTION_WEIGHT: f64 = 0.10;

        let total = status.open_count as f64;
        if total == 0.0 {
            return LaneHealthScore(1.0); // Empty lane = healthy
        }

        // Blocked issues are the strongest negative signal
        let blocked_ratio = status.blocked as f64 / total;
        let blocked_score = 1.0 - blocked_ratio;

        // Staleness: high ready count without claims suggests neglect
        let staleness = if status.ready > 0 && status.claimed == 0 {
            0.3 // Stale lane: work available but nobody working
        } else if status.ready as f64 / total > 0.8 {
            0.5 // Mostly ready, few active claims
        } else {
            1.0 // Balanced or all-claimed
        };

        // Claim balance: too many simultaneous claims risks contention
        let claim_balance = if status.claimed > 2 {
            0.5 // Potential contention
        } else if status.claimed == 0 && status.ready > 0 {
            0.6 // Under-claimed
        } else {
            1.0 // Balanced (1-2 claims)
        };

        // Progress: needs-review items indicate forward momentum
        let progress = if status.needs_review > 0 {
            1.0 // Active review = progress
        } else if status.claimed > 0 {
            0.8 // Active implementation = moderate progress
        } else {
            0.4 // No activity
        };

        // Contention: serial surface contention reduces health
        let contention = if status.serial_surface_contention {
            0.6
        } else {
            1.0
        };

        let score = BLOCKED_PENALTY_WEIGHT * blocked_score
                  + STALENESS_WEIGHT * staleness
                  + CLAIM_BALANCE_WEIGHT * claim_balance
                  + PROGRESS_WEIGHT * progress
                  + CONTENTION_WEIGHT * contention;

        LaneHealthScore(score.clamp(0.0, 1.0))
    }

    pub fn as_f64(&self) -> f64 { self.0 }

    /// Interpretive label for health score ranges.
    pub fn label(&self) -> &'static str {
        match self.0 {
            x if x >= 0.8 => "healthy",
            x if x >= 0.6 => "moderate",
            x if x >= 0.4 => "concerning",
            _ => "critical",
        }
    }
}
```

### 3.5 STATUS.md Entry Record

The on-disk wire format for a single STATUS.md entry, as rendered in
markdown.

```rust
/// Structured representation of a STATUS.md entry.
#[derive(Debug, Clone)]
pub struct StatusMdEntry {
    /// Date in YYYY-MM-DD format.
    pub date: String,

    /// Forgejo issue number this entry closes.
    pub issue_number: u32,

    /// Issue title (first line).
    pub title: String,

    /// Lane status section.
    pub lane_statuses: Vec<LaneEntryStatus>,

    /// Overall pipeline section.
    pub pipeline: PipelineEntry,

    /// Coordination pipeline health section (narrative).
    pub coordination_health: CoordinationHealthEntry,

    /// Recently closed issues section.
    pub recently_closed: Vec<ClosedIssueEntry>,

    /// Roadmap priorities section.
    pub roadmap_priorities: Vec<PriorityEntry>,

    pub gate: String,

    /// Maturity label.
    pub maturity: Option<String>,

    /// Issue this entry closes.
    pub closes: u32,
}

#[derive(Debug, Clone)]
pub struct LaneEntryStatus {
    pub lane_name: String,
    pub open_count: u16,
    pub blocked_count: u16,
    pub claimed_count: u16,
    pub ready_count: u16,
    pub issues: Vec<(u32, String, String)>, // (number, tag, title)
}

#[derive(Debug, Clone)]
pub struct PipelineEntry {
    pub total_open: u16,
    pub lane_breakdown: Vec<(String, u16)>, // (lane_name, count)
    pub ready: u16,
    pub claimed: u16,
    pub needs_review: u16,
    pub blocked: u16,
    pub special_notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CoordinationHealthEntry {
    pub design_phase_status: String,
    pub active_lanes: Vec<(String, String)>, // (lane_name, maturity)
    pub deferred_items: Vec<String>,
    pub narrative: String,
}

#[derive(Debug, Clone)]
pub struct ClosedIssueEntry {
    pub number: u32,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct PriorityEntry {
    pub rank: u8,
    pub description: String,
}
```

---

## 4. Algorithms

### 4.1 STATUS.md Entry Generation

The entry generation algorithm queries Forgejo state, parses the previous
STATUS.md Coordination Status entry, computes the delta, and renders the new
entry.

```
Algorithm: generate_status_entry()

Input:
    - Forgejo API base URL + auth token
    - Path to STATUS.md

Output:
    - New STATUS.md entry rendered as markdown string

Steps:
    1. QUERY_FORGEJO:
       a. GET /repos/forgeadmin/tidefs/issues?state=open&labels=codex:ready,codex:claimed,codex:needs-review,codex:blocked
       b. Group results by lane label (lane:storage-core, lane:coordination, etc.)
       c. For each lane, count issues by claim state label

    2. PARSE_PREVIOUS:
       a. Read STATUS.md from the top
       b. Find the most recent entry with "Coordination pipeline health:" in the body
       c. Extract the previous PipelineHealth from the structured fields
       d. If no previous Coordination Status entry exists, use zeroed baseline

    3. COMPUTE_DELTA:
       a. Compare current Forgejo state against previous PipelineHealth
       b. Identify closed issues: previous.open_issues - current.open_issues (by set difference)
       c. Identify opened issues: current.open_issues - previous.open_issues
       d. Compute lane-level deltas for each lane
       e. Compute pipeline-level deltas

    4. COMPUTE_HEALTH:
       a. For each lane, compute LaneHealthScore
       b. Generate narrative: "The design phase for cluster-wide services is
          {complete/substantially complete/incomplete}. Active implementation
          lanes remain: {comma-separated active lanes}. {Deferred items
          summary}. {Whether any new blocked work or design gaps emerged}."
       c. Flag if any LaneHealthScore < 0.4

    5. COMPUTE_PRIORITIES:
       a. Apply the roadmap priority algorithm from #1723
       b. Generate ordered list of 3-5 highest priorities

    6. RENDER_ENTRY:
       a. Format as markdown following the STATUS.md entry schema
       b. Include all required sections: lane status, pipeline, health, closed, priorities, gate
       c. Add "Closes: #<issue>" footer

    7. RETURN rendered markdown string
```

### 4.2 Delta Computation

The delta computation algorithm identifies what changed between two successive
Coordination Status entries.

```
Algorithm: compute_status_delta(previous, current)

Input:
    - previous: PipelineHealth from the previous STATUS.md entry
    - current: PipelineHealth computed from current Forgejo state

Output:
    - StatusDiff with closed issues, opened issues, lane deltas, pipeline delta

Steps:
    1. CLOSED_ISSUES = set_difference(previous.issue_set, current.issue_set)
       // Issues that existed in the previous state but not in the current state

    2. OPENED_ISSUES = set_difference(current.issue_set, previous.issue_set)
       // Issues that exist in the current state but not in the previous state

    3. For each lane L in (previous.lanes ∪ current.lanes):
       a. prev_lane = previous.lanes[L] or LaneStatus::default()
       b. curr_lane = current.lanes[L] or LaneStatus::default()
       c. If prev_lane.open_count != curr_lane.open_count:
          changed_lanes.push(LaneDelta {
              lane: L,
              previous_open: prev_lane.open_count,
              current_open: curr_lane.open_count,
              previous_claimed: prev_lane.claimed,
              current_claimed: curr_lane.claimed,
          })

    4. PIPELINE_DELTA = PipelineDelta {
           previous_total: previous.total_open,
           current_total: current.total_open,
           previous_active: previous.active_work,
           current_active: current.active_work,
           previous_available: previous.available_work,
           current_available: current.available_work,
       }

    5. NARRATIVE_CHANGED = (
           previous.new_blocked_work != current.new_blocked_work
           || previous.new_design_gaps != current.new_design_gaps
           || previous.design_phase_complete != current.design_phase_complete
           || previous.active_implementation_lanes != current.active_implementation_lanes
       )

    6. RETURN StatusDiff { closed_issues, opened_issues, changed_lanes,
                           pipeline_delta, narrative_changed }
```

### 4.3 Lane Health Scoring

Each lane is scored individually using the `LaneHealthScore::compute()`
algorithm defined in §3.4. The scores are aggregated into an overall pipeline
health assessment:

```
Algorithm: compute_pipeline_health(lanes)

Input:
    - lanes: Vec<LaneStatus>

Output:
    - (overall_score: f64, label: &str, alerts: Vec<String>)

Steps:
    1. For each lane L in lanes:
       a. score[L] = LaneHealthScore::compute(L)

    2. OVERALL_SCORE = weighted_mean(score[lane], weight=lane.open_count)
       // Lanes with more open issues have proportionally greater impact

    3. ALERTS = []
       For each lane L:
         if score[L].as_f64() < 0.4:
           ALERTS.push("CRITICAL: {L} lane health is {score.label}")
         elif score[L].as_f64() < 0.6:
           ALERTS.push("WARNING: {L} lane health is {score.label}")

    4. LABEL = if overall_score >= 0.8 { "healthy" }
               elif overall_score >= 0.6 { "moderate" }
               elif overall_score >= 0.4 { "concerning" }
               else { "critical" }

    5. RETURN (overall_score, LABEL, ALERTS)
```

### 4.4 Staleness Detection

A lane is considered stale if it has `codex:ready` issues but no
`codex:claimed` or `codex:needs-review` activity across two successive
Coordination Status entries.

```
Algorithm: detect_stale_lanes(previous, current)

Input:
    - previous: PipelineHealth from the previous entry
    - current: PipelineHealth from the current entry

Output:
    - Vec<LaneId> of stale lanes

Steps:
    1. For each lane L in current.lanes:
       a. prev_lane = previous.lanes[L] or LaneStatus::default()
       b. curr_lane = current.lanes[L]
       c. is_stale = (
              curr_lane.ready > 0
              && curr_lane.claimed == 0
              && curr_lane.needs_review == 0
              && prev_lane.ready > 0
              && prev_lane.claimed == 0
              && prev_lane.needs_review == 0
          )
       d. If is_stale: stale_lanes.push(L)

    2. RETURN stale_lanes
```

Stale lanes are flagged in the narrative as "No activity in {lane} across
the last two status windows; {n} issues remain available."

### 4.5 Serial Surface Conflict Detection

Before generating a STATUS.md entry, the algorithm checks for potential
serial-write-surface conflicts:

```
Algorithm: check_serial_surface_conflicts(lanes)

Input:
    - lanes: Vec<LaneStatus>

Output:
    - Vec<String> of conflict warnings

Steps:
    1. serial_surfaces = {
          "tidefs-local-filesystem/src/lib.rs": [],
          "tidefs-local-object-store/src/lib.rs": [],
       }

    2. For each lane L in lanes:
       For each issue I in L.salient_issues:
         If I.claim_state == Claimed:
           For each surface S in I.edited_surfaces (read from Forgejo issue body):
             If surface S is in serial_surfaces:
               serial_surfaces[S].push((L.lane, I.number))

    3. CONFLICTS = []
       For each (surface, claimants) in serial_surfaces:
         If len(claimants) > 1:
           CONFLICTS.push("CONFLICT: {surface} has {len(claimants)} active
                          claimants: {claimants}")

    4. RETURN CONFLICTS
```

---

## 5. STATUS.md Entry Format Contract

### 5.1 Required Sections

Every Coordination Status entry MUST include the following sections in order:

1. **Header**: `## YYYY-MM-DD: #<issue> <title>`
2. **Lane Status**: Per-lane open-issue counts with salient issue summaries
3. **Overall Pipeline**: Aggregate metrics across all lanes
4. **Coordination Pipeline Health**: Narrative health assessment
5. **Roadmap Priorities**: Ordered priority list (3-5 items)
7. **Footer**: `- Closes: #<issue>`

### 5.2 Narrative Contract

The Coordination Pipeline Health narrative MUST follow this template:

```
The design phase for cluster-wide services is {complete|substantially complete|in progress}.
Active implementation lanes remain: {lane1} ({maturity1}), {lane2} ({maturity2}), [...].
{Deferred items summary}.
{New blocked work or design gaps status}.
```

Where:
- **completness**: "complete" if all 16 designs are sealed, "substantially
  complete" if ≥14 are sealed, "in progress" otherwise
- **active lanes**: Only lanes with `ImplementedSource` maturity or active claims
- **deferred items**: Keys items deferred to child issues, with issue references
- **blocked/gaps**: "No new blocked work or design gaps have emerged." or a
  specific description

### 5.3 Maturity Labels

Each active lane in the health narrative MUST carry one of these maturity labels:

| Label | Meaning |
|-------|---------|
| `implemented-source` | Code exists with passing unit tests |
| `design-spec` | Complete design document; no implementation |
| `design-sealed` | Frozen design; awaiting wire-up |
| `G<N> foundation complete, G<N+1>+ deferred` | Hierarchical implementation (spacemap pattern) |
| `N/M canonical component crates implemented` | Partial component implementation (P8-03 pattern) |

### 5.4 Anti-Patterns

The following MUST NOT appear in STATUS.md Coordination Status entries:

- **Repeated narrative**: Do not copy the previous entry's narrative verbatim;
  always regenerate from current state.
- **Vague maturity claims**: Never use "mostly done" or "almost there"; use
  the canonical maturity labels from §5.3.
- **Missing lane coverage**: Every coordination lane (Layers 8-11) must be
  represented, even if the lane has zero open issues.
- **Unreferenced claims**: Every claim of "implemented-source" or
  "design-spec" must reference the Forgejo issue number or design document
  path.
- **Future-tense speculation**: Report current state only; use "remain
  deferred" not "will be deferred."

---

## 6. Tradeoffs and Design Decisions

### 6.1 Append-Only vs. In-Place Updates

| Approach | Pros | Cons |
|----------|------|------|
| **Append-only (chosen)** | Full audit trail; no data loss; easy diffing across time; natural for git blame | File grows unbounded; requires parsing logic to find latest entry |
| In-place update | File stays compact; always shows current state | No history; merge conflicts on concurrent edits; hard to detect staleness |

**Decision**: Append-only. The audit trail is essential for pipeline health
trending and historical debugging. The file growth is bounded (STATUS.md
entries are ~30 lines each; at one entry per day, the file grows ~10KB/year).

### 6.2 Narrative vs. Structured-Only Reporting

| Approach | Pros | Cons |
|----------|------|------|
| **Hybrid (chosen)** | Human-readable narrative for quick scan; structured fields for automated parsing | Requires both sections; slight redundancy |
| Structured-only (JSON/YAML) | Perfect for automation | Unreadable for humans; breaks the single-source-of-truth property |
| Narrative-only | Easy to write and read | Impossible to parse automatically; inconsistent across writers |

**Decision**: Hybrid. The structured sections (lane status, pipeline metrics)
appear as markdown lists with consistent keyword prefixes. The narrative
section provides human context. Automated tooling can parse the structured
sections without fragile natural-language parsing.

### 6.3 Per-Entry vs. Cumulative Status

| Approach | Pros | Cons |
|----------|------|------|
| **Per-entry delta (chosen)** | Each entry stands alone; no need to read entire file for current state | Redundancy across entries; must regenerate closed-issue lists each time |
| Cumulative reference | Compact; no redundancy | Must read entire file to understand current state; entry N depends on entry N-1 |

**Decision**: Per-entry with delta annotation. Each entry includes the
current state snapshot (stands alone) plus a "Recently closed" section
that annotates the delta from the previous entry. This balances
self-containment with change awareness.

### 6.4 Centralized vs. Distributed Status Generation

| Approach | Pros | Cons |
|----------|------|------|
| **Coordinator-generated (chosen)** | Consistent format; single writer avoids merge conflicts | Coordinator is a bottleneck; latency between state change and STATUS.md update |
| Worker-generated | Real-time updates; no bottleneck | Inconsistent formatting; merge conflicts on shared file |

**Decision**: Coordinator-generated. STATUS.md is a serial write surface by
design — only the coordination lane worker writes Coordination Status entries.
Other workers write only their own issue-closeout entries, which follow a
simpler format. This prevents merge conflicts while allowing parallel
closeout entries from non-coordination lanes.

### 6.5 Health Score Thresholds

The health score thresholds (0.8 healthy, 0.6 moderate, 0.4 concerning, <0.4
critical) were calibrated against historical coordination lane states:

| Historical State | LaneHealthScore | Intuitive Label |
|-----------------|-----------------|-----------------|
| 0 blocked, 1-2 claimed, 3-5 ready | 0.85 | healthy |
| 0 blocked, 0 claimed, 5+ ready | 0.55 | stale/moderate |
| 1+ blocked, 0 claimed | 0.35 | concerning |
| 3+ blocked, serial contention | 0.15 | critical |

The weights (30% blocked, 25% staleness, 20% claim balance, 15% progress,
10% contention) prioritize correctness (blocked issues are the strongest
negative signal) and activity (stale lanes are the most common failure mode).

---

## 7. Implementation Plan

### 7.1 Phase 1: Schema Formalization (this issue, #1833)

- [x] Define STATUS.md entry schema for Coordination Status entries
- [x] Define data structures: `LaneStatus`, `PipelineHealth`, `StatusDiff`,
  `LaneHealthScore`, `StatusMdEntry`
- [x] Define algorithms: entry generation, delta computation, lane health
  scoring, staleness detection, serial-surface conflict detection
- [x] Define narrative contract and maturity label taxonomy
- [x] Document tradeoffs and design decisions

### 7.2 Phase 2: Type Implementation (future wire-up issue)

- [ ] Implement `LaneHealthScore` and `PipelineHealth` in a new
  `tidefs-types-coordination-status-core` crate (`no_std` + `alloc`)
- [ ] Implement `StatusDiff` computation
- [ ] Implement `StatusMdEntry` rendering
- [ ] Add unit tests for health score boundary conditions
- [ ] Gate: `cargo check --workspace` + crate-level tests

### 7.3 Phase 3: Coordinator Integration (future wire-up issue)

- [ ] Integrate status generation into the coordinator workflow
- [ ] Add Forgejo API query logic for lane/claim-state aggregation
- [ ] Implement STATUS.md parsing to extract the previous Coordination Status
  entry
- [ ] Gate: Integration test with live Forgejo state

### 7.4 Phase 4: Automated Health Monitoring (future wire-up issue)

- [ ] Implement staleness detection as a coordinator check
- [ ] Implement serial-surface conflict detection
- [ ] Add health score trending across successive entries
- [ ] Gate: Health score regression test suite

---

## 8. STATUS.md Entry Lifecycle

```
┌─────────────────┐
│ Forgejo state   │
│ changes         │
│ (labels, claims)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────┐
│ Coordinator     │────▶│ Query Forgejo    │
│ triggers update │     │ API for lane     │
│                 │     │ status           │
└─────────────────┘     └────────┬─────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │ Parse previous   │
                        │ STATUS.md entry  │
                        └────────┬─────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │ Compute StatusDiff│
                        └────────┬─────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │ Generate health  │
                        │ narrative        │
                        └────────┬─────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │ Render new entry │
                        │ per schema       │
                        └────────┬─────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │ Prepend to       │
                        │ STATUS.md        │
                        └──────────────────┘
```

---

## 9. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Stale Forgejo state at query time | Low | Low | Query immediately before entry generation; entry timestamp provides freshness assertion |
| STATUS.md merge conflicts | Low | Medium | Coordination Status entries written only by coordinator; non-coordination entries follow simpler format with no overlapping sections |
| Narrative inconsistency | Medium | Low | Template-based generation (§5.2) eliminates free-form narrative variation |
| Health score miscalibration | Low | Medium | Weights calibrated against historical states; future Phase 4 adds trending to detect drift |
| Missing lane coverage | Low | Medium | Algorithm enumerates all known lanes (§4.1); empty lanes still appear in structured section |

---

## 10. References

- `docs/design/coordination-pipeline-cluster-services-design-seal.md` — #1738 design phase seal
- `docs/design/coordination-review-roadmap-priorities-update.md` — #1723 review and priorities
- `docs/STATUS.md` — deleted historical Forgejo-era coordination status
  register, not current TideFS coordination authority
- `docs/FEATURE_MATRIX.md` — deleted historical Forgejo-era capability matrix,
  not current implementation-status or release-readiness authority
- `docs/CURRENT_VS_FUTURE_CAPABILITIES.md` — deleted historical production-gate
  reference, not current release-readiness authority
- `docs/CLAIMS_GATE_POLICY.md` — claim barrier policy
- `docs/WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md` — serial write surface definitions
- `docs/MEMBERSHIP_SERVICE_DESIGN.md` — membership protocol
- `docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md` — reclaim queues
- `docs/SPACEMAP_ALLOCATOR_DESIGN.md` — spacemap allocator
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md` — P8-03 runtime

---

**Historical coordination pipeline STATUS.md update architecture recorded.**
In its Forgejo-era context, this document defined a schema contract, data
structures, and algorithms for future Coordination Status entries. That
machinery no longer governs current TideFS coordination. Current coordination
state, implementation status, release readiness, and worker scheduling authority
live in GitHub issues and pull requests plus the current documentation entry
points.

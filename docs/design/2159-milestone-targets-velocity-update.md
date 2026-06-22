# Milestone Targets — Velocity-Based Update (#2159)

**Issue**: [#2159](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2159)
**Imported status**: design-spec (historical May 2026 design state; not current TideFS status authority)
**Imported maturity**: **design-spec** — historical milestone-target classification, not feature-matrix authority
**Priority**: P2
**Lane**: coordination / storage-core
**Depends on**: #2116 (prior milestone targets), #2144 (prior status snapshot), #2054 (coordination pipeline)
**Blocks**: All deferred wire-up implementation issues

## Abstract

This document defines the milestone-target architecture for tidefs — version-pinned
capability checkpoints that gate progress from design through implementation to
production readiness. It supersedes the milestone targets set in #2116 with an
updated velocity assessment drawn from the May 2026 snapshot (38 open issues,
31 claimed, 1 ready, 1 needs-review, 4 blocked). The document specifies the data
structures for milestone definitions, the algorithms for velocity computation and
target projection, the integration with the 11-layer dependency matrix, and the
tradeoffs between optimistic and conservative scheduling.

---

## 1. Architecture

### 1.1 Four-Milestone Staircase

Milestone targets form a four-stage staircase aligned with the 11-layer
architecture. Each milestone gates a block of layers and requires a minimum
percentage of design-complete issues within its layer set:

```
v1.0.0  ────────────────────────────────────────────── (production)
  │
v0.8.0  ─── DESIGN-M4: Cluster Infrastructure (L8–L11)
  │
v0.7.0  ─── DESIGN-M3: Data Services + Integrity (L6–L7)
  │
v0.6.0  ─── DESIGN-M2: Filesystem Semantics + Caching (L3–L5)
  │
v0.5.0  ─── DESIGN-M1: Storage Foundation (L0–L2)
  │
v0.x.y  ─── Pre-milestone development releases
```

### 1.2 Milestone Gate Criteria

A milestone is considered gated when:

1. **Design completion** ≥ 90% of issues in the milestone's layer set have
   achieved at least `design-spec` or `design-sealed` maturity.
2. **Implementation wire-up** ≥ 50% of issues have `implemented-source` or
   milestone-specific xtask or integration test suite.
4. **Dependency closure** — all bedrock issues in the layer set have `done`
   status; no open transitive dependencies block the milestone.

### 1.3 Two-Phase Maturity Model

Each issue progresses through two maturity phases before contributing to a
milestone gate:

| Phase | Maturities | Weight | Description |
|-------|-----------|--------|-------------|
| **Design** | `design-spec`, `design-sealed` | 0.4 | Architecture, data structures, algorithms, tradeoffs documented |

Composite maturity score for a layer:

```
score(layer) = Σ (issue_weight × phase_weight × maturity_multiplier)
               ─────────────────────────────────────────────────
                        Σ issue_weight

Where:
  maturity_multiplier = 0.0 for open/blocked
                      = 0.5 for claimed/ready
                      = 1.0 for design-spec/design-sealed
                      = 1.5 for implemented-source
```

---

## 2. Data Structures

### 2.1 Milestone Definition

```rust
/// A version-pinned capability checkpoint.
struct Milestone {
    /// Semantic version target (e.g., v0.5.0).
    target_version: SemVer,
    /// Human-readable label.
    label: &'static str,
    /// Layer range [start, end] inclusive.
    layers: RangeInclusive<u8>,
    /// Minimum composite maturity score required (0.0–1.0).
    min_score: f64,
    /// Minimum design-complete percentage (0–100).
    min_design_pct: u8,
    /// Minimum implementation percentage (0–100).
    min_impl_pct: u8,
    /// Bedrock issues that must be `done`.
    bedrock_gate: &'static [IssueId],
    gate_command: &'static str,
}
```

### 2.2 Current Milestone Table (May 2026)

| Milestone | Version | Layers | Design % | Impl % | Bedrock Gate | Status |
|-----------|---------|--------|----------|--------|-------------|--------|
| DESIGN-M1 | v0.5.0 | L0–L2 | 71% (12/17 done) | 18% (3/17) | #1220, #1285, #1215 done; #1213 (L3) done | active |
| DESIGN-M2 | v0.6.0 | L3–L5 | 61% (11/18 done) | 6% (1/18) | #1179, #1239 done; #1181, #1192 open | deferred |
| DESIGN-M3 | v0.7.0 | L6–L7 | 17% (2/12 done) | 0% | #1287 done; all others open | deferred |
| DESIGN-M4 | v0.8.0 | L8–L11 | 8% (3/36 design-visible) | 6% (2/36) | #1209 done; #1229, #1243, #1248, #1216 open | deferred |

> **Note**: Design % counts only issues with `done` status per the 11-layer
> dependency matrix (#1284). Implementation % counts issues with

### 2.3 Layer Scorecard (Current Snapshot)

| Layer | Issues | Done | Design % | Impl % | Bedrock |
|-------|--------|------|----------|--------|---------|
| L0 | 4 | 1 | 50% | 0% | #1250 (claimed) |
| L1 | 9 | 8 | 89% | 22% | #1220 ★ complete |
| L2 | 4 | 3 | 75% | 25% | #1215 ★ complete |
| L3 | 7 | 5 | 71% | 0% | #1213 ★ complete |
| L4 | 9 | 6 | 67% | 11% | #1179 ★ complete |
| L5 | 2 | 0 | 0% | 0% | — |
| L6 | 8 | 1 | 13% | 0% | — |
| L7 | 4 | 1 | 25% | 0% | — |
| L8 | 1 | 0 | 0% | 0% | — |
| L9 | 8 | 1 | 13% | 0% | #1209 ★ complete |
| L10 | 9 | 1 | 11% | 0% | #1229 (claimed) |
| L11 | 2 | 0 | 0% | 0% | — |

---

## 3. Algorithms

### 3.1 Velocity Computation

Projects closure velocity from the trailing window of closed issues:

```
velocity(days) = closed_issues_in_window / window_days

Current window (last 2 snapshots):
  #2111→#2144: 4 closures over ~1 day  → 4 issues/day (peak, design-seal dominated)
  #2144→now:   4 closures over ~1 day  → 4 issues/day

Long-term (since #1754 design-completion):
  ~25 closures over ~7 days → ~3.5 issues/day

Implementation-only velocity (issues with source changes):
  ~3 closures over ~7 days → ~0.4 issues/day
```

### 3.2 Milestone Projection

Given current velocity _v_ and remaining work _R_, the projected completion
date for milestone _M_ is:

```
projected(M) = today + R(M) / v

Where:
  R(M) = Σ remaining issue workload in M's layer set
  v    = implementation velocity (0.4 issues/day)
```

#### DESIGN-M1 Projection (v0.5.0)

- Remaining: 5 design issues (L0: #1250, #1238, #1279; L2: #1190; plus 1 open L1 issue).
- Implementation: 14 of 17 issues lack implemented-source maturity.
- At 0.4 impl issues/day: ~35 working days → **late Q3 2026** (unchanged from #2116).
- At 2–3 design issues/day (current coordinator cadence): remaining design work clears in ~2 days.
- **Primary bottleneck**: implementation wire-up, not design.

#### DESIGN-M2 Projection (v0.6.0)

- Remaining design: 7 issues (L3: #1205, #1278; L4: #1181, #1192, #1268, #1247; L5: #1184, #1256).
- Implementation: 17 of 18 issues lack implemented-source maturity.
- At 0.4 impl issues/day: ~43 working days after DESIGN-M1 clearance.
- **Blocked by**: DESIGN-M1 dependency chain (L3 depends on L2 #1190, L4 depends on #1179 infrastructure).
- **Projected**: **Q1 2027** with current velocity; **Q4 2026** if implementation velocity doubles.

#### DESIGN-M3 Projection (v0.7.0)

- Remaining design: 10 issues (L6: #1257, #1276, #1255, #1253, #1245, #1246, #1185; L7: #1281, #1280, #1277).
- L6 issues are parallelizable (Group L6-A); L7 issues are parallelizable (Group L7-A).
- Implementation: all 12 issues lack implemented-source maturity (except #1287 = design-spec, #1288 = design-spec).
- **Blocked by**: DESIGN-M2 completion (background services for scrub/repair scheduling).
- **Projected**: **Q3 2027** with current velocity.

#### DESIGN-M4 Projection (v0.8.0)

- Remaining design: majority of L9–L11 issues (34+ issues).
- Implementation: only #1249 (CRUSH placement) and #1209 (MEMBERSHIP design) are done.
- **Critical path**: MEMBERSHIP wire-up (#1209) → coordination services → data plane.
- **Projected**: **2028** with current velocity; **Q4 2027** if #1209 wire-up accelerates.

### 3.3 Critical Path Analysis

The critical path from current state to v1.0.0 traverses:

```
#1190 (writeback) → #1213 (VFS API, done) → #1179 (bg svc, done)
    → #1287 (checksums, done) → #1288 (scrub, done)
    → #1209 (MEMBERSHIP design, done → needs wire-up)
    → #1249 (CRUSH, done) → P8-03 runtime → cluster bootstrap
```

The MEMBERSHIP wire-up (#1209) is the single highest-leverage accelerator:
it unblocks #1208, #1217, #1260, #1283, #1248, #1258, and #1249
runtime integration (7 downstream issues).

---

## 4. Tradeoffs

### 4.1 Optimistic vs. Conservative Targets

| Dimension | Optimistic (v0.5.0 by Q2 2026) | Conservative (v0.5.0 by Q3 2026) |
|-----------|-------------------------------|----------------------------------|
| Assumes | Implementation velocity doubles to 0.8+/day | Velocity holds at 0.4/day |
| Risk | Schedule slip if wire-up velocity doesn't improve | Matches observed data |
| Benefit | Motivates accelerated wire-up work | Realistic stakeholder expectation |
| **Recommendation** | **Conservative** for v0.5.0+; revisit after #1190 wire-up | Default choice |

### 4.2 Design-First vs. Parallel Design+Implement

| Strategy | Pros | Cons | Current State |
|----------|------|------|---------------|
| Design-first (current) | Clean interfaces, no rework from premature implementation | Implementation velocity lags design by 6–12 months | All 16 canonical designs sealed; near-zero wire-up |
| **Recommendation** | **Transition to parallel** for M1/M2 layers where designs are substantially complete | — | Start with #1190 (L2) and #1181 (L4) as parallel pilots |

### 4.3 Serial vs. Parallel Lane Execution

- **Serial (current)**: L0 → L1 → L2 → L3 → ... enforcing strict layer ordering.
  Lowers coordination overhead but stretches the timeline.
- **Parallel by milestone**: DESIGN-M1, DESIGN-M2 layers can progress independently
  once their bedrock issues are done. L6–L7 are parallel-safe within M3.
- **Recommendation**: **Hybrid** — keep serial within M1 (tight L0–L2 coupling)
  but allow M1 and M2 implementation to overlap where dependency chains permit.

### 4.4 Version Cadence

| Cadence | Pros | Cons | Recommendation |
|---------|------|------|----------------|
| Fixed-date (quarterly) | Predictable release rhythm | Forces scope-cutting or slip | — |
| Capability-gated (current) | Each release delivers coherent capability | Unpredictable dates | **Use for v0.x.0 milestones** |
| Hybrid (quarterly minor, annual major) | Balances predictability and quality | Overhead of release management | **Use post-v1.0.0** |

---

## 5. Updated Milestone Targets (May 2026)

### 5.1 DESIGN-M1 — Storage Foundation (L0–L2) → v0.5.0

| Metric | #2116 (prior) | #2159 (updated) | Δ |
|--------|---------------|-----------------|---|
| Design complete | 75% | 71% | −4% (recalculated from matrix) |
| Target version | v0.5.0 | v0.5.0 | unchanged |
| Projected | Q3 2026 | **Q3 2026** | unchanged |
| Primary blocker | L0 format finalization (#1250) | L0 format finalization (#1250), writeback wire-up (#1190) | added #1190 |
| Impl issues remaining | 14 | 14 | unchanged |

**Required for gate**:
- `#1250` Three-contract architecture → design-sealed
- `#1238` Unified on-media format lifecycle → design-sealed
- `#1190` Writeback + transaction model → implemented-source (at least type-level)
- `#1220` On-media record format → implemented-source
- `#1215` Space accounting model → implemented-source

### 5.2 DESIGN-M2 — Filesystem Semantics + Caching (L3–L5) → v0.6.0

| Metric | #2116 (prior) | #2159 (updated) | Δ |
|--------|---------------|-----------------|---|
| Design complete | 72% | 61% | −11% (recalculated) |
| Target version | v0.6.0 | v0.6.0 | unchanged |
| Projected | Q4 2026 | **Q1 2027** | +1 quarter (implementation lag) |
| Primary blocker | Background service phases 5–10 (#1877) | Background service phases 5–10 (#1877), L5 coherency (#1184) | added L5 dep |
| Impl issues remaining | 17 | 17 | unchanged |

### 5.3 DESIGN-M3 — Data Services + Integrity (L6–L7) → v0.7.0

| Metric | #2116 (prior) | #2159 (updated) | Δ |
|--------|---------------|-----------------|---|
| Design complete | 17% | 17% | unchanged |
| Target version | v0.7.0 | v0.7.0 | unchanged |
| Projected | Q2 2027 | **Q3 2027** | +1 quarter |
| Parallelization opportunity | Not assessed | L6-A group (5 issues parallel), L7-A group (3 issues parallel) | new |

### 5.4 DESIGN-M4 — Cluster Infrastructure (L8–L11) → v0.8.0

| Metric | #2116 (prior) | #2159 (updated) | Δ |
|--------|---------------|-----------------|---|
| Design complete | 19% | 8% (recalculated: 3/36 design-done) | −11% |
| Target version | v0.8.0 | v0.8.0 | unchanged |
| Projected | Q4 2027 | **2028** | extended |
| Critical path | #1209 MEMBERSHIP wire-up | #1209 MEMBERSHIP wire-up | unchanged |

### 5.5 v1.0.0 — Production Readiness

- **Projected**: **2029** with current velocity (unchanged from implicit #2116 projection).

---

## 6. Velocity Improvement Recommendations

### 6.1 Immediate (next 2 weeks)

1. **Wire up #1190 (writeback)** — unblocks L2 completion and L3+ write-path semantics.
   This is the highest-leverage single issue: it gates 3 downstream layers.
2. **Promote #1250 to design-sealed** — closes the last open L0 design gap.
3. **Clear the 1 `codex:ready` issue** — prevents idle-worker risk.

### 6.2 Short-term (next 4 weeks)

1. **Begin parallel M1/M2 implementation** — DESIGN-M1 layers (L0–L2) and DESIGN-M2
   layers (L3–L5) can overlap where dependency chains permit.
2. **Staff L6 parallelization** — L6-A group (5 issues: #1255, #1253, #1245, #1246, #1185)
   are independent and can be designed in parallel.
3. **Accelerate #1209 MEMBERSHIP wire-up** — this single issue unblocks 7 downstream
   coordination-service issues.

### 6.3 Medium-term (next 8 weeks)

1. **Transition from design-first to parallel design+implement** for layers where
   designs are ≥ 80% complete (L0–L4).
2. **Establish implementation-velocity tracking** separate from design-velocity
   to detect schedule slips earlier.
3. **Introduce milestone integration tests** — an xtask per milestone that gates

---

## 7. Observability

### 7.1 Velocity Dashboard Fields

| Field | Source | Update Cadence |
|-------|--------|---------------|
| `open_issues` | GitHub issue search/API for `tidefs/tidefs` | Per snapshot |
| `design_completion_pct` | Current GitHub issue state plus repo docs classified as current authority | Per milestone-target refresh |
| `impl_completion_pct` | Current GitHub issue/PR evidence, source evidence, and claim/repo-doc authority | Per milestone-target refresh |
| `closure_rate_daily` | GitHub issue/PR close events between snapshots | Per coordination cycle |
| `critical_path_depth` | Dependency graph traversal | Per milestone-target refresh |
| `ready_issue_count` | GitHub issue search/API using current readiness labels | Per snapshot |
| `blocked_issue_count` | GitHub issue search/API using current blocker labels | Per snapshot |

### 7.2 Alert Thresholds

| Condition | Severity | Action |
|-----------|----------|--------|
| `ready_issue_count == 0` for > 2 cycles | Warning | Coordinator should generate 1–2 ready issues |
| `blocked_issue_count` increasing | Warning | Dependency chain audit |
| `closure_rate_daily < 1.0` for > 5 cycles | Critical | Velocity intervention review |
| `design_completion_pct - impl_completion_pct > 60` for any milestone | Warning | Implementation stall risk |
| `critical_path_depth` unchanged for > 10 cycles | Critical | Bottleneck escalation |

---

## 8. Integration with Existing Artifacts

### 8.1 Current Status Authority

This imported May 2026 design modeled milestone-target refreshes as entries in
the deleted `docs/STATUS.md`. That output path is historical only. Current
TideFS coordination/status authority lives in GitHub issues and pull requests,
with durable repo-doc classification recorded through
`docs/DOCUMENTATION_AUTHORITY_REGISTER.md`, `docs/REVIEW_TODO_REGISTER.md`, and
other documents classified there as current policy or current spec.

Any revived milestone-target refresh should publish through those current
authorities with:
- Current velocity assessment
- Updated milestone table
- Critical path status
- Recommended next actions

### 8.2 Current Implementation Evidence Authority

This design also assumed the deleted `docs/FEATURE_MATRIX.md` as the milestone
implementation-output surface. That maturity column is historical input only.
Milestone gate evidence must now come from live GitHub issue/PR state, current
source and validation evidence, and repo docs classified as current authority;
do not advance or cite the deleted feature matrix as current implementation
status.

### 8.3 Historical 11-Layer Dependency Matrix

In the imported model, the matrix at
`docs/design/11-layer-architecture-dependency-matrix.md` acted as the per-issue
status input. Current coordination authority is live GitHub issue/PR state plus
repo docs that have been classified as current policy or current spec. Use the
matrix as historical design input unless a later source and evidence review
promotes the specific rows needed for current authority.

---

## 9. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Implementation velocity stays near-zero | High | All milestones slip 6–12 months | §6 velocity recommendations; escalate #1190 and #1209 wire-up |
| Coordinator issue proliferation dilutes velocity tracking | Medium | Low | #2054 containment envelope; separate coordinator issues from impl issues in velocity calc |
| Bedrock issue rework cascades to dependents | Low | High | Design-sealed gate requires dependency impact statement before re-opening |
| Single-worker bottleneck on serial surfaces | Medium | Medium | Parallelization groups (§4.3); non-overlapping write sets |

---

## 10. Gate

- `cargo check --workspace` — passes (design document only; no Rust source changes).
- Historical classification: imported **design-spec** milestone-target update. Current status authority for this document is `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`; Rust implementation remains deferred to follow-up GitHub issues and pull requests.
- Closes: #2159

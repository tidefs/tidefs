# Architecture Decision Records (ADRs)

This directory holds architecture decision records for TideFS. Each ADR
captures a single, significant design choice with its context, options
considered, rationale, and consequences.

ADRs are numbered sequentially. This index lists ADR files that remain in the
tree; obsolete pre-release ADR roots may be removed when current authority
lives elsewhere and the deletion is coordinated through GitHub issue, PR, and
git history. Superseded decisions that still carry useful live context are
marked with `Status: Superseded by ADR-NNNN`.

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| 0002 | Persistent orphan index | Accepted | 2026-05-05 |
| 0005 | Crate dependency graph and ownership boundaries | Accepted | 2026-05-05 |
| 0006 | License compliance with cargo-deny | Accepted | 2026-05-05 |
| 0007 | Local and clustered POSIX and block runtime modes | Accepted | 2026-06-20 |
| 0008 | Failed-quorum mutation evidence boundary | Accepted | 2026-06-28 |

## Format

Each ADR follows this template:

```
# ADR-NNNN: Title

Date: YYYY-MM-DD
Status: Proposed | Accepted | Deprecated | Superseded

## Context
## Decision
## Consequences
```

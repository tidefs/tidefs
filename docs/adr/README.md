# Architecture Decision Records (ADRs)

This directory holds architecture decision records for TideFS. Each ADR
captures a single, significant design choice with its context, options
considered, rationale, and consequences.

ADRs are numbered sequentially and never removed — superseded decisions
are marked with `Status: Superseded by ADR-NNNN`.

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| 0001 | End-to-end checksum architecture (G3 pillar) | Accepted | 2026-05-05 |
| 0002 | Persistent orphan index | Accepted | 2026-05-05 |
| 0003 | Shard groups, replicas, and rebake pathway | Accepted | 2026-05-05 |
| 0004 | CommitGroup commit ordering state machine | Accepted | 2026-05-05 |
| 0005 | Crate dependency graph and ownership boundaries | Accepted | 2026-05-05 |
| 0006 | License compliance with cargo-deny | Accepted | 2026-05-05 |

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

# Distributed operator product surface blocker map OW-307D

Maturity: **design-law** blocker map with source checks.

This document is a child slice of OW-307. It binds the remaining parent gate
after OW-307A, OW-307B, and OW-307C: TideFS has typed distributed operator
truth rows, deterministic demo rows, and a summary row, but it does not yet
have a runtime-fed operator product surface.

## Current Admission Verdict

Parent OW-307 remains open.

The current tree has implementation-tracked non-release operator truth building blocks:

- OW-307A defines typed placement, health, rebuild, and risk records;
- OW-307B projects deterministic demo rows through the control-plane daemon;
- OW-307C summarizes those rows for first-glance operator attention;
- OW-307E adds visible source, cut, provenance, exactness, and freshness
  headers to those deterministic rows and summaries;
- `tidefs-xtask check-observation-substrate` binds the OW-307A/B/C/E source
  markers, including the deterministic non-live header classes and visible
  daemon labels.

Those blocks do not prove a production operator surface. The demo rows are
summarizes the rows it is given.

## Required Product Surface

The production truth grammar is
`docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` (missing from the
repository; see #1270).

For OW-307, a future closeout must prove that placement, health, rebuild, and
risk data feed an operator-facing product surface through the same truth_view
law. The minimum product surface must include:

| Required product property | Required source truth | Current state |
|---|---|---|
| runtime source data | admitted runtime mirrors or receipt-backed source classes for placement, health, rebuild, and risk | no live distributed storage runtime or admitted runtime mirror feeds OW-307 rows |
| source and cut headers | named source classes, one visible cut class, and subject/scope binding for each visible block | OW-307E exposes source/cut headers for deterministic demo/source rows, but no admitted live runtime source feeds them |
| provenance, exactness, freshness | visible provenance/exactness/freshness state, including stale or degraded fields | OW-307E exposes deterministic non-live headers, but no live freshness budget or stale/refusal path exists for OW-307 product data |
| product carrier | a CLI, API, dashboard, or archive-reader surface that renders the typed rows and summary without inventing a second grammar | the control-plane daemon prints bounded demo output only |
| render proof | render bundle plus render receipt or stop ticket proving what the operator saw | no OW-307 product render receipt exists |
| refusal behavior | stale, mixed-cut, conflicting-source, redaction-blocked, and missing-runtime cases degrade or refuse visibly | P10-04 requires this (missing from the repository; see #1270), but no OW-307 product refusal path exists |

## Implementation Boundary

This packet does not add a dashboard server, a long-running operator CLI, an
API product surface, runtime placement/health/rebuild/risk mirrors, or any
distributed storage behavior. It records the blocker boundary so future work
does not treat deterministic demo output as a production operator product.

Future OW-307 implementation work must consume the existing typed rows and
summary helper. It must not add a parallel dashboard-local truth grammar, and
it must not let screenshots, grepped logs, raw stdout, or stale metrics become
legal operator truth.

## Parent Gate


- runtime-fed placement, health, rebuild, and risk source rows;
- a product carrier that exposes the rows and summary to an operator;
- visible source class, cut class, provenance, exactness, and freshness state;
- stale, mixed-cut, conflicting-source, missing-runtime, and redaction refusal
  behavior;
- a render receipt, stop ticket, or equivalent current record of the visible
  operator result.

Until then, OW-307 remains open even though its record, demo, summary, and
header building blocks are implementation-tracked non-release.

## Non-Claims

This document does not implement a live distributed storage runtime,
production dashboard server, long-running operator CLI, product API, placement,
replication, rebuild, resilver, failover, or self-healing behavior. It does
not close parent OW-307.



- `nix develop --command cargo fmt --check`;
- source-marker checks over this document, `docs/INDEX.md`, OW-307A/B/C docs,
  and `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` (missing
  from the repository; see #1270);
- `git diff --check`;

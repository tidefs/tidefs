# Focused Claim Validation Input Contract

Maturity: stable input contract for CI workflow dispatch.

This document defines the mode/input matrix for `Focused Claim Validation`
workflow (`focused-claim-validation.yml`). Workers that dispatch this workflow
or read its summary output can treat this contract as the canonical description
of accepted mode-input combinations, the command each mode runs, and the
residual validation scope each mode leaves to other tools.

## Mode/Input Matrix

| Mode | Required input | Forbidden input | Command executed |
| --- | --- | --- | --- |
| `validate-claim` | `claim_id` | `artifact_path` | `cargo run -p tidefs-xtask -- validate-claim <claim_id>` |
| `check-claims-gate` | (none) | `claim_id`, `artifact_path` | `cargo run -p tidefs-xtask -- check-claims-gate` |
| `check-no-hidden-queues` | (none) | `claim_id`, `artifact_path` | `cargo run -p tidefs-xtask -- check-no-hidden-queues` |
| `validate-evidence-manifest` | `artifact_path` | `claim_id` | `cargo run -p tidefs-xtask -- validate-evidence-manifest <artifact_path>` |
| `validate-ublk-completion` | `artifact_path` | `claim_id` | `cargo run -p tidefs-xtask -- validate-ublk-completion-artifact <artifact_path>` |
| `validate-ublk-started-export` | `artifact_path` | `claim_id` | `cargo run -p tidefs-xtask -- validate-ublk-started-export-admission-artifact <artifact_path>` |

### `validate-claim`

Validates a single registered claim's evidence set.

Expected output surface:
- stdout: `status: PASS`, `status: BLOCKED`, or `status: FAIL` line
- Exit 0 for PASS/BLOCKED, exit 1 for FAIL or xtask error
- stderr: error details on failure

Residual validation scope:
- Does not scan publishing-facing wording; use `check-claims-gate`
- Does not validate cross-claim evidence consistency
- Does not check claim registry authority or stale-claim detection

### `check-claims-gate`

Scans publishing-facing capability wording against the claim registry.

Expected output surface:
- stdout: nothing on pass
- Exit 0 on pass, exit 1 on fail
- stderr: per-claim error lines on failure, each prefixed with the failing path

Residual validation scope:
- Does not validate individual claim evidence; use `validate-claim`
- Does not inspect queue roots; use `check-no-hidden-queues`
- Does not validate evidence manifests or runtime artifacts

### `check-no-hidden-queues`

Validates queue-root accounting in touched implementation packages.

Expected output surface:
- stdout: nothing on pass
- Exit 0 on pass, exit 1 on fail
- stderr: queue-root error lines on failure

Residual validation scope:
- Does not scan publishing-facing wording; use `check-claims-gate`
- Does not validate individual claim evidence; use `validate-claim`
- Does not validate evidence manifests or runtime artifacts

### `validate-evidence-manifest`

Validates a claim evidence artifact manifest JSON against its schema and
digest.

Expected output surface:
- stdout: key manifest fields (`claim_id`, `evidence_class`, `tier`, `outcome`,
  `run_id`, `source_ref`, `source`, `scope`) on success
- Exit 0 on pass, exit 1 on failure
- stderr: error details on failure

Residual validation scope:
- Does not validate the claim registry status of the named claim
- Does not check whether the manifest artifact path is still current
- Does not validate runtime behavior; the manifest is a metadata record

### `validate-ublk-completion`

Validates a uBLK qid/tag runtime completion evidence artifact.

Expected output surface:
- stdout: `events`, `terminal_completions`, `queues`, and `depth` counts on
  success
- Exit 0 on pass, exit 1 on failure
- stderr: error details on failure

Residual validation scope:
- Does not validate uBLK started-export admission evidence; use
  `validate-ublk-started-export`
- Does not check the uBLK claim registry status
- Does not validate general evidence manifests; use
  `validate-evidence-manifest`

### `validate-ublk-started-export`

Validates a uBLK started-export admission evidence artifact.

Expected output surface:
- stdout: `claim_state`, `start_dev_succeeded`, `first_request_serviced`,
  `bounded_no_request_observed`, and `cleanup_succeeded` fields on success
- Exit 0 on pass, exit 1 on failure
- stderr: error details on failure

Residual validation scope:
- Does not validate uBLK completion evidence; use
  `validate-ublk-completion`
- Does not check the uBLK claim registry status
- Does not validate general evidence manifests; use
  `validate-evidence-manifest`

## Input Constraints

- `claim_id` must be a non-empty string matching a registered claim id in
  `validation/claims.toml`. It must not contain literal newline characters.
- `artifact_path` must be a non-empty workspace-relative path to an evidence
  artifact file readable by the xtask command. It must not contain literal
  newline characters.
- Inputs that contain shell metacharacters (unescaped backticks, `$()`,
  unquoted shell separators) are rejected before any cargo or xtask command
  runs.
- The `mode` input is a choice field restricted to the six values listed in
  the matrix above.

## Workflow Summary Contract

After input validation, the workflow step summary reports:
- The normalized mode name (one of the six canonical values)
- The accepted `claim_id` or `artifact_path` value, if the mode requires one
- A rejection reason when input validation fails, before any cargo or xtask
  command executes

## Non-Contract Boundaries

This contract does not extend claim authority, modify
`validation/claims.toml`, change claim statuses, produce or validate evidence
manifests or producer artifacts, or broaden the set of validated claims. The
six modes and their input requirements are the same set already implemented by
`tidefs-xtask`; this document makes the dispatch contract explicit without
changing validation behaviour.

## References

- `docs/CLAIMS_GATE_POLICY.md` — claims gate authority and validation tier
  evidence map
- `docs/CLAIM_REGISTRY.md` — generated claim registry
- `validation/claims.toml` — claim registry authority source
- `xtask/tidefs-xtask/src/claims.rs` — xtask claim validation implementation

# Dependency Advisory CI

The `Dependency Advisory` workflow ([.github/workflows/dependency-advisory.yml](../.github/workflows/dependency-advisory.yml))
runs `cargo deny check advisories` against the RustSec advisory database to detect
dependency security drift and yanked crate usage. It is a validation-only gate:
it reports findings but does not update `Cargo.lock`, bump dependency versions,
or change dependency resolution.

## Triggers

- **Pull requests** that touch dependency policy or lockfile inputs:
  `deny.toml`, `Cargo.lock`, `Cargo.toml`, `crates/*/Cargo.toml`, or the
  workflow file itself.
- **Manual dispatch** (`workflow_dispatch`) for ad-hoc drift checks against any
  branch.

The workflow respects the draft-PR skip convention and uses the
`TIDEFS_SELF_HOSTED_READY` repository variable gate.

## Policy

Advisory severity classification lives in `deny.toml` under the `[advisories]`
section:

- `yanked` controls whether yanked crate versions are denied, warned, or
  allowed. The current default is `"warn"`.
- `unmaintained` controls the response to unmaintained-crate advisories.
- `ignore` lists specific advisory ids that are explicitly allowed despite
  the general policy.

Any change to the `[advisories]` policy is a dependency-governance decision.
Dependency remediation (version bumps, replacement crates, lockfile updates)
must be done in a separate, focused pull request; this workflow does not
remediate.

## Output

The workflow produces a step-summary table enumerating each advisory finding
with:

- Package name
- Advisory id (linked to the RustSec advisory)
- Severity classification from the RustSec database
- Whether the finding is blocking (error) or a warning under the current
  `deny.toml` policy

The uploaded 7-day artifact includes `advisories-report.json`, the canonical
JSON report consumed by the summary formatter. Raw stdout and stderr captures
(`advisories.json` and `advisories-stderr.txt`) are included as well because
cargo-deny versions may write JSON diagnostics to either stream.

## Relationship to Other CI Lanes

- **Dependency Advisory** (this lane): RustSec/yanked drift detection only.
- **License gate** (future): `cargo deny check licenses` for allowlist
  enforcement; does not exist yet.
- **Secret Policy**: Scans repository and workflow surfaces for secret leaks;
  unrelated to dependency metadata.
- **Rust Fast / Focused Rust**: Build and test lanes; they use the existing
  `Cargo.lock` and do not evaluate advisory state.

## Remediation Workflow

1. The advisory gate flags a finding in a PR or manual dispatch.
2. An operator or Codex worker creates a separate GitHub issue scoped to the
   specific advisory (e.g., "bump `crate-x` for RUSTSEC-YYYY-XXXX").
3. That issue follows the normal TideFS PR workflow, including its own
   validation and review.
4. After the remediation PR lands, the advisory gate re-runs clean on the
   updated branch.

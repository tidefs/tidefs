# Actionlint CI

The `Actionlint` workflow ([.github/workflows/actionlint.yml](../.github/workflows/actionlint.yml))
runs [actionlint](https://github.com/rhysd/actionlint) against every GitHub
Actions workflow file in `.github/workflows/`. It catches syntax errors,
expression mistakes, invalid runner labels, and shell script issues before
a malformed job reaches the self-hosted runner fleet.

## Triggers

- **Push to `master`** when workflow files or `.github/actionlint.yaml` change.
- **Pull requests** that touch `.github/workflows/**` or
  `.github/actionlint.yaml`.
- **Manual dispatch** (`workflow_dispatch`) for ad-hoc lint runs against any
  branch.

The workflow respects the draft-PR skip convention and the
`TIDEFS_SELF_HOSTED_READY` repository variable gate.

## Configuration

The workflow uses `.github/actionlint.yaml` as its actionlint configuration
source. The current configuration declares the valid self-hosted runner labels:

```yaml
self-hosted-runner:
  labels:
    - tidefs
    - nix
    - kvm
    - fuse
    - ublk
    - rdma
    - kernel
    - xfstests
```

If a workflow references a runner label that is not listed here, actionlint
reports an error.

## What It Checks

- **Syntax**: malformed YAML, missing keys, duplicate keys.
- **Expressions**: invalid `${{ }}` expressions, undefined contexts, type
  mismatches.
- **Runner labels**: labels in `runs-on` that are not declared in
  `.github/actionlint.yaml`.
- **Shell scripts**: shellcheck warnings and errors in inline `run:` scripts
  (requires `shellcheck` on the runner path).

## Output

The workflow writes a step-summary section for each run, containing:

- The actionlint version (via `actionlint -version`).
- The full actionlint report (stdout + stderr).

No large artifacts are uploaded. The summary is visible in the GitHub Actions
run page under the "Run actionlint" step.

## Interpreting Results

- **Exit 0**: no issues found.
- **Exit non-zero**: actionlint found at least one issue. The step summary
  lists each finding with file, line, and message. Fix the reported issues,
  push, and re-run.

## Relationship to Other CI Lanes

- **Secret Policy**: scans repository and workflow surfaces for secret leaks;
  does not check workflow correctness.
- **Dependency Advisory / Dependency License**: crate-level policy gates;
  unrelated to workflow syntax.
- **Rust Fast / Nix Checks**: build and test lanes; they use existing
  workflows and do not evaluate workflow correctness.

This lane is a fast (under 5 minutes), pre-merge correctness gate. It does
not run tests, build code, or validate runtime behavior.

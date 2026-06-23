# Secret Policy CI Contract

Sourced from inspection of `.github/workflows/secret-policy.yml`,
`xtask/tidefs-xtask/src/policy.rs`, `xtask/tidefs-xtask/src/main.rs`,
`docs/GITHUB_CI.md`, and `AGENTS.md`. This document is a statement of
the observed contract; it does not alter enforcement, scanning, or any
source, workflow, or secret material.

## GitHub Secret Boundary

GitHub is not a TideFS secret store. No TideFS repository secrets,
organization secrets, environment secrets, GitHub deploy keys, Actions
`secrets.*` expressions, runner registration tokens, or committed
encrypted secret payloads are configured or committed by TideFS work.
Secrets live only in host-local or operator-owned storage outside
GitHub and outside this repository. Public key and secret names may be
documented; secret values and wrapped material must not appear in the
repository.

CI uses repository variables such as `TIDEFS_SELF_HOSTED_READY` for
scheduling gates only. Repository variables are not secret material.

## Workflow Triggers

| Trigger | Details |
|---|---|
| `push` | `branches: [master]` |
| `pull_request` | `branches: [master]`, types `opened`, `synchronize`, `reopened`, `ready_for_review` |
| `workflow_dispatch` | Manual dispatch; no inputs defined |

Push-triggered and pull-request jobs are gated by the repository
variable `TIDEFS_SELF_HOSTED_READY == '1'`. `workflow_dispatch` ignores
this gate.

Draft pull requests are skipped. Only `ready_for_review` (and other
listed PR events against ready PRs) trigger the job.

## Path Filters (Pull Request)

The job runs on a pull request only when at least one changed file
matches these globs:

```
.github/workflows/**
docs/GITHUB_CI.md
AGENTS.md
xtask/tidefs-xtask/**
Cargo.toml
Cargo.lock
flake.nix
flake.lock
```

Push and `workflow_dispatch` events are not path-filtered.

## Runner Labels

```
runs-on: [self-hosted, linux, x64, tidefs, nix]
```

No GitHub-hosted runner labels are used.

## Permissions And Concurrency

- `permissions: contents: read` (no write access).
- Concurrency group: `${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}`.
- `cancel-in-progress: true` so newer runs for the same ref or PR
  cancel older queued or running copies.

## Job Steps

The single job `no-github-secrets` runs with `timeout-minutes: 10` and
three substantive steps:

1. **Checkout** — `actions/checkout@v6`.
2. **Exercise seeded violation fixtures** — runs the xtask scanner in
   fixture-only mode so a scanner regression that stops detecting
   violations will fail the job even when no real violation exists:
   ```
   nix develop .#ci --command bash -c \
     'cargo run -p tidefs-xtask -- check-secret-policy --seeded-violation-fixtures'
   ```
3. **Scan for forbidden GitHub secret surfaces** — the actual
   repository scan:
   ```
   nix develop .#ci --command bash -c \
     'cargo run -p tidefs-xtask -- check-secret-policy'
   ```

A final `if: always()` step cleans the per-run `$CARGO_TARGET_DIR`.

## Scanner: `tidefs-xtask check-secret-policy`

### Scan Paths

The scanner reads these relative paths from the workspace root:

```
.github/workflows/
docs/GITHUB_CI.md
AGENTS.md
```

Only `.yml` and `.yaml` files are processed under `.github/workflows/`.

### Violation Classes

Each matched line is classified into one of four categories:

| Class | What it detects |
|---|---|
| `secrets-context` | `${{ secrets.X }}` or bare `secrets.X` expressions |
| `deploy-key` | `deploy_key`, `deploy-key`, or `deploy key` (case-insensitive) |
| `runner-token` | `registration-token`, `registration_token`, `registration token`, or `RUNNER_TOKEN` |
| `encrypted-blob` | `encrypted secret`, `gpg --encrypt`/`--decrypt`, `age --encrypt`/`--decrypt`, `openssl enc`/`rsautl`, `committed encrypted`, or `AGE-SECRET-KEY-1` |

### Allowlist

Specific lines in policy documents are exempt so that educational
mentions of the boundary do not trigger false positives:

- `docs/GITHUB_CI.md`: lines that mention `Do not use GitHub deploy keys`,
  `` `secrets.*` workflow expressions ``, `Secrets such as runner registration tokens`,
  or `encrypted secret payloads`.
- `AGENTS.md`: lines that mention `` `secrets.*` ``, `deploy keys`,
  `runner registration tokens`, `encrypted secret payloads`, or `encrypted secret blobs`.
- `.github/workflows/tidefs-codex-nexus-relay.yml`: lines that reference
  the host-local `NEXUS_SECRET_FILE` or `/etc/tidefs-codex-nexus/webhook-secret`.

Host-local secret file paths under `/etc/`, `/root/`, or `/var/lib/`
are also allowed regardless of which file they appear in.

### Seeded Violation Fixtures

Four in-memory fixtures (keyed against the conceptual path
`.github/workflows/seeded-secret-policy-fixture.yml`) exercise each
violation class:

1. `${{ secrets.TIDEFS_SEEDED_TOKEN }}` → `secrets-context`
2. `deploy-key: inert-public-fixture` → `deploy-key`
3. `RUNNER_TOKEN: inert-public-fixture` → `runner-token`
4. `# Store the encrypted secret in GitHub for recovery` → `encrypted-blob`

Each fixture must classify correctly; a mismatch fails the step. The
fixture file does not exist on disk.

### Output

- No violations found: prints `secret-policy ok`, exits 0.
- Violations found: prints one line per violation in the form
  `path:line: forbidden GitHub secret surface (class)` (the source-line
  snippet is **not** included, so the report does not leak the
  triggering material), exits 1.
- Seeded fixture step passes: prints `secret-policy seeded violation fixtures ok`, exits 0.
- Seeded fixture step fails: prints the mismatch, exits 1.

## Evidence Limits

Secret Policy passing is a secret-boundary gate only. It is **not**
dependency, license, runtime, release-candidate, or functional
correctness validation. A passing run means:

- No forbidden GitHub secret surface was detected in the scanned files.
- The scanner's violation classifiers still detect the seeded fixtures.

It does **not** mean the repository is free of non-GitHub secret
material, that dependencies are correctly licensed, that any code
compiles or passes tests, or that the product is ready for release.

## Consistency Notes

At inspection time (2026-06-23):

- `docs/GITHUB_CI.md` describes the secret boundary, the
  self-hosted-only runner policy, and the path-filtered PR scope in
  terms consistent with the workflow YAML and scanner source.
- `AGENTS.md` restates the same boundary with a matching list of
  forbidden surfaces.
- The scanner's allowlist covers every educational boundary mention
  found in `docs/GITHUB_CI.md` and `AGENTS.md`.
- The xtask `check-secret-policy` subcommand and its
  `--seeded-violation-fixtures` flag are wired in `main.rs` and match
  the workflow invocation.
- No mismatch between `docs/GITHUB_CI.md`, `AGENTS.md`, the workflow
  YAML, and scanner behaviour was observed.

# Contributing to TideFS

TideFS is pre-alpha filesystem and storage work. Keep contributions bounded,
reviewable, and honest about behavior observed through real product carriers.

## Read Before Changing The Repository

The complete baseline for ordinary work is:

1. `README.md` — product contract and current development direction;
2. `AGENTS.md` — repository development rules; and
3. `CONTRIBUTING.md` — this contribution path.

Load specialized references only when the touched surface needs them:

- tests: `docs/TEST_SIGNAL_POLICY.md`;
- CI, workflows, runners, or secrets: `docs/GITHUB_CI.md`;
- licensing, provenance, or imported code: `docs/LICENSING.md`;
- durable review debt: `docs/REVIEW_TODO_POLICY.md` and
  `docs/REVIEW_TODO_REGISTER.md`;
- unreleased compatibility or migration behavior:
  `docs/UNRELEASED_AUTHORITY_POLICY.md`; and
- control formats or JSON: `docs/CONTROL_FORMAT_AND_JSON_POLICY.md`.

Use issue-linked architecture or operator references only when the change
touches that subsystem. A document's existence does not make it required
reading or current product authority.

## Development Environment

Prefer the repository CI shell and keep Cargo output outside the repository:

```sh
export CARGO_TARGET_DIR=/tmp/tidefs-target
nix develop .#ci
```

Use `nix develop` when the selected runtime check needs the broader tools from
the default shell. A manual environment must match `rust-toolchain.toml` and
provide the native dependencies required by the focused check. Keep `.envrc`,
local configuration, build output, and runtime artifacts out of commits unless
the issue explicitly changes repository policy.

## Ordinary Definition Of Done

An ordinary TideFS product pull request is complete when all five conditions
hold:

1. It delivers one named observable carrier or failure behavior.
2. It changes the actual carrier path, not only a model, type, parser, fixture,
   or harness.
3. The smallest meaningful outer-boundary test for that behavior passes.
4. Focused touched-package build and static checks plus `git diff --check`
   pass.
5. The pull request gives a short residual product-risk statement.

Ordinary work does not require:

- a claim ID or evidence class;
- a committed evidence manifest or runtime receipt;
- a generated claim, documentation, or authority register refresh;
- a release-readiness or publication verdict;
- an unrelated whole-workspace, kernel, RDMA, xfstests, distributed, or
  release-candidate suite;
- a repeated issue-body gate scan; or
- comments that restate unchanged blockers.

Additional publication or assurance work belongs only to an actual tag,
release candidate, externally consumed compatibility or support statement, or
the security or legal boundary that requires it.

Choose the narrowest commands that prove the acceptance checks. Substitute the
actual package and test filter in focused commands such as:

```sh
cargo check -p PACKAGE --locked
cargo test -p PACKAGE --locked TEST_FILTER
cargo fmt --check
git diff --check
```

Documentation-only changes normally need `git diff --check` and resolution of
every edited link and path. A cleanup change must name the waste removed and
preserve the nearest carrier behavior; deletion volume alone is not proof.

A validation-only change is admissible only when it reproduces a current
product defect, creates the acceptance test for an active product slice,
repairs a test that hides a real failure, or removes low-signal validation
machinery. It must name the product risk and current consumer; test-count
growth is not an outcome.

## Issues, Commits, And Pull Requests

Start implementation from an issue that states one observable outcome, three
to five acceptance checks, exact nonempty file paths, and focused test
commands. Directories, globs, and path prefixes are not prepared write sets.
Stay within that write set or rescope the issue before expanding the patch.

Keep each commit scoped and bisectable, with one coherent reason and an
imperative subject. Do not use merge commits for normal TideFS work. Integrate
through a linear method.

The pull request must link its issue and state the outcome, focused acceptance
and validation evidence, actual versus expected touched paths, and residual
risk. Do not turn its body into a second policy checklist or status ledger.

## Secrets

GitHub and this public repository are not TideFS secret stores. Do not commit
credentials, private keys, tokens, secret values, or encrypted secret payloads,
and do not configure them as GitHub repository, organization, or environment
secrets. Keep TideFS secrets only in host-local or operator-owned storage
outside GitHub and outside this repository.

## Licensing And Provenance

TideFS uses `GPL-2.0-only WITH Linux-syscall-note`. Preserve workspace package
metadata, first-line Rust SPDX headers, Linux-kernel-specific notices, and the
provenance and licenses of vendored or imported code. Do not rewrite third-party
notices to the TideFS license. Read `docs/LICENSING.md` before adding or
modifying imported, vendored, generated, or license-boundary material.

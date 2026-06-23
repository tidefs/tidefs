# Contributing to TideFS

TideFS is pre-alpha filesystem and storage work. Keep contributions small,
traceable, and honest about what the current implementation proves. This guide
points to the policy docs that own the details instead of duplicating them.

## Reading Order

Start with these files before changing behavior or documentation:

1. `README.md`
2. `AGENTS.md`
3. `docs/ARCHITECTURE.md`
4. `docs/LICENSING.md`
5. `docs/GITHUB_CI.md`
6. `docs/TEST_SIGNAL_POLICY.md`
7. `docs/REVIEW_TODO_POLICY.md`
8. `docs/REVIEW_TODO_REGISTER.md`
9. `docs/INDEX.md`

The review register is the durable debt map. The documentation index names
additional design docs and explains that a listed document is not automatically
current authority.

## Development Environment

Prefer the repository flake. The CI shell is the closest local shape to the
standing Rust workflows:

```sh
export CARGO_TARGET_DIR=/tmp/tidefs-target
nix develop .#ci
```

Use the default shell when you need the broader runtime tooling listed by the
flake shell hook:

```sh
nix develop
```

If you use direnv, point your local `.envrc` at the same shell and keep local
environment files out of commits unless a GitHub issue explicitly asks for
repository policy changes. Put this in `.envrc`:

```text
use flake .#ci
```

Then approve it locally:

```sh
direnv allow
```

Manual environments must match `rust-toolchain.toml` and provide the native
tools used by the CI shell, including `bash`, `coreutils`, `jq`, `pkg-config`,
`fuse3`, and `rdma-core`. Runtime lanes may also require KVM, QEMU, FUSE,
ublk, loop devices, xfstests, and RDMA userspace tools; use the self-hosted
GitHub Actions lanes in `docs/GITHUB_CI.md` for those validations.

Always keep build output outside the repository tree.

## Build and Test

Pick the narrowest command that proves the issue acceptance criteria. Cargo
workspace commands should be locked and crate-scoped whenever possible:

```sh
cargo check --workspace --locked
cargo test -p tidefs-xtask --locked
cargo fmt --check
git diff --check
```

The standing `Rust Fast` workflow checks workspace metadata, selected smoke
crates, and a transport smoke test through the `.#ci` shell. Its local shape is:

```sh
nix develop .#ci --command cargo metadata --locked --format-version 1 --no-deps
nix develop .#ci --command ./scripts/ci-test-runner.sh \
  --crates tidefs-xtask,tidefs-extent-map \
  --json ci-test-summary.json
```

When a PR needs focused crate validation beyond the standing smoke set, dispatch
`Focused Rust` against the feature branch:

```sh
branch="$(git branch --show-current)"
gh workflow run "Focused Rust" --ref "$branch" -f crates=tidefs-xtask -f cargo_test_args=''
```

For docs-only changes, `docs/GITHUB_CI.md` explains that standing Rust and Nix
PR checks are path-filtered out. Record `git diff --check`, manual link/command
review, and any explicitly dispatched workflow run in the PR body.

## Commit Style

Use Linux-style hygiene:

- one coherent reason per commit;
- imperative, scoped subject lines;
- small, bisectable diffs;
- no merge commits for normal TideFS work;
- no test-only commits;
- no product claims beyond the evidence in the PR.

If a change updates tests, follow `docs/TEST_SIGNAL_POLICY.md`: prefer product
or invariant signal over marker, fixture, or test-count churn.

## Pull Request Workflow

Start from a GitHub issue with behavior, acceptance criteria, expected write
set, and validation tier. Use `docs/GITHUB_PR_DEVELOPMENT.md` as the authority
for branch, worktree, PR, validation, and multi-Codex coordination policy.

The normal Codex branch shape is:

```text
codexN/issue-<number>-<short-slug>
```

The matching worktree shape is:

```text
/root/tidefs-worktrees/codexN/issue-<number>-<short-slug>
```

On the managed Codex host, publish branches only through
`/root/ai/bin/git-push-approve` and `/root/ai/bin/git-push-guard`. Push the
branch before source edits so ownership is visible, then open a draft PR after
the first scoped commit.

PR bodies should link the issue, summarize the behavior or doc boundary that
changed, list validation commands and GitHub Actions run URLs/artifacts, and
name residual risk. Keep the source issue open while the PR is draft or
unmerged. Integration must use a linear method, never a merge commit.

## Debt and Review Markers

Do not add anonymous `TODO`, `FIXME`, `HACK`, "later", or "continuation"
markers. Durable debt belongs in `docs/REVIEW_TODO_REGISTER.md` with a stable
`TFR-NNN` id. Inline comments may only point to a register item, for example:

```text
Review debt TFR-005: timestamp authority remains split.
```

Address review feedback directly when the fix is in scope. If the comment
exposes real follow-up work, register it with a `TFR-NNN` entry or a focused
GitHub issue instead of leaving an untracked marker.

## Licensing and Provenance

TideFS uses `GPL-2.0-only WITH Linux-syscall-note`. Preserve the Linux-style
license model, first-line Rust SPDX headers, package metadata, and third-party
notices described in `docs/LICENSING.md`.

Do not rewrite vendored or imported third-party notices to the TideFS project
license. New vendored or imported material must carry clear provenance and
must fit the repository license policy before it is committed.

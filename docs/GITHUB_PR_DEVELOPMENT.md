# GitHub PR Development Policy

TideFS foreground development uses GitHub issues and pull requests for all
source changes. This policy supersedes direct implementation on the root
`master` checkout for Codex-authored work.

## Required Flow

- Start from a GitHub issue in `tidefs/tidefs` with acceptance criteria and an
  expected write set.
- Create a dedicated branch from `origin/master` named
  `codexN/issue-<number>-<short-slug>`.
- Create a dedicated worktree at
  `/root/tidefs-worktrees/codexN/issue-<number>-<short-slug>`.
- Push the branch before source edits and open a draft PR after the first
  scoped commit.
- On this host, publish Codex-authored branches through
  `/root/ai/bin/git-push-approve` plus `/root/ai/bin/git-push-guard`. Do not
  bypass a blocked guarded push.
- Keep commits focused and bisectable. Do not make test-only commits or merge
  commits for normal work.
- Push after each meaningful commit or checkpoint so other Codex sessions can
  see current ownership and progress.
- PRs are autonomous integration gates, not human handoff points. The owning
  Codex reviews each PR against the issue acceptance criteria, repo docs,
  product requirements, touched-code behavior, validation evidence, active
  write sets, and CI status.
- Merge only after the branch is rebased onto `origin/master`, active PR write
  sets do not conflict, validation evidence matches the issue scope, and the
  review finds no unresolved requirement or product-claim gap.
- Use a linear merge method, never a merge commit. After merge, sync affected
  worktrees, update or close the issue, and delete the local and remote feature
  branch unless a documented follow-up needs it preserved.

## Multi-Codex Rules

- Each Codex must use its own `codexN` identity, branch, worktree, Cargo target
  directory, and private status file under `/root/ai/state/tidefs/codexN/`.
- Do not overlap another Codex's write set unless the PR or issue records an
  explicit handoff.
- If work is broad enough for multiple Codexes, split it into separate GitHub
  issues before editing.
- Existing dirty root-checkout changes are recovery material, not a workspace
  for new Codex work.

## Validation Cadence

- Validate after substantial implementation, not after every tiny edit.
- A substantial slice is either multiple coherent changes or one root-cause fix
  expected to affect several observations.
- Use self-hosted GitHub Actions for focused touched-package tests and
  `git diff --check` for normal PRs. When the standing `Rust Fast` smoke set
  does not cover the touched crates, dispatch the manual `Focused Rust`
  workflow against the feature branch with the issue-specific crate list and
  any required cargo test filter arguments.
- Use runtime rows only after mounted/FUSE/kernel behavior has actually changed.
- Reserve broad xfstests, RDMA, kernel, and release-candidate runs for PR or
  milestone gates.

## Disk and Artifact Hygiene

- Check disk headroom at start, before heavy validation, and after large
  artifact creation:

```sh
df -h /root /tmp /nix/store 2>/dev/null || true
du -sh /root/ai/tmp /root/ai/state /root/tidefs-worktrees 2>/dev/null || true
```

- Keep build output outside the repo, for example
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-codexN`.
- Keep validation output under
  `/root/ai/tmp/tidefs-validation/<issue>-<timestamp>/`.
- If `/root` has less than 20 percent free or less than 50 GiB free, stop
  starting heavy validation and clean only owned or clearly stale temp
  artifacts.

## Current Work Selection Note

The active FUSE/xfstests top VFS burn-down may be owned by another Codex.
Codex0 and helpers should prefer non-overlapping work such as storage
durability, kernel pool authority, operator UAPI, device lifecycle, snapshots,
transport/cluster authority, and coordination tooling unless explicitly taking
over a VFS issue.

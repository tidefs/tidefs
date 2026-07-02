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

## Linear Merge Enforcement

- The `tidefs/tidefs` repository merge-button configuration must keep
  `allow_merge_commit` disabled and at least one linear method,
  `allow_squash_merge` or `allow_rebase_merge`, enabled. Branch protection or
  repository rulesets may also require linear history when available, but they
  do not replace disabling merge commits in the repository merge settings.
- Integration workers must map the selected integration strategy to
  `gh pr merge --squash` or `gh pr merge --rebase`. Do not use
  `gh pr merge --merge` or REST `merge_method=merge` for PRs targeting
  `master`.
- Before treating a PR as merge-ready, capture a read-only repository merge
  configuration snapshot:

```sh
gh api repos/tidefs/tidefs \
  --jq '{default_branch,allow_merge_commit,allow_squash_merge,allow_rebase_merge}'
```

  The expected `master` integration state is `allow_merge_commit: false` with
  `allow_squash_merge` or `allow_rebase_merge` still true.
- After a PR closed event reports a merge into `master`, audit the recorded
  merge SHA before considering integration complete:

```sh
pr=<number>
merge_sha="$(gh api "repos/tidefs/tidefs/pulls/$pr" --jq '.merge_commit_sha')"
gh api "repos/tidefs/tidefs/git/commits/$merge_sha" \
  --jq '{sha:.sha,parent_count:(.parents | length),parents:[.parents[].sha]}'
```

  A linear squash or rebase integration reports `parent_count: 1`. A closed PR
  with any other parent count is a process regression: record the event in a
  GitHub issue or PR triage note and do not mark integration complete until the
  repository setting, merge command, or integration tooling has been repaired.
  Leave already-published `master` history intact unless the operator
  explicitly authorizes a separate rewrite.
- PR #420 is the historical regression that motivated this guard: its merge
  commit `3b6f60b2ce7d64faec1cc972f8b3b39334a71e7b` has two parents
  (`217e9b0f7deba985a519c1199d8ccefb822652fc` and
  `0c3cceecce81424176020d7e33deee1c7676b4d3`). It remains published history
  and must not be rewritten as part of process enforcement work.

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

This workflow is process authority, not a topical priority list. Work
selection comes from live GitHub issues, pull requests, repository docs, and
the current Codex Nexus view; choose only non-overlapping prepared work unless
an existing owner explicitly hands off a slice.

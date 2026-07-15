# GitHub Contribution Boundary

TideFS uses GitHub issues and pull requests for reviewable source changes.
This repository keeps only the public, repo-local boundary here so it does not
duplicate managed-host Codex workflow policy.

## Public Contribution Path

- Start from a focused issue or pull request whose scope, validation evidence,
  and touched files are clear.
- Keep commits focused and bisectable. Do not use merge commits for normal
  TideFS work.
- Pick the narrowest validation that proves the change. Use
  `CONTRIBUTING.md` for local build and test examples and `docs/GITHUB_CI.md`
  for the self-hosted GitHub Actions lanes.
- Keep capability and release-readiness wording behind the claims gate and
  current evidence.

## Managed Hosts

Managed Codex hosts may impose local branch, worktree, push, artifact, and
multi-worker rules for their own workers. Those host-local rules are process
constraints, not public TideFS product policy, and they must not be duplicated
here. On this host, managed-worker details live outside the repository under
`/root/ai/docs/projects/tidefs/workflows/github-pr-development.md`.

Live issue and pull-request state plus repo docs remain the active work source
of truth. Do not use stale topical notes, old coordination packets, or
historical status files to choose current work.

# TideFS Agent Contract

TideFS work is foreground Codex work unless the operator explicitly says
otherwise. Do not start or depend on parked Nexus/Factory automation.

## Development Rules

- Use GitHub issues and pull requests for Codex-authored source changes. Do
  not implement directly on the root `master` checkout. Create a dedicated
  issue branch from `origin/master`, a dedicated worktree under
  `/root/tidefs-worktrees/codexN/`, push the branch before edits, and open a
  draft PR after the first scoped commit.
- Keep build output outside the repository, normally with
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-codexN`.
- Check disk headroom before work, before heavy validation, and after creating
  large artifacts. Stop heavy validation when `/root` has less than 20 percent
  free or less than 50 GiB free.
- Validate after substantial implementation, not after every tiny edit. Use
  focused checks for ordinary PRs and reserve broad xfstests/RDMA/kernel runs
  for PR or milestone gates.
- Do not store TideFS secrets in GitHub. This includes repository secrets,
  organization secrets, environment secrets, deploy keys, TLS private keys,
  runner registration tokens, API tokens, and encrypted secret blobs intended
  for GitHub-hosted recovery. Secrets live only in host-local or operator-owned
  secret storage outside GitHub.
- Do not commit secrets or encrypted secret payloads to this repository.
  Public keys and secret names may be documented; secret values and wrapped
  secret material must stay out of the tree and out of Git history.
- Do not add anonymous `TODO`, `FIXME`, `HACK`, or "continuation" debt. Record
  debt in `docs/REVIEW_TODO_REGISTER.md`; inline comments may only point to a
  register id such as `Review debt TFR-005`.
- Preserve the GPL-2.0-only WITH Linux-syscall-note licensing model.
- See `docs/GITHUB_PR_DEVELOPMENT.md` for the full issue, worktree, PR,
  validation, and multi-Codex policy.

## Product Bar

TideFS is expected to become a serious filesystem/storage stack, not a toy
preview. Claims must stay behind implementation reality. In particular, do not
claim OpenZFS/Ceph-class status until the register items covering storage
authority, recovery, capacity, snapshots, device lifecycle, kernel residency,
and distributed behavior are actually closed.

## Commit Style

Use kernel-style hygiene: small subjects, imperative mood, no mixed-purpose
lumps, no test-only commits, and no merge commits for normal TideFS work.

# User Requirements

## Original ambition

Build TideFS as a human-understandable, safe, production-grade storage system that can eventually beat the combined practical value of OpenZFS and Ceph.

## Non-negotiable design requirements captured so far

- Human-readable terminology must be the primary project surface.
- Stable internal locators may remain only as stable internal identifiers.
- Rust source must avoid unsafe code unless a future, separately justified boundary requires it.
- TideFS uses the Linux-style `GPL-2.0-only WITH Linux-syscall-note` model.
- The design must not require production fsck after normal crashes.
- Reopen after a normal crash must select a previous committed root, a new committed root, or report explicit integrity/media failure.
- Source behavior, live issue state, current repo docs, and git history are the review inputs.
- Durable debt belongs in `docs/REVIEW_TODO_REGISTER.md`; anonymous inline debt markers are not allowed.
- Work must land as clean, scoped, bisectable commits on `master`.
- Whole-repo authority review comes before narrow hotfix-style behavior changes.
- TideFS must preserve explicit local and clustered runtime modes for both
  POSIX filesystem access and block-volume export. Local modes are product
  modes, not temporary cluster bring-up shortcuts, and must not place cluster
  lock, lease, or membership services on local hot paths without proof of no
  local-mode regression.

## Current judgement

The original ambition is not met yet. TideFS is a pre-alpha filesystem and
storage stack with some real local storage pieces, but it still has broad
authority debt around workspace/package ownership, dataset-scoped inode
identity, timestamp/version semantics, capacity, writeback/fsync/mmap,
kernel residency, snapshots, device lifecycle, and distributed behavior.

The current blocker list is `docs/REVIEW_TODO_REGISTER.md`; the current review
snapshot is `docs/WHOLE_REPO_REVIEW.md`.

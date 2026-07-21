# TideFS Agent Contract

TideFS work is issue-first and integrates through GitHub pull requests. The
`README.md` Product Contract is the sole product-shape authority; do not claim
support beyond behavior observed through a real product carrier.

## Read Before Changing The Repository

The complete baseline for ordinary work is:

1. `README.md` — product contract and current development direction;
2. `AGENTS.md` — repository development rules; and
3. `CONTRIBUTING.md` — contribution path and ordinary definition of done.

Load specialized references from `CONTRIBUTING.md` only when the touched
surface requires them. Managed hosts may add local process and safety
constraints for their workers; those constraints do not expand the repository
baseline or public product policy.

## Ownership And Workspaces

- Start each implementation slice from a live GitHub issue with one
  observable outcome, three to five acceptance checks, exact nonempty file
  paths, and focused test commands. Directories, globs, and path prefixes are
  not prepared write sets.
- Check live issues, pull requests, branches, and worktrees for overlapping
  ownership. Stay within the issue's write set or rescope it before editing.
- Do not implement on the root `master` checkout. Use a dedicated issue branch
  from current `origin/master` and a dedicated worktree under
  `/root/tidefs-worktrees/codexN/`. On this host, publish the branch before
  edits through `/root/ai/bin/git-push-approve` and
  `/root/ai/bin/git-push-guard`; never bypass the guard. Open a draft pull
  request after the first scoped commit.

## Ordinary Completion

An ordinary product pull request is complete when it:

1. delivers one named observable carrier or failure behavior;
2. changes the actual carrier path, not only a model, type, parser, fixture, or
   harness;
3. passes the smallest meaningful outer-boundary test for that behavior;
4. passes focused touched-package build and static checks plus
   `git diff --check`; and
5. gives a short residual product-risk statement.

Do not add agent-only requirements for claim IDs, evidence classes, committed
manifests or receipts, generated-register refreshes, publication verdicts,
unrelated broad suites, repeated gate scans, or blocker restatements.

A validation-only change is admissible only when it reproduces a current
product defect, creates the acceptance test for an active product slice,
repairs a test that hides a real failure, or removes low-signal validation
machinery. It must name the product risk and current consumer; test-count
  growth is not an outcome. A test-only pull request must satisfy this
  exception.

## Validation And Safety

- Keep build output outside the repository, normally in
  `/root/ai/tmp/tidefs-target-codexN`.
- Check disk headroom before work, before heavy validation, and after creating
  large artifacts. Compare a heavy run's measured or conservatively estimated
  peak with available space. If it cannot fit while leaving enough space to
  abort and remove this task's own output, use a focused run or ask the
  operator; do not invent a fixed host threshold or delete another task's data.
- Use the narrowest checks that cover the changed risk. Reserve broad xfstests,
  RDMA, kernel, distributed, and release-candidate runs for relevant pull
  request or milestone gates.
- Never store TideFS secrets in GitHub or this repository. Keep credentials,
  private keys, tokens, secret values, and encrypted secret payloads only in
  host-local or operator-owned storage outside both.
- Preserve the `GPL-2.0-only WITH Linux-syscall-note` model. Read
  `docs/LICENSING.md` before touching imported, vendored, generated, or
  license-boundary material.

## Review And Integration

Keep commits scoped and bisectable, with imperative subjects and no
mixed-purpose changes. A pull request must link its issue and state its outcome,
focused check results, actual versus expected paths, and residual risk. Review
the diff against those inputs, owned paths, carrier behavior, and relevant CI.
Rebase onto current `origin/master`, resolve overlaps and failures, and
integrate with a linear method, never a merge commit. Then sync task-owned
affected worktrees, update the issue, and delete the feature branch.

## Automation Boundary

`tidefs-codex-nexus` is operator-controlled mechanics. It may launch managed
workers only under explicit operator authorization and must select work only
from live GitHub issue and pull-request state plus repository docs. Do not put
TideFS development policy into Nexus or infer permission to start or re-enable
it from repository readiness. Parked legacy Nexus and Factory automation
remain stopped.

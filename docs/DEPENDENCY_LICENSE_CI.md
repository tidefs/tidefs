# Dependency License CI Gate

The `Dependency License` workflow (`dependency-license.yml`) enforces the
accepted TideFS dependency license policy through `cargo-deny`. It runs on
TideFS self-hosted runners from the repo Nix CI development shell and does not
consume GitHub-hosted runner minutes or GitHub Actions secrets.

## Policy Authority

- `deny.toml` — the accepted license allowlist, multi-license clarifications
  (`ring`, `webpki`), and dependency rules.
- `docs/adr/0006-license-compliance-cargo-deny.md` — the architectural decision
  record that established `cargo-deny` as the canonical license-compliance
  tool.

## When It Runs

- Push to `master`.
- Pull request that touches dependency or license-policy files:
  `Cargo.toml`, `Cargo.lock`, `deny.toml`, `flake.nix`, `flake.lock`, the
  workflow itself, the ADR, or this doc.
- Manual dispatch through the GitHub Actions UI or `gh workflow run`.

Draft pull requests skip the check to avoid consuming self-hosted runner
capacity before the PR is ready for review.

## Gate Outcome

The gate passes only when `cargo deny check licenses` succeeds against the
repository `deny.toml`. A failure means one or more direct or transitive
dependencies carry a license outside the approved allowlist. The workflow
summary records the source ref, SHA, command, and pass/fail outcome.

## Manual Run

```sh
gh workflow run dependency-license.yml --ref <branch>
```

## License Allowlist Updates

To add or remove an accepted license, edit `deny.toml` and follow the ADR-0006
revision process. A dependency-license CI gate check that passes on the update
branch confirms the change does not allow unapproved licenses into the
workspace.

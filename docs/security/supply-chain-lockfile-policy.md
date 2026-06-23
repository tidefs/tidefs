# Supply-Chain Lockfile Policy

Last updated: 2026-05-23
Historical issue: Forgejo #6493

## Canonical Boundary

TideFS supply-chain reproducibility is enforced through committed lockfiles
for both Cargo (Rust) and Nix build inputs. Every release build must produce
the same dependency graph.

## Pinned Surfaces

| Surface | Lockfile | Packages | Verification |
|---|---|---|---|
| Rust dependencies | `Cargo.lock` | 452 crates | `cargo check --locked` |
| Nix build inputs | `flake.lock` | nixpkgs + rust-overlay | content-addressed via narHash |

### Cargo.lock

`Cargo.lock` is committed to the repository and tracked by git. It pins every
transitive Rust dependency to an exact version and checksum. The `--locked`
flag on every `cargo check`, `cargo build`, and `cargo test` invocation ensures
the lockfile is consistent with `Cargo.toml` manifest declarations.

### flake.lock

`flake.lock` is a Nix-generated lockfile that pins Nix flake inputs to exact
git revisions and content hashes (narHash). Two inputs are pinned:

- `nixpkgs` (NixOS/nixpkgs, `nixpkgs-unstable` branch): pinned to a specific
  revision with a NAR hash that covers the entire source tree.
- `rust-overlay` (oxalica/rust-overlay): follows the same nixpkgs revision and
  is independently content-addressed.

Nix builds that consume this flake produce identical derivations on any
machine with the same Nix version and system architecture.

## Verification

Verify Cargo lockfile integrity:

```sh
export CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target
cargo check -p tidefs-auth --locked
cargo check -p tidefs-encryption --locked
# Extend to --workspace for broader coverage:
cargo check --workspace --locked
```

Verify Nix flake lock integrity:

```sh
nix flake metadata --json   # confirm inputs match flake.lock
```

## Policy

- Both `Cargo.lock` and `flake.lock` must be committed alongside any
  `Cargo.toml` or `flake.nix` that changes dependencies.
- A dependency update PR must include `cargo check --workspace --locked`
  impractical in a single turn).
- Nix input updates (`nix flake update`) must include a successful
  `nix flake check` or a concrete `nix build` result.
- Broken lockfiles (where `--locked` fails) block merge. The fix is either
  regenerating the lockfile (`cargo update` or `nix flake lock --refresh`)
  with documented justification, or reverting the manifest change.
- Supply-chain compromise detection is through the content-addressed Nix
  model (narHash) and the Cargo registry checksums embedded in `Cargo.lock`.
  For deeper auditing, a future `cargo vet` integration would add
  human-reviewed trust policies; the committed lockfile with `--locked`
  enforcement is the current minimum supply-chain integrity gate.


- `cargo check -p tidefs-auth --locked`: PASS (2026-05-23, commit `origin/master`)
- `cargo check -p tidefs-encryption --locked`: PASS
- `Cargo.lock`: 4653 lines, 452 packages, tracked in git
- `flake.lock`: nixpkgs + rust-overlay pinned, tracked in git

## Relationship to Other Security Surfaces

Supply-chain integrity is a precondition for all other security surfaces:
if dependencies are not pinned, no cryptographic, transport, or storage
integrity claim is meaningful. This gate must be satisfied before any
release signoff.

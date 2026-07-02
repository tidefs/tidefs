# Security And Encryption Boundary Pointers

This file is intentionally only a concise pointer map. It is not a maintained
threat model, release checklist, product audit, or inventory of every security
claim in TideFS.

Current security wording must stay behind the source, claim registry, authority
docs, validation evidence, and live GitHub issues named below. When those
surfaces disagree, do not strengthen this file; fix the source authority or the
owning issue/PR instead.

## Authority Map

- Publishing-facing capability wording: `docs/CLAIMS_GATE_POLICY.md`,
  `validation/claims.toml`, and generated `docs/CLAIM_REGISTRY.md`.
- Mounted compression/encryption boundary:
  `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md` and
  `docs/TRANSFORM_PIPELINE_AUTHORITY.md`.
- Pool encryption secret handles and leases:
  `docs/security/pool-encryption-secret-handle-boundary.md` plus the active
  key-lifecycle work in issue #1823 / PR #2021.
- Transport security: `docs/security/transport-security-boundary.md`,
  `crates/tidefs-auth/src/session_security.rs`, and
  `crates/tidefs-transport/src/session/`.
- Operator authentication and authorization:
  `docs/security/operator-authz-boundary.md`,
  `docs/OPERATOR_UAPI_AUTHORITY.md`, and the active remote-authz work in
  issue #1801 / PR #1982.
- Digest placement and storage integrity: `docs/BLAKE3_USAGE_POLICY.md`,
  object-store integrity trailers, committed-root integrity code, and the
  current storage authority docs that consume those records.
- Unsafe-code provenance: `docs/UNSAFE_AUDIT.md`,
  `docs/security/kernel-unsafe-boundary-inventory.md`, issue #1077, and the
  focused unsafe-audit follow-ups such as #1158 and #1909.
- Supply-chain and CI security boundaries: `docs/GITHUB_CI.md`,
  `deny.toml`, lockfiles, dependency workflows, and workflow YAML.

## Current Non-Claims

- Lower object-store encryption helpers, key-handle types, or test coverage do
  not prove end-to-end mounted device-level encryption. Mounted transforms stay
  blocked until the mounted transform inventory has no blocked production
  raw-store bypass rows for the exact claimed scope.
- Key revocation, retirement, or destruction alone is not a secure erase,
  sanitization, decommissioning, or media-remanence proof. PR #2021 owns the
  narrow key-lifecycle/erase assessment boundary.
- Transport security is session-level. Per-message proof markers are not the
  TideFS transport-security model. Open transport/security bugs such as #1818
  and #1819 keep broader secret-bearing distributed receive/import wording
  blocked until source and validation prove the exact path.
- Root authentication and digest chains are integrity/tamper-detection
  boundaries. They are not pool key management, encrypted media proof, remote
  authorization, release readiness, or whole-product security proof.
- Operator privileged mutations are local-only unless the checked command
  admission table and the source-owned authorization/audit pipeline prove a
  specific remote path. PR #1982 owns the current remote authorization slice
  and does not make every CLI/API handler remote-capable by itself.
- The unsafe inventories document provenance and review status only. They do
  not validate product-wide kernel safety, release readiness, FFI correctness,
  or hardening by themselves.
- Supply-chain controls, pinned lockfiles, dependency CI, and advisory checks
  are build/review boundaries. They are not a statement that all dependencies,
  artifacts, or deployment paths are secure.

## Security Boundary Checklist

Before adding stronger security, encryption, authorization, transport,
unsafe-code, release, kernel, distributed, or successor/comparator wording:

1. Identify the source module, authority doc, claim id, and live issue/PR that
   own the exact scope.
2. Confirm the wording is allowed by `docs/CLAIMS_GATE_POLICY.md`.
3. Confirm the matching claim or product-admission gate in
   `validation/claims.toml` is validated for the same scope, or keep the text
   as a non-claim.
4. Route implementation gaps to focused GitHub issues rather than expanding
   this pointer file into a new roadmap or status document.

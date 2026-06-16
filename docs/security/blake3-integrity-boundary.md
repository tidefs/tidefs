# BLAKE3 Integrity Boundary

Maturity: **historical input** — imported release-train closeout note, not
current release evidence.

Authority classification: TFR-019 / GitHub issue #332 leaves this file as
historical input. [BLAKE3 Usage Policy](../BLAKE3_USAGE_POLICY.md) is the
current BLAKE3 placement policy. This document may inform review of residual
BLAKE3 overfit, but it must not be cited as proof of production checksum,
scrub repair, erasure-coded integrity, or tamper-proof committed-root behavior.

## Policy Authority

`docs/BLAKE3_USAGE_POLICY.md` is the binding policy for BLAKE3-256 usage in
TideFS. This document records an imported closeout snapshot: the intended
boundary was documented and residual overfit was tracked for separate cleanup.
Current conformance must be checked against live source and the claim registry.

## Historical BLAKE3 Usage Notes

The imported closeout treated the following surfaces as within the intended
policy boundary. These notes are review inputs, not current proof that every
surface has production-ready mounted behavior:

- `tidefs-local-object-store` — content-addressed object keys, IntegrityTrailerV2
  digests, segment checksum anchors, committed-root authentication
- `tidefs-scrub-core` — per-object integrity verification and scrub ledger
  digests
- `tidefs-encryption` — BLAKE3-based key derivation from passphrases (KDF mode),
  domain-separated context strings
- `tidefs-auth` — BLAKE3-based session key derivation in transport handshake

## Verification Engine Boundary (REL-SEC-004)

The imported closeout asserted that `tidefs-verification-engine` was the content
integrity verification authority and that scrub repair events
(`ScrubRepairEvent` in `tidefs-scrub-core`) carried an
`integrity_outcome: ObjectVerificationOutcome` field. Treat that as historical
review input. Do not use it as a current scrub/repair/rebuild claim without
source and claim-registry evidence.

## Residual Overfit (Tracked, Non-Owned)

The policy doc SS3 lists specific files with residual BLAKE3 overfit. These are
owned by the respective subsystem issues:

- `crates/tidefs-membership-live/src/types.rs` — ephemeral protocol message
  BLAKE3 digest (SS3.1)
- `crates/tidefs-node-drain/src/drain_state.rs` — DrainRequest blake3_digest
  field (SS3.1)
- Transport files listed in SS3.4 — duplicate integrity layers
- Additional items listed in SS3.2, SS3.3, SS3.5

Current pull requests must review new or changed BLAKE3 use against the current
policy, live source behavior, and the claims gate.

# BLAKE3 Integrity Boundary

Maturity: **integration-cleanup** — confirms the release-policy boundary
established by [BLAKE3 Usage Policy](../BLAKE3_USAGE_POLICY.md).

## Policy Authority

`docs/BLAKE3_USAGE_POLICY.md` is the binding design policy for BLAKE3-256 usage
in TideFS. This document records the release-train closeout: the boundary is
documented, the owned security crates conform, and residual non-owned overfit
is tracked for separate cleanup.

## Proper BLAKE3 Usage (Confirmed Conformant)

These crates use BLAKE3-256 only within the policy boundary (content addressing,
durable integrity trails, committed-root tamper detection, scrub verification,
erasure-coded shard integrity, transport-session boundary key derivation, and
transport epoch bridge state integrity):

- `tidefs-local-object-store` — content-addressed object keys, IntegrityTrailerV2
  digests, segment checksum anchors, committed-root authentication
- `tidefs-scrub-core` — per-object integrity verification, scrub ledger digests,
- `tidefs-encryption` — BLAKE3-based key derivation from passphrases (KDF mode),
  domain-separated context strings
- `tidefs-auth` — BLAKE3-based session key derivation in transport handshake

## Verification Engine Boundary (REL-SEC-004)

The `tidefs-verification-engine` crate is the content integrity verification
authority.  Scrub repair events (`ScrubRepairEvent` in `tidefs-scrub-core`)
now carry an `integrity_outcome: ObjectVerificationOutcome` field that ties
each repair event to a concrete content integrity verification result,
establishing the verification engine as the authority for scrub/repair/rebuild
verification outcomes without BLAKE3-as-generic-proof-marker language.

## Residual Overfit (Tracked, Non-Owned)

The policy doc SS3 lists specific files with residual BLAKE3 overfit outside the
release-train closeout scope of this ticket. These are owned by the respective
subsystem issues:

- `crates/tidefs-membership-live/src/types.rs` — ephemeral protocol message
  BLAKE3 digest (SS3.1)
- `crates/tidefs-node-drain/src/drain_state.rs` — DrainRequest blake3_digest
  field (SS3.1)
- Transport files listed in SS3.4 — duplicate integrity layers
- Additional items listed in SS3.2, SS3.3, SS3.5

These do not block release-train closeout; the policy establishes the boundary
and the publish guard prevents new message-local BLAKE3 from entering the tree.


residual non-owned overfit tracked per existing policy.

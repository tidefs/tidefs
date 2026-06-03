# Transport Security Boundary

Last updated: 2026-05-23
Issue: #6346 (REL-SEC-002)

## Canonical Boundary

TideFS transport security is **session-level**. Node authenticity and per-frame
integrity are owned by the session handshake and per-session cipher, not by
per-message cryptographic tokens.

## Session-Level Security Modules

| Module | Purpose |
|---|---|
| `secure_transport.rs` | HMAC-SHA256 + ChaCha20-Poly1305 per-frame after HELLO |
| `session_handshake.rs` | HELLO/Accept/Reject protocol version and feature negotiation |
| `session_cipher.rs` | Session key management and HKDF derivation |
| `tls.rs` | TLS transport carrier alternative |
| `session_rekey.rs` | Session rekey protocol |
| `crates/tidefs-auth/` | Shared `SessionSecurity` primitives |

## What Must Not Be at the Message Layer

Per-message BLAKE3 membership proofs, per-message MACs, and per-message auth
tags duplicate the session-level boundary and are not the TideFS model.
Fragmented frames already bypass per-message auth by design, making it
inherently incomplete.

BLAKE3 is reserved for content addressing, on-disk integrity (checksums,
committed-root hash chains), scrub/rebuild verification, and explicit
transport-security consolidation.

## Removed Surface (Issue #6346)

- `crates/tidefs-transport/src/auth_token.rs` (1095 lines): removed.
  Per-message BLAKE3-verified membership authorization (`MemberAuthToken`).
  Was never wired into the runtime path (`dispatch_with_auth` had zero
  external callers).
- `MessageDispatcher::dispatch_with_auth`, `set_auth_verifier`,
  `clear_auth_verifier`, `has_auth_verifier`: removed from
  `message_dispatch.rs`.
- `DispatchError::TokenVerificationFailed`: removed.

- `MemberAuthToken` struct, impl, `MembershipCodec`, and all 12 tests
  removed from `crates/tidefs-membership-types/src/lib.rs` (~246 lines).
- `blake3` dependency removed from `tidefs-membership-types/Cargo.toml`
  (only consumer was `MemberAuthToken`).
- Stale BLAKE3 envelope format doc comments in `message_dispatch.rs`
  corrected to CRC32C-verified format.
- `message_auth.rs` (zero-key/MAC bypass path): removed.


### Source Audit

| Check | Result |
|---|---|
| `MemberAuthToken` in all .rs files | None found |
| `auth_token.rs` file existence | Removed |
| `dispatch_with_auth` references | None found |
| `TokenVerificationFailed` references | None found |
| `message_auth.rs` (zero-key bypass) | Removed |
| Per-message MAC/auth in transport/src/ | None found |

### Session-Level Modules Present (line count)

| Module | Lines | Purpose |
|---|---|---|
| `secure_transport.rs` | 437 | HMAC-SHA256 + ChaCha20-Poly1305 per-frame |
| `session/handshake.rs` | 998 | HELLO/Accept/Reject with Ed25519 attestation |
| `session_cipher.rs` | 1192 | Session key management + HKDF derivation |
| `tls.rs` | 354 | TLS transport carrier alternative |
| `session_rekey.rs` | 1020 | Session rekey with state-digest verification |
| `tidefs-auth/src/lib.rs` | 95 | Shared SessionSecurity primitives |

### Cargo Verification

```
cargo check -p tidefs-transport --locked   # PASS (2026-05-23)
```

### BLAKE3 Remaining Uses (All Legitimate)

BLAKE3 remains in transport for content addressing, state digests, and key
derivation, all at the proper layer:

- Content/payload digests: `object_transfer.rs`, `messages.rs`, `message_batcher.rs`, `object_list.rs`
- State digests: `flow_control.rs`, `circuit_breaker.rs`, `dedup_filter.rs`, `peer_manager.rs`, `routing.rs`, `epoch_bridge.rs`
- Key derivation: `session/handshake.rs` (transcript KDF), `reconnect.rs` (resume token), `session_rekey.rs`
- These are content-integrity and state-verification uses, not per-message session-auth duplicates.

### A-Register Findings

- **A4 (BLAKE3 Overfit / Proof-Marker Pattern)**: Advanced. The per-message
  BLAKE3 auth surface (`MemberAuthToken`, `auth_token.rs`, `dispatch_with_auth`,
  `message_auth.rs`) is removed. BLAKE3 is limited to content addressing,
  state digests, and key derivation. The published guard prevents new instances
  from entering the tree.
- **A13 (Distributed Runtime Authority Split)**: Indirectly advanced. Removal
  of `MemberAuthToken` eliminates one overclaimed security marker from the
  distributed path. The canonical session-level boundary is declared in this
  document.

### Open Gap

closure. The source-level boundary is proven at T1 (cargo). The next step is
to run the two-node harness with transport session security enabled and

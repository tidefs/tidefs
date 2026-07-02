# Transport Security Boundary

TideFS transport security is session-level. Node authenticity and frame
confidentiality/integrity are owned by the session handshake, session-security
state, and per-session ciphers. Message-local proof markers are not part of the
current model.

## Source Owners

- `crates/tidefs-auth/src/session_security.rs` owns frame sealing/opening,
  plaintext-vs-encrypted flags, HMAC verification, AEAD opening, nonce
  tracking, and session-security statistics.
- `crates/tidefs-transport/src/session/mod.rs` owns per-session message
  sealing/opening hooks.
- `crates/tidefs-transport/src/session_cipher.rs` owns session cipher state,
  key derivation, sealing, and opening for transport session payloads.
- `crates/tidefs-transport/src/session/handshake.rs`,
  `crates/tidefs-transport/src/session_handshake.rs`, and
  `crates/tidefs-transport/src/transport.rs` own the handshake and
  `perform_handshake()` reachability.
- `crates/tidefs-transport/src/secure_transport.rs` owns the lower secure
  frame wrapper used by transport code.
- `crates/tidefs-transport/src/session_rekey.rs` owns rekey mechanics.
- `crates/tidefs-transport/src/tls.rs` owns the TLS carrier alternative.

## Boundary

- Transport authenticity and confidentiality must be proven at session setup
  and frame open/seal time.
- BLAKE3 may appear in transport for content digests, transcript/state
  digests, and key derivation where the source authority says so. It must not
  reappear as an independent per-message authorization token that bypasses the
  session-security boundary.
- Plaintext/local test paths are valid only when the session has not required
  ciphers. Once ciphers are required, encrypted-frame open failures must fail
  closed instead of falling back to the raw frame.
- Secret-bearing receive/import or distributed operator paths must prove
  authenticated confidentiality for the exact path, or avoid transmitting raw
  secret material.

## Non-Claims

- This document does not claim distributed product readiness, production
  transport hardening, RDMA security, cluster authorization, secret-bearing
  receive/import safety, or release readiness.
- Session-level primitives do not prove every caller requires ciphers before
  sending sensitive data. Issue #1818 owns encrypted-frame fail-closed
  behavior, and issue #1819 owns root-auth key handling over receive/import
  transport.
- Removing obsolete message-local token surfaces in git history does not by
  itself validate current runtime behavior. Current claims require source
  evidence and validation for the path being described.

## Review Rule

Any new transport-security wording must point at the exact source path and
claim scope. If the change is about a secret-bearing or remote privileged path,
review the corresponding live issue/PR first and keep the wording fail-closed
until that implementation and validation land.

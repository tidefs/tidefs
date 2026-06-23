# Unified Storage Encryption Threat Model and Product Path Audit

Last updated: 2026-05-23
Historical issue: Forgejo #6486

This document is the consolidated threat model for TideFS storage encryption.
It inventories every encryption-related claim, maps each claim to specific
and records which A-register findings are advanced or closed.

## 1. Scope and Authority

This threat model covers five security postures across the TideFS storage
stack:

- **At-rest encryption**: object-level confidentiality for data stored on
  disk through the local object store.
- **Key management**: secret handle/key-lease lifecycle, key hierarchy,
  derivation, wrapping, rotation, and zeroization.
- **Transport security**: session-level confidentiality and integrity for
  inter-node communication.
- **Integrity**: durable content integrity verification through BLAKE3
  content addressing and Checksum64 fast corruption detection.
- **Authentication and authorization**: root authentication, session
  attestation, principal proof, capability grants, and audit records.

The document is anchored to the following design authorities:

- `docs/BLAKE3_USAGE_POLICY.md` -- BLAKE3 usage boundary
- `docs/security/blake3-integrity-boundary.md` -- integrity boundary closeout
- `docs/security/transport-security-boundary.md` -- transport session boundary
- `docs/security/pool-encryption-secret-handle-boundary.md` -- P9-04
  handle/lease implementation
- `docs/security/security-release-matrix.md` -- consolidated release matrix
- `docs/security/security-audit-2026-04-30.md` -- kernel unsafe audit

## 2. Threat Model Framework

### 2.1 Assets

| Asset | Form | Protection goal |
|---|---|---|
| User file data | Objects stored in segments on disk | Confidentiality (at-rest encryption), integrity (BLAKE3 + Checksum64) |
| Pool encryption key | 32-byte symmetric key (StoreKey) | Confidentiality (sealed envelope, handle-not-bytes), zeroization |
| Session traffic | Inter-node messages (transport frames) | Confidentiality + integrity (ChaCha20-Poly1305 + HMAC-SHA256) |
| Object metadata | Extent maps, inode tables, directory indices | Integrity (committed-root hash chains, IntegrityTrailerV2) |
| Authentication secrets | Ed25519 signing keys, attestation keys | Confidentiality, one-way transformation |
| Committed roots | Transaction group anchors | Integrity (BLAKE3 chain) |

### 2.2 Threat Actors

| Actor | Capability | Primary targets |
|---|---|---|
| Disk-level adversary | Read raw disk blocks (stolen drive, decommissioned media, disk image leak) | At-rest object data, pool encryption key envelope, metadata |
| Network adversary | Observe, modify, replay, or inject transport frames | Session traffic, handshake negotiation |
| Local unprivileged process | Read filesystem paths, inspect process memory | Key material in env vars, plaintext data in page cache |
| Compromised node | Full access to local storage and memory | Key material, plaintext data, audit trail integrity |
| Supply-chain adversary | Modified dependency or build artifact | Cryptographic primitives, RNG, constant-time guarantees |

### 2.3 Trust Boundaries

```text
Operator interface (CLI)
        |
        v
[Mount/Load boundary] --- encryption key selection, pool open
        |
        v
[Object I/O boundary]  --- per-object AEAD encrypt/decrypt
        |
        v
[Disk boundary]        --- ciphertext on storage media
        |
        v
[Network boundary]     --- transport session cipher, handshake attestation
        |
        v
[Peer boundary]        --- mutual attestation, session authorization
```

## 3. Encryption Claims Inventory

tier. Claims without mounting product code are marked as library/API support,
not mounted product behavior.

### 3.1 At-Rest Object Encryption

**Claim**: User data objects stored on disk are encrypted with
ChaCha20-Poly1305 AEAD using per-object derived keys.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-encryption/src/lib.rs` -- `EncryptedObjectStore` (lines 358-600) |
| Cipher | ChaCha20-Poly1305 (IETF variant, 12-byte nonce, 16-byte tag) |
| Per-object key | Derived via HKDF-SHA256 from StoreKey + ObjectKey, or via `ObjectKeyDeriver` trait |
| Overhead | 28 bytes per object (12-byte nonce + 16-byte tag) |
| Feature gate | `encryption` feature in `tidefs-local-filesystem` |
| Bridged in | `crates/tidefs-local-filesystem/src/encrypted_fs.rs` -- `EncryptedPool` |
| Mounted path | Wired. `MountConfig.encryption` field exists; `run_mount` opens encryption-aware stores via `open_with_block_devices_and_encryption` or `open_with_root_authentication_key_and_encryption`. `tidefsctl mount --encryption-envelope` exposes the product path. |
| A-register | A17 -- library/API support exists; mounted product reachability missing |

**Threat coverage**: Disk-level adversary cannot recover plaintext from
ciphertext-only disk images. Local unprivileged process cannot read plaintext
from cold storage. Does not protect against memory-scraping of a running
mount (requires kernel page-cache encryption, out of scope).

### 3.2 Key Hierarchy

**Claim**: A 3-tier key hierarchy separates master-key, per-pool, and
per-object key material with domain-separated derivation.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-encryption/src/key_hierarchy.rs` (720 lines) |
| Tiers | MasterKey (top) -> PoolKey (per-pool) -> ObjectKey (per-object) |
| Derivation | HKDF-SHA256 with domain-separated BLAKE3 context strings |
| Mounted path | Wired through pool create/import/mount (`tidefsctl mount --encryption-envelope`). |

### 3.3 Key Derivation from Passphrase

**Claim**: Pool encryption keys are derived from operator passphrases using
Argon2id with domain-separated BLAKE3 contexts.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-encryption/src/lib.rs` -- `StoreKey::derive_from_passphrase()` (lines 249-275) |
| KDF | Argon2id (default: 64 MiB memory, 3 iterations, 4 lanes) |
| Salt | Domain-separated BLAKE3 context |
| Note | Prefer secret-handle/key-lease path over direct passphrase derivation for production |

### 3.4 Secret Handle / Key Lease Boundary (P9-04)

**Claim**: Pool encryption keys are managed through opaque handles
(`SecretHandleId`), with plaintext access granted only via time-bounded,
zeroizing leases (`PoolEncryptionKeyLease`). No raw key bytes in persistent
operator configuration.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-encryption/src/secret_handle.rs` (591 lines) |
| Types | `SecretHandleId` (128-bit opaque), `SecretHandleLifecycle` (6 states), `PoolEncryptionSecretHandle`, `PoolEncryptionKeyLease` |
| Lifecycle | SealedInactive -> Active -> (RotatingDualValid) -> Revoked -> Quarantined -> Retired |
| Lease bound | `MAX_LEASE_DURATION` = 1 hour; leases clamped and zeroized on drop |
| Mounted path | Not yet wired. CLI still uses `--encryption-envelope <PATH>` pre-handle flow. |
| A-register | A17 -- type boundary exists; product reachability pending |

### 3.5 Dataset Key Wrapping

**Claim**: Per-dataset encryption keys (DatasetDEK) are sealed into the pool
KeyStore under a PoolWrappingKey derived via Argon2id from the operator
passphrase.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-encryption/src/key_manager.rs` (832 lines) |
| CLI | `tidefsctl dataset seal-key`, `tidefsctl dataset rotate-key` |
| Envelope | `SealedPoolKeyEnvelope` (VEKF v1, 84 bytes) |
| Mounted path | CLI product path exists; not integrated through P9-04 handle boundary |

### 3.6 Key Material Zeroization

**Claim**: Plaintext key material is zeroized on drop for all lease types.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-encryption/src/secret_handle.rs` -- `Drop` impl for `PoolEncryptionKeyLease` |
| Full audit | Not yet complete; zeroization audit of remaining key-material lifetimes tracked in #6487 |
| A-register | A17 -- lease zeroization exists; comprehensive audit pending |

### 3.7 Transport Session Encryption

**Claim**: Inter-node transport frames are encrypted and authenticated at the
session level using ChaCha20-Poly1305 with per-session keys derived via HKDF
from an Ed25519 handshake.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-transport/src/session/` -- `session_cipher.rs`, `secure_transport.rs` |
| Cipher | ChaCha20-Poly1305 per-frame after HELLO handshake |
| Integrity | HMAC-SHA256 per-frame |
| Handshake | Ed25519 mutual attestation (`perform_handshake()` gates non-LocalEmbed endpoints without attestation key) |
| Key derivation | HKDF from handshake-established shared secret |
| No message-local crypto | Per-message BLAKE3/MAC/auth-token explicitly removed (#6346). `MemberAuthToken`, `auth_token.rs` (1095 lines), `dispatch_with_auth` removed. |
| A-register | A17 -- primary transport attestation residual improved; A37 -- negotiation token wording still stale in `Session::init_ciphers_from_raw_key` docs |

**Threat coverage**: Network adversary cannot read or modify session traffic
after handshake. Session keys are not derivable from public transcript tokens
(negotiation token is a public agreement token, not a cipher key).

### 3.8 Transport Session Rekey

**Claim**: Long-lived transport sessions can be rekeyed to limit ciphertext
exposure under a single key.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-transport/src/session/session_rekey.rs` |

### 3.9 Root Authentication

**Claim**: The local filesystem can verify committed-root integrity through
root authentication keys, providing tamper detection for pool state.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-auth/src/security.rs`, `ROOT_AUTHENTICATION_OW015.md` |
| Mechanism | BLAKE3-based committed-root hash chain verification |
| Limitation | Not P9-04 key management: no sealed-key enrollment, rotation, transparent re-encryption, or distributed replica auth |
| A-register | A17 -- root auth is local-filesystem integrity, not production key management |

### 3.10 Session Attestation

**Claim**: Transport sessions mutually attest peer identity via Ed25519
before exchanging data.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-auth/src/attestation.rs`, `crates/tidefs-auth/src/handshake.rs` |
| Mechanism | Ed25519 signing, initiator/responder branches |

### 3.11 Authorization and Capability Grants

**Claim**: Sensitive operations require principal proof, short-lived session
grants, and authorization decisions with override consumption.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-auth/src/authorization.rs`, `crates/tidefs-auth/src/capability.rs`, `crates/tidefs-auth/src/override_mechanism.rs` |
| Types | `Principal`, `CapabilityGrant`, `AuthorizationDecision`, `OverrideConsumption` |
| A-register | A17 -- record types exist; not required by operator/service/cluster mutation paths |

### 3.12 Audit Trail

**Claim**: Security-relevant operations produce durable, tamper-evident audit
records.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-auth/src/audit.rs` |
| Owning gaps | Audit-log durability; historical Forgejo #6490 |

### 3.13 Integrity -- BLAKE3 Content Addressing

**Claim**: Objects are content-addressed via BLAKE3-256 hashes, providing
durable integrity verification independent of encryption.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-local-object-store/` -- `ObjectKey` derivation, `IntegrityTrailerV2` |
| Mechanism | BLAKE3-256 of object content; committed-root hash chains; segment checksum anchors |
| Residual overfit | Tracked in `docs/BLAKE3_USAGE_POLICY.md` SS3; non-owned crates with stale BLAKE3 use |
| A-register | A4 -- advanced; publish guard prevents new message-local BLAKE3 |

### 3.14 Integrity -- Fast Corruption Detection

**Claim**: Hot I/O paths use Checksum64 (CRC32C) for fast corruption
detection, with BLAKE3-256 for durable trails.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-local-object-store/` -- two-tier checksum model |
| Policy | `CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md` |

### 3.15 Kernel Unsafe Boundary

**Claim**: Kernel-mode code enforces `#![forbid(unsafe_code)]` on all
production crates; kernel-facing unsafe blocks have explicit SAFETY
invariants.

| Element | Value |
|---|---|
| Code path | `crates/tidefs-block-kmod/`, `crates/tidefs-posix-vfs-kmod/` |
| Audit | `docs/security/security-audit-2026-04-30.md` -- 41 of 42 production crates forbid unsafe; 1 exception with documented SAFETY invariants |
| Owning gaps | Kernel unsafe boundary consolidated review; historical Forgejo #6492 |

### 3.16 No Message-Local Crypto Proof Markers

**Claim**: TideFS does not use per-message BLAKE3, MAC, or auth-token proof
markers. Integrity and authenticity are session-level or storage-level
boundaries.

| Element | Value |
|---|---|
| Enforcement | Publish guard; removed surfaces: `MemberAuthToken`, `auth_token.rs`, `dispatch_with_auth` |
| A-register | A37 -- primary public-token hazard fixed; stale docs wording remains |

## 4. Product Path Audit

This section traces each encryption claim from the operator interface through
the mounted code path to disk. Claims without a complete product path are
explicitly marked.

### 4.1 Pool Create with Encryption (NOT WIRED)

```text
operator: tidefsctl pool create --encryption-envelope <PATH> ...
    |
    v
[Review debt TFR-006] PoolCreateConfig.encryption: Option<StoreKey> should be
       set via secret handle -> key lease -> into_key()
    |
    v
[Review debt TFR-006] EncryptedPool::open() or LocalObjectStore wrapped in
       EncryptedObjectStore
    |
    v
[EXISTS] EncryptedObjectStore (tidefs-encryption)
    |
    v
[EXISTS] ChaCha20-Poly1305 per-object AEAD on every put()
```

Current state: `PoolCreateConfig` accepts `Option<StoreKey>` (#6327 landed),
but the CLI `tidefsctl pool create` does not yet consume the secret-handle
path. The `--encryption-envelope <PATH>` flag passes a raw file path rather
than a `SecretHandleId`.

### 4.2 Pool Import with Encryption (PARTIALLY WIRED)

```text
operator: tidefsctl pool import ...
    |
    v
    |
    v
[PARTIAL] Key fingerprint (BLAKE3 keyed hash prefix) computed at creation,
          tracked through import, reported to operator
```

matches the pool label's encryption flags and refuses import of encrypted
pools without a key.

### 4.3 Pool Mount with Encryption (WIRED, T1)

```text
operator: tidefsctl pool mount ...
    |
    v
[EXISTS] MountConfig.encryption field accepts EncryptionConfig (P9-04 sealed-envelope model)
    |
    v
[EXISTS] run_mount() opens through `open_with_block_devices_and_encryption` or `open_with_root_authentication_key_and_encryption`
    |
    v
[EXISTS] EncryptedPool wraps store transparently
```


### 4.4 Transport Session Establishment (WIRED, T1)

```text
peer A                                          peer B
  |                                                |
  |--- HELLO (Ed25519 attestation) --------------->|
  |                                                |
  |<-- Accept (Ed25519 attestation) -------------- |
  |                                                |
  |--- negotiation token (public transcript) ----->|
  |                                                |
  |<-- negotiation token (public transcript) ------|
  |                                                |
  |=== Session established ===                     |
  |    cipher: ChaCha20-Poly1305                   |
  |    integrity: HMAC-SHA256                      |
  |    key: HKDF(shared_secret)                    |
```

mutual attestation and missing-key rejection. The negotiation token is a
public transcript-agreement token, not a cipher key (#5927).

### 4.5 Scrub Integrity Verification (SOURCE-LEVEL, NOT MOUNTED)

```text
[EXISTS] tidefs-scrub-core -- per-object BLAKE3 integrity verification
    |
    v
[EXISTS] ScrubRepairEvent carries ObjectVerificationOutcome
    |
    v
[PARTIAL] SuspectLog and repair handoff durability (A31)
    |
    v
```

## 5. Gap Analysis

### 5.1 Critical Gaps (Block Release Claims)

| Gap | Description | Owning issue | Current tier |
|---|---|---|---|
| Key material zeroization audit | Full audit of all key-material lifetimes beyond lease types | #6487 | T1 (partial) |

### 5.2 Important Gaps (Do Not Block Userspace Release)

| Gap | Description | Owning issue |
|---|---|---|
| Distributed auth/authz/audit call paths | Authorization decisions not required by cluster mutation paths | A17, #6344 |
| Fuzzing corpus | No fuzz corpus for encryption/parser/format boundaries | #6494 |
| Kernel-mode encryption | No kernel-mode encryption path; kernel reads ciphertext through userspace | #6357 |

### 5.3 Residual Cleanup

| Item | Description | Reference |
|---|---|---|
| Stale `NegotiationComplete` key wording | `Session::init_ciphers_from_raw_key` docs still reference raw key bytes from `NegotiationComplete` | A37 |
| Stale `encrypted_loopback` test naming | Loopback test still documented as "encrypted" exchange using public token | A37 |
| Stale BLAKE3 overfit | Non-owned crates with residual BLAKE3 proof-marker usage | SS3 in BLAKE3 policy |

## 6. A-Register Findings Addressed

This document advances or records the status of every encryption-relevant
A-register finding:

- **A17 (Security/Auth/Encryption Design Split)**: This threat model
  and mounted-path reachability, advancing the "Resolve mounted at-rest
  encryption authority" needed action. The remaining A17 gap (mounted
  at-rest encryption product reachability) is now precisely documented as
  was implemented by closed #6327. The product path elements
  (MountConfig, run_mount, CLI wiring).

  model records the current state: the primary production hazard is fixed
  (#5927), loopback tests use honest fixed test keys, but stale doc wording
  remains in `Session::init_ciphers_from_raw_key` and `encrypted_loopback`
  test naming. The needed actions from A37 are restated as residual cleanup
  items.

- **A4 (BLAKE3 Overfit / Proof-Marker Pattern)**: This threat model
  confirms the BLAKE3 usage policy boundary is enforced by the publish guard.
  The residual non-owned overfit is tracked in the policy doc SS3.

## 7. Threat Coverage Summary

| Threat actor | Covered by | Coverage level |
|---|---|---|
| Disk-level adversary (cold) | At-rest encryption (3.1), key envelope (3.4) | Source-level; not mounted |
| Disk-level adversary (warm/running) | Not covered | Requires kernel page-cache encryption (out of scope) |
| Network adversary (passive) | Transport session encryption (3.7) | T1 (cargo); T3 pending |
| Network adversary (active, impersonation) | Session attestation (3.10), handshake gating (3.7) | T1 (cargo) |
| Local unprivileged process (cold storage) | At-rest encryption (3.1) | Source-level |
| Local unprivileged process (running mount) | Not covered | Requires kernel page-cache isolation |
| Compromised node (key extraction) | Secret handle/key lease (3.4), zeroization (3.6) | Type boundary; runtime pending |
| Supply-chain adversary | Kernel unsafe audit (3.15), lockfile gate (#6493) | Partial |
| Metadata tampering | BLAKE3 integrity (3.13), committed-root chains | T1 (cargo) |
| Audit trail forgery | Not covered | #6490 (design-level) |


compile and their unit tests pass at the cargo tier:

```sh
cargo check -p tidefs-auth -p tidefs-encryption -p tidefs-transport --locked
cargo test -p tidefs-encryption --locked
cargo test -p tidefs-auth --locked
```


## 9. References

- `docs/security/security-release-matrix.md` -- consolidated release matrix
- `docs/security/transport-security-boundary.md` -- transport session boundary
- `docs/security/pool-encryption-secret-handle-boundary.md` -- P9-04 handle/lease
- `docs/security/blake3-integrity-boundary.md` -- BLAKE3 integrity boundary
- `docs/BLAKE3_USAGE_POLICY.md` -- BLAKE3 usage policy
- `docs/security/security-audit-2026-04-30.md` -- kernel unsafe audit
- `/root/ai/docs/projects/tidefs/state/full-review-attention-register.md` -- A4, A17, A37

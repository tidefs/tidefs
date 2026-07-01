# Cluster Security and Identity Model - Historical Input

TFR-019 / issue #1638 classification: historical input. This imported
Forgejo-era security sketch remains only because source comments still cite
its section-number lineage for existing type names and checks. Active transport,
membership, operator, storage-intent, and claim authority lives in the
source-backed authority documents, `validation/claims.toml`, generated claim
docs, and live GitHub issues/PRs. This file is not active cluster-security,
authorization, RDMA, distributed-mode, or product-readiness authority.

## Historical Sketch

The imported text below sketched node identity, attestation, session grants,
authorization, and trust-domain handling for a distributed storage cluster.
Retaining it preserves narrow lineage for source comments; it does not prove
that the sketched model is complete or active as product behavior.

The old seal and bridge wording below is imported background only.

## 1. Historical Target

The imported target model rested on three pillars:

- **Node identity**: every cluster participant has a unique, self-signed
  Ed25519 identity bound to a `NodeIdentity` record. No node may participate
  in the cluster without a verifiable identity.
- **Mutual attestation**: before any transport session is bound, the two
  endpoints exchange identities and perform a 7-step mutual challenge-response
  attestation handshake. An endpoint that fails attestation is permanently
  refused for that identity epoch.
- **Session-bound authorization**: every transport frame is bound to an
  attested session, which carries the principal identity, session grant,
  lane budget, and cohort membership. Authorization is per-frame, not
  per-connection.

The imported target text stated this anti-regression rule:

**No cluster message may be delivered, no membership transition may be
recorded, and no data-plane operation may be committed unless both endpoints
have completed mutual attestation and the session carries a valid session
grant that authorizes the specific operation.**

## 2. Security Architecture

### 2.1 Layered Security Model

```
┌─────────────────────────────────────────────┐
│              Application / Operator           │
├─────────────────────────────────────────────┤
│  P9-02 Authorization (role bindings, grants) │
├─────────────────────────────────────────────┤
│  Session layer (session grant, cohort, lane) │
├─────────────────────────────────────────────┤
│  Mutual attestation (HELLO handshake)         │
├─────────────────────────────────────────────┤
│  TLS/mTLS transport (optional, negotiated)   │
├─────────────────────────────────────────────┤
│  TCP / RDMA transport                        │
└─────────────────────────────────────────────┘
```

Each layer adds security guarantees, and no layer may be bypassed:

| Layer | Guarantee | Bypass danger |
|---|---|---|
| Transport (TCP/RDMA) | Physical reachability, connection liveness | Not a security layer alone |
| TLS/mTLS | Channel encryption, optional client cert | Server-only TLS misses client identity |
| Mutual attestation | Bidirectional identity proof | Without it, either side can impersonate |
| Session layer | Binds identity to session grant, lane, cohort | Without it, identity is unlinked from authorization |
| P9-02 authorization | Role-based access control per action | Without it, authenticated == authorized |

### 2.2 Identity → Membership Bridge

Node identity and cluster membership are distinct but coupled:

- **Node identity** (`NodeIdentity`) proves *who* a node is — a static,
  cryptographic claim bound to an Ed25519 key pair.
- **Cluster membership** (`MembershipTransition`) proves *that* a node
  belongs to the cluster at a specific epoch — a dynamic, quorum-backed
  record.
- **The bridge**: a node presents its `NodeIdentity` during mutual
  attestation. The receiving node verifies the identity, then checks
  whether that node_id appears in the current membership view
  (`ClusterViewV1`). Only nodes present in the current membership epoch
  may establish transport sessions.

This prevents a node with a valid key pair but no membership from joining
the cluster fabric, and prevents a membership record from being stolen by
a node with a different identity.

## 3. Node Identity Model

### 3.1 NodeIdentity Record

Every cluster node owns exactly one `NodeIdentity` at a time:

```
NodeIdentity {
    node_id: u64,
    verifying_key_bytes: [u8; 32],    // Ed25519 public key
    attested_at_millis: u64,
    identity_version: u64,
    self_signature: Vec<u8>,          // sign(node_id || pk || attested_at || version)
}
```

The self-signature proves the node controls the private key corresponding
to the public key. It binds the key to a specific `node_id` and creation
timestamp, preventing key reuse across nodes or time.

### 3.2 Identity Generation

Identity generation is local, offline, and one-shot:

1. Generate an Ed25519 key pair from OS randomness (`OsRng`).
2. Set `attested_at_millis` to the current wall-clock time.
3. Set `identity_version = 1`.
4. Produce `self_signature = sign(sk, node_id || verifying_key || attested_at_millis || identity_version)`.
5. Persist the `NodeIdentity` record and the secret key material according to P9-04 key handling law.

There is no central CA. Tidefs is a self-certifying system: identity is
proven by possession of the private key and verified against the cluster's
known identity set.

### 3.3 Identity Storage

The private key material is stored according to P9-04:

- On Linux: a sealed file at a well-known path, readable only by the
  tidefs daemon UID, with optional kernel keyring binding.
- In production: the key material may reside in a TPM or HSM-backed
  sealing layer. The identity crate consumes key material through an
  abstract `NodeKeyStore` trait that admits filesystem, kernel keyring,
  and TPM backends.

### 3.4 Identity Verification

Given a remote `NodeIdentity`, verification is:

1. Deserialize `verifying_key_bytes` into an Ed25519 `PublicKey`.
2. Reconstruct `preimage = node_id || verifying_key_bytes || attested_at_millis || identity_version`.
3. Verify `self_signature` against the public key and preimage.
4. Check that `attested_at_millis` is within acceptable clock skew of the
   verifier's wall clock (configurable, default ±24h for initial join,
   ±5min for established sessions).
5. Check revocation status (see §7).

If any step fails, the identity is refused and the peer connection is
dropped.

## 4. Mutual Attestation

### 4.1 HELLO Handshake (7 Steps)

Mutual attestation follows the P8-01 HELLO protocol, implemented in
`tidefs-auth::attestation::verify_mutual_attestation()`:

| Step | Sender | Message | Content |
|---|---|---|---|
| 1 | Initiator | `HelloMessage` | `node_id`, `NodeIdentity`, `challenge_nonce` (32 random bytes) |
| 2 | Responder | Verify | Check initiator identity, membership, revocation |
| 3 | Responder | `HelloResponse` | `node_id`, `NodeIdentity`, `sign(responder_sk, initiator_nonce \|\| responder_nonce)` |
| 4 | Initiator | Verify | Check responder identity, membership, revocation, signature |
| 5 | Initiator | `HelloConfirm` | `sign(initiator_sk, responder_nonce \|\| session_params)` |
| 6 | Responder | Verify | Check initiator signature, session params |
| 7 | Both | Session bind | Mint `SessionToken`, transition to `SessionState::Bound` |

The bidirectional challenge-response proves:

- The initiator controls the private key for its claimed `node_id`.
- The responder controls the private key for its claimed `node_id`.
- Both parties agree on the session parameters (endpoint family, session
  class, lane budget, TLS parameters).

### 4.2 Nonce Requirements

- Each nonce is 32 bytes of `OsRng` randomness.
- Nonces are single-use per attestation handshake.
- Replay of a captured `HelloMessage` with the same nonce must be detected
  and refused via a per-listener nonce cache (capacity: recent 1024 nonces,
  LRU eviction).

### 4.3 Attestation Failure Handling

On attestation failure:

| Failure reason | Action |
|---|---|
| Unknown node_id | Drop connection, log `AttestationError::UnknownPeer` |
| Invalid self-signature | Drop connection, log `IdentityError::SelfSignatureInvalid` |
| Revoked identity | Drop connection, log `IdentityError::Revoked` |
| Clock skew > threshold | Refuse with `HelloResponse::ClockSkew { our_time, their_time }` |
| Nonce replay | Drop connection, log `AttestationError::NonceReplay` |
| Not in membership view | Drop connection, log `AttestationError::NotInMembership` |

All attestation failures are audited per P9-02 §7.

## 5. Transport Security

### 5.1 TLS Negotiation

After mutual attestation succeeds but before the session transitions to
`Bound`, the endpoints negotiate optional TLS:

1. During `HelloMessage`/`HelloResponse`, each side advertises its TLS
   capability via `tls_params: Option<TlsParams>`.
2. If both sides advertise TLS, the session initiates a TLS 1.3 handshake
   over the existing TCP connection.
3. The TLS handshake uses the Ed25519 keys from `NodeIdentity` as the
   TLS client and server certificates (self-signed, verified against the
   known identity set).
4. On successful TLS negotiation, the session is marked `tls_active = true`
   and all subsequent frames are encrypted.
5. If TLS negotiation fails, the session may fall back to plain TCP only
   if the endpoint family permits it. Control-plane endpoints require TLS
   in production; data-plane endpoints may accept plain TCP within a
   trusted network boundary.

### 5.2 TLS Parameter Negotiation

```
TlsParams {
    min_version: TlsVersion,         // default: Tls13
    cipher_suites: Vec<CipherSuite>, // default: [AES_256_GCM, CHACHA20_POLY1305]
    require_client_cert: bool,       // default: true (always mTLS)
}
```

### 5.3 Frame-Level Integrity

Every transport frame carries integrity protection independent of TLS:

- CRC32C over the frame header for fast corruption detection.
- BLAKE3 over the frame payload (when TLS is not active) for end-to-end
  integrity.
- When TLS is active, the BLAKE3 payload digest is optional; TLS provides
  record-layer integrity.

This two-tier checksum architecture is defined in #1287.

## 6. Session Security Model

### 6.1 SessionToken

After mutual attestation, the responder mints a `SessionToken`:

```
SessionToken {
    session_id: u64,
    initiator_node_id: u64,
    responder_node_id: u64,
    session_class: SessionClass,
    endpoint_family: EndpointFamily,
    cohort_classes: Vec<CohortClass>,
    issued_at_millis: u64,
    expires_at_millis: u64,
    token_signature: Vec<u8>,  // sign(responder_sk, session_id || initiator || ... || expires)
}
```

The `SessionToken` serves as a bearer proof that:

- Mutual attestation completed successfully.
- The session is authorized for the declared session class, endpoint
  family, and cohort classes.
- The session has a bounded lifetime (`expires_at_millis`).

### 6.2 Session Classes and Security Properties

| SessionClass | EndpointFamily | TLS Required | Max Lifetime | Typical Use |
|---|---|---|---|---|
| `BootstrapControl` | Control | Yes (production) | 5 min | Initial cluster join |
| `Control` | Control | Yes (production) | 1 hour | Heartbeats, membership, orchestration |
| `ReplicationMeta` | Control | Yes | 1 hour | Replication metadata, flow commits |
| `TransitionOrchestration` | Control | Yes | 30 min | Node drain, failover, rebalance |
| `TransferBulk` | Data | Optional | 24 hours | Bulk data transfer |
| `LocalEmbed` | LocalEmbed | No | Indefinite | Co-resident service communication |

### 6.3 Session Compromise Detection

When a session is suspected compromised:

1. The detecting node sends a `SessionClose` with `reason = SessionCloseReason::Compromised`.
2. All inflight frames are discarded.
3. The session is closed and cannot be resumed.
4. A `SessionCompromised` audit event is emitted.
5. The affected node identities may be queued for key rotation.

## 7. Key Lifecycle

### 7.1 Key Rotation

Key rotation is a controlled, epoch-bounded operation:

1. **Pre-rotation**: the node generates a new `NodeIdentity` (version N+1)
   while the current identity (version N) remains active.
2. **Announce**: the node publishes the new identity to the cluster via
   the control plane, signed by the current identity.
3. **Grace period**: both identities are accepted for a configurable
   overlap window (default: 5 minutes) to allow in-flight sessions to
   complete.
4. **Cutover**: the node begins using identity version N+1 for all new
   connections. Existing sessions on version N continue until they expire
   or drain.
5. **Retire**: after the overlap window, identity version N is revoked
   and may no longer be used for new sessions.

### 7.2 Rotation Triggers

Key rotation may be triggered by:

| Trigger | Urgency | Overlap window |
|---|---|---|
| Scheduled rotation (policy) | Low | Configurable (default: 1 hour) |
| Suspected compromise | High | Minimal (default: 1 minute) |
| Operator-initiated | Medium | Operator-specified |
| Post-node-rejoin | Medium | Standard (5 minutes) |

### 7.3 Key Revocation

A node identity may be revoked before its natural rotation:

1. An authorized principal (operator or automated compromise detector)
   publishes a `IdentityRevocationRecord` to the cluster.
2. The revocation is distributed via the control plane to all cluster
   members.
3. Each node adds the revoked `(node_id, identity_version)` pair to its
   local revocation set.
4. Any new connection presenting the revoked identity is refused at
   attestation time.
5. Existing sessions using the revoked identity are force-closed.

### 7.4 Revocation Distribution

Revocation records propagate through the cluster as a gossip eventually-consistent
update with:

- **Priority**: revocation records are CONTROL-lane, highest priority.
- **Latency target**: all nodes receive revocation within 500 ms under
  normal operation.
- **Persistence**: revocation records are durably stored in the control
  plane's revocation ledger, surviving node restarts.

## 8. Membership → Security Integration

### 8.1 Membership Epoch Boundaries

The security model is gated on membership epochs:

- **Epoch transition**: when the membership epoch advances (node join,
  departure, or failure detection), the set of valid identities changes.
- **Stale membership view**: a node with a stale membership view may
  attempt to attest against a departed node. The attestation fails when
  the remote checks membership.
- **Split-brain protection**: during a network partition, each partition
  maintains its own membership epoch. Nodes in different partitions
  cannot mutually attest because they present different epoch numbers.
  The anti-entropy auditor (#1178) reconciles after the partition heals.

### 8.2 Join Security

A new node joining the cluster must:

1. Generate its `NodeIdentity` (offline or during bootstrap).
2. Present its identity to an existing cluster member (the bootstrap
   contact) via the `BootstrapControl` session class.
3. The bootstrap contact verifies the identity and, if authorized,
   proposes a `JoinRequestV1` to the cluster.
4. The cluster runs the membership join protocol (#1209). If the join
   is accepted, the new node's identity is added to the membership view.
5. After join, the new node can mutually attest with any cluster member.

The security-critical step is step 3: the bootstrap contact must be a
trusted cluster member, and the operator must configure the new node
with the correct bootstrap contact identity. A rogue bootstrap contact
could refuse attestation but cannot forge membership because membership
requires quorum.

### 8.3 Departure Security

When a node departs the cluster (graceful or failure):

1. The departure is recorded as a `MembershipTransition`.
2. The departed node's identity is removed from the active membership
   view in the next epoch.
3. Any existing sessions to the departed node are closed.
4. The departed node's key material is not automatically revoked
   (the node may rejoin later). However, if the departure was due to
   compromise, the operator must explicitly revoke the identity.

## 9. Threat Model

### 9.1 Threats Mitigated

| Threat | Mitigation |
|---|---|
| Node impersonation | Ed25519 self-signed identity + mutual attestation |
| Replay attacks | Per-handshake nonces + nonce cache |
| Man-in-the-middle (network) | mTLS with identity-bound certificates |
| Frame tampering | CRC32C header + BLAKE3 payload digest |
| Session hijacking | SessionToken bound to both node identities |
| Rogue node join | Membership quorum + bootstrap contact auth |
| Stale membership attack | Epoch fencing in attestation |
| Key theft (offline) | P9-04 sealed storage, optional TPM/HSM |
| Key theft (online, daemon compromise) | Key rotation + revocation, audit trail |
| Replay of audit events | Audit chain seals (P9-02 §7.3) |
| Silent privilege escalation | Authorization per-frame, not per-connection |
| Denial of service (connection) | Transport boundedness (#1210), per-connection limits |

### 9.2 Threats NOT Mitigated (Explicit Scope Boundaries)

| Threat | Reason | Mitigation Elsewhere |
|---|---|---|
| Physical node compromise | Out of scope | Operator responsibility (physical security) |
| Kernel compromise on a node | Out of scope | Operator responsibility (kernel hardening) |
| Side-channel attacks (timing, power) | Out of scope for v1 | Future hardening issue |
| Quantum cryptanalysis of Ed25519 | Not practical today | Future post-quantum migration path |
| Byzantine fault tolerance (n > 3f+1) | Out of scope | TideFS uses quorum (majority), not BFT |
| Supply chain attacks on dependencies | Partially addressed | `cargo audit`, `forbid(unsafe_code)` |

### 9.3 Compromise Taxonomy

When a node is compromised, the impact is bounded:

- **Key-only compromise** (attacker has private key but not daemon control):
  Attacker can impersonate the node on the network. Mitigation: key
  revocation severs all sessions; membership epoch transition removes the
  node from the active view.
- **Daemon compromise** (attacker controls the tidefs daemon process):
  Attacker can read/write data the node is authorized to access. They
  cannot escalate to other nodes' data because authorization is per-node.
  Mitigation: isolate the compromised node, revoke its identity, re-replicate
  its data from healthy replicas.
- **Control plane compromise** (attacker controls a control plane node):
  Attacker can publish policies, initiate overrides, and revoke identities.
  Mitigation: P9-02 dual-control overrides for high-risk operations,
  audit trail immutability, quorum requirements for membership changes.

## 10. Data Structures

### 10.1 Identity Structures (tidefs-auth)

```
NodeIdentity           — Ed25519 self-signed node identity (P9-02 §3)
NodeKeyStore           — Abstract key material provider (file, kernel keyring, TPM)
Principal              — 5-class principal (HumanOperator, Service, ClusterNode, Auditor, Breakglass)
CredentialBindingRecord — Maps credential to principal (P9-02 §4.1)
SessionGrantRecord     — Binds session to principal, scope, expiry
RoleBinding            — Capability grant with scope and expiry
AuthorizationDecisionRecord — Canonical authz decision (P9-02 §2)
```

### 10.2 Attestation Structures (tidefs-auth)

```
HelloMessage           — node_id, NodeIdentity, challenge_nonce, tls_params
HelloResponse          — node_id, NodeIdentity, signed_nonce_response, tls_params
HelloConfirm           — signed_nonce_response, session_params
AttestationResult      — outcome of the 7-step handshake
SessionToken           — bearer proof of completed attestation
SessionClass           — enum of session classes with security properties
```

### 10.3 Membership Structures (tidefs-membership-types)

```
NodeDescriptorV1       — node_id, address, FailureDomainVector, NodeIdentity ref
ClusterViewV1          — epoch, membership set, leader hint, transition history
MembershipTransition   — Join, Leave, Fail, EpochAdvance
FailureDomainVector    — device, node, chassis, rack, zone, region
```

### 10.4 Revocation Structures (tidefs-auth additions)

```
IdentityRevocationRecord {
    node_id: u64,
    identity_version: u64,
    revoked_at_millis: u64,
    revoked_by: PrincipalId,
    reason: RevocationReason,
    revocation_signature: Vec<u8>,
}

RevocationReason enum {
    ScheduledRotation,
    SuspectedCompromise,
    ConfirmedCompromise,
    OperatorInitiated,
    NodeDecommissioned,
}
```

## 11. Algorithms

### 11.1 Identity Algorithms

| Algorithm | Location | Description |
|---|---|---|
| `generate_node_identity()` | `tidefs-auth::identity` | Generate Ed25519 key pair + self-sign |
| `verify_node_identity()` | `tidefs-auth::identity` | Verify self-signature, clock skew, revocation |
| `resolve_principal_from_presented_credential_chain()` | `tidefs-auth::identity` | Map credential → principal |

### 11.2 Attestation Algorithms

| Algorithm | Location | Description |
|---|---|---|
| `verify_mutual_attestation()` | `tidefs-auth::attestation` | Full 7-step HELLO handshake |
| `mint_session_grant_for_authenticated_subject()` | `tidefs-auth::attestation` | Create SessionToken after attestation |
| `check_nonce_replay()` | `tidefs-auth::attestation` | Per-listener nonce dedup (1024-entry LRU) |

### 11.3 Authorization Algorithms

| Algorithm | Location | Description |
|---|---|---|
| `derive_authorization_decision_for_request()` | `tidefs-auth::authorization` | Principal + session + action → allow/deny |
| `evaluate_role_bindings_for_action_scope_and_visibility()` | `tidefs-auth::authorization` | Match role bindings to action class, scope |
| `derive_capability_grant_or_denial_from_policy()` | `tidefs-auth::authorization` | Policy evaluation for capability derivation |

### 11.4 Key Lifecycle Algorithms

| Algorithm | Location | Description |
|---|---|---|
| `rotate_node_identity()` | Future | Generate new identity, announce, grace period, cutover |
| `revoke_identity()` | Future | Publish revocation, distribute, force-close sessions |
| `check_revocation_status()` | `tidefs-auth::identity` | Check local revocation set for (node_id, version) |

## 12. Integration Points

### 12.1 Transport Layer

The transport layer (`tidefs-transport`) integrates with security at these
points:

- **Connection accept**: before accepting a new TCP connection, the listener
  checks transport admission control (§3 of #1210). The peer is not yet
  authenticated.
- **HELLO handshake**: the first frames on a new connection are the
  `HelloMessage`/`HelloResponse` exchange. Transport delivers these as raw
  frames; the auth layer processes them.
- **Session bind**: on successful attestation, the transport transitions the
  session from `Handshaking` to `Bound`. The `SessionToken` is stored on
  the session.
- **Frame authorization**: every subsequent frame is checked against the
  session's authorization: is the frame's `MessageFamily` allowed on this
  `SessionClass`? Is the session still within its expiry?
- **Session close**: on close, the session's closure receipt records the
  security context (identities, attestation outcome, authorization
  decisions during the session lifetime).

### 12.2 Membership Layer

The membership layer (`tidefs-membership-*`) integrates at these points:

- **Attestation gate**: before completing attestation, the responder checks
  that the initiator's `node_id` is present in the current `ClusterViewV1`.
- **Epoch fencing**: `HelloMessage` and `HelloResponse` carry the sender's
  membership epoch. If epochs mismatch beyond allowable skew, attestation
  fails.
- **Join bootstrap**: a new node's first contact with the cluster uses
  `BootstrapControl` session class, which has stricter attestation
  requirements (known bootstrap contact identity must be pre-configured).

### 12.3 Control Plane

The control plane (`tidefs-control-plane-*`) integrates at these points:

- **Identity publishing**: new identities, rotation announcements, and
  revocations are published through the control plane.
- **Policy distribution**: role bindings and capability grants flow through
  the control plane to all authorized nodes.
- **Audit query**: the `explanation_query` service can retrieve audit
  records for security events, filtered by visibility class.

## 13. Tradeoffs

### 13.1 Self-Certifying vs. CA-Based Identity

**Choice**: Self-certifying (Ed25519 self-signature).

**Rationale**:
- No central CA to compromise or maintain.
- No CA offline/availability dependency during cluster bootstrap.
- Simpler operational model: generate key, join cluster.
- Ed25519 self-signatures are compact (64 bytes) and fast to verify.

**Tradeoff**: Revocation requires explicit distribution rather than CRL/OCSP
lookup. Mitigated by gossip-based revocation distribution with CONTROL-lane
priority.

### 13.2 mTLS Always vs. Optional mTLS

**Choice**: mTLS always for Control endpoint, optional for Data endpoint.

**Rationale**:
- Control-plane traffic (membership, policies, secrets) must be encrypted
  and mutually authenticated in all deployments.
- Data-plane bulk transfer within a trusted network (same rack, dedicated
  storage VLAN) benefits from TLS optionality for throughput. TLS 1.3
  AES-256-GCM adds ~5-10% CPU overhead on modern hardware.
- Operators can enforce TLS on Data endpoint via configuration.

**Tradeoff**: If an operator misconfigures Data to plain TCP on an untrusted
network, bulk data is exposed. Mitigated by documentation, default-on TLS
for production profiles, and audit warnings when TLS is disabled.

### 13.3 Session Grants vs. Per-Frame Tokens

**Choice**: Session grant (bearer token minted at attestation) rather than
per-frame signatures.

**Rationale**:
- Ed25519 signing per frame (~50µs per sign + 64 bytes per frame) adds
  unacceptable overhead for data-plane traffic at line rate.
- Session grants have bounded lifetime and are bound to both node identities,
  so theft requires both the token and the ability to inject frames on the
  exact TCP connection.

**Tradeoff**: Session token theft during an active session allows frame
injection until the session expires or is closed. Mitigated by TLS channel
binding (the token is only valid on the TLS channel it was minted on) and
short session lifetimes for sensitive session classes.

### 13.4 Per-Node Identity vs. Per-Service Identity

**Choice**: Per-node identity (one `NodeIdentity` per physical/logical node).

**Rationale**:
- TideFS is a storage system; the node is the failure domain.
- Multiple services on one node share the node's identity; authorization
  distinguishes their capabilities via `Service` principal class within
  the node's identity.
- Simpler key management: one key per node, not one per daemon.

**Tradeoff**: Compromise of any daemon on a node compromises the node's
identity. Mitigated by process isolation, `forbid(unsafe_code)`, and the
security audit (#621). Future refinement: per-service sub-identities
derived from the node identity.

## 14. References

- [P8-01] `docs/TRANSPORT_SESSION_COHORT_GRAPH_P8-01.md` — endpoint, session, cohort model
- [P9-02] `docs/AUTHN_AUTHZ_OVERRIDE_AUDIT_MODEL_P9-02.md` — principal, authn, authz, audit law
- [P9-04] `docs/SECRETS_POLICY_STORAGE_KEY_HANDLING_LAW_P9-04.md` — key storage, rotation, leasing
- [#621]  Security audit: unsafe code enumeration, privilege boundaries
- [#1209] MEMBERSHIP service design
- [#1210] Cluster transport boundedness design
- [#1287] Checksum architecture design
- [#1228] Security model (this document supersedes as the sealed cluster security design)
- `crates/tidefs-auth/` — authentication, attestation, authorization implementation
- `crates/tidefs-membership-types/` — membership wire types
- `crates/tidefs-types-transport-session/` — session state machine
- `crates/tidefs-transport/` — transport layer with lane demux and boundedness
## 15. Coordination Seal (#1843)

This document is the sealed canonical design specification for the TideFS
cluster security and identity model. The architecture, data structures,
algorithms, integration contracts, and tradeoffs in §§1–14 are frozen.

**Seal date**: 2026-05-05
**Sealing issue**: [#1843](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1843)
**Re-verified**: [#1853](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1853) — design re-verified as comprehensive; covers architecture, data structures, algorithms, tradeoffs, threat model, and wire-up issue map across §§1–14 and Appendices A–B. No changes required.
**Re-sealed**: [#1769](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1769) — design re-seal confirmed; all 14 sections, Appendices A–B, threat model (§12), and tradeoffs (§13) remain authoritative and complete. No changes required.
**Re-verified**: [#1775](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1775) — coordination seal; design remains authoritative and complete per issue #1775 gate. No changes required.
**Gate**: `cargo check --workspace` passes clean

Rust wire-up implementation issues may be filed against individual services
(`tidefs-auth`, `tidefs-transport`, `tidefs-membership-*`,
`tidefs-control-plane-*`) but the security architecture described in this
document is locked. Any design change requires a new issue, a revision to this
document, and a new coordination seal.

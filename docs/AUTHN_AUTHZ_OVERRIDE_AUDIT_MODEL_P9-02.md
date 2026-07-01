# authn / authz / override / audit model (P9-02) (v0.328)

This document is the source-of-truth for the production-depth control-plane security law.

It answers the question:

**How does tidefs prove who is acting, what they may do, when narrow emergency overrides are legal, and how every high-risk decision becomes durable audit truth instead of local privilege folklore?**

See also:
- `docs/CLOCKS_TIMING_FENCES_DRIFT_ASSUMPTIONS_P8-04.md`
- `docs/FORMAT_IDENTITY_UPGRADE_REPLAY_CONTINUITY_LAW_P2-04.md`
- `docs/VFS_BLOCK_INTEGRATION_KERNEL_UAPI_LAW_P7-04.md`
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Core result

The production design now has one explicit principal/security law:

- one authoritative family: **`family.identity_access.identity_access_audit_0`**
- one enforcement law: **`law.authn_authz_override_audit.authn_authz_audit_0`**
- one rule for mutating or sensitive read actions:
  - **every decision must bind principal proof, session proof, authorization proof, optional override proof, and audit proof in one canonical chain**
- one rule for emergency operations:
  - **overrides are typed, scoped, expiring, receipt-bearing, and later explainable; they are never ambient privilege**
- one rule for audit truth:

This law applies to:
- human operator access through `control_plane` CLI/API,
- service-to-service requests among `control_plane`, `policy_authority`, `explanation_query`, `posix_filesystem_adapter`, and `block_volume_adapter`,
- cluster node identity and high-risk maintenance flows,
- sensitive explanation/query access,
- and future kernel-consumed capability mirrors.

It does **not** allow:
- Unix uid `0` by itself to count as final authority,
- environment variables or local config files to smuggle legal privilege,
- shared long-lived bearer tokens without bounded session grants,
- silent breakglass paths,
- or adapter-local authz dialects that cannot be reconstructed from receipts and audit records.

## 2. Canonical access decision tuple

Every mutating operation and every visibility-sensitive read must be reducible to the tuple:

- `principal_ref`
- `credential_binding_refs[]`
- `session_grant_ref`
- `requested_action_class`
- `resource_scope_selector`
- `policy_revision_ref`
- `matched_role_binding_refs[]`
- `derived_capability_grant_refs[]`
- `required_override_class` or `override_ticket_ref`
- `audit_event_ref`

That tuple may be cached or rendered differently at different surfaces, but it may not be absent from the authoritative meaning of the decision.

## 3. Principal model

The production system now distinguishes these principal classes:

1. **human operator principal**
   - an accountable person identity
   - used for observe, stage, publish, override, failover, and audit work
   - must never be shared as a generic team account if the action is mutating or high-risk

2. **service principal**
   - a named daemon or automation identity (`control_plane`, `policy_authority`, `posix_filesystem_adapter`, `block_volume_adapter`, `explanation_query`, repair workers, test/orchestration agents)
   - bounded by service family and deployment scope
   - may hold short-lived delegated grants but not ambient operator power

3. **cluster node principal**
   - a node-scoped machine identity bound to cluster membership and cohort rules
   - may prove node membership and carry queue/runtime requests
   - does not become a policy publisher merely because it is a cluster member

4. **auditor principal**
   - a read-mostly human or service identity allowed to inspect receipts, decisions, and audit chains
   - may see only the visibility classes allowed by policy
   - may not silently escalate into publish or override authority

5. **breakglass principal**
   - a high-risk emergency class
   - must be short-lived, heavily audited, and normally dual-controlled
   - exists so outages can be recovered without turning “temporary emergency” into permanent hidden sovereignty

The anti-regression rule is explicit:

**system locality, shell access, or daemon process ownership do not themselves define design rule authority. They only matter when bound to an explicit principal and session.**

## 4. Authentication law

Authentication is a proof problem, not a hostname or socket-location assumption.

### 4.1 Accepted credential classes

The design allows multiple credential classes, but every one must bind to a named principal:

- interactive operator credentials,
- service-to-service mutual-auth credentials,
- cluster node membership credentials,
- and emergency breakglass credentials.

The concrete secret/key storage mechanics are now settled in `docs/SECRETS_POLICY_STORAGE_KEY_HANDLING_LAW_P9-04.md`, but the legal meaning was already fixed here:
- every presented credential must resolve to one `CredentialBindingRecord`,
- every accepted authentication must mint one short-lived `SessionGrantRecord`,
- and every later decision must point back to that session.

### 4.2 Session grants

Authentication success does not mean indefinite privilege.
It means the system may mint a bounded session grant with:
- audience,
- assurance/risk class,
- monotonic expiry deadline,
- scope ceiling,
- and revocation linkage.

Session grants must be:
- short-lived,
- audience-bound,
- channel-bound when possible,

### 4.3 Time law interaction

Session validity uses the timing law from `docs/CLOCKS_TIMING_FENCES_DRIFT_ASSUMPTIONS_P8-04.md`:
- expiry and grace evaluation uses local monotonic/boottime discipline,
- narrative timestamps may use HLC/realtime render,
- but wall-clock string formatting is never the authority proof for session validity.

### 4.4 No ambient trust shortcuts

The following are forbidden as stand-alone authn truths:
- localhost-only assumptions,
- “came from the admin VM” assumptions,
- unsigned reverse-proxy headers,
- implicit trust in a process because it already has a socket,
- or kernel/userspace boundary crossings that drop the original principal/session linkage.

## 5. Authorization law

Authorization is determined from published policy and explicit bindings, not from code paths or deployment folklore.

### 5.1 Action classes

At minimum the production system recognizes these action classes:
- observe/query,
- stage,
- publish,
- override issue,
- override consume,
- override revoke,
- repair publish,
- failover/cutover stage or commit,
- and security/audit administration.

### 5.2 Scope selectors

A grant may target scopes such as:
- whole cluster,
- one policy domain,
- one authority domain,
- one charter,
- one product family or product instance class,
- one node cohort,

No grant may be interpreted as “global” unless the scope selector says so explicitly.

### 5.3 Binding and evaluation rules

Authorization must be derived through this sequence:
1. authenticate into a short-lived session grant,
2. load active `RoleBindingRecord` objects from published policy,
3. derive candidate capability grants for the requested action and scope,
4. determine whether an override is required,
5. emit one `AuthorizationDecisionRecord`,
6. and attach one `AuditEventRecord`.

The decision rule is deny-by-default.
If a request cannot be justified by published role bindings plus, when required, a valid override ticket, it must be refused explicitly.

### 5.4 Separation of duties

The production law fixes these anti-sovereignty cuts:
- read/audit principals do not mutate merely because they can observe,
- ordinary publishers do not automatically get override issuance power,
- override issuers do not get to erase or rewrite witness findings,
- and a principal may not silently mint grants for itself outside published policy.

Policy may make ordinary low-risk publish paths single-actor where justified, but the dangerous classes remain explicitly splittable:
- override issuance,
- failover/cutover forcing,
- and visibility expansion for sensitive audit data.

## 6. Override law

The earlier control-plane charter already defined `OverrideTicket` as a typed, expiring governance noun.
This document fixes the production-depth legality around it.

### 6.1 Override classes

The live system must support at least these override classes:
- reserve/floor relaxation,
- product admission bypass,
- expensive-path admission,
- repair publication,
- failover/cutover acceleration,
- and sensitive visibility disclosure.

### 6.2 Constraint profiles

Every override class must bind to one `OverrideConstraintProfileRecord` that states:
- allowed action classes,
- maximum scope class,
- maximum duration,
- maximum use count,
- whether dual control is required,

### 6.3 Issuance and consumption

Override issuance is separate from override consumption.
A ticket may exist but still be unusable for a request if:
- the session lacks the right principal class,
- the requested action is outside the ticket’s allowed action classes,
- the scope is too wide,
- the time window is over,
- the use budget is exhausted,
- or the ticket has been revoked.

Every successful use must emit one `OverrideConsumptionRecord` linked to:
- the ticket,
- the authorization decision,
- the action receipt,
- and the audit event.

### 6.4 Non-sovereignty rule

Overrides may temporarily relax policy, but they may never:
- rewrite immutable receipts,
- suppress findings that already exist,
- convert rebuildable narrative products into authority,
- or become an undocumented permanent configuration channel.

## 7. Audit law

Audit truth must survive outages, personnel turnover, and hostile scrutiny.

### 7.1 What must be audited

At minimum the system must emit audit events for:
- authentication success and failure,
- session issuance and revocation,
- authorization allow and deny decisions for mutating or sensitive actions,
- override issue, consume, expire, and revoke,
- policy publish,
- repair publish,
- failover/cutover force paths,
- and visibility-sensitive queries over audit/security data.

### 7.2 What counts as legal truth

Legal operator/security truth is the linked tuple of:
- decision records,
- ticket records and consumption records,
- receipts/findings,
- and sealed audit chain anchors.


### 7.3 Audit chain seals

Audit events must be periodically sealed into ordered chain anchors so the system can prove:
- event ordering within a scope,
- batch completeness,


### 7.4 Query visibility

Audit is not automatically world-readable.
Every audit render must respect explicit visibility classes so `explanation_query` or operator APIs can produce:
- full internal views,
- redacted operator views,
- or explanation-safe views.

Redaction may reduce visibility.
It may not invent alternate history.

## 8. Cross-charter and userspace/kernel parity

This law is shared across the live product surfaces:
- `control_plane` authenticates operators and publishes policy-facing decisions,
- `policy_authority` consumes the same principal/session/grant law for authoritative write paths,
- `explanation_query` renders visibility-filtered security and audit answers,
- `posix_filesystem_adapter` and `block_volume_adapter` consume delegated grants or capability mirrors when Linux-facing operations need policy-backed decisions,
- and future kernel modules may enforce only previously materialized capability mirrors; they may not mint policy authority, override truth, or audit finality locally.

The response-envelope family therefore needs stable security result classes such as:
- `authn_failed`,
- `session_expired`,
- `authz_denied`,
- `override_required`,
- `override_invalid`,
- and `visibility_redacted`.

## 9. Boundary with adjacent production items

This document closes `P9-02`, but it does **not** close:
- `P9-03` upgrade/failover/cutover operator runbooks,
- or typed fault-injection, chaos, and corruption validation.

The adjacent `P9-04` secret and policy-storage law is now explicit in `docs/SECRETS_POLICY_STORAGE_KEY_HANDLING_LAW_P9-04.md`.
The boundary is deliberate:
- `P9-02` fixes principal/session/grant/override/audit semantics,
- `P9-03` now says how operators execute those powers during real rollouts and emergencies in `docs/UPGRADE_FAILOVER_CUTOVER_OPERATOR_RUNBOOKS_P9-03.md`,
- and `P9-04` now says where long-lived secret material lives, how it is rotated, how it is leased at runtime, and how it is encrypted or sealed.

## 10. Records required by this law

The central data-structures map now requires:
- `PrincipalRecord`
- `CredentialBindingRecord`
- `SessionGrantRecord`
- `RoleBindingRecord`
- `CapabilityGrantRecord`
- `AuthorizationDecisionRecord`
- `OverrideConstraintProfileRecord`
- `OverrideConsumptionRecord`
- `AuditEventRecord`
- `AuditChainAnchorRecord`

## 11. Algorithms required by this law

The central algorithms map now requires:
- `resolve_principal_from_presented_credential_chain()`
- `mint_session_grant_for_authenticated_subject()`
- `evaluate_role_bindings_for_action_scope_and_visibility()`
- `derive_capability_grant_or_denial_from_policy()`
- `derive_authorization_decision_for_request()`
- `determine_override_requirement_or_sufficiency()`
- `issue_typed_override_ticket_under_dual_control()`
- `consume_override_ticket_and_bind_it_to_action()`
- `append_audit_event_and_seal_chain_if_needed()`

## 12. Acceptance effect on the design pack

With this law settled:
- `P9-02` becomes detailed enough for later implementation planning,
- the operator/security surface is no longer allowed to hide behind local shell privilege or vague “admin mode” language,
- and the next unresolved production items are no longer principal/authz/audit ambiguity.

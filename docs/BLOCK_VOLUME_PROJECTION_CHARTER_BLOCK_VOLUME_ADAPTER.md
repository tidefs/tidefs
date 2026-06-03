# block / volume projection charter - `charter.block_volume.block_volume_adapter` (v0.298) — continuity: Block Volume Adapter (`block_volume_adapter`)

This document closes the highest-leverage open charter gap recorded in Forgejo project state (`W4-02`).

It answers the design question that remained too implicit in the review chain:

> If block / volume export is first-class but still only a projection, what exactly is it allowed to promise, what does it depend on, and what must it never quietly become?

See also:
- `docs/TIDEFS_DOCTRINE.md`
- `docs/IMPLEMENTATION_IMPLICATIONS.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## Executive result

**`charter.block_volume.block_volume_adapter` defines the Linux-facing block / volume surface as a first-class projection charter over one published projection root: logical block addresses, export device names, volume UUIDs, queue tags, flush barriers, and resize operations are block-continuity tokens derived from authoritative graph identities, revisions, heads, policy revisions, and receipts; successful block mutations must obey declared write exactness and durability classes, while optional products may accelerate translation, locality, and serving but may never become hidden correctness authority.**

That means:
- block export is first-class enough to deserve its own charter,
- but it is still forbidden to become the authoritative ontology,
- the charter must say what a successful write, flush, discard, zero, and resize actually mean,
- and hidden thin-provisioning, hidden split-brain multi-writer behavior, or adapter-private durability folklore are all explicitly out of bounds.

## Why this charter matters

Without an explicit block / volume charter, the design is still vulnerable to previous-system drift:
- “volume” quietly becomes a native noun again,
- `/dev/ublkbN` starts sounding like durable identity,
- block writes inherit vague filesystem durability stories,
- and performance helpers or translation products quietly become semantic authority.

This charter is the cut that prevents that regression.

## Charter identity and scope

### Charter id
`charter.block_volume.block_volume_adapter`

Like the other first-class charters:
- it is named,
- future variants must compare themselves to it explicitly,
- and it remains subordinate to the authoritative graph / revision / ledger model.

### Surface served
This charter governs block / volume export through:
- current and future userspace block adapters,
- `ublk`-style exports,
- admin discovery/listing of exportable volumes,
- and later block-client adapters that must speak a named charter rather than a vague “volume mode”.

### Projection root
An export binds to one **published projection root** for one selected volume projection.
That projection root is authoritative for:
- which object / revision lineage is being exported,
- the currently visible logical capacity,
- the write exactness / durability profile,
- the resize policy,
- the discard / zero policy,
- and the authority domain that may mutate it.

The export does **not** bind directly to “the dataset” or “the file” as metaphysical truth.
It binds to a named block/volume projection root under a named charter.

## What `block_volume_adapter` is for — continuity: Block Volume Adapter (`block_volume_adapter`)

This charter exists to provide:
- conventional block read/write access over a selected exported volume,
- conventional flush / FUA / discard / write-zeroes behavior under explicit contracts,
- explicit capacity and resize semantics,
- enough exactness and observability to support real block consumers,

It does **not** exist to redefine the authoritative storage model around volumes.

## Authoritative mapping

### Authoritative nouns
The authoritative nouns remain:
- `ObjectId`
- `RevisionId`
- typed facets
- heads
- projection roots
- claims / reserves / witness sets
- policy revisions and override tickets
- receipts / response envelopes

### Projection nouns
`block_volume_adapter` introduces continuity tokens that are **projection-local** rather than deepest truth:
- `VolumeProjection`
- `LogicalBlockView`
- `BlockHandleProjection`
- `FlushBarrierToken`
- volume UUIDs
- export device names (`/dev/ublkbN`, future aliases)
- queue ids / request tags / logical block numbers

### Identity rule
`ObjectId` is authoritative.
The block charter may expose multiple alias forms:
- a human-facing volume UUID,
- a runtime export-device path,
- a charter-scoped block handle,
- and logical block offsets.

None of those are deepest identity.

Implications:
- export-device names are ephemeral adapter tokens,
- volume UUIDs are stable charter aliases only as long as the projection root and receipts say they are,
- and a repair publication or projection-root replacement may legitimately preserve the same `ObjectId` while changing the adapter-visible export token.

### Address-space rule
Logical block addresses are projection tokens over the current published byte facet under the volume projection root.
They are not independent objects.

A block read therefore means:
- identify the volume projection root,
- resolve the published byte-state revision for that root,
- map the requested block range through the charter’s logical block size,
- then answer through the charter’s exactness / freshness / durability contract.

## Projection records and declared fields

The charter now makes these projection records concrete.

### `VolumeProjection`
A block-volume projection must declare at least:
- `projection_root_id`
- `object_ref`
- `charter_id = charter.block_volume.block_volume_adapter`
- `volume_uuid_alias`
- `logical_block_size`
- `physical_block_size`
- `capacity_bytes`
- `capacity_promise_class`
- `write_exactness_class`
- `durability_profile`
- `discard_zero_policy`
- `resize_policy`
- `writer_authority_domain`
- `service_budget_domain`
- `policy_revision_ref`

### `LogicalBlockView`
The runtime block mapping view must identify:
- `volume_projection_ref`
- block-range selector
- current observed authority anchor / head
- freshness fence or flush barrier observed
- response-envelope ref if the read path was degraded or product-assisted

### `BlockHandleProjection`
The runtime writer/reader handle must identify:
- `volume_projection_ref`
- access mode (`ro` / `rw`)
- authority-domain lease ref (if mutable)
- exactness class in effect
- durability profile in effect
- last observed `FlushBarrierToken`

### `FlushBarrierToken`
A flush barrier token must name:
- the charter instance / export,
- the publication or durability receipt it corresponds to,
- the covered request cohort,
- and the durability class satisfied.

This is the block-surface equivalent of being able to answer “what exactly did flush mean here?”

## Mutation authority model

### Read-only export
A read-only export has no publication authority.
It may serve from authoritative immutable state and from freshness-governed products, but it may not move heads, resize capacity, or admit write/discard/zero operations.

### Writable export
A writable export is valid only if the export instance is admitted into the relevant authority domain.
For `block_volume_adapter`, the intended default remains:
- **single-writer lease fast path** (`SINGLE_WRITER_LEASE` / `MULTI_WRITER_LEASE`),
- writer-local when possible,
- with broader multi-writer behavior an explicitly more expensive class rather than ambient default.

### Success-return rule for writes
A successful block mutation must satisfy the declared `write_exactness_class` of the export.
For `block_volume_adapter`, the baseline class is:
- **exact-on-success for the admitted export scope**.

That means a successful write / discard / write-zeroes reply implies:
- the relevant mutation is legally admitted for that export,
- the block charter can explain it through receipts and authority anchors,
- and the export’s current durability profile says what survives immediately and what requires a flush barrier.

This charter intentionally allows different durability profiles, but it does **not** allow fake success.
If the durability / exactness class cannot honestly be met, the operation must fail or degrade explicitly.

### Flush and FUA
`FLUSH` / `FUA` are not performance folklore.
Under `block_volume_adapter`, they must bind to:
- an explicit durability class,
- an explicit receipt or barrier token,
- and an explicit answer to “which prior writes are now covered?”

If the system cannot produce that answer, it is not implementing the charter correctly.

### Resize
Resize is not an ambient right of ordinary block writes.
`block_volume_adapter` requires:
- explicit resize policy on the projection,
- explicit policy-domain permission,
- explicit reserve / budget admission,
- and an explicit publication / receipt chain.

Ordinary writes past end may **not** silently resize the volume.

## Exactness and freshness contract

### Exactness class
The intended exactness class for `block_volume_adapter` is:
- **block-exact within the currently admitted export scope**,
- with explicit unsupported or denied answers for operations outside the charter cut,
- and no silent substitution of stale or product-only answers where exactness is promised.

### Freshness class
The block charter is stricter than many explanatory surfaces but still not universal hidden coherence.
It promises:
- the current export sees its own successful mutations under the declared exactness/durability profile,
- readers that share the same admitted export scope must obey the charter’s freshness fence / barrier law,
- remote or alternate exports may lag unless the policy and multi-writer class explicitly buy stronger coordination.

### Baseline anti-folklore rule
A block consumer may be told:
- exact and durable now,
- exact but requiring flush for stronger durability,
- denied by reserve / policy / lease,
- unsupported by charter cut,
- or conflict-blocked by multi-writer contract.

What it may **not** be treated is a cheap success that the underlying authority model cannot later justify.

## Product dependence

### Products that may support the charter
`block_volume_adapter` may use rebuildable products for:
- extent / translation acceleration,
- locality-aware placement maps,
- precomputed zero / discard maps,
- queue-placement products,
- reverse explainers for block ranges,
- and future remote-serving helper products.

### Non-negotiable rule
A missing or stale product may make block export slower.
It may **not** make the charter semantically wrong silently.

If a product is absent or stale, one of these must happen:
- authoritative fallback serves the operation,
- the charter returns an explicitly degraded-but-valid answer,
- or the charter denies the operation with a truthful reason.

What may not happen:
- hidden dependence on stale translation products,
- or product-local state becoming the only real answer to where the bytes “are”.

## Reserve, budget, and capacity promise

### Capacity promise classes
`block_volume_adapter` now makes capacity promise explicit.
A volume projection must declare one of these promise classes:

1. **`capacity.reserved_exact`**
   - the full advertised logical capacity is backed by admitted reserve/claim obligations under current policy.

2. **`capacity.policy_thin`**
   - the advertised logical capacity exceeds current reserved backing, but the charter explicitly discloses that this is thin admission governed by policy, reserve floors, and denial thresholds.

The anti-folklore rule is explicit:
- silent thin provisioning is forbidden.
- if thin capacity exists, it must be declared by the charter and visible to explanation/query and control-policy surfaces.

### Budget and reserve ordering
The block charter spends from:
- publication / serving costs for the export,
- service-budget domains assigned to the volume projection,
- and reserve obligations admitted for capacity and rebuild safety.

It may **not** silently spend:
- protected repair reserve,
- witness reserve,
- or failover escrow that was promised to keep the export recoverable.

Under pressure, the order is:
1. deny or degrade optional products,
2. deny non-essential convenience operations,
3. preserve the declared block exactness / durability contract for already-admitted writes,
4. refuse further growth or mutation before protected reserve floors are violated.

## Distributed and multi-writer law

### Default distributed posture
The default posture for `block_volume_adapter` is:
- one admitted RW export authority domain at a time,
- writer-local when possible,
- read-only mirrors allowed under named freshness fences,
- and failover / handoff governed by lease and reserve-escrow law.

### Multi-writer is explicit and expensive
If a workload wants concurrent writers on one exported volume, the charter must name which `MW*` class is being paid for.

The baseline anti-regression rule is:
- **ambient cheap symmetric shared RW block mutation is forbidden.**

### Failover
Failover / handoff must preserve:
- admitted reserve obligations,
- witness coverage,
- lease/epoch continuity,
- and the ability to explain which flush barriers and receipts were committed before the handoff.

If those cannot be preserved, the export must fail closed rather than fake continuity.

## Observability requirements

Every export should be explainable in charter terms.
At minimum, the system should be able to answer:
- which charter id is in force,
- which projection root and object are exported,
- which capacity promise class is active,
- which write exactness class is active,
- which durability profile is active,
- which writer authority domain and lease are in force,
- which flush barrier receipt / token was last observed,
- whether the export is thin or fully reserved,
- and which intentional cuts apply.


## Intentional cuts for `block_volume_adapter` — continuity: Block Volume Adapter (`block_volume_adapter`)

The current charter should say these cuts out loud.

### Not promised as sovereign truth
- volume UUID is not deepest identity
- export device path is not deepest identity
- block number is not an object identity

### Not promised as ambient cheap cluster behavior
- no hidden split-brain RW export
- no hidden multi-writer exactness without a named expensive-path class
- no universal coherence stronger than the declared freshness / barrier law

### Not promised as silent capacity behavior
- no implicit resize by writes
- no silent thin overcommit
- no invisible reserve-floor violation to keep appearances friendly

### Not promised as local adapter folklore
- queue ids, tag ids, or kernel device names are not portable truth
- helper products may accelerate, but may not become hidden correctness authority

## Relation to other charters

### Relation to `charter.posix_fuse.posix_filesystem_adapter` — continuity: POSIX Filesystem Adapter (`posix_filesystem_adapter`)
`posix_filesystem_adapter` and `block_volume_adapter` may project the same authoritative byte-state objects.
But they remain different charters with different tokens and different user-visible contracts.

Consistency rule:
- if both charters claim success for overlapping mutable state, that success must be jointly explainable through the same authority anchors, receipts, and policy revisions.

### Relation to `charter.control_policy.control_plane` — continuity: Control Plane (`control_plane`)
`control_plane` governs:
- who may export RW,
- resize policy,
- capacity promise class,
- expensive-path admission,
- and service-floor/product rules for the block charter.

### Relation to `charter.explain_query.explanation_query` — continuity: Explanation Query (`explanation_query`)
`explanation_query` must be able to answer questions like:
- why was this volume export admitted RW?
- what reserve class backs its capacity promise?
- which flush barrier receipt covers this completed write?
- why was discard denied?
- why was resize refused?

## Current archived-stage interpretation

During the current design-consolidation phase, `block_volume_adapter` should be treated as:
- a first-class design charter,
- and a source-of-truth constraint on any later ublk / volume implementation work.

This document does **not** authorize implementation.
It makes block / volume semantics explicit enough that future archived-stage or design rule-native work can no longer drift back into vague “volume mode” thinking.

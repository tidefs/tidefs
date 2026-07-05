# tidefs-durability-layout

Crate-local durability layout descriptors, topology helpers, and placement
checks used by TideFS storage code.

This README orients contributors to the APIs in this crate. Product placement,
pool recovery, and release-admission authority lives in the repo-level docs and
issues listed in [Scope Boundaries](#scope-boundaries).

## Durability Policy

A `DurabilityPolicy` encodes the data placement policy:

- **Mirror**: N-way replication (`copies` replicas, 1..=32).
- **ErasureStyle**: k data + m parity shards (1..=32 each).
- **Hybrid**: Mirror across failure domains, erasure-code within each.

Self-verification uses BLAKE3 domain-separated checksums
(context: `TideFS DurabilityLayoutV1 v1`).

## Failure Domain Model

`FailureDomainLevel` defines the four-tier hierarchical failure boundary model
used by this crate:

| Level       | Scope                     |
|-------------|---------------------------|
| Device      | Individual drive / NVMe   |
| Node        | Host / server             |
| Rack        | Physical rack / power domain |
| Datacenter  | Availability zone         |

Higher levels contain lower levels. A level is contained within itself
(Device is contained in Device). The containment semantics enable
placement queries like "do these two devices share a rack?".

### FailureDomainTopology

Flat topology registry (`failure_domain.rs`): nodes assigned to racks and
datacenters, devices assigned to nodes. Provides modeled topology helpers:

- `simulate_node_failure`: computes worst-case modeled
  replica loss using ceil-based distribution.
- Boolean helpers named `can_survive_any_single_node_failure`,
  `can_survive_any_single_rack_failure`,
  `can_survive_n_node_failures`. These report crate-local topology/policy
  calculations; they are not product admission evidence by themselves.

### FailureDomainTree

Deterministic hierarchical tree (`failure_domain_tree.rs`): constructed
from a flat list of `FailureDomainEntry` records (device to node to rack
to dc). The tree is BLAKE3-sealed (context: `TideFS FailureDomainTree v1`)
for offline integrity verification. Provides:

- `share_domain`: check whether two devices share a failure domain at
  any hierarchy level.
- `parent_of`: resolve the ancestor ID at a given level.
- `devices_in_domain`: enumerate all devices under a domain.
- `domain_ids`: list all IDs at a given level.
- `serialize` / `deserialize_verified`: deterministic binary round-trip
  with BLAKE3 integrity guard.

### LayoutValidator

Stateless validator (`layout_validator.rs`): takes a `DurabilityLayoutV1` and a
`FailureDomainTopology`, then reports modeled policy/topology inconsistencies.
It emits `LayoutValidationError` for hard violations and `ValidationWarning`
for suboptimal configurations such as a single rack, over-provisioning, or
replicas sharing nodes.

## Placement

`DomainPlacementMapper` (`layout.rs`) maps object IDs deterministically
to failure-domain targets using BLAKE3 domain-separated hashing per
level. Same (object_id, policy, topology) always yields the same
placement.

`DeviceGroupMapper` (`device_group.rs`) assigns shards to
failure-domain-separated device groups for multi-level redundancy.

`LayoutPolicy` (`policy.rs`) defines crate-local target selection, replica
counts, failure-domain separation constraints, and rebuild-trigger thresholds.
`DefaultLayoutPolicy` is the concrete single-policy implementation.

`LayoutVerifier` (`verify.rs`) validates actual object placements
against the declared policy, detecting co-located replicas,
under-replication, and constraint breaches.

## Scope Boundaries

The types in this crate are source-backed building blocks. They do not, by
themselves, prove pool-wide placement behavior, recovery orchestration,
read-after-topology-change behavior, or any release-admission claim.

Use these existing authorities for broader behavior:

- `../../docs/POOL_WIDE_REDUNDANCY_PLACEMENT_CONTRACT.md` for pool-wide
  placement and receipt behavior.
- `../../docs/ERASURE_CODED_STORE_AUTHORITY.md` for erasure-coded store scope.
- GitHub issues #18, #1735, #1745, #1792, #1860, and #1861 for remaining
  placement, recovery, scrub, and product-admission work.

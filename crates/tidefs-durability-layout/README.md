# tidefs-durability-layout

TideFS-native durability layout descriptor unifying mirror and erasure-style
policies across device and node failure domains.

## Durability Policy

A `DurabilityPolicy` encodes the data placement policy:

- **Mirror**: N-way replication (`copies` replicas, 1..=32).
- **ErasureStyle**: k data + m parity shards (1..=32 each).
- **Hybrid**: Mirror across failure domains, erasure-code within each.

Self-verification uses BLAKE3 domain-separated checksums
(context: `TideFS DurabilityLayoutV1 v1`).

## Failure Domain Model

`FailureDomainLevel` defines the four-tier hierarchical failure boundary
model that applies identically to local multi-device and clustered
multi-node topologies:

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

Flat topology registry (`failure_domain.rs`): nodes assigned to racks
and datacenters, devices assigned to nodes. Provides:

- Failure simulation: `simulate_node_failure` computes worst-case
  replica loss using ceil-based distribution.
- Survival checks: `can_survive_any_single_node_failure`,
  `can_survive_any_single_rack_failure`,
  `can_survive_n_node_failures`.

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

Stateless validator (`layout_validator.rs`): takes a
`DurabilityLayoutV1` and a `FailureDomainTopology`, checks that the
policy can survive single-node, multi-node, rack-level, and
datacenter-level failures. Emits `LayoutValidationError` for hard
violations and `ValidationWarning` for suboptimal configurations
(single rack, over-provisioned, replicas sharing nodes).

## Placement

`DomainPlacementMapper` (`layout.rs`) maps object IDs deterministically
to failure-domain targets using BLAKE3 domain-separated hashing per
level. Same (object_id, policy, topology) always yields the same
placement.

`DeviceGroupMapper` (`device_group.rs`) assigns shards to
failure-domain-separated device groups for multi-level redundancy.

`LayoutPolicy` (`policy.rs`) defines the placement contract:
target selection, replica counts, failure-domain separation constraints,
and rebuild-trigger thresholds. `DefaultLayoutPolicy` is the concrete
single-policy implementation.

`LayoutVerifier` (`verify.rs`) validates actual object placements
against the declared policy, detecting co-located replicas,
under-replication, and constraint breaches.

## Single Durability Mechanism

The same `DurabilityPolicy`, `FailureDomainLevel` hierarchy, and
`LayoutValidator` cover local (single-host multi-device) and clustered
(multi-node) deployments. The placement planner, rebuild runtime,
and scrub repair engine all consume the same failure-domain types
and validators — there is no separate local vs. clustered code path.

## Retired Validation Validation

The old `durability_validation` source-model validation module was retired.
Durability-layout APIs remain product code, but release closure must come from
mounted filesystem, block-volume, or multi-node artifacts that exercise real
placement and recovery behavior rather than canonical source-model rows.

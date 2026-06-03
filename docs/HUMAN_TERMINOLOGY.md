# Human terminology authority

Maturity: **design-law** naming authority for preview-facing source and docs.

TideFS uses human-readable architecture names as the primary source and documentation language. Opaque compact family labels are not acceptable for preview-facing source, package names, CLI output, docs, or new public APIs.

## Current implemented architecture names

| Human name | Rust/package locator | Plain-English role |
|---|---|---|
| Control Plane | `control_plane` | Operator/control API, request envelopes, carrier frames, and control-plane receipts. |
| Publication Pipeline | `publication_pipeline` | Emission tickets and admitted-decision publication. |
| Response Registry | `response_registry` | Visible answers, response indexes, and recall bindings. |
| Truth View | `truth_view` | Operator-visible truth and archive-recall bundles. |
| Archive Control | `archive_control` | Archive disposition, tombstones, and non-live guards. |
| POSIX Filesystem Adapter | `posix_filesystem_adapter` | POSIX/VFS projection path; future FUSE and kernel adapter. |
| Block Volume Adapter | `block_volume_adapter` | Block-volume projection path; future userspace block export and kernel block integration. |
| Explanation Query | `explanation_query` | Operator explanation/query surface. |
| Canonical Schema Codec | `schema_codec` | Fixed-width little-endian encode/decode records and packet codecs. |
| Package Profile Catalog | `package_profile_catalog` | Build profile, capability, bundle, and service-surface manifests. |
| VFS Boundary Mirror | `vfs_boundary_mirror` | Fixed-size VFS boundary mirrors between owned and ABI-safe values. |
| Authority Publication Kernel | `authority_publication` | Future authority publication and head/root movement family. |
| Claim/Reserve/Witness Kernel | `claim_reserve_witness` | Future claim, reserve, witness, repair, escrow, and quorum family. |
| Response Normalizer | `response_normalizer` | Future response-language and charter-rendering family. |

## Current source examples

Human package paths:

```text
crates/tidefs-types-control-plane-core
crates/tidefs-types-publication-pipeline-core
crates/tidefs-types-response-registry-core
crates/tidefs-types-posix-filesystem-adapter-core
crates/tidefs-types-secret-key-policy-core
crates/tidefs-schema-codec-posix-filesystem-adapter
crates/tidefs-schema-codec-vfs
apps/tidefs-posix-filesystem-adapter-daemon/src/runtime
apps/tidefs-posix-filesystem-adapter-daemon
```

Human Rust identifiers:

```text
ControlPlaneRequestEnvelopeHead
PolicyAuthorityRequestCapsuleRecord
PublicationPipelineEmissionTicketRecord
ResponseRegistryVisibleAnswerRecord
PosixFilesystemAdapterProductWakeReceiptRecord
SecretLeaseGrantRecord
LocalFileSystem
LocalObjectStoreFormatRule
```

## Stable locators

Readable locators such as `control_plane`, `policy_authority`, and `schema_codec` may appear in crate imports, stable IDs, and wire strings. They are allowed because they remain understandable English labels.

The rule is not “never use a compact string.” The rule is: **never introduce opaque family labels when a human-readable locator can be used instead.**

## Storage naming rule

The Local Object Store and Local Filesystem already follow the preferred naming pattern:

```text
crates/tidefs-local-object-store
crates/tidefs-local-filesystem
```

Future storage, userspace, kernelspace, and distributed components should follow this pattern.


and source names must not make runtime-output trees, packets, or historical
closeout labels part of the current product surface.

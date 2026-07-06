# Device Lifecycle And Remanence Authority

Issue #1276 records the current TFR-012 device lifecycle decision boundary.
Issue #1536 records the zeroing and media-privacy boundary inside that
decision. Issue #2006 records the follow-up source re-scan for zero-visible
operations, label/superblock zeroing, discard acceptance, cryptographic erase,
secure erase, sanitization, and decommissioning readiness. This is a
documentation authority slice only. It does not change product behavior, admit a
new device mode, or claim production secure erase, cryptographic erase, online
replacement, online removal, decommissioning readiness, or discard/TRIM
readiness.

## Evidence Reviewed

- `docs/REVIEW_TODO_REGISTER.md` TFR-012.
- Closed GitHub issues #14 and #16 for directory-media rejection and the
  byte-addressable pool-member contract.
- GitHub issues #1137 and #983 as nearby documentation-authority and stale-label
  context. Both were closed when this decision was written and are non-blocking
  context for this slice.
- Current pool/device source surfaces in `apps/tidefsctl/`,
  `crates/tidefs-pool-import/`, `crates/tidefs-pool-scan/`,
  `crates/tidefs-local-object-store/`,
  `crates/tidefs-types-pool-label-core/`,
  `crates/tidefs-block-volume-adapter-core/`,
  `crates/tidefs-local-filesystem/`, `crates/tidefs-compression/`, and
  `crates/tidefs-encryption/`.
- Current authority and non-claim docs:
  `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`,
  `docs/CAPACITY_ACCOUNTING_AUTHORITY.md`,
  `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`,
  `docs/TRANSFORM_PIPELINE_AUTHORITY.md`, and
  `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md`.
- Issue #1536 reviewed the zero-visible/media-privacy evidence above plus the
  current block-volume file-image zeroing source, the deleted OW-301 lineage
  retained by git history and issue #1637, and transform privacy guardrails
  before choosing a docs-only clarification for this slice.
- Issue #2006 re-scanned this document, `pool_destroy(..., zero_superblock)`,
  `tidefsctl pool destroy --zero-superblock` reporting, live-owner destroy
  argument routing, block-volume/file-image discard and write-zeroes source, the
  #1823 cryptographic-erase/key-lifecycle authority, the #2004 discard
  capability boundary, the #2005 segment-reclaim remanence boundary, and open PR
  changed files on 2026-07-06. The scan found no source hook required for this
  slice: the current operator-facing wording says which label or zero-visible
  operation ran, not that backing media became private or unrecoverable.

## Current Surfaces

| Surface | Current source behavior | Authority boundary |
|---|---|---|
| User pool-device admission | `tidefsctl pool create --devices` accepts block devices, accepts regular files only behind hidden `--file-devices`, and rejects directories even with that flag. `PoolCreator` opens byte-addressable paths, writes dual labels, writes the initial committed-root region, and zeroes the start of the data region. | Current pool-member media are byte-addressable: production block devices or explicit development regular-file images. Directory object-store roots are not user-admitted pool media. |
| Hidden development media | `DeviceBacking` distinguishes `BlockDevice`, `RegularFileDev`, and `DirectoryObjectStoreCompat`. The first two are byte-addressable pool members; the directory variant remains compatibility/test storage. | Regular files are development byte devices. Directory compatibility is not a pool-member device mode and cannot imply discard or remanence capability. |
| Pool labels and config | `PoolLabelV1` stores pool state, device GUID, device index/count, topology generation, class, capacity, features, and layout sidecar data. `pool_destroy(..., zero_superblock=true)` can zero the label area after marking the pool destroyed, and `remove_device_from_label()` only decrements `device_count` and increments `topology_generation`. | Labels identify and persist topology facts. Label/superblock zeroing is import refusal and stale-label hygiene, not proof of evacuation, replacement durability, refcount zero, whole-device zeroing, cryptographic erase, or privacy semantics. |
| Operator removal/rebuild commands | `tidefsctl device remove` routes to a reachable live owner or fails closed. Retired `--backing-dir`, `--surviving-dirs`, and hidden directory rebuild modes refuse before opening directory stores. | CLI argument parsing is not device lifecycle authority. A product removal must be owner-mediated and receipt-backed. |
| Local pool removal helpers | `Pool::safe_remove_device()` writes a removal-pending marker, enumerates placement receipts, rewrites receipt-backed logical objects through surviving devices, fails closed on unreceipted logical keys, removes the device only after evacuation, and can resume from the marker. The mounted live-owner path reports evacuation counts and also reports that active label persistence is still TFR-011/TFR-012 work. | This is useful implementation evidence, but not a closed online-removal product contract until mounted topology labels, resumable authority, validation, and remanence policy are completed. |
| Replacement helpers | `Pool::replace_device()` swaps in a new device, updates local config/media/layout stats, rebuilds the allocator, bumps placement epoch, and records `DeviceReplacement` state for TFR-012 evacuation and detach completion. | Replacement is not product-ready authority. It lacks the completed evacuation/detach, label, durability, and remanence boundary required for online replacement. |
| Directory object-store discard | `SingleDevice` directory compatibility returns `supports_discard() == false`; zero-length discard is a no-op, and non-zero discard fails explicitly. Directory-only pool trim/free tests report zero bytes discarded. | Directory compatibility has no discard/TRIM/remanence claim. |
| Pool discard/TRIM forwarding | `Pool::discard_ranges()`, `discard_unused()`, `free_blocks()`, and `trim_free_space()` call `discard_range()` only on devices that report `supports_discard()` and return accepted byte counts. | The API is a dispatch surface, not a product promise. Product discard needs per-backing capability probing, typed refusal/result evidence, and validation. |
| Segment reclaim | Segment free still performs best-effort `fallocate -p` hole punching for freed segment files when that compatibility path has segment files. Failures are ignored. | Hole punching is a sparse-file space reclamation hint, not media erasure, secure delete, or proven TRIM. |
| Block-volume discard/write-zeroes | The block-volume core and file-backed image model record discard intents, refuse unsupported or misaligned discard, and make discard/write-zeroes ranges zero-visible in the model/file image. The file image may punch holes and falls back to zero-fill. | Zero-visible here means later reads through the block-volume model or file image return zero bytes for that range. This is scoped block-volume data-semantics evidence, not live pool-device discard readiness and not a remanence, cryptographic-erase, or secure-erase guarantee. |
| Local filesystem sparse/zero operations | `punch_hole`, `zero_range`, truncate, rewrite trims, and `trim_blocks()` update logical/physical accounting, queue reclaim, and forward explicit trim ranges to the pool store. | Zero-visible filesystem semantics and capacity accounting are separate from media-remanence policy. |
| Capacity and reclaim | `CapacityAuthority` owns mounted capacity projections and `record_free()`. Background reclaim queues processed object keys for deletion by the owning filesystem. | Capacity recovery and object deletion are not physical erasure evidence. Reclaim must publish committed free/reclaim evidence before any remanence claim can consume it. |
| Transform wrappers | Compression and encryption device wrappers forward `supports_discard()` and `discard_range()` unchanged and state that transforms do not affect TRIM byte ranges. Mounted transform docs still block device-level compression/encryption claims while raw-store bypass rows remain. | Transform pass-through is not privacy authority. Compression/encryption affect observability, plaintext identity, stored-frame identity, and remanence risk; they need an explicit policy before product claims. |

## Authority Models Compared

| Model | Strengths | Problems | Decision |
|---|---|---|---|
| Pool-authoritative placement, refcount, and receipt-driven lifecycle | Uses the layer that owns placement receipts, redundancy policy, live owner routing, topology generation, capacity updates, and reclaim ordering. It can fail closed on unreceipted data and commit label changes only after evacuation/replacement evidence is durable. | Requires follow-up implementation and runtime validation across pool, mounted owner, label persistence, and reclaim paths. | Chosen product boundary. |
| CLI/local-helper-driven evacuation and label edits | Simple to trigger and close to operator commands. Existing retired directory helpers and label helpers show how small operations can be scripted. | It cannot prove all data was moved, cannot own mounted writers, cannot own replacement receipt durability, and can mistake directory compatibility paths for real media. | Rejected as product authority. CLI commands are routing/projection surfaces only. |
| Explicit discard-capability and remanence policy | Separates "range accepted by a discard-capable backing" from "data is unrecoverable." It allows typed refusal for unsupported media and clear privacy non-claims for regular files, transforms, and device firmware behavior. | Requires per-backing probes/results, validation rows, and policy wording before product claims. | Chosen product boundary. |
| Best-effort sparse-file hole punching as TRIM/remanence authority | Cheap and already present in compatibility/file-image paths. | Hole punching may be ignored, may leave data recoverable below the file system, and does not compose with block devices, encryption, compression, snapshots, or reclaim receipts. | Rejected for product claims. Allowed only as a compatibility/development space-reuse hint. |
| Transform-wrapper pass-through as privacy authority | Keeps discard byte ranges unchanged through simple wrappers. | It ignores whether discarded byte ranges identify plaintext, compressed frames, encrypted frames, checksums, receipts, or raw media bytes. | Rejected. Transform-aware storage authority must define privacy semantics before discard/remanence claims. |

## Zeroing And Media-Privacy Alternatives

Issue #1536 compared these options:

| Alternative | Decision for this slice | Reason and follow-up boundary |
|---|---|---|
| Docs-only non-claim clarification | Adopted. | The reviewed source and authority docs already support zero-visible data semantics in block-volume/file-image paths, label-area zeroing for pool destroy/import refusal, discard acceptance/refusal surfaces, and transform-wrapper pass-through. None of those require new runtime behavior to state the current non-claims. |
| Typed policy/refusal hook for future commands | Deferred to follow-up implementation issues. | A hook is required before an operator command may claim remanence policy, media sanitization, decommissioning readiness, or typed privacy refusal/result reporting. The non-overlapping rows below keep that work in device capability/reporting, command projection, pool labels, and runtime-validation slices instead of this docs-only decision. |
| Separate encryption/key-lifecycle follow-up for cryptographic erase semantics | Deferred and kept outside this TFR-012 slice. | Cryptographic erase would need transform-authority conformance, key-hierarchy and key-destruction semantics, persisted transform metadata, recovery/rekey behavior, and validation that encrypted data is unreachable after key lifecycle events. Lower encryption wrappers and key handles are not enough to make that claim. |

## Decision

TideFS current authority is:

1. Pool members are byte-addressable media only: block devices for production and
   explicit regular-file images for hidden development mode.
2. Directory `LocalObjectStore` compatibility remains internal/test/offline
   compatibility. It is not product pool media, does not support discard, and
   does not provide remanence or secure-delete evidence.
3. Product device removal/replacement authority must live at the pool owner that
   can freeze or route writers, consume placement/refcount evidence, rewrite or
   rebuild through the redundancy policy, publish committed evacuation or
   replacement receipts, update labels/topology only after durability evidence,
   and leave resumable crash state.
4. Discard/TRIM authority must be explicit per backing. A future implementation
   must distinguish unsupported media, accepted discard requests, zero-visible
   data semantics, bytes actually reported accepted, and any stronger privacy
   claim. Accepted discard is still not secure erase unless a later policy and
   validation issue proves that exact scope.
5. Segment reclaim, object deletion, `record_free()`, file-image hole punching,
   block-volume zero visibility, and filesystem `zero_range` are capacity or
   data-semantics operations. They are not media-remanence guarantees.
6. Transform wrappers forwarding discard unchanged is an implementation detail.
   Privacy/remanence semantics for compressed or encrypted storage must be
   decided at the transform-aware storage authority, not inferred from wrapper
   byte-range pass-through.
7. Label/superblock zeroing can make a TideFS label area unreadable as a pool
   label, and pool creation may zero known bootstrap/data-region bytes. That is
   not whole-device zeroing, secure erase, cryptographic erase, or
   decommissioning evidence.

## Current Semantic Boundary

| Semantics | Current TideFS support | Evidence required for a stronger claim |
|---|---|---|
| Zero-visible block-volume/file-image reads | Supported inside the block-volume core/file-image model: discard or write-zeroes ranges are made visible as zeros through that model. | A stronger claim would need live block-device/ublk behavior, guest/filesystem validation, and media-specific discard/result evidence; it still would not imply secure erase by itself. |
| Local filesystem zero-range and sparse-hole reads | Supported as logical mounted data semantics and capacity/accounting behavior. | A stronger claim would need receipt-backed reclaim evidence and backing-media policy proving what happened below the logical file layer. |
| Pool label/superblock zeroing | Supported as label-area hygiene and import refusal for explicit destroy paths. | A stronger decommissioning claim would need whole-device scope, evacuation/refcount evidence, crash-safe command receipts, and media privacy policy for every backing. |
| Accepted discard/TRIM requests | Not product-ready. Current pool paths can forward ranges only when a backing reports discard support, and directory compatibility refuses non-zero discard. | A stronger claim needs per-backing capability probing, accepted-byte reporting, fail-closed refusals, and focused validation for the exact device class. |
| Segment/object reclaim and file-image hole punching | Capacity and sparse-file space-reuse hints only. | A stronger remanence claim needs policy that consumes committed placement/reclaim evidence and proves backing-media behavior; best-effort hole punching is insufficient. |
| Transform-wrapper discard forwarding | Implementation detail only. | Compression/encryption privacy claims need transform-authority conformance, stored-frame metadata, key lifecycle policy, and validation; byte-range pass-through is not enough. |
| Cryptographic erase | Not supported and not claimed by zeroing, discard, label deletion, or key-state changes alone. #1823 owns the narrow key-lifecycle assessment. | A stronger claim needs transform metadata, stored-frame reachability, fully encrypted payload classification, documented media/remanence limits, and targeted validation before product wording may change. |
| Secure erase, sanitization, or decommissioning readiness | Not supported and not claimed. | These need separate design authority, source hooks or command projection as applicable, whole-device or media-specific evidence, and targeted validation before product wording may change. |

## Explicit Non-Claims

This decision does not claim:

- secure erase, cryptographic erase, sanitization, or decommissioning readiness;
- production remanence guarantees for block devices, SSDs, regular-file images,
  sparse files, thin-provisioned storage, encrypted pools, compressed pools, or
  directory compatibility stores;
- product-ready online device removal, replacement, hot-spare activation, or
  failed-device rebuild;
- that `trim_blocks()`, `discard_ranges()`, block-volume discard, file-image
  hole punching, or segment free proves TRIM on real backing devices;
- that zero-visible reads after discard/write-zeroes imply data is unrecoverable
  from the backing medium;
- that `--zero-superblock`, `"zero_superblock"`, or `superblock zeroed: yes`
  means more than TideFS label/superblock-area hygiene and import refusal;
- that directory-backed compatibility paths are valid pool-member devices;
- that label-only topology edits are sufficient without evacuation/refcount and
  durability evidence;
- that OpenZFS/Ceph prior-art references are current TideFS parity, availability,
  or operational-superiority claims.

## Unresolved Risks

- The pool removal helper has placement-receipt awareness and resume markers,
  but mounted active-label persistence and full runtime validation remain open.
- Replacement state exists, but old-device evacuation, detach, label commit, and
  failed-device rebuild authority are not closed.
- No current byte-device path proves real discard capability or typed discard
  result reporting for production pool members.
- Segment and object reclaim can free capacity while old bytes may remain on
  backing media.
- Transform ordering, raw-store bypass rows, and stored-frame identity still
  block any mounted device-level compression/encryption privacy claim.
- Device firmware behavior, thin provisioning, RAID controllers, filesystems
  below regular-file images, and cloud/block backends may ignore or reinterpret
  discard and zeroing commands.

## Follow-Up Issue Map

Open or match focused GitHub issues from this map before implementation. These
rows are intended to keep write sets non-overlapping.

| Follow-up slice | Expected write set | Acceptance boundary | Validation tier |
|---|---|---|---|
| Real byte-device discard capability | `crates/tidefs-local-object-store/src/device.rs`, `store.rs`, pool discard helpers, `crates/tidefs-pool-scan/`, and focused `apps/tidefsctl/` reporting if needed. | Probe/report discard capability for `BlockDevice` and `RegularFileDev`, keep unsupported media fail-closed, and distinguish accepted discard from secure erase. | Focused Rust plus the smallest GitHub Actions row that covers device admission/discard behavior. |
| Segment-reclaim remanence policy | `crates/tidefs-local-object-store/src/store.rs`, reclaim queue/drain surfaces, and a narrow docs update to this authority if behavior changes. | Decide whether segment free remains capacity-only or emits typed remanence/refusal evidence; never count best-effort hole punching as secure erase. | Documentation/source inspection first, then focused reclaim/object-store validation if behavior changes. |
| Online removal authority closeout | `crates/tidefs-local-object-store/src/pool/mod.rs`, mounted live-owner routing/reporting in `crates/tidefs-local-filesystem/`, pool label persistence helpers, and focused `apps/tidefsctl device remove` projection. | Removal completes only after committed evacuation/refcount evidence, durable label/topology update, resumable crash state, and explicit no-remanence claim or policy hook. | Focused Rust plus targeted runtime workflow for the smallest mounted/live-owner removal row. |
| Online replacement and rebuild authority | Replacement/rebuild state in `crates/tidefs-local-object-store/src/pool/mod.rs`, placement/rebuild receipt consumers, label persistence helpers, and focused operator projection. | Replacement records durable replacement/rebuild evidence, detaches the old device only after evidence is stable, and states media-remanence treatment. | Focused Rust plus targeted runtime workflow for replacement/rebuild once isolated. |
| Zeroing and media privacy policy | Issue #2006 re-scanned this authority doc, pool destroy/zero-superblock docs and command projection, block-volume/file-image zero docs, live-owner destroy argument routing, #1823, #2004, #2005, and open PR changed files. | Zero-visible data semantics, label/superblock zeroing, discard acceptance, cryptographic erase, secure erase, sanitization, and decommissioning readiness are separate. Current wording may report the exact zeroing/discard action, but must not imply privacy, remanence, sanitization, or decommissioning evidence from that action. | Documentation/source inspection completed for the current wording; no runtime unless behavior changes or a later issue adds typed reporting/refusal hooks. |
| Cryptographic erase and key lifecycle semantics | Issue #1823 narrows this source boundary in `docs/TRANSFORM_PIPELINE_AUTHORITY.md`, `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`, `docs/security/pool-encryption-secret-handle-boundary.md`, `crates/tidefs-encryption/`, and `crates/tidefs-secret-key-policy-runtime/`. | Source-owned lifecycle assessment covers active, rotating, revoked, quarantined, retired, missing, stale, and recovery-after-crash mounted access states. Key revocation/destruction cannot be presented as secure erase unless transform metadata, stored-frame reachability, media/remanence limits, and fully encrypted payload classification are explicitly proven; plaintext, compressed-only, unencrypted, partially transformed, raw-store-bypassed, or previously exposed media remain fail-closed non-claims. | Focused encryption/key-lifecycle Rust validation plus mounted-transform and claims-gate checks; no remanence, decommissioning, or secure-erase claim is admitted by this row alone. |
| Device lifecycle runtime validation matrix | Workflow inputs or validation harness metadata only after implementation slices define exact behavior. | Add smallest supported rows for discard, removal, replacement, rebuild, and remanence-policy refusals without broadening this design issue. | GitHub Actions focused validation; no local heavy validation. |

## Merge Gate For Future Slices

Any future issue or PR that treats device removal, replacement, discard, zeroing,
or remanence as product-ready must link this document, name the follow-up row it
implements, and show evidence for the exact boundary it claims. If a slice needs
to change `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` or historical design files,
it must be its own documentation-authority issue rather than expanding this
TFR-012 decision.

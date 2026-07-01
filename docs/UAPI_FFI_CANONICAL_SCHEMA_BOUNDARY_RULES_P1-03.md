# UAPI / FFI / canonical-schema boundary rules (P1-03) (v0.357)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This document is the source-of-truth for the production-depth UAPI / FFI /
canonical-schema boundary rules for tidefs.

It answers the question:

**How does tidefs let FUSE packets, ioctl/statx/flag structs, future ublk and
kernel-visible frames, and `repr(C)` or `ctypes` call boundaries exist without
letting any Linux-visible or C-visible layout become a second canonical schema
universe or a hidden source of authority?**

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md`
- `docs/STD_NO_STD_KERNEL_USERSPACE_BOUNDARY_RULES_P1-02.md`
- `docs/DOCTRINE_FAMILY_TO_RUST_TYPE_MAP_P2-01.md`
- `docs/CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md`
- `docs/LINUX_7_0_BASELINE_CONTRACT_SUPPORTED_SUBSYSTEMS_P0-01.md`
- `docs/PRODUCT_VARIANT_MATRIX_P0-02.md`
- `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`
- `docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md`
- `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md`
- `docs/BLOCK_VOLUME_UBLK_STARTED_EXPORT_ADMISSION_BOUNDARY_ISSUE_341.md`
- `docs/VFS_BLOCK_INTEGRATION_KERNEL_UAPI_LAW_P7-04.md`
- `docs/RUST_FOR_LINUX_CRATE_TRAIT_BOUNDARIES_P7-02.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Core result

The production design now has one explicit family for UAPI / FFI /
canonical-schema boundary truth:

- one coordinating family:
  **`family.uapi_ffi_canonical_schema_boundary.vfs_boundary_mirror`**
- one topology law:
  **`law.uapi_ffi_canonical_schema_boundary.vfs_boundary_mirror`**
- one canonical boundary chain:
  - **design rule family / `type_map` row / `binary_schema` payload -> canonical schema owner -> borrowed view or owned mirror -> boundary descriptor -> userspace wire frame / kernel-visible UAPI struct / C-call frame -> exactness / continuity receipt -> `response_registry` / `truth_view` / gate binding**

The production design now also fixes:

- **8 stable boundary-surface classes**
- **8 stable value-shape classes**
- **10 stable conversion-edge classes**
- **7 stable continuity / exactness classes**
- **10 required record families**
- **10 required algorithms**

This means tidefs is no longer allowed to say only:

- "the Linux header or `repr(C)` struct is basically the real type,"
- "FUSE packets can just be the request model and the reply model at once,"
- "ioctl/statx/flag mirrors can quietly define the durable semantics,"
- "a `ctypes` frame can carry canonical ownership if it is convenient,"
- or "adapter-local errno, handle, or padding conventions are close enough to
  the design rule rows."

It must instead say:

- which surface class is canonical and which classes are mirrors only,
- which borrowed views are exact projections over `binary_schema` bytes,
- which owned mirrors or builders are legal at each boundary,
- which fixed-width layout, padding, reserved-zero, and optional-tail rules
  govern each Linux-visible or C-visible frame,
- which status / errno / feature-mask surfaces are render-only and explicitly
  lossy,
- and which receipt proves the boundary still agrees with `type_map`, `binary_schema`, `environment_boundary`,
  `linux_baseline`, `product_variant`, and `package_profile_catalog`.

The anti-regression rule is explicit:

**No future Rust or kernel-prepared code may let FUSE packets, ioctl/statx
structs, ublk-style command frames, `repr(C)` wrappers, `ctypes` call payloads,
or Linux-visible errno/flag mirrors become canonical type owners unless that
move is first represented in the declared `vfs_boundary_mirror` surface, shape, conversion,
and continuity records fixed here.**

## 2. Scope and boundaries

This document governs:

- the stable classes for Linux-visible and C-visible boundary surfaces,
- the binding from `type_map` owner rows and `binary_schema` byte families to borrowed views,
  owned mirrors, and adapter-local boundary frames,
- the exactness law for fixed-width structs, bitmasks, optional tails,
  reserved/padding bytes, and negotiation capsules,
- the rule that FUSE, ioctl, statx, fs-flag, and future ublk or kernel-visible
  layouts are mirror-only surfaces rather than sovereign schema owners,
- the rule that `repr(C)` / `ctypes` call frames may move handles and fixed
  values across the boundary without leaking allocator ownership or canonical
  meaning,
  later kernel-prepared stages still share one representation law.

That boundary is deliberate.
`P1-03` fixes **where canonical schema ends and where Linux-visible or C-visible
layout begins**.

It now consumes the explicit `workspace_layout` workspace-family / crate-service-boundary law
in `docs/WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md`, the
explicit `environment_boundary` std / `no_std` / userspace / kernel boundary law in
`docs/STD_NO_STD_KERNEL_USERSPACE_BOUNDARY_RULES_P1-02.md`, the explicit `type_map`
design rule-family to Rust-type map in
`docs/DOCTRINE_FAMILY_TO_RUST_TYPE_MAP_P2-01.md`, the explicit `binary_schema` canonical
binary law in `docs/CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md`,
the explicit `linux_baseline` Linux 7.0 baseline contract in
`docs/LINUX_7_0_BASELINE_CONTRACT_SUPPORTED_SUBSYSTEMS_P0-01.md`, the explicit
`product_variant` product-variant matrix in `docs/PRODUCT_VARIANT_MATRIX_P0-02.md`, the
explicit `package_profile_catalog` build / packaging / feature-matrix law in
`docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`, the explicit `posix_filesystem_adapter` daemon /
process-topology law in `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md`, and the
explicit `P7-04` VFS/block integration / Linux 7.0 UAPI law in
`docs/VFS_BLOCK_INTEGRATION_KERNEL_UAPI_LAW_P7-04.md`, so type ownership,
environment boundaries, bytes-on-the-wire, Linux-visible structs, package rows,
and future kernel surfaces are no longer allowed to drift into adapter-local
convenience.

It now also consumes the explicit `seam_map` shared design rule-native seam-map law in `docs/SHARED_DOCTRINE_NATIVE_SEAM_MAP_P0-03.md`, so seam ownership, client/boundary bindings, kernel-promotion cuts, and anti-leak rules are no longer allowed to drift from the declared cross-system registry. It now also consumes the explicit `non_authority_deletion` non-authority / deletion law in `docs/NON_AUTHORITY_DELETION_LAW_P0-04.md`, so live archived residue, archive-only carriers, tombstone/delete bindings, and non-authority proof are no longer allowed to drift from the declared product boundary. They may **not** invent a
second representation law, a second `repr(C)` owner universe, or a second
Linux-visible semantics grammar outside `vfs_boundary_mirror`.

## 3. Repo anchor snapshot

The production law is grounded in real repo surfaces rather than pure future
prose:

  request / handle / attr / stat / lock families are typed engine-owned values,
  not Linux wire structs.
  adapter boundary is a protocol surface over typed engine values rather than a
  direct `/dev/fuse` or `ioctl` struct dependency.
  prove that Linux FUSE wire layout, field-width, and encode/decode machinery
  are materially separate from engine-owned types.
  transport carriers can consume the same typed engine surface without becoming
  sovereign schema owners.
  layout details, statx attributes, dirent typing, and utime markers are real
  boundary families that need named law.
- `docs/VFS_BLOCK_INTEGRATION_KERNEL_UAPI_LAW_P7-04.md`,
  `docs/BLOCK_VOLUME_UBLK_STARTED_EXPORT_ADMISSION_BOUNDARY_ISSUE_341.md`, and
  `docs/POSIX_CHARTER_TEST_XFSTESTS_MATRIX_P5-04.md` already assume that
  Linux-visible carrier structs are projection mirrors, not hidden authority.

## 4. Metrics snapshot

| Metric | Count |
|---|---:|
| Stable boundary-surface classes | 8 |
| Stable value-shape classes | 8 |
| Stable conversion-edge classes | 10 |
| Stable continuity / exactness classes | 7 |
| Required record families | 10 |
| Required algorithms | 10 |
| Existing FUSE ABI support modules grounded here | 5 |
| Existing transport backends grounded here | 2 |
| Existing dedicated ABI tests grounded here | 4 |

## 5. Boundary-surface law

### 5.1 Stable boundary-surface classes

The future Rust tree and later kernel-prepared surfaces must use exactly these
boundary classes:

| Surface class | Meaning | Authority status |
|---|---|---|
| `surface.vfs_boundary_mirror.canonical_schema_owner.s0` | design rule-owned `type_map` / `binary_schema` / receipt/schema truth | authoritative |
| `surface.vfs_boundary_mirror.borrowed_canonical_view.s1` | borrowed zero-copy decode view over canonical bytes | exact non-sovereign mirror |
| `surface.vfs_boundary_mirror.owned_boundary_mirror.s2` | owned mirror, builder, or adapter-local helper derived from canon | non-sovereign mirror |
| `surface.vfs_boundary_mirror.userspace_protocol_frame.s3` | userspace wire frame such as FUSE request/reply payloads | non-sovereign mirror |
| `surface.vfs_boundary_mirror.kernel_uapi_struct.s4` | Linux-visible ioctl/statx/flag or later kernel/client struct layout | non-sovereign mirror |
| `surface.vfs_boundary_mirror.c_ffi_call_frame.s5` | `repr(C)` or `ctypes` call argument/return layout | non-sovereign mirror |
| `surface.vfs_boundary_mirror.negotiation_capsule.s6` | version / feature / capability / init negotiation frame | gate-relevant mirror |
| `surface.vfs_boundary_mirror.status_refusal_mirror.s7` | errno, status code, refusal tag, or render-only outcome mirror | explicitly lossy mirror |

### 5.2 Surface invariants

The boundary law is strict:

- `s0` is the only class that may own durable semantics, policy meaning,
  replay-significant schema, or authoritative receipt lineage.
- `s1` may borrow canonical bytes or scalar views but may not own allocator,
  OS-handle, process, or kernel-object state.
- `s2` may hold fixed-width copies, byte buffers, builders, or wrapper newtypes,
  but it may not quietly define new semantics or durability law.
- `s3`, `s4`, and `s5` may carry Linux-visible or C-visible layout, but they
  may only mirror canon through declared conversion edges.
- `s6` is allowed to influence gate admission, but it is not durable schema
  truth; the durable truth is the capability or gate receipt bound back to
  `linux_baseline`, `product_variant`, `package_profile_catalog`, `environment_boundary`, and `kernel_gateway`.
- `s7` is allowed to be lossy. It may collapse truth into errno, status tag,
  short refusal code, or operator-visible flag set only when `response_registry` / `truth_view`
  render policy says that loss is legal.
- no `s3`, `s4`, `s5`, `s6`, or `s7` class may own object identity,
  publication epoch, policy revision, override truth, or replay cursor meaning.

## 6. Value-shape, conversion, and exactness law

### 6.1 Stable value-shape classes

| Shape class | Meaning | Typical examples |
|---|---|---|
| `shape.vfs_boundary_mirror.fixed_scalar.q0` | fixed-width scalar with declared endian and width | `u32`, `u64`, little-endian counters |
| `shape.vfs_boundary_mirror.bitflag_mask.q1` | declared bitmask with reserved-bit policy | FUSE init flags, ioctl flag masks |
| `shape.vfs_boundary_mirror.fixed_layout_struct.q2` | fixed-layout struct with declared padding and reserved fields | FUSE headers, statx structs |
| `shape.vfs_boundary_mirror.counted_varlen_buffer.q3` | length-delimited byte tail or payload | xattr bytes, ioctl arg buffers |
| `shape.vfs_boundary_mirror.raw_bytes_name_or_path.q4` | raw bytes that are not assumed UTF-8 | POSIX names, symlink payloads |
| `shape.vfs_boundary_mirror.opaque_handle_or_cookie.q5` | opaque token that never becomes durable canon | file handles, cookies, fd-like ids |
| `shape.vfs_boundary_mirror.enum_or_status_tag.q6` | enum tag, errno/status code, or refusal tag | node kinds, errno mirrors |
| `shape.vfs_boundary_mirror.negotiated_capability_vector.q7` | versioned feature or capability vector | INIT negotiation flags, feature masks |

### 6.2 Stable conversion-edge classes

| Edge class | Source -> target | Status | Meaning |
|---|---|---|---|
| `edge.vfs_boundary_mirror.canon_to_binary_schema.e0` | design rule / `type_map` -> `binary_schema` | allowed | canonical design rule families become canonical bytes through `binary_schema` only |
| `edge.vfs_boundary_mirror.binary_schema_to_borrowed_view.e1` | `binary_schema` -> `s1` | allowed | zero-copy borrowed views derive from canonical bytes |
| `edge.vfs_boundary_mirror.borrowed_to_owned_mirror.e2` | `s1` -> `s2` | allowed | owned mirrors/builders may be materialized from exact canonical views |
| `edge.vfs_boundary_mirror.owned_to_userspace_frame.e3` | `s2` -> `s3` | allowed | userspace wire payloads are rendered from declared mirrors |
| `edge.vfs_boundary_mirror.userspace_frame_to_engine_value.e4` | `s3` -> engine-owned typed values | allowed | adapters decode wire frames into typed engine requests/replies |
| `edge.vfs_boundary_mirror.owned_to_kernel_uapi.e5` | `s2` <-> `s4` | allowed | ioctl/statx/flag mirrors re-encode from declared owned mirrors |
| `edge.vfs_boundary_mirror.owned_to_c_ffi.e6` | `s2` <-> `s5` | allowed | `repr(C)` / `ctypes` frames marshal through declared mirror types |
| `edge.vfs_boundary_mirror.canon_to_status_mirror.e7` | canon / receipt -> `s7` | allowed if declared lossy | results/refusals map to errno/status/render-only mirrors |
| `edge.vfs_boundary_mirror.boundary_to_canon_ownership.e9` | `s3`/`s4`/`s5`/`s6`/`s7` -> `s0` owner | forbidden | no Linux-visible or C-visible layout becomes canonical owner by convenience |

### 6.3 Stable continuity / exactness classes

| Continuity class | Meaning |
|---|---|
| `wire.vfs_boundary_mirror.fixed_exact.c0` | layout is exact, fixed-width, endian-declared, and fully lossless |
| `wire.vfs_boundary_mirror.feature_gated_tail.c2` | optional fields appear only under a declared feature/version gate |
| `wire.vfs_boundary_mirror.version_negotiated_caps.c3` | capability set is valid only through explicit negotiation records |
| `wire.vfs_boundary_mirror.lossless_mirror.c4` | mirror round-trips without semantic loss |
| `wire.vfs_boundary_mirror.declared_lossy_render.c5` | mirror is intentionally lossy and may be used only for render/refusal surfaces |
| `wire.vfs_boundary_mirror.refusal_required.c6` | incompatible or owner-violating conversion must refuse rather than silently coerce |

### 6.4 Exactness rules

The exactness law is explicit:

- every `s3`, `s4`, or `s5` layout must declare width, endian, alignment,
  reserved bytes, optional-tail law, and whether it is fixed or negotiated;
- `usize`, `isize`, native `long`, naked pointers, ambient allocator ownership,
  and platform-width-dependent layout are forbidden in canonical boundary
  records;
- raw names and paths stay bytes across the boundary unless the chartered
  surface explicitly declares a render-only text mirror;
- opaque handles and cookies remain runtime-local tokens and must never become
  durable object ids or canonical receipt keys;
- status/errno mirrors may collapse semantics only through `wire.vfs_boundary_mirror`
  lossy-render records;
- and any undecodable, width-violating, or reserved-bit-breaking frame must
  produce a declared refusal rather than a hidden adapter-local fallback.

## 7. Canonical ownership matrix

| Concern | Canonical owner | Admitted mirrors | Forbidden drift |
|---|---|---|---|
| object identity, receipts, policy revisions, replay-significant rows | design rule families, `type_map`, `binary_schema`, receipt/schema records | `s1`, `s2` | any FUSE/UAPI/FFI struct as owner |
| inode/attr/xattr/lock/file-range semantics | engine-owned typed values and canonical schema rows | FUSE request/reply frames, ioctl mirrors | adapter-local archived/Rust structs defining semantics |
| block/export/fence/resize semantics | canonical rows plus `schema_codec`/`response_registry` receipts | future ublk or ioctl mirrors | queue-local command structs becoming truth |
| negotiation and capability admission | `linux_baseline` / `product_variant` / `package_profile_catalog` / gate receipts | init/capability vectors, feature masks | raw feature bits acting as durable source-of-truth |
| OS handles, cookies, mount args, fd-like tokens | runtime capsules and `memory_arena_0` ownership tokens | `u64` handles, `ctypes` frames, ioctl args | durable canon depending on process-local handles |
| errno / status / refusal tags | canonical refusal/result classes and render policy | Linux errno, short status enums, operator result tags | errno or status tag re-defining canonical cause |

## 8. Canonical boundary/schema families

| Record | Purpose | Authority class |
|---|---|---|
| `UapiFfiSurfaceClassRecord` | one declared surface class, carrier family, authority status, and owner law | authoritative declaration |
| `UapiFfiValueShapeRecord` | one declared fixed-width / bitmask / varlen / handle shape class and encoding law | authoritative declaration |
| `UapiFfiMirrorTypeRecord` | one borrowed view, owned mirror, builder, or wrapper type bound to `type_map` rows or `binary_schema` families | authoritative binding |
| `UapiFfiWireLayoutRecord` | one userspace wire header/body/tail layout with endian, width, and reserved-field policy | authoritative declaration |
| `UapiFfiKernelUapiRecord` | one kernel-visible ioctl/statx/flag or later UAPI mirror with conversion and continuity law | authoritative declaration |
| `UapiFfiCallFrameRecord` | one `repr(C)` or `ctypes` call frame with ownership, handle, and error contract | authoritative declaration |
| `UapiFfiNegotiationProfileRecord` | one version / feature / capability profile and gate binding | authoritative binding |
| `UapiFfiStatusMappingRecord` | one canonical result/refusal to errno/status/render mirror mapping | authoritative mapping |
| `UapiFfiConversionEdgeRecord` | one admitted or forbidden conversion edge between surface classes | authoritative declaration |
| `UapiFfiBoundaryGateReceipt` | proof one boundary family obeys `vfs_boundary_mirror` layout, continuity, and owner rules | authoritative gate artifact |

These families are added to `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`
by this turn.

## 9. Required algorithms

The production UAPI / FFI boundary law requires these algorithms to exist in
the shared algorithm set:

1. **`declare_vfs_boundary_mirror_surface_classes_and_owner_cut()`**
2. **`bind_type_map_rows_and_binary_schema_families_to_vfs_boundary_mirror_mirror_types()`**
3. **`declare_vfs_boundary_mirror_wire_layout_and_reserved_field_policy()`**
4. **`encode_canonical_payload_into_userspace_protocol_frame()`**
5. **`decode_userspace_protocol_frame_into_typed_engine_value()`**
6. **`encode_or_decode_kernel_uapi_mirror_from_owned_boundary_value()`**
7. **`marshal_or_unmarshal_c_ffi_call_frame_without_canonical_leakage()`**
8. **`compile_errno_status_and_refusal_mappings_from_canonical_results()`**
10. **`issue_vfs_boundary_mirror_boundary_gate_receipt_or_stop_ticket()`**

## 10. Whole-system operational paths added by this law

1. `/dev/fuse` request arrives -> `fuse_abi_wire` layout is decoded into one
   declared `s3` userspace protocol frame -> `decode_userspace_protocol_frame_into_typed_engine_value()` produces typed engine values instead of treating Linux headers as canonical request owners
2. `setattr`, `statx`, fs-flag, or ioctl path needs Linux-visible layout -> one
   `UapiFfiKernelUapiRecord` plus `UapiFfiStatusMappingRecord` maps canonical
   values and refusals into `s4` kernel UAPI structs and `s7` errno/status
   mirrors -> Linux-visible surfaces stop redefining authority semantics
3. mount helper or raw `ctypes` path calls `mount(2)` or another C boundary ->
   one `UapiFfiCallFrameRecord` carries only admitted fixed-width values,
   byte strings, and opaque handles -> process-local ownership and allocator
   state stay outside canon
4. mixed-client-kernel or later kernel-prepared candidate is packaged -> one
   `vfs_boundary_mirror` negotiation profile binds `linux_baseline` host assumptions, `environment_boundary` environment
   domains, and `product_variant` / `package_profile_catalog` rows to admitted mirror layouts -> userspace and
   future kernel carriers share one representation law instead of diverging into
   userspace-only and kernel-only struct folklore
5. future feature adds one optional field, flag bit, or tail section ->
   `wire.vfs_boundary_mirror` chooses fixed-exact, reserved-zero, feature-gated-tail,
   version-negotiated, or refusal-required treatment -> continuity and gate
   receipts admit or stop the move without letting Linux-visible or C-visible
   layout quietly become canonical truth

## 11. Acceptance effect on the design pack

With this law settled:

- `P1-03` becomes detailed enough for later implementation planning,
- the repo now has one explicit answer to where `type_map` / `binary_schema` / receipt truth
  ends and where FUSE, ioctl, statx, fs-flag, future ublk, and `repr(C)` /
  `ctypes` layout begins,
- future Rust userspace, future Rust-for-Linux bridge crates, and package/gate
  surfaces now share one representation grammar instead of adapter-local layout
  folklore,
- no tracked production-design work remains below `L3`,
- and later refinement, review, planning, and implementation must now consume the explicit canonical-to-wire/UAPI/FFI conversion law declared here.

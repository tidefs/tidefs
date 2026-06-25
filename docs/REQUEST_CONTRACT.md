# TideFS Request Contract

Documentation authority: Current spec under
`docs/DOCUMENTATION_AUTHORITY_REGISTER.md` for the bounded
request/completion contract shape only.

This document describes the adapter boundary law for the first TideFS-owned
request and completion contract. The implementation is a type and codec slice
only. It does not rewire FUSE, ublk, kernel VFS, RPC, storage, placement,
rebuild, reclaim, or offload runtime behavior.

## Authority

The canonical portable records live in `tidefs-types-vfs-core`. The fixed-width
little-endian codecs live in `tidefs-schema-codec-vfs`. Issue #282 reuses
those existing anchors from `docs/NEXTGEN_VERIFICATION_CONTRACT_ROADMAP.md`
instead of creating a second VFS request type system.

External protocols refine into this boundary:

1. The adapter records its own environment facts.
2. It maps the operation into a `RequestEnvelope` carrying `RequestMetadata`
   and a `TideRequest`.
3. Runtime admission, execution, and storage semantics remain owned by the
   current product paths.
4. The result maps back through `TideCompletion`.

Adapters may reject or classify operations before this boundary, but once they
emit a TideFS request they must not invent competing filesystem semantics.

## Versioning

The current wire version is `ContractVersion(1)`. The v1 request envelope is
128 bytes and the v1 completion is 96 bytes. Both records are fixed-width
little-endian packets with explicit version and encoded-length fields.

Decoders reject:

- unsupported contract versions;
- wrong byte lengths;
- encoded-length drift;
- unknown metadata/status tags;
- non-zero reserved fields.

Unknown request domains or opcodes decode into explicit unsupported request
payloads. That keeps trace and adapter tests honest without claiming runtime
support for the operation.

## Feature Policy

The contract core remains `no_std` with `unsafe_code` forbidden. Portable
request and completion records do not require `alloc`; owned or variable-size
adapter values must stay behind the existing alloc-gated owned VFS boundary.

The codec crate also remains `no_std` with `unsafe_code` forbidden. It exposes
only the production-safe v1 codec and golden-vector self-check. Proof-only
features are not part of the default build.

Use this focused command for the contract codec seed:

```text
cargo run -p tidefs-xtask -- check-contract-codecs
```

This command checks the embedded request/completion golden vectors and the
reserved-field failure paths. It is a codec/tooling check, not a runtime
adapter validation claim.

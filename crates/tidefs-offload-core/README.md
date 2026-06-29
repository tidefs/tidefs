# tidefs-offload-core

`tidefs-offload-core` defines the first TideFS offload descriptor and
completion ABI. The crate is CPU-reference authority only: accelerators may
eventually consume the same records, but GPU, FPGA, DMA, kernel, RDMA, and
storage-runtime integration are outside this package.

The bounded claim scope is descriptor validation, buffer lease matching,
completion validation, and deterministic CPU reference kernels. It is not a
production acceleration claim.

## External Backend Conformance Manifest

`OffloadExternalBackendConformanceManifest` records a backend name, backend
class, backend result vector digest, descriptor/completion ABI versions, CPU
reference digest, exact completion-status mapping, validation tier, and the
non-authoritative authority scope. Validation requires the backend result
vector digest to match the CPU reference digest, use the v1
descriptor/completion ABI, preserve every exact `OffloadStatus` value, and
remain scoped to non-authoritative offload behavior.

The manifest is a comparison record only. A passing manifest does not validate
GPU, FPGA, DMA, kernel, RDMA, or other production acceleration by itself, and
it never makes offload the authority for storage semantics.

## Claim-Facing Evidence Wrappers

The committed offload TOML artifacts under `validation/artifacts/offload/`
remain the producer evidence. Their neighboring `*.manifest.json` files are
the v2 `EvidenceArtifactManifest` wrappers consumed by the claims gate.

Those wrappers bind the non-authoritative offload claim to exact artifact
paths, BLAKE3 digests, validation tiers, deterministic fixture ids, source
refs, pass outcomes, and residual-risk wording. They do not convert
CPU-reference or external-backend conformance evidence into GPU/FPGA
production acceleration, DMA, kernel, RDMA, SIMD, hardware-equivalence,
storage-runtime integration, or storage-semantics authority.

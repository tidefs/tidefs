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

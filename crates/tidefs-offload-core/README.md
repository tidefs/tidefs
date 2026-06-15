# tidefs-offload-core

`tidefs-offload-core` defines the first TideFS offload descriptor and
completion ABI. The crate is CPU-reference authority only: accelerators may
eventually consume the same records, but GPU, FPGA, DMA, kernel, RDMA, and
storage-runtime integration are outside this package.

The bounded claim scope is descriptor validation, buffer lease matching,
completion validation, and deterministic CPU reference kernels. It is not a
production acceleration claim.

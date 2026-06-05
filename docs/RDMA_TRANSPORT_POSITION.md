# RDMA transport position (v0.399)

Maturity: **spec-draft** for transport design with host-probe

RDMA is an optional transport accelerator for later clustered data movement. It
is not part of the correctness baseline and must not become a hidden admission
requirement.

## Current decision

RDMA maps to the existing transport and pinning laws:

- `docs/LINUX_7_0_BASELINE_CONTRACT_SUPPORTED_SUBSYSTEMS_P0-01.md` classifies
  RDMA as `cut.linux_baseline.rdma_required_fastpath.x0`.
- `docs/TRANSPORT_SESSION_COHORT_GRAPH_P8-01.md` owns endpoint, session,
  cohort, lane, envelope, resume, and closure semantics.
- `docs/ZERO_COPY_DMA_PINNING_PAGE_LOAN_LAW_P4-04.md` owns registered memory,
  pin, loan, DMA, reserve, and fallback semantics.

That means RDMA may improve `transfer_bulk`, `replica_transfer_verify`,
`state_transfer`, and selected demand-fetch paths, but it may not redefine
publication, durability, membership, failover, or control semantics.

## First admitted shape

The first RDMA work should be a transport carrier experiment under
`transport_session_0`, not a storage semantics feature.

Required properties:

- TCP-class transport remains the baseline fallback.
- Control/election/fence traffic stays legal without RDMA.
- Every RDMA memory registration is represented as a pin/loan obligation.
- Every send/receive/read/write completion maps back to the shared envelope and
  closure law.
- Missing RDMA produces a typed degrade or refusal for the RDMA carrier, not a
  product failure.

## Test strategy

Use software RDMA before hardware:

   on the host or inside a QEMU VM.
2. `rdma_rxe` over a disposable Ethernet netdev for RoCE-like testing.
3. `siw` over a disposable Ethernet netdev for iWARP-like testing.
4. Two-node QEMU test once `transport_session_0` has executable carrier code.
5. Hardware RDMA only after the software path proves fallback and pin-drain
   semantics.

The probe helper is non-mutating by default. Its mutating modes are for
disposable hosts or QEMU:

```sh
```

mutating-mode guard, and two-node disposable/QEMU admission gate.

## Current host observation

On the initial v0.399 probe host:

- `rdma` from iproute2 is present.
- No RDMA device is visible under `/sys/class/infiniband`.
- Kernel modules for software RDMA are available: `rdma_rxe` and `siw`.
- the Nix app supplies RDMA user tools through `rdma-core`; `ibv_devinfo`
  reports no IB devices on the current host.

TideFS does not have a product RDMA data path yet.

The OW-308 harness classifies this state as `blocked_no_active_link` with
`transport_session_0_fallback=tcp_required`.

# kmod/

TideFS Rust-for-Linux kernel module root.

## Bridge substrate (c6 / stratum s2)

`tidefs-kmod-bridge` is the shared Rust-for-Linux common bridge substrate
(`kmod.common.bridge.k0`) for future TideFS kernel leaf modules.

### What's implemented

- **Trait contracts** t0–t9 defining the typed seam between canonical authority
  and Linux kernel mechanics.
- **Opaque kernel object facades** for super_block, dentry, inode, file, folio,
  page-window, bio, and request_queue.
- **Lock/pin/workqueue classifiers** from the canonical P7-03 model.
- **Bridge error types** for all kernel-boundary failure modes.
- **Composite `KernelBridge` marker trait** as a compile-time gate for leaf modules.

### What's deferred

- Concrete Linux type bindings (require the kernel build environment from K7-02).
- Leaf module implementations (posix_filesystem_adapter K7-05, block_volume_adapter K7-08).
- The optional policy_authority kernel capsule.

### Dependency model

```
s0 (no_std core types) ──┐
                          ├──> s2 (bridge traits + facades) ──> s3 (leaf modules)
s1 (alloc mirror/render) ─┘
```

The bridge depends only on s0 and s1 crates; it never depends on s3 leaf
modules, userspace control-plane implementation crates, or Linux kernel headers.

### Kernel baseline

Linux 7.0 is the target. All references to Linux 6.18 are historical only.


## Kernel Safety Boundaries (A14 audit — #5808)

This crate defines the bridge safety contract for all kernel leaf modules.

### Opaque-pointer constructors

Every `Opaque*::from_ptr()` constructor in [`types.rs`](src/types.rs) is
`unsafe fn`.  Callers must guarantee the raw pointer references a valid,
live kernel object of the matching type, and the `// SAFETY:` comment must
name the specific kernel reference-counting or RCU rule that keeps the
pointer live for the operation duration.

### KernelLockClass canonical order

[`KernelLockClass`](src/types.rs) discriminants encode the canonical P7-03
lockdep partial order (PolicyRwsem → DomainMutex → RangeRwsem → PinMutex →
ObjectSpin → SeqCountEpoch/RcuAnchor).  `derive(Ord)` enforces this order.
Leaf modules must not introduce ad-hoc lock orders.

### WorkqueueFamily naming

[`WorkqueueFamily`](src/types.rs) names match the 8 canonical P7-03 workqueue
families: ControlSerial, NamespaceMut, PageWriteback, BlockSubmitComplete,
PinDrain, ReclaimRelocate, ObserveExport, EmergencyRecovery.

### Callback registration contract

Kernel leaf modules that register Rust functions as Linux VFS/block callbacks
(file_operations, inode_operations, super_operations, block_device_operations)
must:
- Match the kernel ABI exactly.
- Construct opaque handles via `unsafe { ...::from_ptr(ptr) }` with a live
  kernel pointer guarantee.
- Declare lock classes per the P7-03 hierarchy.

### Deviations and blockers

No upstream Rust-for-Linux deviations are recorded at this time.  Lock class
discriminants and workqueue family names are source-level alignment with P7-03;
runtime lockdep integration requires a Rust-for-Linux `LockClassKey` binding
that is not yet available (tracked in the kernel compile validation doc).

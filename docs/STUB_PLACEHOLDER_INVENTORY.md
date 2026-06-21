# Stub/Placeholder Inventory

**Issue**: [#713](https://github.com/tidefs/tidefs/issues/713)
**Register**: TFR-013 (`docs/REVIEW_TODO_REGISTER.md`)
**Authority**: `docs/workspace-package-classification.md`

This file is a cross-reference update from issue [#789](https://github.com/tidefs/tidefs/issues/789). The full inventory is being created in PR [#780](https://github.com/tidefs/tidefs/pull/780).

---

## 5. Planned Authority Surface Crates

The `docs/workspace-package-classification.md` role table marks 22 package roots as "planned authority surface; follow-up issue required". Each has substantial source code but is not yet authorized for product release claims.

Each crate now has a dedicated follow-up issue (#815–#836) scoped to establish its authority claim or reclassify it.

| Package | Issue | Role | Disposition |
| --- | --- | --- | --- |
| `tidefs-anti-entropy-auditor` | [#815](https://github.com/tidefs/tidefs/issues/815) | product-code | Establish authority claim |
| `tidefs-block-kmod` | [#816](https://github.com/tidefs/tidefs/issues/816) | adapter-operator | Establish authority claim |
| `tidefs-compaction` | [#817](https://github.com/tidefs/tidefs/issues/817) | product-code | Establish authority claim |
| `tidefs-crash-oracle` | [#818](https://github.com/tidefs/tidefs/issues/818) | proof-harness | Establish authority claim |
| `tidefs-data-cleaner` | [#819](https://github.com/tidefs/tidefs/issues/819) | product-code | Establish authority claim |
| `tidefs-distributed-model-check` | [#820](https://github.com/tidefs/tidefs/issues/820) | proof-harness | Establish authority claim |
| `tidefs-env-fuse-model` | [#821](https://github.com/tidefs/tidefs/issues/821) | proof-harness | Establish authority claim |
| `tidefs-env-ublk-model` | [#822](https://github.com/tidefs/tidefs/issues/822) | proof-harness | Establish authority claim |
| `tidefs-erasure-coded-store` | [#823](https://github.com/tidefs/tidefs/issues/823) | product-code | Establish authority claim |
| `tidefs-geometry-convert` | [#824](https://github.com/tidefs/tidefs/issues/824) | product-code | Establish authority claim |
| `tidefs-kernel-cutover-runtime` | [#825](https://github.com/tidefs/tidefs/issues/825) | product-code | Establish authority claim |
| `tidefs-kmod-posix-vfs` | [#826](https://github.com/tidefs/tidefs/issues/826) | adapter-operator | Establish authority claim |
| `tidefs-model-core` | [#827](https://github.com/tidefs/tidefs/issues/827) | proof-harness | Establish authority claim |
| `tidefs-offload-core` | [#828](https://github.com/tidefs/tidefs/issues/828) | product-code | Establish authority claim |
| `tidefs-online-defrag` | [#829](https://github.com/tidefs/tidefs/issues/829) | product-code | Establish authority claim |
| `tidefs-performance-contract` | [#830](https://github.com/tidefs/tidefs/issues/830) | product-code | Establish authority claim |
| `tidefs-posix-filesystem-adapter-reply` | [#831](https://github.com/tidefs/tidefs/issues/831) | adapter-operator | Establish authority claim |
| `tidefs-posix-guarantee-verifier` | [#832](https://github.com/tidefs/tidefs/issues/832) | proof-harness | Establish authority claim |
| `tidefs-secret-key-policy-runtime` | [#833](https://github.com/tidefs/tidefs/issues/833) | policy-tooling | Establish authority claim |
| `tidefs-snapshot-pruner` | [#834](https://github.com/tidefs/tidefs/issues/834) | product-code | Establish authority claim |
| `tidefs-two-node-harness` | [#835](https://github.com/tidefs/tidefs/issues/835) | proof-harness | Establish authority claim |
| `tidefs-vfs-rpc` | [#836](https://github.com/tidefs/tidefs/issues/836) | product-code | Establish authority claim |

Classification: **Implement** — each needs a dedicated follow-up issue to establish its authority claim or reclassify it. Issues #815–#836 carry the per-crate implementation scope.

---

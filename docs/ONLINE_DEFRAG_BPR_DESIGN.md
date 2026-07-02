# Online Defrag BPR Historical Input

This file has been collapsed from a Forgejo-era online-defrag/block-pointer
rewrite design root into a non-authoritative pointer. Do not add new mechanism
design, status, roadmap, proof, benchmark, or comparison prose here.

Current relocation and defrag truth lives in source, storage-intent authority,
validation, claims policy, and live GitHub issue state:

- `crates/tidefs-online-defrag/` owns the current online-defrag service code.
- `crates/tidefs-relocation-planner/` and
  `crates/tidefs-relocation-governor/` own the current source surfaces for
  relocation planning and admission.
- `docs/STORAGE_INTENT_POLICY_AUTHORITY.md`, `docs/COMPACTION_AUTHORITY.md`,
  `docs/CAPACITY_ACCOUNTING_AUTHORITY.md`, `validation/claims.toml`,
  `docs/CLAIMS_GATE_POLICY.md`, and generated `docs/CLAIM_REGISTRY.md` own the
  current authority and claim boundaries.
- Live implementation gaps remain in GitHub issues such as #18, #1864, and
  #1868 rather than in this historical root.

This collapsed file is not evidence of implemented online defrag, block pointer
rewrite safety, relocation runtime safety, source-receipt retirement, capacity
recovery, performance, release readiness, production readiness, or
OpenZFS/Ceph successor/comparator behavior. Any future product-facing claim
must pass through the registered claim ids and evidence classes for the exact
scope.

The remaining reference from `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` is
left for the active authority-register cleanup owners. Once that reference is
gone, this file should be deleted instead of expanded.

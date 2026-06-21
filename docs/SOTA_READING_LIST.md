# Storage / filesystem SOTA reading list (v0.190)

This file is a **curated starting list** of papers and primary references that
are directly relevant to tidefs goals.

Policy:

- Prefer primary sources (conference papers, official docs).
- Keep it categorized, short, and actionable.
- When a new gap is discovered, add at least one “baseline” and one “SOTA” reference.

This is not intended to be exhaustive. It exists so we can systematically
track baseline and state-of-the-art design inputs. Listing a paper or system
here is not evidence that TideFS currently exceeds it; product-facing
comparison still needs claim-registry and comparator-evidence approval.

---

## 1) Placement, rebalancing, and data migration

- **CRUSH** (Ceph placement): Ceph-hosted CRUSH paper PDF
- **CRUSH expansion / migration control**: “Oasis: Controlling Data Migration in Expansion of Object-Based Storage Systems” (ACM, 2023): https://dl.acm.org/doi/full/10.1145/3568424
- **Stripeless placement for EC systems**: “Stripeless Data Placement for Erasure-Coded In-Memory Storage” (OSDI 2025): https://www.usenix.org/conference/osdi25/presentation/wang-hongyu

## 2) Erasure coding and repair

- **Survey**: “A Survey of the Past, Present, and Future of Erasure Coding in Storage Systems” (ACM, 2025): https://dl.acm.org/doi/10.1145/3708994
- **I/O-efficient repairs**: “LESS is More for I/O-Efficient Repairs in Erasure-Coded Storage” (FAST 2026): https://www.usenix.org/conference/fast26/presentation/cheng

## 3) Caching and page-cache behavior

- **Page cache scanning**: “StreamCache: Revisiting Page Cache for File Scanning on Fast Storage Devices” (USENIX ATC 2024): https://www.usenix.org/system/files/atc24-li-zhiyue.pdf

## 4) Heterogeneous memory and persistent memory file systems

- **DRAM+PM cache management**: “Optimizing File Systems on Heterogeneous Memory by … (FLAC)” (USENIX FAST 2024): https://www.usenix.org/system/files/fast24-liu-yubo.pdf

## 5) Transactions and journaling designs

- FAST'25 technical sessions list (starting point for journaling/fsync research): https://www.usenix.org/conference/fast25/technical-sessions
- DJFS (directory-granularity journaling, FAST 2025): https://dl.acm.org/doi/10.5555/3724648.3724651
- **Crash-consistency trade-offs at scale**: “Crash Consistency Overhead in Modern Storage” (OSDI 2025): https://www.usenix.org/conference/osdi25/presentation/sun-siying
- **Operation-log versioning FS**: “SolFS: An Operation-Log Versioning File System for Hash-free Mobile Cloud Backup and Restore” (USENIX ATC 2025): https://www.usenix.org/conference/atc25/presentation/pan

## 6) Distributed metadata services and consistency

- **Directory semantics decoupling**: “Accelerating Distributed Filesystem Metadata Service via Decoupling Directory Semantics from Metadata Indexing” (SoCC 2025): https://dl.acm.org/doi/10.1145/3772052.3772237
- **Correctness / fuzzing**: “Finding Metadata Inconsistencies in Distributed File Systems via Cross-Node Operation Modeling” (USENIX Security 2025): https://www.usenix.org/system/files/usenixsecurity25-ma-fuchen.pdf

## 7) General venues to watch

- USENIX FAST proceedings index: https://www.usenix.org/conferences/byname/93
- SOSP / OSDI: https://www.usenix.org/conferences/byname/80
- USENIX ATC 2025 technical sessions: https://www.usenix.org/conference/atc25/technical-sessions
- OSDI 2025 technical sessions: https://www.usenix.org/conference/osdi25/technical-sessions

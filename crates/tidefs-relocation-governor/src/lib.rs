// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Relocation governor: unified admission, lifecycle, anti-thrash, and
//! scheduling model for defrag, compaction, rebake, rebuild, evacuation,
//! promotion, demotion, geo catch-up, and wear rebalance.
//!
//! This crate owns the relocation-governor admission and scheduling model
//! required by the storage-intent authority (#839 / PR #840,
//! `docs/STORAGE_INTENT_POLICY_AUTHORITY.md`). It consumes storage-intent
//! records from #841 / PR #959 and authority rules from #839 / PR #840.
//!
//! # Scope
//!
//! This crate defines the governor types, hard-gate predicate, anti-thrash
//! rules, HDD/SSD/WAN heuristics, and the bounded background-service handoff
//! for admitted relocation runtime jobs. Concrete local/distributed data movers
//! remain separate components; the governor service refuses or blocks instead
//! of fabricating mover, verification, publication, or source-retirement
//! evidence.
//!
//! # Relocation reasons
//!
//! The governor unifies these relocation reasons:
//!
//! - `policy-satisfaction` — placement no longer satisfies authoritative policy
//! - `repair` — degraded data must be rebuilt from surviving replicas
//! - `evacuation` — member or device drain
//! - `hdd-defrag` — rotational seek/scan locality improvement
//! - `ssd-compaction` — segment drain, reclaim-debt reduction
//! - `rebake` — data-shape transform (compression, checksum, erasure)
//! - `promotion` — tier-up: HDD→SSD, SSD→NVMe, etc.
//! - `demotion` — tier-down: NVMe→SSD, SSD→HDD, etc.
//! - `geo-catchup` — WAN/internet replica RPO catch-up
//! - `wear-rebalance` — flash/NVMe endurance-aware movement
//!
//! # Non-claim boundary
//!
//! This crate is not a mounted-filesystem or concrete data-mover implementation
//! and does not claim product superiority over existing storage systems.
//! Runtime activation remains gated on the evidence producers and
//! action-execution surfaces named by issue #848 and issue #1864.

pub mod admission;
pub mod anti_thrash;
pub mod governor;
pub mod hard_gates;
pub mod hdd_heuristics;
pub mod heuristics;
pub mod lifecycle;
pub mod reasons;
pub mod scheduling;
pub mod ssd_heuristics;
pub mod wan_heuristics;

pub use admission::{AdmissionDecision, AdmissionRecord, AdmissionVerdict};
pub use anti_thrash::{AntiThrashState, CooldownRecord, MovementDebt, PaybackRecord};
pub use governor::{RelocationGovernor, RelocationGovernorConfig};
pub use hard_gates::{HardGateResult, HardGates};
pub use heuristics::{HeuristicInput, HeuristicResult, RelocationActionClass};
pub use lifecycle::{GovernorLifecycleState, LifecycleTransition};
pub use reasons::GovernorRelocationReason;
pub use scheduling::RelocationGovernorService;

/// Canonical identifier for this governor surface.
pub const RELOCATION_GOVERNOR_SPEC: &str = "tidefs-relocation-governor-v1-issue-848";

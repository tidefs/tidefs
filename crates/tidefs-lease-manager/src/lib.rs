#![forbid(unsafe_code)]

//! tidefs-lease-manager: Distributed lease manager.
//!
//! Higher-level lease lifecycle management built on [`tidefs_lease`] types:
//! GRANT/REVOKE/RENEW lifecycle, quorum-acknowledged acquisition, automatic
//! node-failure revocation, and lease priority inheritance for lock chains.

pub mod manager;
pub mod membership;
pub mod priority;

#[cfg(test)]
mod tests;

pub use manager::{LeaseManager, LeaseManagerConfig, LeaseManagerError, ManagerStats};
pub use membership::{MembershipEvent, MembershipObserver};
pub use priority::{LeasePriority, PriorityInheritance};

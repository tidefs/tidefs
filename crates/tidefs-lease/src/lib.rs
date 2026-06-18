// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![allow(clippy::too_many_arguments)]
//! tidefs-lease: Cluster-wide lease mechanism.
//!
//! Time-bounded grants of exclusive/shared authority over mutation domains
//! with quorum-backed issuance, automatic renewal, fencing, and receipt
//! integration.
//!
//! # Design rule (P8-03 core law 5)
//!
//! "Scarce mutable authority is only issued through time-bounded, witness-
//! attested leases. No node may mutate a shared domain without holding a
//! valid, unexpired, unfenced lease for that domain."

pub mod issuance;
pub mod lease_state_machine;
pub mod lifecycle;
pub mod lock_table;
pub mod protocol;
pub mod types;
pub mod wire;

#[cfg(test)]
mod tests;

pub use lease_state_machine::*;
pub use lock_table::*;
pub use protocol::{LeaseMessage, LeaseMessageCodec, LeaseProtocol, LeaseProtocolError};
pub use types::*;
pub use wire::*;

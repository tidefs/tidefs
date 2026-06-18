// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Backend disclosure type for the runtime authority spine.
//!
//! [`BackendDisclosure`] is the single type that declares which transport
//! backend is active. Every subsystem (transport, membership, placement,
//! replication) consults the same disclosure so there is one coherent
//! authority model instead of separate deterministic-only and live-only
//! truths.
//!
//! This module is a pure membership-side type surface; it does not add
//! transport, replication, or placement dependencies beyond what the
//! crate already carries. The storage-node binary wires the disclosure
//! into each subsystem.

use std::fmt;
use std::net::SocketAddr;

/// Declares the active transport backend for a running storage node.
///
/// Every variant is self-describing, carries the address when applicable,
/// and provides a single [`is_live`](Self::is_live) predicate so callers
/// can distinguish production networks from deterministic harnesses
/// without inspecting variant internals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendDisclosure {
    /// RDMA transport with the given device or address string.
    Rdma(String),
    /// TCP transport bound to the given socket address.
    Tcp(SocketAddr),
    /// In-process loopback (single-node deterministic testing).
    Loopback,
    /// Fully deterministic in-memory backend for unit and validation
    /// harnesses that do not touch the network stack.
    DeterministicInMemory,
    /// Authority spine constructed but no transport active (build-only
    /// or compile-validation mode).
    NotRun,
}

impl BackendDisclosure {
    /// Returns `true` when the backend uses a real network transport
    /// (RDMA or TCP). Returns `false` for loopback, deterministic
    /// in-memory, and not-run modes.
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Rdma(_) | Self::Tcp(_))
    }

    /// Human-readable backend name (e.g. `"rdma"`, `"tcp"`).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Rdma(_) => "rdma",
            Self::Tcp(_) => "tcp",
            Self::Loopback => "loopback",
            Self::DeterministicInMemory => "deterministic-in-memory",
            Self::NotRun => "not-run",
        }
    }
}

impl fmt::Display for BackendDisclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rdma(addr) => write!(f, "rdma:{addr}"),
            Self::Tcp(addr) => write!(f, "tcp:{addr}"),
            Self::Loopback => f.write_str("loopback"),
            Self::DeterministicInMemory => f.write_str("deterministic-in-memory"),
            Self::NotRun => f.write_str("not-run"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Variant construction ───────────────────────────────────────────

    #[test]
    fn rdma_variant() {
        let d = BackendDisclosure::Rdma("mlx5_0".into());
        assert!(d.is_live());
        assert_eq!(d.name(), "rdma");
        assert_eq!(d.to_string(), "rdma:mlx5_0");
    }

    #[test]
    fn tcp_variant() {
        let addr: SocketAddr = "10.0.0.1:9090".parse().unwrap();
        let d = BackendDisclosure::Tcp(addr);
        assert!(d.is_live());
        assert_eq!(d.name(), "tcp");
        assert_eq!(d.to_string(), "tcp:10.0.0.1:9090");
    }

    #[test]
    fn loopback_variant() {
        let d = BackendDisclosure::Loopback;
        assert!(!d.is_live());
        assert_eq!(d.name(), "loopback");
        assert_eq!(d.to_string(), "loopback");
    }

    #[test]
    fn deterministic_in_memory_variant() {
        let d = BackendDisclosure::DeterministicInMemory;
        assert!(!d.is_live());
        assert_eq!(d.name(), "deterministic-in-memory");
        assert_eq!(d.to_string(), "deterministic-in-memory");
    }

    #[test]
    fn not_run_variant() {
        let d = BackendDisclosure::NotRun;
        assert!(!d.is_live());
        assert_eq!(d.name(), "not-run");
        assert_eq!(d.to_string(), "not-run");
    }

    #[test]
    fn is_live_only_true_for_rdma_and_tcp() {
        assert!(BackendDisclosure::Rdma("rxe0".into()).is_live());
        assert!(BackendDisclosure::Tcp("127.0.0.1:0".parse().unwrap()).is_live());
        assert!(!BackendDisclosure::Loopback.is_live());
        assert!(!BackendDisclosure::DeterministicInMemory.is_live());
        assert!(!BackendDisclosure::NotRun.is_live());
    }

    #[test]
    fn clone_and_eq() {
        let a = BackendDisclosure::Tcp("192.168.1.1:8080".parse().unwrap());
        let b = a.clone();
        assert_eq!(a, b);

        let c = BackendDisclosure::Tcp("192.168.1.1:8080".parse().unwrap());
        assert_eq!(a, c);

        let d = BackendDisclosure::Tcp("192.168.1.2:8080".parse().unwrap());
        assert_ne!(a, d);

        assert_eq!(
            BackendDisclosure::Rdma("mlx5_0".into()),
            BackendDisclosure::Rdma("mlx5_0".into())
        );
        assert_ne!(
            BackendDisclosure::Rdma("mlx5_0".into()),
            BackendDisclosure::Rdma("mlx5_1".into())
        );
    }

    #[test]
    fn debug_output_contains_variant_name() {
        let d = BackendDisclosure::Loopback;
        let debug = format!("{d:?}");
        assert!(debug.contains("Loopback"), "debug: {debug}");
    }
}

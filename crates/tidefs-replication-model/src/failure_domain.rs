// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Failure domain hierarchy for replication intent.
//!
//! A [`FailureDomain`] defines the level at which replicas or erasure-coded
//! shards must be spread to achieve fault tolerance. The hierarchy is
//! Device < Node < Rack < Datacenter: a failure at a lower level is contained
//! within a higher level.

use serde::{Deserialize, Serialize};

/// Hierarchy level for failure domain separation.
///
/// Replicas placed in distinct failure domains at the specified level can
/// survive failures when enough healthy domains remain to meet the minimum
/// surviving target count (1 for mirror, k for erasure coding).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FailureDomain {
    /// Individual drive or NVMe device. Lowest isolation.
    Device,
    /// Individual host / server.
    Node,
    /// Physical rack / power domain.
    Rack,
    /// Datacenter / availability zone.
    Datacenter,
}

impl FailureDomain {
    /// Returns `true` if `count` domain failures can be tolerated when data is
    /// spread across `spread` distinct domains at this level and at least
    /// `min_surviving` healthy domains are needed for data availability.
    ///
    /// For mirror replication, `min_surviving` is 1 (any replica suffices).
    /// For erasure coding, `min_surviving` is the data shard count k.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Mirror: 3 copies on 3 nodes, tolerate up to 2 node failures
    /// assert!(FailureDomain::Node.can_tolerate_failures(2, 3, 1));
    ///
    /// // EC 4+2: 6 shards on 6 racks, tolerate up to 2 rack failures
    /// assert!(FailureDomain::Rack.can_tolerate_failures(2, 6, 4));
    /// assert!(!FailureDomain::Rack.can_tolerate_failures(3, 6, 4));
    /// ```
    #[must_use]
    pub const fn can_tolerate_failures(&self, count: u8, spread: u8, min_surviving: u8) -> bool {
        // After `count` failures, we need at least `min_surviving` healthy
        // domains remaining. Condition: spread - count >= min_surviving.
        spread >= count.saturating_add(min_surviving)
    }

    /// Returns the minimum number of distinct targets required to survive
    /// `count` failures when at least `min_surviving` healthy targets are
    /// needed.
    #[must_use]
    pub const fn min_spread_for_failure_tolerance(&self, count: u8, min_surviving: u8) -> u8 {
        count.saturating_add(min_surviving)
    }

    /// Returns `true` if this domain level is at least as broad as `other`.
    ///
    /// Device is narrower than Node, which is narrower than Rack, etc.
    /// A Datacenter-level separation implies Node-level separation.
    #[must_use]
    pub const fn covers(&self, other: FailureDomain) -> bool {
        self.domain_rank() >= other.domain_rank()
    }

    /// Numeric rank for ordering: Device=0, Node=1, Rack=2, Datacenter=3.
    #[must_use]
    const fn domain_rank(self) -> u8 {
        match self {
            FailureDomain::Device => 0,
            FailureDomain::Node => 1,
            FailureDomain::Rack => 2,
            FailureDomain::Datacenter => 3,
        }
    }
}

impl core::fmt::Display for FailureDomain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FailureDomain::Device => write!(f, "device"),
            FailureDomain::Node => write!(f, "node"),
            FailureDomain::Rack => write!(f, "rack"),
            FailureDomain::Datacenter => write!(f, "datacenter"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tolerance_device_mirror_2() {
        // 2 copies on 2 devices, need 1 surviving
        assert!(FailureDomain::Device.can_tolerate_failures(1, 2, 1));
        assert!(!FailureDomain::Device.can_tolerate_failures(2, 2, 1));
        assert!(!FailureDomain::Device.can_tolerate_failures(1, 1, 1));
    }

    #[test]
    fn tolerance_node_mirror_3() {
        // 3 copies on 3 nodes, need 1 surviving
        assert!(FailureDomain::Node.can_tolerate_failures(1, 3, 1));
        assert!(FailureDomain::Node.can_tolerate_failures(2, 3, 1));
        assert!(!FailureDomain::Node.can_tolerate_failures(3, 3, 1));
    }

    #[test]
    fn tolerance_rack_ec_4plus2() {
        // 4+2 EC: 6 shards on 6 racks, need 4 surviving (k=4)
        assert!(FailureDomain::Rack.can_tolerate_failures(1, 6, 4));
        assert!(FailureDomain::Rack.can_tolerate_failures(2, 6, 4));
        assert!(!FailureDomain::Rack.can_tolerate_failures(3, 6, 4));
    }

    #[test]
    fn tolerance_rack_mirror_6() {
        // 6-way mirror on 6 racks, need 1 surviving
        assert!(FailureDomain::Rack.can_tolerate_failures(1, 6, 1));
        assert!(FailureDomain::Rack.can_tolerate_failures(5, 6, 1));
        assert!(!FailureDomain::Rack.can_tolerate_failures(6, 6, 1));
    }

    #[test]
    fn min_spread_for_tolerance() {
        assert_eq!(
            FailureDomain::Node.min_spread_for_failure_tolerance(0, 1),
            1
        );
        assert_eq!(
            FailureDomain::Node.min_spread_for_failure_tolerance(1, 1),
            2
        );
        assert_eq!(
            FailureDomain::Node.min_spread_for_failure_tolerance(2, 4),
            6
        );
    }

    #[test]
    fn covers_hierarchy() {
        assert!(FailureDomain::Rack.covers(FailureDomain::Device));
        assert!(FailureDomain::Rack.covers(FailureDomain::Node));
        assert!(FailureDomain::Rack.covers(FailureDomain::Rack));
        assert!(!FailureDomain::Rack.covers(FailureDomain::Datacenter));

        assert!(FailureDomain::Datacenter.covers(FailureDomain::Device));
        assert!(FailureDomain::Datacenter.covers(FailureDomain::Node));
        assert!(FailureDomain::Datacenter.covers(FailureDomain::Rack));

        assert!(!FailureDomain::Device.covers(FailureDomain::Node));
    }

    #[test]
    fn serde_roundtrip() {
        for domain in &[
            FailureDomain::Device,
            FailureDomain::Node,
            FailureDomain::Rack,
            FailureDomain::Datacenter,
        ] {
            let json = serde_json::to_string(domain).expect("serialize");
            let round: FailureDomain = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*domain, round);
        }
    }

    #[test]
    fn display_formatting() {
        assert_eq!(format!("{}", FailureDomain::Device), "device");
        assert_eq!(format!("{}", FailureDomain::Node), "node");
        assert_eq!(format!("{}", FailureDomain::Rack), "rack");
        assert_eq!(format!("{}", FailureDomain::Datacenter), "datacenter");
    }
}

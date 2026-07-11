// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! JSON configuration file support for tidefs-storage-node.
//!
//! Provides [`StorageNodeConfig::from_json_file`] and [`JsonStorageNodeConfig`]
//! for loading daemon configuration from a JSON file, complementing the CLI
//! argument interface.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// JSON-deserializable representation of storage node configuration.
///
/// Field names match the CLI long-option names for consistency.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct JsonStorageNodeConfig {
    pub node_id: u64,
    pub bind: SocketAddr,

    #[serde(default)]
    pub store_paths: Vec<PathBuf>,

    pub pool_device: Option<PathBuf>,
    #[serde(default)]
    pub pool_devices: Vec<PathBuf>,
    pub pool_lock_dir: Option<PathBuf>,
    pub node_identity: Option<String>,

    pub fs_root: Option<PathBuf>,
    pub root_auth_key_hex: Option<String>,

    pub member_class: Option<String>,
    pub failure_domain: Option<u64>,

    pub membership_bind: Option<SocketAddr>,
    #[serde(default)]
    pub membership_peers: Vec<JsonMembershipPeer>,
    #[serde(default)]
    pub replica_peers: Vec<JsonMembershipPeer>,

    #[serde(default)]
    pub rdma: bool,

    #[serde(default = "default_replication_factor")]
    pub replication_factor: u8,

    /// Carrier policy: "prefer" (default) or "enforce" for fail-closed RDMA.
    #[serde(default)]
    pub carrier_policy: Option<String>,

    /// Path to a file that is created (or touched) once startup
    /// completes and the daemon is ready to serve requests.
    pub ready_file: Option<PathBuf>,

    /// Drain timeout in seconds for graceful node-drain on shutdown.
    #[serde(default = "default_drain_timeout_secs")]
    pub drain_timeout_secs: u64,

    /// Optional directory for membership checkpoint persistence.
    #[serde(default)]
    pub membership_checkpoint_dir: Option<PathBuf>,
}

const fn default_drain_timeout_secs() -> u64 {
    30
}

const fn default_replication_factor() -> u8 {
    1
}

/// One membership seed peer in JSON form.
#[derive(Deserialize, Clone, Debug)]
pub struct JsonMembershipPeer {
    pub node_id: u64,
    pub addr: SocketAddr,
    #[serde(default = "default_member_class_str")]
    pub member_class: String,
    pub failure_domain: Option<u64>,
}

fn default_member_class_str() -> String {
    "voter".into()
}

// Re-export the server's types for use in this module.
use super::server::{MembershipPeerConfig, StorageNodeConfig};
use crate::authority_spine::RuntimeAuthority;
use tidefs_membership_epoch::MemberClass;
use tidefs_membership_live::BackendDisclosure;
use tidefs_transport::carrier_selection::CarrierPolicy;

fn parse_member_class_str(s: &str) -> Result<MemberClass, String> {
    match s {
        "voter" => Ok(MemberClass::Voter),
        "learner" => Ok(MemberClass::Learner),
        "witness" | "witness-only" => Ok(MemberClass::WitnessOnly),
        "data" | "data-only" => Ok(MemberClass::DataOnly),
        "shadow" | "shadow-only" => Ok(MemberClass::ShadowOnly),
        "quarantined" => Ok(MemberClass::Quarantined),
        other => Err(format!(
            "unknown member class: {other}. \
             valid values: voter, learner, witness, witness-only, \
             data, data-only, shadow, shadow-only, quarantined"
        )),
    }
}

impl TryFrom<JsonStorageNodeConfig> for StorageNodeConfig {
    type Error = String;

    fn try_from(j: JsonStorageNodeConfig) -> Result<Self, Self::Error> {
        let carrier_policy = j
            .carrier_policy
            .as_deref()
            .map(str::parse::<CarrierPolicy>)
            .transpose()?;

        let member_class = j
            .member_class
            .as_deref()
            .and_then(|s| parse_member_class_str(s).ok());

        let membership_peers: Vec<MembershipPeerConfig> = j
            .membership_peers
            .iter()
            .map(|p| {
                let mc = parse_member_class_str(&p.member_class).unwrap_or(MemberClass::Voter);
                MembershipPeerConfig {
                    node_id: p.node_id,
                    addr: p.addr,
                    member_class: mc,
                    failure_domain: p.failure_domain.unwrap_or(p.node_id),
                }
            })
            .collect();
        let replica_peers: Vec<MembershipPeerConfig> = j
            .replica_peers
            .iter()
            .map(|p| {
                let mc = parse_member_class_str(&p.member_class).unwrap_or(MemberClass::Voter);
                MembershipPeerConfig {
                    node_id: p.node_id,
                    addr: p.addr,
                    member_class: mc,
                    failure_domain: p.failure_domain.unwrap_or(p.node_id),
                }
            })
            .collect();

        let root_auth_key = j
            .root_auth_key_hex
            .as_deref()
            .and_then(|hex| tidefs_local_filesystem::RootAuthenticationKey::from_hex(hex).ok());
        let disclosure = if j.rdma {
            BackendDisclosure::Rdma(j.bind.to_string())
        } else {
            BackendDisclosure::Tcp(j.bind)
        };
        let authority = RuntimeAuthority::build(
            disclosure,
            j.node_id,
            member_class,
            j.failure_domain,
            j.replication_factor,
        )?;

        let mut pool_device_paths = Vec::new();
        if let Some(path) = j.pool_device {
            pool_device_paths.push(path);
        }
        pool_device_paths.extend(j.pool_devices);

        if j.store_paths.is_empty() || j.store_paths.iter().any(|path| path.as_os_str().is_empty())
        {
            return Err(
                "storage node config requires at least one non-empty explicit store path"
                    .to_string(),
            );
        }

        Ok(StorageNodeConfig {
            bind_addr: j.bind,
            node_id: j.node_id,
            authority: Some(authority),
            store_paths: j.store_paths,
            pool_device_paths,
            pool_lock_dir: j.pool_lock_dir,
            node_identity: j.node_identity,
            fs_root: j.fs_root,
            root_auth_key,
            member_class,
            failure_domain: j.failure_domain,
            membership_bind_addr: j.membership_bind,
            membership_peers,
            replica_peers,
            rdma: j.rdma,
            carrier_policy,
            ready_file: j.ready_file,
            drain_timeout_secs: j.drain_timeout_secs,
            membership_checkpoint_dir: j.membership_checkpoint_dir,
            cluster_lease_config: None,
        })
    }
}

impl StorageNodeConfig {
    /// Load configuration from a JSON file at `path`.
    pub fn from_json_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config file {}: {e}", path.display()))?;
        let json_cfg: JsonStorageNodeConfig = serde_json::from_str(&content)
            .map_err(|e| format!("failed to parse config file {}: {e}", path.display()))?;
        Self::try_from(json_cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_json(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.json");
        std::fs::write(&path, content).expect("write config");
        (dir, path)
    }

    #[test]
    fn parse_minimal_config() {
        let json = r#"{
  "node_id": 1,
  "bind": "127.0.0.1:9000"
}"#;
        let cfg = serde_json::from_str::<JsonStorageNodeConfig>(json).expect("parse");
        assert_eq!(cfg.node_id, 1);
        assert_eq!(cfg.bind, "127.0.0.1:9000".parse().unwrap());
        assert!(cfg.store_paths.is_empty());
        assert!(cfg.pool_device.is_none());
        assert!(cfg.pool_devices.is_empty());
        assert!(cfg.node_identity.is_none());
        assert!(!cfg.rdma);
        assert_eq!(cfg.replication_factor, 1);
    }

    #[test]
    fn parse_full_config() {
        let json = r#"{
  "node_id": 7,
  "bind": "0.0.0.0:9999",
  "store_paths": ["/data/tidefs/store1", "/data/tidefs/store2"],
  "pool_device": "/dev/tidefs/pool0",
  "pool_devices": ["/dev/tidefs/pool1", "/dev/tidefs/pool2"],
  "pool_lock_dir": "/dev/tidefs/import",
  "node_identity": "node-7.rack-3",
  "fs_root": "/data/tidefs/fs",
  "root_auth_key_hex": "0101010101010101010101010101010101010101010101010101010101010101",
  "member_class": "learner",
  "failure_domain": 3,
  "membership_bind": "127.0.0.1:9001",
  "membership_peers": [
    { "node_id": 2, "addr": "10.0.0.1:8000", "member_class": "voter", "failure_domain": 2 },
    { "node_id": 3, "addr": "10.0.0.2:8001" }
  ],
  "replica_peers": [
    { "node_id": 4, "addr": "10.0.0.4:9100" }
  ],
  "rdma": false,
  "ready_file": "/run/tidefs/node-7.ready",
  "drain_timeout_secs": 60
}"#;
        let cfg = serde_json::from_str::<JsonStorageNodeConfig>(json).expect("parse");
        assert_eq!(cfg.node_id, 7);
        assert_eq!(cfg.bind, "0.0.0.0:9999".parse().unwrap());
        assert_eq!(cfg.store_paths.len(), 2);
        assert_eq!(cfg.pool_device, Some(PathBuf::from("/dev/tidefs/pool0")));
        assert_eq!(
            cfg.pool_devices,
            vec![
                PathBuf::from("/dev/tidefs/pool1"),
                PathBuf::from("/dev/tidefs/pool2")
            ]
        );
        assert_eq!(cfg.node_identity, Some("node-7.rack-3".into()));
        assert_eq!(cfg.member_class, Some("learner".into()));
        assert_eq!(cfg.failure_domain, Some(3));
        assert_eq!(cfg.membership_peers.len(), 2);
        assert_eq!(cfg.membership_peers[0].node_id, 2);
        assert_eq!(cfg.membership_peers[1].node_id, 3);
        assert_eq!(cfg.replica_peers.len(), 1);
        assert_eq!(cfg.replica_peers[0].node_id, 4);
        assert_eq!(cfg.replication_factor, 1);
        assert_eq!(
            cfg.ready_file,
            Some(PathBuf::from("/run/tidefs/node-7.ready"))
        );
        assert_eq!(cfg.drain_timeout_secs, 60);
    }

    #[test]
    fn parse_missing_node_id_fails() {
        let json = r#"{"bind": "127.0.0.1:9000"}"#;
        assert!(serde_json::from_str::<JsonStorageNodeConfig>(json).is_err());
    }

    #[test]
    fn parse_invalid_bind_addr_fails() {
        let json = r#"{"node_id": 1, "bind": "not-an-address"}"#;
        assert!(serde_json::from_str::<JsonStorageNodeConfig>(json).is_err());
    }

    #[test]
    fn parse_invalid_member_class_falls_back_to_none() {
        let json = r#"{
  "node_id": 1,
  "bind": "127.0.0.1:9000",
  "store_paths": ["/tmp/tidefs-storage-node-test-invalid-member-class"],
  "member_class": "bogus"
}"#;
        let jcfg = serde_json::from_str::<JsonStorageNodeConfig>(json).expect("json parse ok");
        let cfg = StorageNodeConfig::try_from(jcfg).expect("config convert");
        assert!(cfg.member_class.is_none());
    }

    #[test]
    fn json_pool_devices_merge_single_and_list() {
        let json = r#"{
  "node_id": 1,
  "bind": "127.0.0.1:9000",
  "store_paths": ["/tmp/tidefs-storage-node-test-pool-devices"],
  "pool_device": "/dev/tidefs/pool0",
  "pool_devices": ["/dev/tidefs/pool1", "/dev/tidefs/pool2"]
}"#;
        let cfg = StorageNodeConfig::try_from(
            serde_json::from_str::<JsonStorageNodeConfig>(json).expect("json"),
        )
        .expect("convert");
        assert_eq!(
            cfg.pool_device_paths,
            vec![
                PathBuf::from("/dev/tidefs/pool0"),
                PathBuf::from("/dev/tidefs/pool1"),
                PathBuf::from("/dev/tidefs/pool2")
            ]
        );
    }

    #[test]
    fn parse_defaults() {
        let json = r#"{"node_id": 42, "bind": "127.0.0.1:8000"}"#;
        let cfg = serde_json::from_str::<JsonStorageNodeConfig>(json).expect("parse");
        assert!(!cfg.rdma);
        assert_eq!(cfg.replication_factor, 1);
        assert!(cfg.store_paths.is_empty());
        assert!(cfg.membership_peers.is_empty());
        assert!(cfg.replica_peers.is_empty());
        assert_eq!(cfg.drain_timeout_secs, 30);
    }

    #[test]
    fn json_carrier_policy_prefer_propagates() {
        let json = r#"{
  "node_id": 42,
  "bind": "127.0.0.1:8000",
  "store_paths": ["/tmp/tidefs-storage-node-test-carrier-prefer"],
  "carrier_policy": "prefer"
}"#;
        let cfg = StorageNodeConfig::try_from(
            serde_json::from_str::<JsonStorageNodeConfig>(json).expect("json"),
        )
        .expect("convert");
        assert_eq!(cfg.carrier_policy, Some(CarrierPolicy::Prefer));
    }

    #[test]
    fn json_carrier_policy_enforce_propagates() {
        let json = r#"{
  "node_id": 42,
  "bind": "127.0.0.1:8000",
  "store_paths": ["/tmp/tidefs-storage-node-test-carrier-enforce"],
  "rdma": true,
  "carrier_policy": "enforce"
}"#;
        let cfg = StorageNodeConfig::try_from(
            serde_json::from_str::<JsonStorageNodeConfig>(json).expect("json"),
        )
        .expect("convert");
        assert!(cfg.rdma);
        assert_eq!(cfg.carrier_policy, Some(CarrierPolicy::Enforce));
    }

    #[test]
    fn json_unknown_carrier_policy_fails_closed() {
        let json = r#"{
  "node_id": 42,
  "bind": "127.0.0.1:8000",
  "carrier_policy": "fallback"
}"#;
        let result = StorageNodeConfig::try_from(
            serde_json::from_str::<JsonStorageNodeConfig>(json).expect("json"),
        );
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("unknown carrier policy"));
    }

    #[test]
    fn json_config_rejects_missing_store_paths() {
        let json = r#"{
  "node_id": 42,
  "bind": "127.0.0.1:8000"
}"#;
        let result = StorageNodeConfig::try_from(
            serde_json::from_str::<JsonStorageNodeConfig>(json).expect("json"),
        );
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("store path"));
    }

    #[test]
    fn json_config_rejects_empty_store_paths() {
        let json_content = r#"{
  "node_id": 42,
  "bind": "127.0.0.1:8000",
  "store_paths": []
}"#;
        let (_dir, path) = write_json(json_content);
        let result = StorageNodeConfig::from_json_file(&path);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("store path"));
    }

    #[test]
    fn json_config_rejects_blank_store_path() {
        let json_content = r#"{
  "node_id": 42,
  "bind": "127.0.0.1:8000",
  "store_paths": [""]
}"#;
        let (_dir, path) = write_json(json_content);
        let result = StorageNodeConfig::from_json_file(&path);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("non-empty"));
    }

    #[test]
    fn from_json_file_roundtrip() {
        let json_content = r#"{
  "node_id": 9,
  "bind": "127.0.0.1:7777",
  "store_paths": ["/tmp/vs1"],
  "node_identity": "test-node-9",
  "member_class": "voter",
  "drain_timeout_secs": 15
}"#;
        let (_dir, path) = write_json(json_content);
        let cfg = StorageNodeConfig::from_json_file(&path).expect("load");
        assert_eq!(cfg.node_id, 9);
        assert_eq!(cfg.bind_addr, "127.0.0.1:7777".parse().unwrap());
        assert_eq!(cfg.store_paths, vec![PathBuf::from("/tmp/vs1")]);
        assert_eq!(cfg.node_identity, Some("test-node-9".into()));
        assert_eq!(cfg.member_class, Some(MemberClass::Voter));
        let authority = cfg.authority.expect("config should build authority");
        assert!(authority.is_live());
        assert_eq!(authority.node_id(), 9);
        assert_eq!(authority.member_class(), Some(MemberClass::Voter));
        assert_eq!(authority.replication_factor(), 1);
    }

    #[test]
    fn from_json_file_preserves_live_authority() {
        let json_content = r#"{
  "node_id": 11,
  "bind": "127.0.0.1:17777",
  "store_paths": ["/tmp/tidefs-storage-node-test-live-authority"],
  "member_class": "learner",
  "failure_domain": 4,
  "replication_factor": 3
}"#;
        let (_dir, path) = write_json(json_content);
        let cfg = StorageNodeConfig::from_json_file(&path).expect("load");
        let authority = cfg.authority.expect("config should build authority");
        assert!(authority.is_live());
        assert_eq!(authority.node_id(), 11);
        assert_eq!(authority.member_class(), Some(MemberClass::Learner));
        assert_eq!(authority.failure_domain(), Some(4));
        assert_eq!(authority.replication_factor(), 3);
    }

    #[test]
    fn from_json_file_nonexistent() {
        let path = PathBuf::from("/tmp/nonexistent-config-xyz.json");
        assert!(StorageNodeConfig::from_json_file(&path).is_err());
    }

    #[test]
    fn from_json_file_invalid_syntax() {
        let (_dir, path) = write_json("not valid json {");
        assert!(StorageNodeConfig::from_json_file(&path).is_err());
    }

    #[test]
    fn unknown_fields_rejected() {
        let json = r#"{"node_id": 1, "bind": "127.0.0.1:9000", "bogus": true}"#;
        assert!(serde_json::from_str::<JsonStorageNodeConfig>(json).is_err());
    }
}

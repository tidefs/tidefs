// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Cluster commands: manage prototype multi-node TideFS cluster surfaces and
//! development diagnostics.
//!
//! `cluster pool create` dispatches per-node create requests through
//! live transport sessions and carries typed per-node
//! `ClusterPoolCreateResponse` evidence back to the caller.  The command is
//! still prototype operator UAPI: it does not claim final distributed pool
//! status, membership, repair, or transaction authority.
//!
//! Review debt TFR-017: import, lease ownership, and clustered mount remain
//! historical POOLCLUSTER tracker work (#6605-#6610).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use clap::Subcommand;

use tidefs_cluster::{
    ClusterPlacementPolicy, ClusterPoolConfig, ClusterPoolMessage, ClusterPoolOrchestrator,
    CreateOutcome, FailureDomain, HealState, LossEvent, NodeCreateResult, NodeDevice,
    OrchestratorError, PlacementHealCoordinator, PlacementMap, PoolCreateDispatchEvidence,
    PoolTransport, CLUSTER_POOL_CREATE_DISPATCH_EVIDENCE,
};
use tidefs_membership_epoch::HealthClass;
use tidefs_transport::{NodeInfo, SessionId, Transport, TransportAddr};

const CLUSTER_EXERCISE_SURFACE_CLASS: &str = "development-diagnostic";
const CLUSTER_EXERCISE_ROUTING: &str = "development-exercise";
const CLUSTER_EXERCISE_BOUNDARY: &str = concat!(
    "development diagnostic only: not operator status, ",
    "not final placement status, not repair authority, ",
    "not membership authority, and not product-grade recovery closure"
);
const CLUSTER_EXERCISE_OPERATOR_STATUS: bool = false;
const CLUSTER_EXERCISE_FINAL_PLACEMENT_STATUS: bool = false;
const CLUSTER_EXERCISE_REPAIR_AUTHORITY: bool = false;
const CLUSTER_EXERCISE_MEMBERSHIP_AUTHORITY: bool = false;
const CLUSTER_EXERCISE_PRODUCT_RECOVERY_CLOSURE: bool = false;

#[derive(Subcommand, Debug)]
pub enum ClusterCommand {
    /// Manage prototype clustered pools
    Pool {
        #[command(subcommand)]
        cmd: ClusterPoolCommand,
    },

    /// Run development placement-map diagnostics
    Placement {
        #[command(subcommand)]
        cmd: ClusterPlacementCommand,
    },

    /// Run development placement-heal diagnostics
    Heal {
        #[command(subcommand)]
        cmd: ClusterHealCommand,
    },

    /// Query live cluster status with source classification
    Status {
        /// Pool name for live-owner routing
        pool_name: String,

        /// Output as JSON
        #[arg(long = "json")]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ClusterPoolCommand {
    /// Prototype clustered pool creation; not final distributed operator UAPI
    Create {
        /// Pool name (max 255 bytes UTF-8)
        pool_name: String,

        /// Node-device bindings in the form <node_id>:<device_path>.
        /// Example: --node-devices 1:/dev/sda 1:/dev/sdb 2:/dev/sdc
        #[arg(
            short = 'n',
            long = "node-devices",
            required = true,
            num_args = 1..,
            value_name = "NODE_ID:DEVICE_PATH"
        )]
        node_devices: Vec<String>,

        /// Node addresses in the form <node_id>=<host:port>.
        /// Example: --node-addr 1=192.168.1.1:8080 --node-addr 2=192.168.1.2:8080
        #[arg(
            short = 'a',
            long = "node-addr",
            required = true,
            num_args = 1..,
            value_name = "NODE_ID=ADDR"
        )]
        node_addrs: Vec<String>,

        /// Redundancy policy: single (default), replicated=N, or erasure=D+P
        #[arg(short = 'r', long = "redundancy", default_value = "single")]
        redundancy: String,

        /// Output as JSON
        #[arg(long = "json")]
        json: bool,

        /// Allow regular files as pool devices (development only)
        #[arg(long = "file-devices", hide = true)]
        file_devices: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ClusterPlacementCommand {
    /// Run a development PlacementMap diagnostic example
    Exercise {
        /// Epoch for the placement map
        #[arg(long = "epoch", default_value = "1")]
        epoch: u64,

        /// Output as JSON
        #[arg(long = "json")]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ClusterHealCommand {
    /// Run a development PlacementHealCoordinator diagnostic example:
    /// populate placement, trigger loss, walk Idle->Assessing
    Exercise {
        /// Epoch for the heal coordinator
        #[arg(long = "epoch", default_value = "1")]
        epoch: u64,

        /// Member ID to simulate as lost
        #[arg(long = "lost-member", default_value = "2")]
        lost_member: u64,

        /// Output as JSON
        #[arg(long = "json")]
        json: bool,
    },
}

// ---------------------------------------------------------------------------
// Command dispatcher
// ---------------------------------------------------------------------------

pub fn handle_cluster(cmd: ClusterCommand) {
    match cmd {
        ClusterCommand::Pool { cmd } => handle_cluster_pool(cmd),
        ClusterCommand::Placement { cmd } => handle_cluster_placement(cmd),
        ClusterCommand::Heal { cmd } => handle_cluster_heal(cmd),
        ClusterCommand::Status { pool_name, json } => handle_cluster_status(pool_name, json),
    }
}

fn handle_cluster_pool(cmd: ClusterPoolCommand) {
    match cmd {
        ClusterPoolCommand::Create {
            pool_name,
            node_devices,
            node_addrs,
            redundancy,
            json,
            file_devices,
        } => handle_cluster_pool_create(
            pool_name,
            node_devices,
            node_addrs,
            redundancy,
            json,
            file_devices,
        ),
    }
}

// ---------------------------------------------------------------------------
// cluster pool create
// ---------------------------------------------------------------------------

fn parse_node_device_pairs(raw: &[String]) -> Result<Vec<(u64, PathBuf)>, String> {
    let mut pairs = Vec::new();
    let mut seen: BTreeMap<(u64, std::path::PathBuf), usize> = BTreeMap::new();
    for (i, entry) in raw.iter().enumerate() {
        let colon_pos = entry.find(':').ok_or_else(|| {
            format!(
                "invalid node-device pair at position {i}: \"{entry}\" — expected <node_id>:<device_path>"
            )
        })?;

        let node_str = &entry[..colon_pos];
        let dev_str = &entry[colon_pos + 1..];

        if node_str.is_empty() || dev_str.is_empty() {
            return Err(format!(
                "invalid node-device pair at position {i}: \"{entry}\" — both node_id and device_path must be non-empty"
            ));
        }

        let node_id: u64 = node_str.parse().map_err(|_| {
            format!("invalid node_id \"{node_str}\" at position {i}: expected unsigned integer")
        })?;

        let path = PathBuf::from(dev_str);
        let key = (node_id, path.clone());
        if let Some(prev) = seen.get(&key) {
            return Err(format!(
                "duplicate device at position {i}: node {node_id} path \"{}\" already specified at position {prev}",
                dev_str
            ));
        }
        seen.insert(key, i);
        pairs.push((node_id, path));
    }
    Ok(pairs)
}

fn parse_node_addresses(raw: &[String]) -> Result<BTreeMap<u64, SocketAddr>, String> {
    let mut map = BTreeMap::new();
    for (i, entry) in raw.iter().enumerate() {
        let eq_pos = entry.find('=').ok_or_else(|| {
            format!(
                "invalid node-addr at position {i}: \"{entry}\" — expected <node_id>=<host:port>"
            )
        })?;

        let node_str = &entry[..eq_pos];
        let addr_str = &entry[eq_pos + 1..];

        if node_str.is_empty() || addr_str.is_empty() {
            return Err(format!(
                "invalid node-addr at position {i}: \"{entry}\" — both node_id and address must be non-empty"
            ));
        }

        let node_id: u64 = node_str.parse().map_err(|_| {
            format!("invalid node_id \"{node_str}\" at position {i}: expected unsigned integer")
        })?;

        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|_| format!("invalid socket address \"{addr_str}\" at position {i}"))?;

        if map.contains_key(&node_id) {
            return Err(format!(
                "duplicate node_id {node_id} in --node-addr at position {i}"
            ));
        }
        map.insert(node_id, addr);
    }
    Ok(map)
}

fn parse_placement(raw: &str) -> Result<ClusterPlacementPolicy, String> {
    match raw {
        "single" => return Ok(ClusterPlacementPolicy::Stripe),
        "stripe" => return Err(retired_redundancy_alias_error(raw, "single")),
        _ => {}
    }

    if let Some(rest) = raw.strip_prefix("replicated=") {
        let copies = parse_nonzero_u8(rest, raw, "replicated copies", "replicated=N")?;
        return if copies == 1 {
            Ok(ClusterPlacementPolicy::Stripe)
        } else {
            Ok(ClusterPlacementPolicy::MirrorAcrossNodes { copies })
        };
    }

    if raw.starts_with("mirror=") {
        return Err(retired_redundancy_alias_error(raw, "replicated=N"));
    }

    if let Some(rest) = raw.strip_prefix("erasure=") {
        let (data, parity) = parse_erasure_shards(rest, raw)?;
        return Ok(ClusterPlacementPolicy::ErasureCoded { data, parity });
    }

    if raw.starts_with("ec=") {
        return Err(retired_redundancy_alias_error(raw, "erasure=D+P"));
    }

    Err(format!(
        "unknown redundancy policy \"{raw}\"; expected single, replicated=N, or erasure=D+P"
    ))
}

fn parse_nonzero_u8(
    raw_value: &str,
    raw_policy: &str,
    field: &str,
    shape: &str,
) -> Result<u8, String> {
    let value: u8 = raw_value
        .parse()
        .map_err(|_| format!("invalid {field} in \"{raw_policy}\": expected {shape}"))?;
    if value == 0 {
        return Err(format!("{field} must be >= 1 in \"{raw_policy}\""));
    }
    Ok(value)
}

fn parse_erasure_shards(raw_spec: &str, raw_policy: &str) -> Result<(u8, u8), String> {
    let plus_pos = raw_spec
        .find('+')
        .ok_or_else(|| format!("invalid erasure policy \"{raw_policy}\": expected erasure=D+P"))?;
    let data = parse_nonzero_u8(
        &raw_spec[..plus_pos],
        raw_policy,
        "erasure data shards",
        "erasure=D+P",
    )?;
    let parity = parse_nonzero_u8(
        &raw_spec[plus_pos + 1..],
        raw_policy,
        "erasure parity shards",
        "erasure=D+P",
    )?;
    Ok((data, parity))
}

fn retired_redundancy_alias_error(raw: &str, replacement: &str) -> String {
    format!(
        "retired redundancy alias \"{raw}\" is not accepted; use {replacement} (expected single, replicated=N, or erasure=D+P)"
    )
}

fn format_cluster_redundancy(policy: ClusterPlacementPolicy) -> String {
    match policy {
        ClusterPlacementPolicy::Stripe => "single".to_string(),
        ClusterPlacementPolicy::MirrorAcrossNodes { copies } => format!("replicated={copies}"),
        ClusterPlacementPolicy::ErasureCoded { data, parity } => {
            format!("erasure={data}+{parity}")
        }
    }
}

fn cluster_pool_create_evidence() -> PoolCreateDispatchEvidence {
    CLUSTER_POOL_CREATE_DISPATCH_EVIDENCE
}

fn cluster_pool_create_node_results_json(
    node_results: &BTreeMap<u64, NodeCreateResult>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut node_results_json = serde_json::Map::new();
    for (&node_id, result) in node_results {
        let device_hexes: Vec<String> = result.device_guids.iter().map(hex_guid).collect();
        node_results_json.insert(
            node_id.to_string(),
            serde_json::json!({
                "success": result.success,
                "device_guids": device_hexes,
                "error": result.error,
            }),
        );
    }
    node_results_json
}

fn cluster_pool_create_success_json(
    outcome: &CreateOutcome,
    canonical_redundancy: &str,
    topology_generation: u64,
) -> serde_json::Value {
    let evidence = outcome.dispatch_evidence;
    serde_json::json!({
        "pool_name": outcome.pool_name,
        "pool_guid": hex_guid(&outcome.pool_guid),
        "total_nodes": outcome.total_nodes,
        "succeeded": outcome.succeeded,
        "node_results": cluster_pool_create_node_results_json(&outcome.node_results),
        "redundancy": canonical_redundancy,
        "topology_generation": topology_generation,
        "surface_class": evidence.surface_class(),
        "routing": evidence.routing(),
        "transport_evidence": evidence.transport_evidence(),
        "runtime_evidence": evidence.runtime_evidence(),
        "operator_uapi_boundary": evidence.operator_uapi_boundary(),
    })
}

fn cluster_pool_create_partial_failure_json(
    error: &OrchestratorError,
    outcome: &CreateOutcome,
    canonical_redundancy: &str,
    topology_generation: u64,
) -> serde_json::Value {
    let evidence = outcome.dispatch_evidence;
    serde_json::json!({
        "ok": false,
        "command": "cluster pool create",
        "error": error.to_string(),
        "pool_name": outcome.pool_name,
        "pool_guid": hex_guid(&outcome.pool_guid),
        "total_nodes": outcome.total_nodes,
        "succeeded": outcome.succeeded,
        "node_results": cluster_pool_create_node_results_json(&outcome.node_results),
        "redundancy": canonical_redundancy,
        "topology_generation": topology_generation,
        "surface_class": evidence.surface_class(),
        "routing": evidence.routing(),
        "transport_evidence": evidence.transport_evidence(),
        "runtime_evidence": evidence.runtime_evidence(),
        "operator_uapi_boundary": evidence.operator_uapi_boundary(),
    })
}

fn format_cluster_pool_create_success(
    outcome: &CreateOutcome,
    canonical_redundancy: &str,
    topology_generation: u64,
) -> String {
    use std::fmt::Write as _;

    let evidence = outcome.dispatch_evidence;
    let mut out = String::new();
    writeln!(
        &mut out,
        "cluster pool prototype created through live transport: {}",
        outcome.pool_name
    )
    .unwrap();
    writeln!(
        &mut out,
        "  surface:        {}/{}",
        evidence.surface_class(),
        evidence.routing()
    )
    .unwrap();
    writeln!(
        &mut out,
        "  transport:      {}",
        evidence.transport_evidence()
    )
    .unwrap();
    writeln!(
        &mut out,
        "  runtime:        {}",
        evidence.runtime_evidence()
    )
    .unwrap();
    writeln!(
        &mut out,
        "  boundary:       {}",
        evidence.operator_uapi_boundary()
    )
    .unwrap();
    writeln!(
        &mut out,
        "  pool GUID:      {}",
        hex_guid(&outcome.pool_guid)
    )
    .unwrap();
    writeln!(
        &mut out,
        "  nodes:          {}/{} succeeded",
        outcome.succeeded, outcome.total_nodes
    )
    .unwrap();
    writeln!(&mut out, "  redundancy:     {canonical_redundancy}").unwrap();
    writeln!(&mut out, "  topology gen:   {topology_generation}").unwrap();

    for (&node_id, result) in &outcome.node_results {
        let status = if result.success { "OK" } else { "FAILED" };
        let device_str: Vec<String> = result.device_guids.iter().map(hex_guid).collect();
        writeln!(&mut out, "  node {node_id}: {status}").unwrap();
        if result.success {
            writeln!(&mut out, "    device guids:  {device_str:?}").unwrap();
        }
        if let Some(ref err) = result.error {
            writeln!(&mut out, "    error:         {err}").unwrap();
        }
    }

    out
}

fn format_cluster_pool_create_partial_failure(
    error: &OrchestratorError,
    outcome: &CreateOutcome,
) -> String {
    use std::fmt::Write as _;

    let evidence = outcome.dispatch_evidence;
    let mut out = String::new();
    writeln!(
        &mut out,
        "tidefsctl: prototype cluster pool create through live transport partially failed: {error}"
    )
    .unwrap();
    writeln!(
        &mut out,
        "  surface:   {}/{}",
        evidence.surface_class(),
        evidence.routing()
    )
    .unwrap();
    writeln!(&mut out, "  transport: {}", evidence.transport_evidence()).unwrap();
    writeln!(&mut out, "  runtime:   {}", evidence.runtime_evidence()).unwrap();
    writeln!(
        &mut out,
        "  boundary:  {}",
        evidence.operator_uapi_boundary()
    )
    .unwrap();
    writeln!(
        &mut out,
        "  nodes:     {}/{} succeeded",
        outcome.succeeded, outcome.total_nodes
    )
    .unwrap();
    for (&node_id, result) in &outcome.node_results {
        let status = if result.success { "OK" } else { "FAILED" };
        writeln!(&mut out, "  node {node_id}: {status}").unwrap();
        if let Some(ref err) = result.error {
            writeln!(&mut out, "    error: {err}").unwrap();
        }
    }
    out
}

fn format_cluster_pool_create_failure(error: &OrchestratorError) -> String {
    use std::fmt::Write as _;

    let evidence = cluster_pool_create_evidence();
    let mut out = String::new();
    writeln!(
        &mut out,
        "tidefsctl: prototype cluster pool create through live transport failed: {error}"
    )
    .unwrap();
    writeln!(
        &mut out,
        "  surface:  {}/{}",
        evidence.surface_class(),
        evidence.routing()
    )
    .unwrap();
    writeln!(
        &mut out,
        "  boundary: {}",
        evidence.operator_uapi_boundary()
    )
    .unwrap();
    out
}

// ---------------------------------------------------------------------------
// TcpClusterTransport — PoolTransport backed by tidefs_transport sessions
// ---------------------------------------------------------------------------

const CLUSTER_POOL_MAGIC: &[u8; 4] = b"CP01";

struct TcpClusterTransport {
    transport: RefCell<Transport>,
    sessions: BTreeMap<u64, SessionId>,
}

impl TcpClusterTransport {
    fn new(
        local_node_id: u64,
        node_addrs: &BTreeMap<u64, SocketAddr>,
        _connect_timeout: Duration,
    ) -> Result<Self, String> {
        let mut transport = Transport::new(local_node_id);
        let mut sessions = BTreeMap::new();

        for (&node_id, &addr) in node_addrs {
            transport.add_node(NodeInfo::new(node_id, vec![TransportAddr::Tcp(addr)], 0));

            let session_id = transport
                .connect(node_id)
                .map_err(|e| format!("connect to node {node_id} ({addr}): {e:?}"))?;

            transport
                .perform_handshake(session_id)
                .map_err(|e| format!("handshake with node {node_id}: {e:?}"))?;

            sessions.insert(node_id, session_id);
        }

        Ok(Self {
            transport: RefCell::new(transport),
            sessions,
        })
    }

    fn frame_message(msg: &ClusterPoolMessage) -> Result<Vec<u8>, String> {
        let payload = msg.encode().map_err(|e| format!("encode: {e}"))?;
        let mut wire = Vec::with_capacity(4 + payload.len());
        wire.extend_from_slice(CLUSTER_POOL_MAGIC);
        wire.extend_from_slice(&payload);
        Ok(wire)
    }
}

impl PoolTransport for TcpClusterTransport {
    type Error = tidefs_cluster::OrchestratorError;

    fn send(&self, target_node_id: u64, message: ClusterPoolMessage) -> Result<(), Self::Error> {
        let session_id = self.sessions.get(&target_node_id).copied().ok_or(
            tidefs_cluster::OrchestratorError::UnknownNode {
                node_id: target_node_id,
            },
        )?;

        let wire = Self::frame_message(&message)
            .map_err(|e| tidefs_cluster::OrchestratorError::Transport(e))?;

        self.transport
            .borrow_mut()
            .send_message(session_id, &wire)
            .map_err(|e| tidefs_cluster::OrchestratorError::Transport(format!("send: {e:?}")))
    }

    fn recv(&self) -> Result<Option<(u64, ClusterPoolMessage)>, Self::Error> {
        let sessions: Vec<(u64, SessionId)> = self.sessions.iter().map(|(k, v)| (*k, *v)).collect();
        let mut transport = self.transport.borrow_mut();

        for (node_id, session_id) in &sessions {
            match transport.recv_message(*session_id) {
                Ok(raw) => {
                    if raw.len() >= 4 && raw[..4] == *CLUSTER_POOL_MAGIC {
                        match ClusterPoolMessage::decode(&raw[4..]) {
                            Ok(msg) => {
                                return Ok(Some((*node_id, msg)));
                            }
                            Err(e) => {
                                eprintln!("tidefsctl: decode error from node {node_id}: {e:?}");
                            }
                        }
                    }
                }
                Err(tidefs_transport::TransportError::WouldBlock(_)) => {
                    continue;
                }
                Err(e) => {
                    eprintln!("tidefsctl: recv error on node {node_id}: {e:?}");
                }
            }
        }

        Ok(None)
    }
}

fn handle_cluster_pool_create(
    pool_name: String,
    node_devices: Vec<String>,
    node_addrs: Vec<String>,
    redundancy: String,
    json: bool,
    file_devices: bool,
) {
    // 1. Parse node-device pairs.
    let pairs = match parse_node_device_pairs(&node_devices) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("tidefsctl: {e}");
            process::exit(1);
        }
    };

    // 2. Parse node addresses.
    let addrs = match parse_node_addresses(&node_addrs) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tidefsctl: {e}");
            process::exit(1);
        }
    };

    // 3. Validate every node in --node-devices has a --node-addr entry.
    for (node_id, _) in &pairs {
        if !addrs.contains_key(node_id) {
            eprintln!(
                "tidefsctl: node {node_id} appears in --node-devices but has no --node-addr entry"
            );
            process::exit(1);
        }
    }

    // 4. Parse public redundancy policy into the current transport placement enum.
    let placement = match parse_placement(&redundancy) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("tidefsctl: {e}");
            process::exit(1);
        }
    };
    let canonical_redundancy = format_cluster_redundancy(placement);

    // 5. Build NodeDevice entries and ClusterPoolConfig.
    let pool_guid: [u8; 16] = generate_pool_guid();
    let mut devices: Vec<NodeDevice> = Vec::with_capacity(pairs.len());
    let mut next_global_idx: u32 = 0;

    let mut node_device_count: BTreeMap<u64, u32> = BTreeMap::new();
    for (node_id, _) in &pairs {
        *node_device_count.entry(*node_id).or_insert(0) += 1;
    }

    let mut node_local_idx: BTreeMap<u64, u32> = BTreeMap::new();

    for (node_id, device_path) in &pairs {
        let local_idx = node_local_idx.get(node_id).copied().unwrap_or(0);
        let global_idx = next_global_idx;
        next_global_idx += 1;

        let device_guid: [u8; 16] = {
            use std::io::Read;
            let mut buf = [0u8; 16];
            if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
                let _ = f.read_exact(&mut buf);
            } else {
                let mut d = pool_guid;
                d[0] ^= (global_idx as u8).wrapping_mul(17);
                buf = d;
            }
            buf
        };

        let capacity_bytes: u64 = match std::fs::metadata(device_path) {
            Ok(meta) => meta.len(),
            Err(_) => 0u64,
        };
        if capacity_bytes == 0 {
            eprintln!(
                "tidefsctl: warning: cannot determine capacity for {} (will be validated at create time)",
                device_path.display()
            );
        }

        let failure_domain = FailureDomain::for_node(*node_id);

        devices.push(NodeDevice::new(
            device_path.clone(),
            device_guid,
            local_idx,
            global_idx,
            capacity_bytes,
            *node_id,
            failure_domain,
        ));

        node_local_idx.insert(*node_id, local_idx + 1);
    }

    let config = ClusterPoolConfig::new(pool_guid, pool_name.clone(), devices, placement)
        .with_file_devices_for_development(file_devices);

    if !config.has_sufficient_nodes() {
        eprintln!(
            "tidefsctl: pool \"{pool_name}\" has {} nodes, but redundancy requires at least {}",
            config.node_count(),
            config.redundancy.min_nodes()
        );
        process::exit(1);
    }

    if config.has_duplicate_global_indices() {
        eprintln!(
            "tidefsctl: pool \"{pool_name}\" has duplicate global device indices; each device must have a unique index"
        );
        process::exit(1);
    }

    // 6. Connect to target nodes via transport.
    let local_client_id = u64::MAX; // operator CLI node ID
    let transport = match TcpClusterTransport::new(local_client_id, &addrs, Duration::from_secs(10))
    {
        Ok(t) => t,
        Err(e) => {
            let error = OrchestratorError::Transport(format!("transport setup failed: {e}"));
            eprint!("{}", format_cluster_pool_create_failure(&error));
            process::exit(1);
        }
    };

    // 7. Dispatch create requests through transport.
    let evidence = cluster_pool_create_evidence();
    eprintln!(
        "tidefsctl: dispatching prototype cluster pool create through {} to {} node(s); boundary: {}",
        evidence.transport_evidence(),
        config.node_count(),
        evidence.operator_uapi_boundary()
    );

    let request_id = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    };

    // 200 iterations × 50ms = 10s total timeout.
    let timeout_iterations = 200;

    match ClusterPoolOrchestrator::dispatch_create(
        &config,
        request_id,
        &transport,
        timeout_iterations,
    ) {
        Ok(outcome) => {
            if json {
                let json_out = cluster_pool_create_success_json(
                    &outcome,
                    &canonical_redundancy,
                    config.topology_generation,
                );
                println!("{}", serde_json::to_string_pretty(&json_out).unwrap());
            } else {
                print!(
                    "{}",
                    format_cluster_pool_create_success(
                        &outcome,
                        &canonical_redundancy,
                        config.topology_generation
                    )
                );
            }
        }
        Err(e) => {
            // When quorum fails, report per-node partial results.
            if let OrchestratorError::QuorumNotReached {
                outcome: Some(outcome),
                ..
            } = &e
            {
                if json {
                    let json_out = cluster_pool_create_partial_failure_json(
                        &e,
                        outcome,
                        &canonical_redundancy,
                        config.topology_generation,
                    );
                    println!("{}", serde_json::to_string_pretty(&json_out).unwrap());
                } else {
                    eprint!(
                        "{}",
                        format_cluster_pool_create_partial_failure(&e, outcome)
                    );
                }
            } else {
                eprint!("{}", format_cluster_pool_create_failure(&e));
            }
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// cluster placement exercise
// ---------------------------------------------------------------------------

fn handle_cluster_placement(cmd: ClusterPlacementCommand) {
    match cmd {
        ClusterPlacementCommand::Exercise { epoch, json } => {
            handle_placement_exercise(epoch, json);
        }
    }
}

fn handle_placement_exercise(epoch: u64, json: bool) {
    use std::collections::BTreeSet;

    let mut pm = PlacementMap::new(epoch);

    // Populate a 3-node, 5-object mirror-2 placement.
    pm.insert(10, 1);
    pm.insert(10, 2);
    pm.insert(20, 2);
    pm.insert(20, 3);
    pm.insert(30, 1);
    pm.insert(30, 3);
    pm.insert(40, 1);
    pm.insert(40, 2);
    pm.insert(40, 3);
    pm.insert(50, 1);
    pm.insert(50, 2);

    // Exercise query methods.
    let obj10_replicas: Vec<u64> = pm
        .replicas_of(10)
        .map(|s| s.iter().copied().collect())
        .unwrap_or_default();
    let member1_objects: Vec<u64> = pm
        .objects_of(1)
        .map(|s| s.iter().copied().collect())
        .unwrap_or_default();

    // Exercise loss impact.
    let mut lost = BTreeSet::new();
    lost.insert(2);
    let impact = pm.compute_loss_impact(&lost);
    let wholly_lost = pm.compute_wholly_lost_objects(&lost);

    // Exercise divergence check.
    let expected: std::collections::BTreeMap<u64, BTreeSet<u64>> = [
        (10, BTreeSet::from([1, 2])),
        (20, BTreeSet::from([2, 3])),
        (30, BTreeSet::from([1, 3])),
        (40, BTreeSet::from([1, 2, 3])),
        (50, BTreeSet::from([1, 2])),
    ]
    .into();
    let (_missing, _excess) = pm.compute_divergence(&expected);

    if json {
        let json_out = serde_json::json!({
            "operation": "cluster_placement_exercise",
            "surface_class": CLUSTER_EXERCISE_SURFACE_CLASS,
            "routing": CLUSTER_EXERCISE_ROUTING,
            "authority_boundary": CLUSTER_EXERCISE_BOUNDARY,
            "operator_status": CLUSTER_EXERCISE_OPERATOR_STATUS,
            "final_placement_status": CLUSTER_EXERCISE_FINAL_PLACEMENT_STATUS,
            "repair_authority": CLUSTER_EXERCISE_REPAIR_AUTHORITY,
            "membership_authority": CLUSTER_EXERCISE_MEMBERSHIP_AUTHORITY,
            "product_recovery_closure": CLUSTER_EXERCISE_PRODUCT_RECOVERY_CLOSURE,
            "epoch": pm.epoch(),
            "member_count": pm.member_count(),
            "object_count": pm.object_count(),
            "total_replicas": pm.total_replicas(),
            "object_10_replicas": obj10_replicas,
            "member_1_objects": member1_objects,
            "loss_impact_member_2": {
                "affected_objects": impact.keys().collect::<Vec<_>>(),
                "wholly_lost": wholly_lost.iter().collect::<Vec<_>>(),
            },
            "methods_exercised": [
                "new", "insert", "epoch", "replicas_of", "objects_of",
                "member_count", "object_count", "total_replicas",
                "compute_loss_impact", "compute_wholly_lost_objects",
                "compute_divergence"
            ],
        });
        println!("{}", serde_json::to_string_pretty(&json_out).unwrap());
    } else {
        println!(
            "PlacementMap development diagnostic (epoch {}):",
            pm.epoch()
        );
        println!("  surface:     {CLUSTER_EXERCISE_SURFACE_CLASS}/{CLUSTER_EXERCISE_ROUTING}");
        println!("  boundary:    {CLUSTER_EXERCISE_BOUNDARY}");
        println!("  operator status: false");
        println!("  placement status: false");
        println!("  repair authority: false");
        println!("  recovery closure: false");
        println!("  members:     {}", pm.member_count());
        println!("  objects:     {}", pm.object_count());
        println!("  replicas:    {}", pm.total_replicas());
        println!("  obj 10 reps: {obj10_replicas:?}");
        println!("  member 1 objs: {member1_objects:?}");
        println!(
            "  loss member 2: affected_objects={:?} wholly_lost={:?}",
            impact.keys().collect::<Vec<_>>(),
            wholly_lost.iter().collect::<Vec<_>>()
        );
    }
}

// ---------------------------------------------------------------------------
// cluster heal exercise
// ---------------------------------------------------------------------------

fn handle_cluster_heal(cmd: ClusterHealCommand) {
    match cmd {
        ClusterHealCommand::Exercise {
            epoch,
            lost_member,
            json,
        } => {
            handle_heal_exercise(epoch, lost_member, json);
        }
    }
}

fn handle_heal_exercise(epoch: u64, lost_member: u64, json: bool) {
    use std::collections::{BTreeMap, BTreeSet};

    // Create coordinator with populated placement.
    let mut coordinator = PlacementHealCoordinator::new(epoch, None);

    {
        let pm = coordinator.placement_mut();
        pm.insert(10, 1);
        pm.insert(10, 2);
        pm.insert(20, 2);
        pm.insert(20, 3);
        pm.insert(30, 1);
        pm.insert(30, 3);
        pm.insert(40, 1);
        pm.insert(40, 2);
        pm.insert(40, 3);
        pm.insert(50, 1);
        pm.insert(50, 2);
    }

    // Build loss event.
    let mut lost_members = BTreeSet::new();
    lost_members.insert(lost_member);

    let mut available_members = BTreeMap::new();
    for m in [1u64, 2, 3] {
        if m != lost_member {
            available_members.insert(m, HealthClass::Healthy);
        }
    }

    let event = LossEvent {
        lost_members,
        epoch,
        detected_at_ns: 1_000_000_000,
        available_members,
    };

    let affected = coordinator.detect_loss(event);
    let state = coordinator.state();
    let stats = coordinator.stats();

    if json {
        let json_out = serde_json::json!({
            "operation": "cluster_heal_exercise",
            "surface_class": CLUSTER_EXERCISE_SURFACE_CLASS,
            "routing": CLUSTER_EXERCISE_ROUTING,
            "authority_boundary": CLUSTER_EXERCISE_BOUNDARY,
            "operator_status": CLUSTER_EXERCISE_OPERATOR_STATUS,
            "final_placement_status": CLUSTER_EXERCISE_FINAL_PLACEMENT_STATUS,
            "repair_authority": CLUSTER_EXERCISE_REPAIR_AUTHORITY,
            "membership_authority": CLUSTER_EXERCISE_MEMBERSHIP_AUTHORITY,
            "product_recovery_closure": CLUSTER_EXERCISE_PRODUCT_RECOVERY_CLOSURE,
            "epoch": epoch,
            "lost_member": lost_member,
            "initial_state": format!("{:?}", HealState::Idle),
            "post_loss_state": format!("{:?}", state),
            "heal_active": state.is_active(),
            "heal_terminal": state.is_terminal(),
            "stats": {
                "objects_affected": stats.objects_affected,
                "objects_wholly_lost": stats.objects_wholly_lost,
                "objects_to_rebuild": stats.objects_to_rebuild,
                "objects_rebuilt": stats.objects_rebuilt,
                "bytes_rebuilt": stats.bytes_rebuilt,
                "objects_remaining": stats.objects_remaining,
                "fraction_complete": stats.fraction_complete(),
            },
            "affected_objects": affected.map(|s| s.iter().copied().collect::<Vec<u64>>()),
            "placement": {
                "member_count": coordinator.placement().member_count(),
                "object_count": coordinator.placement().object_count(),
                "total_replicas": coordinator.placement().total_replicas(),
            },
            "states_exercised": ["Idle", "Assessing"],
            "methods_exercised": [
                "new", "placement_mut", "placement", "insert",
                "detect_loss", "state", "is_active", "is_terminal",
                "stats", "fraction_complete", "member_count",
                "object_count", "total_replicas"
            ],
        });
        println!("{}", serde_json::to_string_pretty(&json_out).unwrap());
    } else {
        println!("PlacementHealCoordinator development diagnostic (epoch {epoch}):");
        println!(
            "  surface:            {CLUSTER_EXERCISE_SURFACE_CLASS}/{CLUSTER_EXERCISE_ROUTING}"
        );
        println!("  boundary:           {CLUSTER_EXERCISE_BOUNDARY}");
        println!("  operator status:    false");
        println!("  placement status:   false");
        println!("  repair authority:   false");
        println!("  recovery closure:   false");
        println!("  lost member:        {lost_member}");
        println!("  initial state:      {:?}", HealState::Idle);
        println!("  post-loss state:    {state:?}");
        println!("  heal active:        {}", state.is_active());
        println!("  heal terminal:      {}", state.is_terminal());
        println!("  objects affected:   {}", stats.objects_affected);
        println!("  objects to rebuild: {}", stats.objects_to_rebuild);
        println!("  fraction complete:  {:.2}", stats.fraction_complete());
        if let Some(ref objs) = affected {
            println!(
                "  affected objects:   {:?}",
                objs.iter().collect::<Vec<_>>()
            );
        }
    }
}

// ---------------------------------------------------------------------------
/// Query live cluster status through the live owner, or fail closed
/// with source-classified refusal when no live owner is reachable.
fn handle_cluster_status(pool_name: String, json: bool) {
    let live_truth =
        super::operator_truth::OperatorTruthCarrier::live_route("cluster", "status", &pool_name);
    // Try the live owner first; exits if reachable.
    if !json {
        eprintln!("{}", live_truth.live_route_attempt_line());
    }
    super::live_owner::route_status_if_owner_exists("cluster", "status", &pool_name, json);

    // No live owner reachable; fail closed with source classification.
    let refusal_truth = super::operator_truth::OperatorTruthCarrier::no_live_refusal(
        "cluster", "status", &pool_name,
    );
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&refusal_truth.json_value()).unwrap()
        );
        process::exit(1);
    } else {
        for line in refusal_truth.operator_lines() {
            eprintln!("{line}");
        }
        super::live_owner::refuse_no_live_status_evidence("cluster", "status", &pool_name, json);
    }
}

// Helpers
// ---------------------------------------------------------------------------

/// Read 16 random bytes from `/dev/urandom` for a pool GUID.
fn generate_pool_guid() -> [u8; 16] {
    use std::io::Read;
    let mut buf = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    } else {
        // Fallback: non-crypto random from current time.
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((nanos >> (i * 8)) & 0xFF) as u8;
        }
    }
    buf
}

fn hex_guid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],  bytes[1],  bytes[2],  bytes[3],
        bytes[4],  bytes[5],
        bytes[6],  bytes[7],
        bytes[8],  bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tidefs_cluster::ClusterRedundancy;

    #[derive(Debug, Parser)]
    struct TestClusterCli {
        #[command(subcommand)]
        cmd: ClusterCommand,
    }

    // -- parse_node_device_pairs tests --

    #[test]
    fn parse_single_pair() {
        let pairs = parse_node_device_pairs(&["1:/dev/sda".into()]).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], (1, PathBuf::from("/dev/sda")));
    }

    #[test]
    fn parse_three_nodes() {
        let pairs = parse_node_device_pairs(&[
            "1:/dev/sda".into(),
            "2:/dev/sdb".into(),
            "3:/dev/sdc".into(),
        ])
        .unwrap();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0], (1, PathBuf::from("/dev/sda")));
        assert_eq!(pairs[1], (2, PathBuf::from("/dev/sdb")));
        assert_eq!(pairs[2], (3, PathBuf::from("/dev/sdc")));
    }

    #[test]
    fn parse_multiple_devices_per_node() {
        let pairs = parse_node_device_pairs(&[
            "1:/dev/sda".into(),
            "1:/dev/sdb".into(),
            "2:/dev/sdc".into(),
        ])
        .unwrap();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].0, 1);
        assert_eq!(pairs[1].0, 1);
        assert_eq!(pairs[2].0, 2);
    }

    #[test]
    fn parse_cluster_pool_create_file_devices_flag() {
        let cli = TestClusterCli::try_parse_from([
            "test",
            "pool",
            "create",
            "tank",
            "--node-devices",
            "1:/tmp/dev.img",
            "--node-addr",
            "1=127.0.0.1:12001",
            "--file-devices",
        ])
        .unwrap();

        match cli.cmd {
            ClusterCommand::Pool {
                cmd:
                    ClusterPoolCommand::Create {
                        file_devices, json, ..
                    },
            } => {
                assert!(file_devices);
                assert!(!json);
            }
            other => panic!("unexpected parsed command: {other:?}"),
        }
    }

    #[test]
    fn parse_empty_rejected() {
        assert!(parse_node_device_pairs(&["".into()]).is_err());
    }

    #[test]
    fn parse_no_colon_rejected() {
        assert!(parse_node_device_pairs(&["1/dev/sda".into()]).is_err());
    }

    #[test]
    fn parse_empty_node_id_rejected() {
        assert!(parse_node_device_pairs(&[":/dev/sda".into()]).is_err());
    }

    #[test]
    fn parse_empty_device_path_rejected() {
        assert!(parse_node_device_pairs(&["1:".into()]).is_err());
    }

    #[test]
    fn parse_invalid_node_id_rejected() {
        assert!(parse_node_device_pairs(&["abc:/dev/sda".into()]).is_err());
    }

    #[test]
    fn parse_large_node_id() {
        let pairs = parse_node_device_pairs(&["18446744073709551615:/dev/sda".into()]).unwrap();
        assert_eq!(pairs[0].0, u64::MAX);
    }

    // -- parse_node_addresses tests --

    #[test]
    fn parse_single_addr() {
        let addrs = parse_node_addresses(&["1=127.0.0.1:8080".into()]).unwrap();
        assert_eq!(addrs.len(), 1);
        assert!(addrs.contains_key(&1));
        assert_eq!(addrs[&1], "127.0.0.1:8080".parse().unwrap());
    }

    #[test]
    fn parse_multiple_addrs() {
        let addrs = parse_node_addresses(&[
            "1=10.0.0.1:8000".into(),
            "2=10.0.0.2:8000".into(),
            "3=10.0.0.3:8000".into(),
        ])
        .unwrap();
        assert_eq!(addrs.len(), 3);
        assert!(addrs.contains_key(&1));
        assert!(addrs.contains_key(&2));
        assert!(addrs.contains_key(&3));
    }

    #[test]
    fn parse_addr_empty_rejected() {
        assert!(parse_node_addresses(&["".into()]).is_err());
        assert!(parse_node_addresses(&["=127.0.0.1:8080".into()]).is_err());
        assert!(parse_node_addresses(&["1=".into()]).is_err());
    }

    #[test]
    fn parse_addr_invalid_node_id_rejected() {
        assert!(parse_node_addresses(&["abc=127.0.0.1:8080".into()]).is_err());
    }

    #[test]
    fn parse_addr_invalid_addr_rejected() {
        assert!(parse_node_addresses(&["1=not-an-address".into()]).is_err());
    }

    #[test]
    fn parse_addr_duplicate_node_rejected() {
        assert!(
            parse_node_addresses(&["1=10.0.0.1:8000".into(), "1=10.0.0.2:8000".into()]).is_err()
        );
    }

    // -- parse_placement tests --

    #[test]
    fn parse_single() {
        assert_eq!(
            parse_placement("single").unwrap(),
            ClusterPlacementPolicy::Stripe
        );
    }

    #[test]
    fn parse_replicated_1_as_single() {
        assert_eq!(
            parse_placement("replicated=1").unwrap(),
            ClusterPlacementPolicy::Stripe
        );
    }

    #[test]
    fn parse_replicated_2() {
        assert_eq!(
            parse_placement("replicated=2").unwrap(),
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 }
        );
    }

    #[test]
    fn parse_replicated_3() {
        assert_eq!(
            parse_placement("replicated=3").unwrap(),
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 3 }
        );
    }

    #[test]
    fn parse_replicated_invalid_copies_rejected() {
        assert!(parse_placement("replicated=abc").is_err());
    }

    #[test]
    fn parse_replicated_zero_rejected() {
        assert!(parse_placement("replicated=0").is_err());
    }

    #[test]
    fn parse_erasure_4_2() {
        assert_eq!(
            parse_placement("erasure=4+2").unwrap(),
            ClusterPlacementPolicy::ErasureCoded { data: 4, parity: 2 }
        );
    }

    #[test]
    fn parse_erasure_8_3() {
        assert_eq!(
            parse_placement("erasure=8+3").unwrap(),
            ClusterPlacementPolicy::ErasureCoded { data: 8, parity: 3 }
        );
    }

    #[test]
    fn parse_erasure_invalid_format_rejected() {
        assert!(parse_placement("erasure=4-2").is_err());
        assert!(parse_placement("erasure=4*2").is_err());
        assert!(parse_placement("erasure=abc").is_err());
    }

    #[test]
    fn parse_erasure_zero_data_rejected() {
        assert!(parse_placement("erasure=0+2").is_err());
    }

    #[test]
    fn parse_erasure_zero_parity_rejected() {
        assert!(parse_placement("erasure=4+0").is_err());
    }

    #[test]
    fn parse_retired_redundancy_aliases_rejected() {
        let stripe = parse_placement("stripe").unwrap_err();
        assert!(stripe.contains("retired redundancy alias"));
        assert!(stripe.contains("single"));

        let mirror = parse_placement("mirror=2").unwrap_err();
        assert!(mirror.contains("retired redundancy alias"));
        assert!(mirror.contains("replicated=N"));

        let ec = parse_placement("ec=4+2").unwrap_err();
        assert!(ec.contains("retired redundancy alias"));
        assert!(ec.contains("erasure=D+P"));
    }

    #[test]
    fn parse_unknown_rejected() {
        assert!(parse_placement("raidz").is_err());
        assert!(parse_placement("raid5").is_err());
    }

    #[test]
    fn format_cluster_redundancy_uses_canonical_policy_language() {
        assert_eq!(
            format_cluster_redundancy(ClusterPlacementPolicy::Stripe),
            "single"
        );
        assert_eq!(
            format_cluster_redundancy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 3 }),
            "replicated=3"
        );
        assert_eq!(
            format_cluster_redundancy(ClusterPlacementPolicy::ErasureCoded { data: 4, parity: 2 }),
            "erasure=4+2"
        );
    }

    #[test]
    fn cluster_output_boundary_labels_match_surface_roles() {
        let create_evidence = cluster_pool_create_evidence();
        assert_eq!(create_evidence.surface_class(), "prototype");
        assert_eq!(create_evidence.routing(), "live-transport-prototype-uapi");
        assert!(
            create_evidence
                .transport_evidence()
                .contains("PoolTransport"),
            "cluster pool create output must name typed transport evidence"
        );
        assert!(
            create_evidence
                .runtime_evidence()
                .contains("ClusterPoolCreateResponse"),
            "cluster pool create output must name typed runtime evidence"
        );
        assert!(
            create_evidence
                .operator_uapi_boundary()
                .contains("not final distributed pool UAPI"),
            "cluster pool create output must stay prototype-framed while using live dispatch"
        );

        assert_eq!(CLUSTER_EXERCISE_SURFACE_CLASS, "development-diagnostic");
        assert_eq!(CLUSTER_EXERCISE_ROUTING, "development-exercise");
        assert!(
            CLUSTER_EXERCISE_BOUNDARY.contains("not operator status")
                && CLUSTER_EXERCISE_BOUNDARY.contains("repair authority"),
            "placement/heal exercise output must deny status and repair authority"
        );
    }

    fn sample_create_outcome(node_results: BTreeMap<u64, NodeCreateResult>) -> CreateOutcome {
        CreateOutcome {
            pool_guid: [0x11; 16],
            pool_name: "tank".into(),
            total_nodes: node_results.len(),
            succeeded: node_results
                .values()
                .filter(|result| result.success)
                .count(),
            node_results,
            dispatch_evidence: cluster_pool_create_evidence(),
        }
    }

    #[test]
    fn cluster_pool_create_success_output_names_live_transport_prototype_boundary() {
        let outcome = sample_create_outcome(BTreeMap::from([(
            1,
            NodeCreateResult {
                success: true,
                device_guids: vec![[0x22; 16]],
                error: None,
            },
        )]));

        let text = format_cluster_pool_create_success(&outcome, "single", 7);
        assert!(text.contains("cluster pool prototype created through live transport"));
        assert!(text.contains("surface:        prototype/live-transport-prototype-uapi"));
        assert!(text.contains("transport:      typed PoolTransport delivery"));
        assert!(text.contains("runtime:        per-node ClusterPoolCreateResponse"));
        assert!(text.contains("boundary:       not final distributed pool UAPI"));
        assert!(text.contains("node 1: OK"));

        let json = cluster_pool_create_success_json(&outcome, "single", 7);
        assert_eq!(json["surface_class"], "prototype");
        assert_eq!(json["routing"], "live-transport-prototype-uapi");
        assert_eq!(
            json["transport_evidence"],
            "typed PoolTransport delivery over live transport sessions"
        );
        assert_eq!(
            json["runtime_evidence"],
            "per-node ClusterPoolCreateResponse quorum evidence"
        );
        assert_eq!(json["node_results"]["1"]["success"], true);
    }

    #[test]
    fn cluster_pool_create_partial_failure_output_keeps_boundary() {
        let outcome = sample_create_outcome(BTreeMap::from([
            (
                1,
                NodeCreateResult {
                    success: true,
                    device_guids: vec![[0x33; 16]],
                    error: None,
                },
            ),
            (
                2,
                NodeCreateResult {
                    success: false,
                    device_guids: vec![],
                    error: Some("device too small".into()),
                },
            ),
        ]));
        let error = OrchestratorError::QuorumNotReached {
            succeeded: outcome.succeeded,
            total: outcome.total_nodes,
            outcome: Some(outcome.clone()),
        };

        let text = format_cluster_pool_create_partial_failure(&error, &outcome);
        assert!(
            text.contains("prototype cluster pool create through live transport partially failed")
        );
        assert!(text.contains("surface:   prototype/live-transport-prototype-uapi"));
        assert!(text.contains("runtime:   per-node ClusterPoolCreateResponse"));
        assert!(text.contains("boundary:  not final distributed pool UAPI"));
        assert!(text.contains("node 2: FAILED"));
        assert!(text.contains("device too small"));

        let json = cluster_pool_create_partial_failure_json(&error, &outcome, "single", 7);
        assert_eq!(json["ok"], false);
        assert_eq!(json["command"], "cluster pool create");
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("quorum not reached"));
        assert_eq!(json["surface_class"], "prototype");
        assert_eq!(json["routing"], "live-transport-prototype-uapi");
        assert_eq!(
            json["transport_evidence"],
            "typed PoolTransport delivery over live transport sessions"
        );
        assert_eq!(
            json["runtime_evidence"],
            "per-node ClusterPoolCreateResponse quorum evidence"
        );
        assert!(json["operator_uapi_boundary"]
            .as_str()
            .unwrap()
            .contains("not final distributed pool UAPI"));
        assert_eq!(json["node_results"]["2"]["success"], false);
        assert_eq!(json["node_results"]["2"]["error"], "device too small");
    }

    #[test]
    fn cluster_exercise_refusals_deny_status_repair_and_recovery_authority() {
        assert!(!CLUSTER_EXERCISE_OPERATOR_STATUS);
        assert!(!CLUSTER_EXERCISE_FINAL_PLACEMENT_STATUS);
        assert!(!CLUSTER_EXERCISE_REPAIR_AUTHORITY);
        assert!(!CLUSTER_EXERCISE_MEMBERSHIP_AUTHORITY);
        assert!(!CLUSTER_EXERCISE_PRODUCT_RECOVERY_CLOSURE);
        assert!(CLUSTER_EXERCISE_BOUNDARY.contains("not operator status"));
        assert!(CLUSTER_EXERCISE_BOUNDARY.contains("not final placement status"));
        assert!(CLUSTER_EXERCISE_BOUNDARY.contains("not repair authority"));
        assert!(CLUSTER_EXERCISE_BOUNDARY.contains("not product-grade recovery closure"));
    }

    // -- hex_guid tests --

    #[test]
    fn hex_guid_format() {
        let bytes: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let hex = hex_guid(&bytes);
        assert_eq!(hex, "00112233-4455-6677-8899-aabbccddeeff");
    }

    // -- TcpClusterTransport frame/decode tests --

    #[test]
    fn tcp_transport_frame_roundtrip() {
        use tidefs_cluster::ClusterPoolCreateRequest;
        let msg = ClusterPoolMessage::CreateRequest(ClusterPoolCreateRequest {
            request_id: 42,
            pool_guid: [0x11; 16],
            pool_name: "test".into(),
            target_node_id: 1,
            node_devices: vec![],
            redundancy: ClusterRedundancy::None,
            placement: ClusterPlacementPolicy::Stripe,
            allow_file_devices: false,
        });

        let wire = TcpClusterTransport::frame_message(&msg).unwrap();
        assert_eq!(&wire[..4], CLUSTER_POOL_MAGIC);
        let decoded = ClusterPoolMessage::decode(&wire[4..]).unwrap();
        assert_eq!(decoded, msg);
    }

    // -- cluster status tests --

    #[test]
    fn cluster_status_routes_to_live_owner_by_pool_name() {
        // Verify the cluster status command exists and parses.
        // Full live-owner routing is exercised in integration;
        // this test validates the CLI shape.
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            cmd: super::ClusterCommand,
        }
        let args = TestCli::try_parse_from(["test", "status", "testpool"]);
        assert!(args.is_ok(), "cluster status with pool name should parse");
    }

    #[test]
    fn cluster_status_accepts_json_flag() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            cmd: super::ClusterCommand,
        }
        let args = TestCli::try_parse_from(["test", "status", "testpool", "--json"]);
        assert!(args.is_ok(), "cluster status --json should parse");
    }

    #[test]
    fn cluster_status_rejects_missing_pool_name() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            cmd: super::ClusterCommand,
        }
        let args = TestCli::try_parse_from(["test", "status"]);
        assert!(
            args.is_err(),
            "cluster status without pool name must be rejected"
        );
    }

    #[test]
    fn cluster_status_truth_carrier_refuses_without_live_owner() {
        let carrier = super::super::operator_truth::OperatorTruthCarrier::no_live_refusal(
            "cluster", "status", "testpool",
        );
        let lines = carrier.operator_lines();
        let operator_text = lines.join("\n");
        let json = carrier.json_value();

        for expected in [
            "path:       tidefsctl cluster status",
            "evidence:   refused",
            "states:     live-within-budget, stale, deterministic-non-live, refused",
            "source:     source.truth_view.runtime_mirror.a2",
            "cut:        cut.truth_view.live_window.c0",
            "provenance: prov.truth_view.live_mirror.p4",
            "exactness:  exact.truth_view.degraded_or_partial.e3",
            "freshness:  fresh.truth_view.refused.f4",
            "refusal:    no reachable live owner; cached local metadata is non-authoritative",
        ] {
            assert!(
                operator_text.contains(expected),
                "operator text should contain {expected:?}; got:\n{operator_text}"
            );
        }
        assert!(
            !operator_text.trim_start().starts_with('{'),
            "default cluster status refusal should be operator text, not JSON"
        );

        assert_eq!(json["command"], "cluster");
        assert_eq!(json["operation"], "status");
        assert_eq!(json["pool_name"], "testpool");
        assert_eq!(json["status_path"], "tidefsctl cluster status");
        assert_eq!(json["evidence_state"], "refused");
        assert_eq!(json["source"], "source.truth_view.runtime_mirror.a2");
        assert_eq!(json["cut"], "cut.truth_view.live_window.c0");
        assert_eq!(json["provenance"], "prov.truth_view.live_mirror.p4");
        assert_eq!(json["exactness"], "exact.truth_view.degraded_or_partial.e3");
        assert_eq!(json["freshness"], "fresh.truth_view.refused.f4");
        assert_eq!(
            json["refusal"],
            "no reachable live owner; cached local metadata is non-authoritative"
        );
        assert_eq!(
            json["supported_evidence_states"],
            serde_json::json!([
                "live-within-budget",
                "stale",
                "deterministic-non-live",
                "refused"
            ])
        );

        let surface = &json["distributed_surface_record"];
        assert_eq!(surface["live_view"], "view.truth_view.cluster_health.v8");
        assert_eq!(
            surface["signal"],
            "operator.truth_view.distributed.health.o1"
        );
        assert_eq!(surface["status"], "status.truth_view.operator.blocked.s4");
        assert_eq!(surface["source"], json["source"]);
        assert_eq!(surface["cut"], json["cut"]);
        assert_eq!(surface["provenance"], json["provenance"]);
        assert_eq!(surface["exactness"], json["exactness"]);
        assert_eq!(surface["freshness"], json["freshness"]);

        let bundle = &json["truth_bundle_record"];
        assert_eq!(bundle["route"], "route.control_plane.truth_surface.r4");
        assert_eq!(bundle["surface"], "surface.truth_view.system.overview.s0");
        assert_eq!(bundle["source"], json["source"]);
        assert_eq!(bundle["cut"], json["cut"]);
        assert_eq!(bundle["provenance"], json["provenance"]);
        assert_eq!(
            bundle["audience"],
            "audience.truth_view.operator_summary.v1"
        );
        assert_eq!(bundle["answer_kind"], "answer.response_registry.refusal.k1");
    }
}

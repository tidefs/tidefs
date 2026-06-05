//! Cluster commands: manage multi-node TideFS clusters and clustered
//! pool lifecycle (create, import, mount across nodes).
//!
//! `cluster pool create` dispatches per-node create requests through
//! live transport sessions.  Each target storage node writes real
//! PoolLabelV1 labels on its assigned devices and returns per-device
//! results.  The CLI aggregates responses, verifies quorum, and
//! reports structured per-node outcomes.
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
    FailureDomain, HealState, LossEvent, NodeDevice, PlacementHealCoordinator, PlacementMap,
    PoolTransport,
};
use tidefs_membership_epoch::HealthClass;
use tidefs_transport::{NodeInfo, SessionId, Transport, TransportAddr};

#[derive(Subcommand, Debug)]
pub enum ClusterCommand {
    /// Manage clustered pools
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
}

#[derive(Subcommand, Debug)]
pub enum ClusterPoolCommand {
    /// Create a new pool across multiple cluster nodes
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

        /// Redundancy/placement policy: stripe (default), mirror=N, ec=D+P
        #[arg(short = 'r', long = "redundancy", default_value = "stripe")]
        redundancy: String,

        /// Output as JSON
        #[arg(long = "json")]
        json: bool,
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
        } => handle_cluster_pool_create(pool_name, node_devices, node_addrs, redundancy, json),
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
        "stripe" => Ok(ClusterPlacementPolicy::Stripe),
        s if s.starts_with("mirror=") => {
            let copies: u8 = s[7..]
                .parse()
                .map_err(|_| format!("invalid mirror copies in \"{raw}\": expected mirror=N"))?;
            if copies < 2 {
                return Err(format!("mirror copies must be at least 2, got {copies}"));
            }
            Ok(ClusterPlacementPolicy::MirrorAcrossNodes { copies })
        }
        s if s.starts_with("ec=") => {
            let spec = &s[3..];
            let plus_pos = spec
                .find('+')
                .ok_or_else(|| format!("invalid erasure coding spec \"{raw}\": expected ec=D+P"))?;
            let data: u8 = spec[..plus_pos]
                .parse()
                .map_err(|_| format!("invalid data shards in \"{raw}\""))?;
            let parity: u8 = spec[plus_pos + 1..]
                .parse()
                .map_err(|_| format!("invalid parity shards in \"{raw}\""))?;
            if data == 0 || parity == 0 {
                return Err(format!(
                    "erasure coding data and parity must be >= 1, got D={data} P={parity}"
                ));
            }
            Ok(ClusterPlacementPolicy::ErasureCoded { data, parity })
        }
        other => Err(format!(
            "unknown redundancy policy \"{other}\"; expected stripe, mirror=N, or ec=D+P"
        )),
    }
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

    // 4. Parse placement policy.
    let placement = match parse_placement(&redundancy) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("tidefsctl: {e}");
            process::exit(1);
        }
    };

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

    let config = ClusterPoolConfig::new(pool_guid, pool_name.clone(), devices, placement);

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
            eprintln!("tidefsctl: transport setup failed: {e}");
            process::exit(1);
        }
    };

    // 7. Dispatch create requests through transport.
    eprintln!(
        "tidefsctl: dispatching cluster pool create to {} node(s)...",
        config.node_count()
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
                let mut node_results_json = serde_json::Map::new();
                for (&node_id, result) in &outcome.node_results {
                    let device_hexes: Vec<String> =
                        result.device_guids.iter().map(hex_guid).collect();
                    node_results_json.insert(
                        node_id.to_string(),
                        serde_json::json!({
                            "success": result.success,
                            "device_guids": device_hexes,
                            "error": result.error,
                        }),
                    );
                }

                let json_out = serde_json::json!({
                    "pool_name": outcome.pool_name,
                    "pool_guid": hex_guid(&outcome.pool_guid),
                    "total_nodes": outcome.total_nodes,
                    "succeeded": outcome.succeeded,
                    "node_results": node_results_json,
                    "placement": format!("{:?}", config.placement),
                    "topology_generation": config.topology_generation,
                });
                println!("{}", serde_json::to_string_pretty(&json_out).unwrap());
            } else {
                println!("cluster pool created: {}", outcome.pool_name);
                println!("  pool GUID:      {}", hex_guid(&outcome.pool_guid));
                println!(
                    "  nodes:          {}/{} succeeded",
                    outcome.succeeded, outcome.total_nodes
                );
                println!("  placement:      {:?}", config.placement);
                println!("  topology gen:   {}", config.topology_generation);

                for (&node_id, result) in &outcome.node_results {
                    let status = if result.success { "OK" } else { "FAILED" };
                    let device_str: Vec<String> =
                        result.device_guids.iter().map(hex_guid).collect();
                    println!("  node {node_id}: {status}");
                    if result.success {
                        println!("    device guids:  {:?}", device_str);
                    }
                    if let Some(ref err) = result.error {
                        println!("    error:         {err}");
                    }
                }
            }
        }
        Err(e) => {
            // When quorum fails, report per-node partial results.
            if let tidefs_cluster::OrchestratorError::QuorumNotReached {
                outcome: Some(outcome),
                ..
            } = &e
            {
                eprintln!("tidefsctl: cluster pool create partially failed: {e}");
                eprintln!(
                    "  nodes: {}/{} succeeded",
                    outcome.succeeded, outcome.total_nodes
                );
                for (&node_id, result) in &outcome.node_results {
                    let status = if result.success { "OK" } else { "FAILED" };
                    eprintln!("  node {node_id}: {status}");
                    if let Some(ref err) = result.error {
                        eprintln!("    error: {err}");
                    }
                }
            } else {
                eprintln!("tidefsctl: cluster pool create failed: {e}");
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
        println!("PlacementMap exercise (epoch {}):", pm.epoch());
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
        println!("PlacementHealCoordinator exercise (epoch {epoch}):");
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
    fn parse_stripe() {
        assert_eq!(
            parse_placement("stripe").unwrap(),
            ClusterPlacementPolicy::Stripe
        );
    }

    #[test]
    fn parse_mirror_2() {
        assert_eq!(
            parse_placement("mirror=2").unwrap(),
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 }
        );
    }

    #[test]
    fn parse_mirror_3() {
        assert_eq!(
            parse_placement("mirror=3").unwrap(),
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 3 }
        );
    }

    #[test]
    fn parse_mirror_invalid_copies_rejected() {
        assert!(parse_placement("mirror=abc").is_err());
    }

    #[test]
    fn parse_mirror_too_few_copies_rejected() {
        assert!(parse_placement("mirror=1").is_err());
    }

    #[test]
    fn parse_ec_4_2() {
        assert_eq!(
            parse_placement("ec=4+2").unwrap(),
            ClusterPlacementPolicy::ErasureCoded { data: 4, parity: 2 }
        );
    }

    #[test]
    fn parse_ec_8_3() {
        assert_eq!(
            parse_placement("ec=8+3").unwrap(),
            ClusterPlacementPolicy::ErasureCoded { data: 8, parity: 3 }
        );
    }

    #[test]
    fn parse_ec_invalid_format_rejected() {
        assert!(parse_placement("ec=4-2").is_err());
        assert!(parse_placement("ec=4*2").is_err());
        assert!(parse_placement("ec=abc").is_err());
    }

    #[test]
    fn parse_ec_zero_data_rejected() {
        assert!(parse_placement("ec=0+2").is_err());
    }

    #[test]
    fn parse_ec_zero_parity_rejected() {
        assert!(parse_placement("ec=4+0").is_err());
    }

    #[test]
    fn parse_unknown_rejected() {
        assert!(parse_placement("raidz").is_err());
        assert!(parse_placement("raid5").is_err());
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
            placement: ClusterPlacementPolicy::Stripe,
        });

        let wire = TcpClusterTransport::frame_message(&msg).unwrap();
        assert_eq!(&wire[..4], CLUSTER_POOL_MAGIC);
        let decoded = ClusterPoolMessage::decode(&wire[4..]).unwrap();
        assert_eq!(decoded, msg);
    }
}

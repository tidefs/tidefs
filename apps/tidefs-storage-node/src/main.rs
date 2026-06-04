//! tidefs-storage-node: network-accessible replicated object store.
//!
//! Usage:
//!   tidefs-storage-node server --node-id N --bind ADDR [--store PATH...] [--fs-root PATH --root-auth-key HEX]
//!   tidefs-storage-node client --node-id N --server-node-id S --connect ADDR CMD [ARGS...]

// Signal handling (SIGINT/SIGTERM) requires unsafe libc calls;
// the library crate (lib.rs) retains forbid(unsafe_code).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use tidefs_cluster::ClusterLeaseConfig;
use tidefs_local_filesystem::RootAuthenticationKey;
use tidefs_membership_epoch::MemberClass;
use tidefs_membership_live::BackendDisclosure;
use tidefs_storage_node::authority_spine::RuntimeAuthority;
use tidefs_storage_node::client;
use tidefs_storage_node::server::{MembershipPeerConfig, StorageNode, StorageNodeConfig};

fn parse_socket_addr(s: &str) -> Result<SocketAddr, String> {
    s.parse().map_err(|e| format!("invalid address '{s}': {e}"))
}

fn parse_membership_peer(s: &str) -> Result<MembershipPeerConfig, String> {
    let (node_id, addr) = s
        .split_once('@')
        .ok_or_else(|| "membership peer must be <NODE>@<ADDR>".to_string())?;
    let node_id: u64 = node_id
        .parse()
        .map_err(|e| format!("invalid membership peer node id '{node_id}': {e}"))?;
    let addr: SocketAddr = addr
        .parse()
        .map_err(|e| format!("invalid membership peer address '{addr}': {e}"))?;
    Ok(MembershipPeerConfig {
        node_id,
        addr,
        member_class: MemberClass::Voter,
        failure_domain: node_id,
    })
}

fn parse_member_class(s: &str) -> Result<MemberClass, String> {
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

// ── CLI definition ──

#[derive(Parser)]
#[command(
    name = "tidefs-storage-node",
    about = "Networked storage node daemon with transport listener and replicated object store",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the storage node server daemon.
    Server(Box<ServerArgs>),
    /// Issue a one-shot client request to a running storage node.
    Client(ClientArgs),
}

#[derive(Args)]
struct ServerArgs {
    #[arg(long)]
    node_id: u64,

    #[arg(long, value_parser = parse_socket_addr)]
    bind: SocketAddr,

    #[arg(long, value_parser = parse_member_class)]
    member_class: Option<MemberClass>,

    #[arg(long)]
    failure_domain: Option<u64>,

    #[arg(long, value_parser = parse_socket_addr)]
    membership_bind: Option<SocketAddr>,

    #[arg(long = "membership-peer", value_parser = parse_membership_peer)]
    membership_peers: Vec<MembershipPeerConfig>,

    #[arg(long = "replica-peer", value_parser = parse_membership_peer)]
    replica_peers: Vec<MembershipPeerConfig>,

    #[arg(long = "store")]
    store_paths: Vec<PathBuf>,

    #[arg(long = "fs-root")]
    fs_root: Option<PathBuf>,

    #[arg(long = "root-auth-key")]
    root_auth_key_hex: Option<String>,

    #[arg(long = "pool-device")]
    pool_device: Option<PathBuf>,

    #[arg(long = "rdma", default_value_t = false)]
    rdma: bool,
    /// Carrier policy: "prefer" (default) allows TCP fallback; "enforce" fails
    /// closed when an RDMA claim cannot be satisfied.
    #[arg(long = "carrier-policy", default_value = "prefer")]
    carrier_policy: String,
    #[arg(long = "config")]
    config_file: Option<PathBuf>,

    #[arg(long = "node-identity")]
    node_identity: Option<String>,

    #[arg(long = "replication-factor", default_value_t = 1)]
    replication_factor: u8,

    #[arg(long = "membership-checkpoint-dir")]
    /// Directory for membership checkpoint persistence; enables cold-start recovery on restart.
    membership_checkpoint_dir: Option<PathBuf>,

    /// Enable the cluster lease runtime for clustered pool import ownership.
    /// When set, the node creates a ClusterLeaseRuntime with a FenceAuthority,
    /// acquires a membership lease, and issues write fences. Required for
    /// clustered pool mount (--cluster) and multi-node pool operations.
    #[arg(long = "cluster-lease", default_value_t = false)]
    cluster_lease: bool,
}

#[derive(Args)]
struct ClientArgs {
    #[arg(long)]
    node_id: u64,

    #[arg(long)]
    server_node_id: u64,

    #[arg(long, value_parser = parse_socket_addr)]
    connect: SocketAddr,

    #[arg(long = "rdma", default_value_t = false)]
    rdma: bool,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    cmd: Vec<String>,
}

// ── Signal handling (self-pipe trick) ──

#[cfg(unix)]
static SIGNAL_PIPE_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

#[cfg(unix)]
extern "C" fn signal_pipe_handler(_sig: i32) {
    use std::sync::atomic::Ordering;
    let fd = SIGNAL_PIPE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let buf = [1u8];
        unsafe {
            libc::write(fd, buf.as_ptr() as *const libc::c_void, 1);
        }
    }
}

#[cfg(unix)]
fn os_pipe() -> Result<(std::fs::File, std::fs::File), std::io::Error> {
    use std::os::unix::io::FromRawFd;
    let mut fds = [-1i32; 2];
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe {
        (
            std::fs::File::from_raw_fd(fds[0]),
            std::fs::File::from_raw_fd(fds[1]),
        )
    })
}

#[cfg(unix)]
fn spawn_signal_pipe_listener(
    mut read_end: std::fs::File,
    write_end: std::fs::File,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    std::thread::spawn(move || {
        let _write_end_keepalive = write_end;
        let mut buf = [0u8; 16];
        let _ = std::io::Read::read(&mut read_end, &mut buf);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    });
}

#[cfg(unix)]
fn install_signal_handlers(stop: std::sync::Arc<std::sync::atomic::AtomicBool>) -> bool {
    use std::sync::atomic::Ordering;

    let (read_end, write_end) = match os_pipe() {
        Ok((r, w)) => (r, w),
        Err(_) => return false,
    };

    use std::os::unix::io::AsRawFd;
    SIGNAL_PIPE_FD.store(write_end.as_raw_fd(), Ordering::Relaxed);

    unsafe {
        libc::signal(libc::SIGINT, signal_pipe_handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_pipe_handler as libc::sighandler_t);
    }

    spawn_signal_pipe_listener(read_end, write_end, stop);

    true
}

#[cfg(not(unix))]
fn install_signal_handlers(_stop: std::sync::Arc<std::sync::atomic::AtomicBool>) -> bool {
    false
}

// ── Entry point ──

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Server(args) => run_server(*args),
        Command::Client(args) => run_client(args),
    }
}

// ── Server ──

fn run_server(args: ServerArgs) -> ! {
    let ServerArgs {
        config_file,
        node_id,
        bind: bind_addr,
        member_class,
        failure_domain,
        membership_bind: membership_bind_addr,
        membership_peers,
        replica_peers,
        store_paths,
        fs_root,
        root_auth_key_hex,
        pool_device,
        rdma,
        carrier_policy,
        node_identity,
        replication_factor,
        membership_checkpoint_dir,
        cluster_lease,
    } = args;

    let config = if let Some(cfg_path) = &config_file {
        // Load configuration from JSON file; CLI overrides not supported in
        // this mode — the JSON file is the sole source of config.
        StorageNodeConfig::from_json_file(cfg_path.as_ref()).unwrap_or_else(|e| {
            eprintln!("failed to load config file {}: {e}", cfg_path.display());
            std::process::exit(1);
        })
    } else {
        // ── Construct the runtime authority spine ─────────────────────
        let disclosure = if rdma {
            BackendDisclosure::Rdma(bind_addr.to_string())
        } else {
            BackendDisclosure::Tcp(bind_addr)
        };

        let authority = RuntimeAuthority::build(
            disclosure,
            node_id,
            member_class,
            failure_domain,
            replication_factor,
        )
        .unwrap_or_else(|e| {
            eprintln!("failed to build runtime authority spine: {e}");
            std::process::exit(1);
        });

        eprintln!(
            "[storage-node] authority spine: backend={} node_id={} live={} rf={}",
            authority.backend(),
            authority.node_id(),
            authority.is_live(),
            authority.replication_factor(),
        );

        let store_paths = if store_paths.is_empty() {
            vec![PathBuf::from("/tmp/tidefs-store")]
        } else {
            store_paths
        };

        let root_auth_key = match (fs_root.as_ref(), root_auth_key_hex) {
            (Some(_), Some(hex)) => {
                Some(RootAuthenticationKey::from_hex(&hex).unwrap_or_else(|e| {
                    eprintln!("invalid --root-auth-key: {e}");
                    std::process::exit(1);
                }))
            }
            (Some(_), None) => {
                eprintln!("--fs-root requires --root-auth-key");
                std::process::exit(1);
            }
            (None, _) => None,
        };

        StorageNodeConfig {
            bind_addr,
            node_id,
            member_class,
            failure_domain,
            membership_bind_addr,
            membership_peers,
            replica_peers,
            store_paths,
            fs_root,
            root_auth_key,
            pool_device_path: pool_device,
            pool_lock_dir: None,
            node_identity,
            rdma,
            carrier_policy: Some(carrier_policy),
            authority: Some(authority),
            ready_file: None,
            drain_timeout_secs: 30,
            membership_checkpoint_dir,
            cluster_lease_config: if cluster_lease {
                Some(ClusterLeaseConfig::default())
            } else {
                None
            },
        }
    };

    let mut node = StorageNode::start(config).unwrap_or_else(|e| {
        eprintln!("failed to start storage node: {e}");
        std::process::exit(1);
    });

    // Run the staged node-join protocol.
    node.begin_join_protocol();

    // Signal readiness: write the ready marker if configured.
    node.write_ready_marker();

    let stop_flag = node.stop_flag();
    let shutdown_installed = install_signal_handlers(Arc::clone(&stop_flag));

    if !shutdown_installed {
        eprintln!("[storage-node] signal handlers not installed (not a unix platform?)");
    }

    // Spawn a thread that monitors the stop flag and triggers drain+shutdown.
    let shutdown_handle = {
        let stop_clone = Arc::clone(&stop_flag);
        thread::spawn(move || {
            // Poll for stop signal
            while !stop_clone.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(100));
            }
            // Signal received — the main run loop will exit and we'll drain.
        })
    };

    match node.run() {
        Err(e) => {
            eprintln!("storage node fatal: {e}");
            std::process::exit(1);
        }
        Ok(()) => {
            let _ = shutdown_handle.join();
            std::process::exit(0);
        }
    }
}

fn run_client(args: ClientArgs) -> ! {
    let ClientArgs {
        node_id,
        server_node_id,
        connect: server_addr,
        cmd,
        rdma,
    } = args;

    let cmd_name = cmd.first().map(|s| s.as_str()).unwrap_or("help");
    let cmd_rest = &cmd[1.min(cmd.len())..];

    match client::run_client(
        node_id,
        server_node_id,
        server_addr,
        cmd_name,
        cmd_rest,
        rdma,
    ) {
        Err(e) => {
            eprintln!("client error: {e}");
            std::process::exit(1);
        }
        Ok(()) => std::process::exit(0),
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Vec<String> argv from the subcommand name and flag/value pairs.
    fn make_argv(subcommand: &str, args: &[&str]) -> Vec<String> {
        let mut argv: Vec<String> = vec!["tidefs-storage-node".into(), subcommand.into()];
        for s in args {
            argv.push(s.to_string());
        }
        argv
    }

    fn parse_server(args: &[&str]) -> ServerArgs {
        let argv = make_argv("server", args);
        let cli = Cli::try_parse_from(argv).expect("clap parse");
        match cli.command {
            Command::Server(s) => *s,
            _ => panic!("expected Server"),
        }
    }

    fn parse_client(args: &[&str]) -> ClientArgs {
        let argv = make_argv("client", args);
        let cli = Cli::try_parse_from(argv).expect("clap parse");
        match cli.command {
            Command::Client(c) => c,
            _ => panic!("expected Client"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn signal_pipe_listener_keeps_daemon_running_until_signal() {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (read_end, write_end) = os_pipe().expect("create signal pipe");
        let mut signal_write = write_end.try_clone().expect("clone signal writer");

        spawn_signal_pipe_listener(read_end, write_end, Arc::clone(&stop));

        thread::sleep(Duration::from_millis(100));
        assert!(
            !stop.load(Ordering::Relaxed),
            "listener must not treat a live signal pipe as shutdown"
        );

        std::io::Write::write_all(&mut signal_write, &[1]).expect("write signal byte");
        for _ in 0..20 {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }

        assert!(
            stop.load(Ordering::Relaxed),
            "listener must stop after a signal byte"
        );
    }

    #[test]
    fn cli_parse_server_minimal() {
        let args = parse_server(&["--node-id", "1", "--bind", "127.0.0.1:9000"]);
        assert_eq!(args.node_id, 1);
        assert_eq!(args.bind, "127.0.0.1:9000".parse().unwrap());
        assert!(args.store_paths.is_empty());
        assert!(args.pool_device.is_none());
        assert!(args.node_identity.is_none());
        assert_eq!(args.replication_factor, 1);
    }

    #[test]
    fn cli_parse_server_full() {
        let args = parse_server(&[
            "--node-id",
            "7",
            "--bind",
            "0.0.0.0:9999",
            "--member-class",
            "learner",
            "--failure-domain",
            "3",
            "--membership-bind",
            "127.0.0.1:9001",
            "--membership-peer",
            "2@127.0.0.1:9002",
            "--replica-peer",
            "3@127.0.0.1:9100",
            "--store",
            "/data/tidefs/store1",
            "--store",
            "/data/tidefs/store2",
            "--fs-root",
            "/data/tidefs/fs",
            "--root-auth-key",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "--pool-device",
            "/dev/tidefs/pool0",
            "--node-identity",
            "node-7.rack-3",
            "--replication-factor",
            "3",
        ]);
        assert_eq!(args.node_id, 7);
        assert_eq!(args.bind, "0.0.0.0:9999".parse().unwrap());
        assert_eq!(args.member_class, Some(MemberClass::Learner));
        assert_eq!(args.failure_domain, Some(3));
        assert_eq!(
            args.membership_bind,
            Some("127.0.0.1:9001".parse().unwrap())
        );
        assert_eq!(args.membership_peers.len(), 1);
        assert_eq!(args.membership_peers[0].node_id, 2);
        assert_eq!(
            args.membership_peers[0].addr,
            "127.0.0.1:9002".parse().unwrap()
        );
        assert_eq!(args.replica_peers.len(), 1);
        assert_eq!(args.replica_peers[0].node_id, 3);
        assert_eq!(
            args.replica_peers[0].addr,
            "127.0.0.1:9100".parse().unwrap()
        );
        assert_eq!(
            args.store_paths,
            vec![
                PathBuf::from("/data/tidefs/store1"),
                PathBuf::from("/data/tidefs/store2"),
            ]
        );
        assert_eq!(args.fs_root, Some(PathBuf::from("/data/tidefs/fs")));
        assert_eq!(
            args.root_auth_key_hex,
            Some("0101010101010101010101010101010101010101010101010101010101010101".into())
        );
        assert_eq!(args.pool_device, Some(PathBuf::from("/dev/tidefs/pool0")));
        assert_eq!(args.node_identity, Some("node-7.rack-3".into()));
        assert_eq!(args.replication_factor, 3);
    }

    #[test]
    fn cli_parse_server_member_class_variants() {
        for (input, expected) in &[
            ("voter", MemberClass::Voter),
            ("learner", MemberClass::Learner),
            ("witness", MemberClass::WitnessOnly),
            ("witness-only", MemberClass::WitnessOnly),
            ("data", MemberClass::DataOnly),
            ("data-only", MemberClass::DataOnly),
            ("shadow", MemberClass::ShadowOnly),
            ("shadow-only", MemberClass::ShadowOnly),
            ("quarantined", MemberClass::Quarantined),
        ] {
            let args = parse_server(&[
                "--node-id",
                "1",
                "--bind",
                "127.0.0.1:9000",
                "--member-class",
                input,
            ]);
            assert_eq!(args.member_class, Some(*expected), "failed for {input}");
        }
    }

    #[test]
    fn cli_parse_server_multiple_membership_peers() {
        let args = parse_server(&[
            "--node-id",
            "1",
            "--bind",
            "127.0.0.1:9000",
            "--membership-peer",
            "2@10.0.0.1:8000",
            "--membership-peer",
            "3@10.0.0.2:8001",
        ]);
        assert_eq!(args.membership_peers.len(), 2);
        assert_eq!(args.membership_peers[0].node_id, 2);
        assert_eq!(
            args.membership_peers[0].addr,
            "10.0.0.1:8000".parse().unwrap()
        );
        assert_eq!(args.membership_peers[1].node_id, 3);
        assert_eq!(
            args.membership_peers[1].addr,
            "10.0.0.2:8001".parse().unwrap()
        );
    }

    #[test]
    fn cli_parse_server_replica_peer() {
        let args = parse_server(&[
            "--node-id",
            "1",
            "--bind",
            "127.0.0.1:9000",
            "--replica-peer",
            "2@10.0.0.1:9100",
        ]);
        assert!(args.membership_peers.is_empty());
        assert_eq!(args.replica_peers.len(), 1);
        assert_eq!(args.replica_peers[0].node_id, 2);
        assert_eq!(args.replica_peers[0].addr, "10.0.0.1:9100".parse().unwrap());
    }

    #[test]
    fn cli_parse_server_rejects_invalid_member_class() {
        let argv = make_argv(
            "server",
            &[
                "--node-id",
                "1",
                "--bind",
                "127.0.0.1:9000",
                "--member-class",
                "bogus",
            ],
        );
        let result = Cli::try_parse_from(argv);
        assert!(result.is_err(), "should reject bogus member class");
    }

    #[test]
    fn cli_parse_server_rejects_invalid_bind_addr() {
        let argv = make_argv("server", &["--node-id", "1", "--bind", "not-an-address"]);
        let result = Cli::try_parse_from(argv);
        assert!(result.is_err(), "should reject invalid bind address");
    }

    #[test]
    fn cli_parse_server_rejects_missing_node_id() {
        let argv = make_argv("server", &["--bind", "127.0.0.1:9000"]);
        let result = Cli::try_parse_from(argv);
        assert!(result.is_err(), "should reject missing --node-id");
    }

    #[test]
    fn cli_parse_server_rejects_missing_bind() {
        let argv = make_argv("server", &["--node-id", "1"]);
        let result = Cli::try_parse_from(argv);
        assert!(result.is_err(), "should reject missing --bind");
    }

    #[test]
    fn cli_parse_client_put() {
        let args = parse_client(&[
            "--node-id",
            "2",
            "--server-node-id",
            "1",
            "--connect",
            "127.0.0.1:9000",
            "put",
            "mykey",
            "myvalue",
        ]);
        assert_eq!(args.node_id, 2);
        assert_eq!(args.server_node_id, 1);
        assert_eq!(args.connect, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(args.cmd, vec!["put", "mykey", "myvalue"]);
    }

    #[test]
    fn cli_parse_client_put_file() {
        let args = parse_client(&[
            "--node-id",
            "2",
            "--server-node-id",
            "1",
            "--connect",
            "127.0.0.1:9000",
            "put",
            "--file",
            "/tmp/payload.bin",
            "mykey",
        ]);
        assert_eq!(args.cmd, vec!["put", "--file", "/tmp/payload.bin", "mykey"]);
    }

    #[test]
    fn cli_parse_client_get() {
        let args = parse_client(&[
            "--node-id",
            "3",
            "--server-node-id",
            "5",
            "--connect",
            "10.0.0.1:9000",
            "get",
            "mykey",
        ]);
        assert_eq!(args.cmd, vec!["get", "mykey"]);
    }

    #[test]
    fn cli_parse_client_send_incremental() {
        let args = parse_client(&[
            "--node-id",
            "1",
            "--server-node-id",
            "2",
            "--connect",
            "127.0.0.1:9000",
            "send",
            "--incremental",
            "abcdef0123456789abcdef0123456789abcdef0123456789",
        ]);
        assert_eq!(args.cmd[0], "send");
    }

    #[test]
    fn cli_parse_client_requires_cmd() {
        let argv = make_argv(
            "client",
            &[
                "--node-id",
                "1",
                "--server-node-id",
                "2",
                "--connect",
                "127.0.0.1:9000",
            ],
        );
        let result = Cli::try_parse_from(argv);
        assert!(result.is_err(), "should require a command");
    }

    #[test]
    fn cli_parse_client_rejects_invalid_connect() {
        let argv = make_argv(
            "client",
            &[
                "--node-id",
                "1",
                "--server-node-id",
                "2",
                "--connect",
                "bogus",
                "stats",
            ],
        );
        let result = Cli::try_parse_from(argv);
        assert!(result.is_err(), "should reject invalid connect address");
    }

    #[test]
    fn parse_membership_peer_valid() {
        let peer = parse_membership_peer("42@10.0.0.1:8000").unwrap();
        assert_eq!(peer.node_id, 42);
        assert_eq!(peer.addr, "10.0.0.1:8000".parse().unwrap());
        assert_eq!(peer.member_class, MemberClass::Voter);
        assert_eq!(peer.failure_domain, 42);
    }

    #[test]
    fn parse_membership_peer_missing_at() {
        assert!(parse_membership_peer("42-10.0.0.1:8000").is_err());
    }

    #[test]
    fn parse_membership_peer_invalid_node_id() {
        assert!(parse_membership_peer("abc@10.0.0.1:8000").is_err());
    }

    #[test]
    fn parse_membership_peer_invalid_addr() {
        assert!(parse_membership_peer("42@bogus").is_err());
    }

    #[test]
    fn parse_member_class_invalid() {
        assert!(parse_member_class("bogus").is_err());
    }

    #[test]
    fn cli_parse_server_rdma_flag() {
        let args = parse_server(&["--node-id", "1", "--bind", "127.0.0.1:9000", "--rdma"]);
        assert!(args.rdma);
    }

    #[test]
    fn cli_parse_server_rdma_defaults_false() {
        let args = parse_server(&["--node-id", "1", "--bind", "127.0.0.1:9000"]);
        assert!(!args.rdma);
    }

    #[test]
    fn cli_parse_client_rdma_flag() {
        let args = parse_client(&[
            "--node-id",
            "2",
            "--server-node-id",
            "1",
            "--connect",
            "127.0.0.1:9000",
            "--rdma",
            "stats",
        ]);
        assert!(args.rdma);
        assert_eq!(args.cmd, vec!["stats"]);
    }

    #[test]
    fn cli_parse_client_rdma_defaults_false() {
        let args = parse_client(&[
            "--node-id",
            "2",
            "--server-node-id",
            "1",
            "--connect",
            "127.0.0.1:9000",
            "stats",
        ]);
        assert!(!args.rdma);
    }

    #[test]
    fn cli_parse_server_replication_factor_default() {
        let args = parse_server(&["--node-id", "1", "--bind", "127.0.0.1:9000"]);
        assert_eq!(args.replication_factor, 1);
    }

    #[test]
    fn cli_parse_server_replication_factor_custom() {
        let args = parse_server(&[
            "--node-id",
            "1",
            "--bind",
            "127.0.0.1:9000",
            "--replication-factor",
            "5",
        ]);
        assert_eq!(args.replication_factor, 5);
    }

    #[test]
    fn config_from_server_args_minimal() {
        let args = parse_server(&["--node-id", "1", "--bind", "127.0.0.1:9000"]);
        let config = StorageNodeConfig {
            bind_addr: args.bind,
            node_id: args.node_id,
            member_class: args.member_class,
            failure_domain: args.failure_domain,
            membership_bind_addr: args.membership_bind,
            membership_peers: args.membership_peers,
            replica_peers: args.replica_peers,
            store_paths: if args.store_paths.is_empty() {
                vec![PathBuf::from("/tmp/tidefs-store")]
            } else {
                args.store_paths
            },
            fs_root: args.fs_root,
            root_auth_key: None,
            pool_device_path: args.pool_device,
            pool_lock_dir: None,
            node_identity: args.node_identity,
            ready_file: None,
            drain_timeout_secs: 30,
            membership_checkpoint_dir: None,
            cluster_lease_config: None,
            rdma: false,
            carrier_policy: None,
            authority: None,
        };
        assert_eq!(config.node_id, 1);
        assert_eq!(config.bind_addr, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config.store_paths, vec![PathBuf::from("/tmp/tidefs-store")]);
        assert!(config.pool_device_path.is_none());
        assert!(config.node_identity.is_none());
    }

    #[test]
    fn config_from_server_args_with_pool_and_identity() {
        let args = parse_server(&[
            "--node-id",
            "7",
            "--bind",
            "0.0.0.0:9999",
            "--pool-device",
            "/dev/tidefs/pool0",
            "--node-identity",
            "storage-north-3",
        ]);
        let config = StorageNodeConfig {
            bind_addr: args.bind,
            node_id: args.node_id,
            member_class: args.member_class,
            failure_domain: args.failure_domain,
            membership_bind_addr: args.membership_bind,
            membership_peers: args.membership_peers,
            replica_peers: args.replica_peers,
            store_paths: if args.store_paths.is_empty() {
                vec![PathBuf::from("/tmp/tidefs-store")]
            } else {
                args.store_paths
            },
            fs_root: args.fs_root,
            root_auth_key: None,
            pool_device_path: args.pool_device,
            pool_lock_dir: None,
            node_identity: args.node_identity,
            ready_file: None,
            drain_timeout_secs: 30,
            membership_checkpoint_dir: None,
            cluster_lease_config: None,
            rdma: false,
            carrier_policy: None,
            authority: None,
        };
        assert_eq!(config.node_id, 7);
        assert_eq!(
            config.pool_device_path,
            Some(PathBuf::from("/dev/tidefs/pool0"))
        );
        assert_eq!(config.node_identity, Some("storage-north-3".into()));
    }
}

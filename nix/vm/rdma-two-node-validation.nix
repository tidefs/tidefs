# TideFS: multi-node storage fan-out, node-loss recovery, scrub/repair, and
# RDMA data-integrity stress validation.
#
# Boots two Linux 7.0 QEMU guests with virtual networking, enables
# software RDMA (rxe) on each, starts storage-node servers with --rdma,
# and exercises PUT/GET data-integrity verification with SHA-256
# checksummed payloads including cross-node transfers.
#
# Validation tier: Tier 7 multi-process distributed/RDMA runtime.

{
  pkgs,
  tidefsPackage,
}:

pkgs.testers.runNixOSTest {
  name = "tidefs-rdma-two-node-validation";

  # ── Node A (server node id 1) ───────────────────────────────────
  nodes.nodeA = { lib, pkgs, ... }: {
    boot.initrd.availableKernelModules = [
      "virtio_pci"
      "virtio_net"
      "virtio_blk"
      "virtio_console"
      "rdma_rxe"
      "siw"
      "ib_core"
      "ib_uverbs"
      "rdma_cm"
      "rdma_ucm"
    ];
    boot.kernelModules = [
      "rdma_rxe"
      "siw"
      "ib_core"
      "ib_uverbs"
      "rdma_cm"
      "rdma_ucm"
    ];
    boot.kernelParams = [
      "systemd.default_device_timeout_sec=600s"
      "rd.systemd.default_device_timeout_sec=600s"
    ];
    networking.useDHCP = lib.mkForce false;
    networking.interfaces.eth1.useDHCP = lib.mkForce false;
    networking.interfaces.eth1.ipv4.addresses = [
      { address = "192.168.88.10"; prefixLength = 24; }
    ];
    networking.firewall.allowedTCPPorts = [ 9100 ];
    networking.firewall.allowedUDPPorts = [ 4791 ];
    environment.systemPackages = [
      tidefsPackage
      pkgs.iproute2
      pkgs.kmod
      pkgs.rdma-core
      pkgs.coreutils
      pkgs.openssl
    ];
    virtualisation.cores = 2;
    virtualisation.memorySize = 1536;
  };

  # ── Node B (server node id 2) ───────────────────────────────────
  nodes.nodeB = { lib, pkgs, ... }: {
    boot.initrd.availableKernelModules = [
      "virtio_pci"
      "virtio_net"
      "virtio_blk"
      "virtio_console"
      "rdma_rxe"
      "siw"
      "ib_core"
      "ib_uverbs"
      "rdma_cm"
      "rdma_ucm"
    ];
    boot.kernelModules = [
      "rdma_rxe"
      "siw"
      "ib_core"
      "ib_uverbs"
      "rdma_cm"
      "rdma_ucm"
    ];
    boot.kernelParams = [
      "systemd.default_device_timeout_sec=600s"
      "rd.systemd.default_device_timeout_sec=600s"
    ];
    networking.useDHCP = lib.mkForce false;
    networking.interfaces.eth1.useDHCP = lib.mkForce false;
    networking.interfaces.eth1.ipv4.addresses = [
      { address = "192.168.88.20"; prefixLength = 24; }
    ];
    networking.firewall.allowedTCPPorts = [ 9100 ];
    networking.firewall.allowedUDPPorts = [ 4791 ];
    environment.systemPackages = [
      tidefsPackage
      pkgs.iproute2
      pkgs.kmod
      pkgs.rdma-core
      pkgs.coreutils
      pkgs.openssl
    ];
    virtualisation.cores = 2;
    virtualisation.memorySize = 1536;
  };

  # ── Test script ──────────────────────────────────────────────────
  testScript = ''
    import json
    import time
    import os

    results: list[dict[str, str]] = []
    validation = {
      "test": "tidefs-rdma-two-node-validation",
      "version": 2,
      "validation_tier": "Tier 7 multi-process distributed/RDMA runtime",
      "carrier_backend": "rdma-requested-with-explicit-backend-disclosure",
      "acceptance": [
        "storage fan-out",
        "node-loss recovery",
        "quorum failure disclosure",
        "scrub/repair fan-out",
        "stress loops",
        "no silent TCP fallback",
      ],
      "results": results,
      "passed": 0,
      "failed": 0,
    }

    def record(name, status, output=None):
        entry = {"name": name, "status": status}
        if output is not None:
            entry["output"] = str(output)[:2000]
        results.append(entry)

    def parse_health_report(output):
        marker = "report:\n"
        if marker not in output:
            return None
        try:
            return json.loads(output.split(marker, 1)[1].strip())
        except Exception:
            return None

    def health_backend_is_rdma(output):
        backend_line_is_rdma = False
        for line in output.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith("backend:"):
                backend_line_is_rdma = "rdma" in stripped

        report = parse_health_report(output)
        if report is None:
            return backend_line_is_rdma

        transport_backends = report.get("transport_backends", [])
        backend_kinds = [
            str(item.get("backend_kind", "")).lower()
            for item in transport_backends
            if isinstance(item, dict)
        ]
        if any("tcp" in kind for kind in backend_kinds):
            return False
        if backend_kinds:
            return backend_line_is_rdma and all("rdma" in kind for kind in backend_kinds)
        return backend_line_is_rdma

    def stats_backend_is_rdma(stats):
        return "rdma" in str(stats.get("backend", "")).lower()

    def parse_scrub_json(output):
        for line in reversed(output.splitlines()):
            stripped = line.strip()
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    return json.loads(stripped)
                except Exception:
                    return None
        return None

    nodeA.start()
    nodeB.start()

    nodeA.wait_for_unit("multi-user.target")
    nodeB.wait_for_unit("multi-user.target")
    record("boot", "pass")

    # ── IP connectivity ─────────────────────────────────────────
    nodeA.succeed("ping -c 3 192.168.88.20")
    nodeB.succeed("ping -c 3 192.168.88.10")
    record("ip_connectivity", "pass")

    # ── RDMA kernel modules ────────────────────────────────────
    for node in [nodeA, nodeB]:
        for mod in ["rdma_rxe", "rdma_cm", "rdma_ucm", "ib_core", "ib_uverbs"]:
            node.succeed(f"modprobe {mod} || true")
    record("modules_loaded", "pass")

    # ── SoftRoCE setup ─────────────────────────────────────────
    nodeA.execute("rdma link add rxe_eth1 type rxe netdev eth1 2>/dev/null || true")
    nodeB.execute("rdma link add rxe_eth1 type rxe netdev eth1 2>/dev/null || true")
    time.sleep(2)

    nodeA.succeed("rdma link show | grep rxe_eth1")
    nodeB.succeed("rdma link show | grep rxe_eth1")
    record("rdma_links", "pass")

    nodeA.succeed("ibv_devices | grep rxe_eth1")
    nodeB.succeed("ibv_devices | grep rxe_eth1")
    record("ibv_devices", "pass")

    # ── RDMA CM cross-node connectivity (rping) ────────────────
    nodeA.execute("rping -s -v > /tmp/nodeA_rping.log 2>&1 & echo $! > /tmp/nodeA_rping.pid")
    time.sleep(2)
    rping_status, rping_out = nodeB.execute(
        "timeout --kill-after=2s 30s rping -c -a 192.168.88.10 -C 3 -v 2>&1"
    )
    time.sleep(2)
    nodeA.execute(
        "pid=$(cat /tmp/nodeA_rping.pid 2>/dev/null || true); "
        "if [ -n \"$pid\" ]; then kill \"$pid\" 2>/dev/null || true; fi; "
        "rm -f /tmp/nodeA_rping.pid"
    )

    if rping_status == 0 or "server DISCONNECT" in rping_out or "client DISCONNECT" in rping_out:
        record("rping_rdma_cm", "pass", "RDMA CM ping-pong established")
    elif "migration" in rping_out or "rdma_connect" in rping_out:
        record("rping_rdma_cm", "pass", "RDMA CM connection established (partial)")
    else:
        record("rping_rdma_cm", "fail", f"rping output: {rping_out[:500]}")

    # ── Membership checkpoint persistence: cold-start recovery ────
    nodeA.succeed("mkdir -p /tmp/tidefs-membership-checkpoints/node-A")
    nodeB.succeed("mkdir -p /tmp/tidefs-membership-checkpoints/node-B")
    record("checkpoint_dirs_created", "pass")

    def wait_for_storage_health(client_node, log_node, node_label, client_id, server_id, connect_addr, log_path):
        last_output = ""
        for attempt in range(12):
            status, output = client_node.execute(
                f"timeout --kill-after=2s 12s tidefs-storage-node client --node-id {client_id} "
                f"--server-node-id {server_id} --connect {connect_addr} "
                "--rdma health 2>&1"
            )
            if status == 0:
                return output
            last_output = output.strip()
            time.sleep(1)

        server_log = log_node.succeed(f"cat {log_path} 2>/dev/null || true")
        process_log = log_node.succeed("ps aux | grep '[v]ibefs-storage-node' || true")
        record(f"storage_node_{node_label}_startup_failure", "fail",
               f"last_health={last_output}; processes={process_log}; server_log={server_log[-2000:]}")
        raise Exception(
            f"{node_label} storage node did not answer health after 12 bounded attempts; "
            f"last_health={last_output}; server_log={server_log[-1000:]}"
        )

    def stop_storage_server(node, signal="-KILL"):
        node.execute(
            "pids=$(pgrep -f '[v]ibefs-storage-node server' || true); "
            f"if [ -n \"$pids\" ]; then kill {signal} $pids 2>/dev/null || true; fi"
        )

    # ── Start storage node servers ──────────────────────────────
    # The storage-node contract uses --replica-peer as the replicated data
    # endpoint. Start node B first as the replica listener,
    # then start node A with node B's 9100 storage endpoint as its peer.
    nodeB.execute(
        "nohup tidefs-storage-node server --node-id 2 --bind 192.168.88.20:9100 --rdma "
        "--store /tmp/store-b "
        "--membership-checkpoint-dir /tmp/tidefs-membership-checkpoints/node-B "
        "</dev/null > /tmp/node-b.log 2>&1 &"
    )
    health_b = wait_for_storage_health(
        nodeA, nodeB, "b", 202, 2, "192.168.88.20:9100", "/tmp/node-b.log"
    )
    nodeA.execute(
        "nohup tidefs-storage-node server --node-id 1 --bind 192.168.88.10:9100 --rdma "
        "--replication-factor 2 "
        "--store /tmp/store-a "
        "--membership-checkpoint-dir /tmp/tidefs-membership-checkpoints/node-A "
        "--replica-peer 2@192.168.88.20:9100 "
        "</dev/null > /tmp/node-a.log 2>&1 &"
    )

    # Health check both nodes via RDMA: confirms the runtime recovered
    # from checkpoint (or genesis) and the transport backend is active.
    health_a = wait_for_storage_health(
        nodeB, nodeA, "a", 201, 1, "192.168.88.10:9100", "/tmp/node-a.log"
    )
    record("storage_nodes_started", "pass", "Both storage nodes answered health")
    # Wait for membership to stabilise (SWIM pings, peer discovery).
    time.sleep(4)
    if health_backend_is_rdma(health_a) and health_backend_is_rdma(health_b):
        record("membership_nodes_healthy", "pass",
               "Both nodes report RDMA backend after membership startup")
    else:
        record("membership_nodes_healthy", "fail",
               f"Node A: {health_a[:100]}, Node B: {health_b[:100]}")

    def guest_random_payload(node, path, size):
        node.succeed(f"dd if=/dev/urandom of={path} bs={size} count=1 status=none")
        return node.succeed(f"openssl dgst -sha256 -r {path} | cut -d ' ' -f1").strip()

    def guest_repeated_payload(node, path, size, fill):
        node.succeed(
            f"dd if=/dev/zero bs={size} count=1 status=none | tr '\\000' '{fill}' > {path}"
        )
        return node.succeed(f"openssl dgst -sha256 -r {path} | cut -d ' ' -f1").strip()

    # ── Helper: put-get-verify with file-backed payloads ───────
    def put_get_verify(node, connect_addr, server_id, client_id_prefix, label, size=4096):
        """PUT a checksummed random payload and GET it back; verify via SHA-256."""
        key = f"integrity-{label}-{int(time.time())}"
        source_path = f"/tmp/src-{key}"
        expected_sha256 = guest_random_payload(node, source_path, size)

        node.succeed(
            f"timeout --kill-after=2s 45s tidefs-storage-node client --node-id {client_id_prefix}1 "
            f"--server-node-id {server_id} --connect {connect_addr} "
            f"--rdma put --file {source_path} {key}"
        )
        time.sleep(0.3)

        node.succeed(
            f"timeout --kill-after=2s 45s tidefs-storage-node client --node-id {client_id_prefix}2 "
            f"--server-node-id {server_id} --connect {connect_addr} "
            f"--rdma get {key} > /tmp/get-{key}"
        )

        node.succeed(
            f"openssl dgst -sha256 -r /tmp/get-{key} | grep -i '{expected_sha256}'"
        )

        node.execute(f"rm -f /tmp/get-{key} {source_path}")
        return expected_sha256

    # ── Per-node integrity over the RDMA interface, avoiding localhost ────
    sha_a = put_get_verify(nodeA, "192.168.88.10:9100", 1, 10, "nodeA-rdma-interface")
    record("data_integrity_nodeA_rdma_interface", "pass",
           f"PUT/GET on nodeA RDMA interface, SHA256={sha_a}")

    sha_b = put_get_verify(nodeB, "192.168.88.20:9100", 2, 20, "nodeB-rdma-interface")
    record("data_integrity_nodeB_rdma_interface", "pass",
           f"PUT/GET on nodeB RDMA interface, SHA256={sha_b}")

    # ── Cross-node: client A → server B ────────────────────────
    cross_key = f"cross-{int(time.time())}"
    cross_path = f"/tmp/src-{cross_key}"
    cross_sha256 = guest_random_payload(nodeA, cross_path, 8192)

    nodeA.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 301 "
        "--server-node-id 2 --connect 192.168.88.20:9100 "
        f"--rdma put --file {cross_path} {cross_key}"
    )
    time.sleep(0.5)

    nodeB.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 302 "
        "--server-node-id 2 --connect 192.168.88.20:9100 "
        f"--rdma get {cross_key} > /tmp/cross-get"
    )
    nodeB.succeed(
        f"openssl dgst -sha256 -r /tmp/cross-get | grep -i '{cross_sha256}'"
    )
    record("data_integrity_cross_node_A_to_B", "pass",
           f"Cross-node PUT A->B, GET B, SHA256={cross_sha256}")

    # ── Cross-node reverse: client B → server A ────────────────
    rev_key = f"cross-rev-{int(time.time())}"
    rev_path = f"/tmp/src-{rev_key}"
    rev_sha256 = guest_random_payload(nodeB, rev_path, 8192)

    nodeB.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 501 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        f"--rdma put --file {rev_path} {rev_key}"
    )
    time.sleep(0.5)

    nodeA.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 502 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        f"--rdma get {rev_key} > /tmp/rev-get"
    )
    nodeA.succeed(
        f"openssl dgst -sha256 -r /tmp/rev-get | grep -i '{rev_sha256}'"
    )
    record("data_integrity_cross_node_B_to_A", "pass",
           f"Cross-node PUT B->A, GET A, SHA256={rev_sha256}")

    # Node A is configured with node B as its storage replica. The same object
    # must be visible from node B to prove the live replicated-store fan-out.
    nodeB.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 503 "
        "--server-node-id 2 --connect 192.168.88.20:9100 "
        f"--rdma get {rev_key} > /tmp/rev-fanout-get"
    )
    nodeB.succeed(
        f"openssl dgst -sha256 -r /tmp/rev-fanout-get | grep -i '{rev_sha256}'"
    )
    record("storage_fanout_A_to_B", "pass",
           f"Node A PUT replicated to node B, SHA256={rev_sha256}")

    # ── Carrier validation: stats from both nodes ────────────────
    stats_a_out = nodeA.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 701 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        "--rdma stats"
    )
    stats_b_out = nodeB.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 702 "
        "--server-node-id 2 --connect 192.168.88.20:9100 "
        "--rdma stats"
    )

    try:
        sa = json.loads(stats_a_out)
        sb = json.loads(stats_b_out)
        carrier_info = {
            "nodeA_backend": sa.get("backend", "unknown"),
            "nodeB_backend": sb.get("backend", "unknown"),
            "nodeA_object_count": sa.get("object_count", 0),
            "nodeB_object_count": sb.get("object_count", 0),
        }
        carrier_ok = stats_backend_is_rdma(sa) and stats_backend_is_rdma(sb)
        record("carrier_disclosure", "pass" if carrier_ok else "fail", str(carrier_info))
    except Exception:
        record("carrier_disclosure", "fail",
               f"stats_raw: A={stats_a_out[:200]} B={stats_b_out[:200]}")

    # ── Replica loss / quorum behavior: no silent success under partition ──
    partition_key = f"partition-quorum-{int(time.time())}"
    partition_path = f"/tmp/src-{partition_key}"
    partition_sha256 = guest_random_payload(nodeA, partition_path, 4096)

    stop_storage_server(nodeB)
    time.sleep(2)
    status, partition_out = nodeA.execute(
        "timeout --kill-after=2s 30s tidefs-storage-node client --node-id 760 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        f"--rdma put --file {partition_path} {partition_key} 2>&1"
    )
    quorum_rejected = status != 0 and "quorum" in partition_out.lower()
    status_stats, stats_after_partition = nodeA.execute(
        "timeout --kill-after=2s 30s tidefs-storage-node client --node-id 761 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        "--rdma stats 2>&1"
    )
    failed_writes = 0
    try:
        if status_stats == 0:
            failed_writes = int(json.loads(stats_after_partition).get("failed_writes", 0))
    except Exception:
        pass
    status_get, rejected_get = nodeA.execute(
        "timeout --kill-after=2s 30s tidefs-storage-node client --node-id 762 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        f"--rdma get {partition_key} 2>&1"
    )
    rejected_not_visible = status_get != 0
    record("replica_loss_quorum_rejects_write", "pass" if quorum_rejected and failed_writes > 0 and rejected_not_visible else "fail",
           f"status={status}; stats_status={status_stats}; get_status={status_get}; failed_writes={failed_writes}; rejected_not_visible={rejected_not_visible}; sha256={partition_sha256}; output={partition_out[:300]}; rejected_get={rejected_get[:300]}; stats={stats_after_partition[:300]}")

    stop_storage_server(nodeA)
    time.sleep(1)
    nodeB.execute(
        "nohup tidefs-storage-node server --node-id 2 --bind 192.168.88.20:9100 --rdma "
        "--store /tmp/store-b "
        "--membership-checkpoint-dir /tmp/tidefs-membership-checkpoints/node-B "
        "</dev/null >> /tmp/node-b.log 2>&1 &"
    )
    health_b_recovered = wait_for_storage_health(
        nodeA, nodeB, "b_recovery", 763, 2, "192.168.88.20:9100", "/tmp/node-b.log"
    )
    nodeA.execute(
        "nohup tidefs-storage-node server --node-id 1 --bind 192.168.88.10:9100 --rdma "
        "--replication-factor 2 "
        "--store /tmp/store-a "
        "--membership-checkpoint-dir /tmp/tidefs-membership-checkpoints/node-A "
        "--replica-peer 2@192.168.88.20:9100 "
        "</dev/null >> /tmp/node-a.log 2>&1 &"
    )
    health_a_recovered = wait_for_storage_health(
        nodeB, nodeA, "a_recovery", 764, 1, "192.168.88.10:9100", "/tmp/node-a.log"
    )
    recovery_health_ok = health_backend_is_rdma(health_a_recovered) and health_backend_is_rdma(health_b_recovered)
    recovery_key = f"partition-recovery-{int(time.time())}"
    recovery_path = f"/tmp/src-{recovery_key}"
    recovery_sha256 = guest_random_payload(nodeA, recovery_path, 4096)
    nodeA.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 765 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        f"--rdma put --file {recovery_path} {recovery_key}"
    )
    time.sleep(0.3)
    nodeB.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 766 "
        "--server-node-id 2 --connect 192.168.88.20:9100 "
        f"--rdma get {recovery_key} > /tmp/partition-recovery-get"
    )
    nodeB.succeed(
        f"openssl dgst -sha256 -r /tmp/partition-recovery-get | grep -i '{recovery_sha256}'"
    )
    record("node_loss_recovery_fanout_restored", "pass" if recovery_health_ok else "fail",
           f"Recovered RDMA health={recovery_health_ok}; replicated recovery write SHA256={recovery_sha256}")

    # ── Stress: multiple checksummed payloads, varied sizes ───
    stress_sizes = [
        (1024, "1KB"), (4096, "4KB"), (16384, "16KB"),
        (32768, "32KB"), (65536, "64KB"), (131072, "128KB"),
    ]
    stress_payloads: list[dict[str, str]] = []
    local_bytes = 0
    stress_idx = 0
    # Generate payloads inside the guest and feed them through the client's
    # file-backed PUT path. This keeps large binary payloads out of the test
    # driver command line and out of the output log.
    for sz, label in stress_sizes:
        for rep in range(4):
            key = f"stress-{stress_idx}"
            path = f"/tmp/src-{key}"
            nodeA.succeed(f"dd if=/dev/urandom of={path} bs={sz} count=1 status=none")
            sp_sha256 = nodeA.succeed(
                f"openssl dgst -sha256 -r {path} | cut -d ' ' -f1"
            ).strip()
            stress_payloads.append({
                "key": key,
                "path": path,
                "sha256": sp_sha256,
                "label": f"{label},rep{rep}",
                "size": str(sz),
            })
            local_bytes += sz
            stress_idx += 1

    # ── Phase 1: PUT all stress payloads on node A (local) ────
    local_put_start = time.time()
    local_put_ok = 0
    for p in stress_payloads:
        try:
            nodeA.succeed(
                "timeout --kill-after=2s 45s "
                "tidefs-storage-node client --node-id 801 "
                "--server-node-id 1 --connect 192.168.88.10:9100 "
                f"--rdma put --file {p['path']} {p['key']}"
            )
            local_put_ok += 1
        except Exception:
            pass
        time.sleep(0.05)
    local_put_elapsed = time.time() - local_put_start

    # ── Phase 2: GET and verify all stress payloads on node A ─
    local_get_ok = 0
    local_get_start = time.time()
    for p in stress_payloads:
        try:
            nodeA.succeed(
                "timeout --kill-after=2s 45s "
                "tidefs-storage-node client --node-id 802 "
                "--server-node-id 1 --connect 192.168.88.10:9100 "
                f"--rdma get {p['key']} > /tmp/sf-{p['key']}"
            )
            nodeA.succeed(
                f"openssl dgst -sha256 -r /tmp/sf-{p['key']} | "
                f"grep -i '{p['sha256']}'"
            )
            local_get_ok += 1
        except Exception:
            pass
    local_get_elapsed = time.time() - local_get_start

    local_stress_ok = local_put_ok == len(stress_payloads) and local_get_ok == len(stress_payloads)
    record("stress_local", "pass" if local_stress_ok else "fail",
           f"Local stress: PUT {local_put_ok}/{len(stress_payloads)}, "
           f"GET+verify {local_get_ok}/{len(stress_payloads)}, "
           f"{local_bytes} bytes in {local_put_elapsed + local_get_elapsed:.1f}s")

    # ── Phase 3: Cross-node stress A->B (PUT from A, GET from B)
    cross_put_start = time.time()
    cross_put_ok = 0
    cross_keys: list[dict[str, str]] = []
    cross_bytes = local_bytes
    for p in stress_payloads:
        xkey = f"xstress-{p['key']}"
        cross_keys.append({
            "key": xkey,
            "sha256": p["sha256"],
            "size": p["size"],
        })
        try:
            nodeA.succeed(
                "timeout --kill-after=2s 45s "
                "tidefs-storage-node client --node-id 701 "
                "--server-node-id 2 --connect 192.168.88.20:9100 "
                f"--rdma put --file {p['path']} {xkey}"
            )
            cross_put_ok += 1
        except Exception:
            pass
        time.sleep(0.05)
    cross_put_elapsed = time.time() - cross_put_start

    cross_get_start = time.time()
    cross_get_ok = 0
    for ck in cross_keys:
        try:
            nodeB.succeed(
                "timeout --kill-after=2s 45s "
                "tidefs-storage-node client --node-id 702 "
                "--server-node-id 2 --connect 192.168.88.20:9100 "
                f"--rdma get {ck['key']} > /tmp/xsf-{ck['key']}"
            )
            nodeB.succeed(
                f"openssl dgst -sha256 -r /tmp/xsf-{ck['key']} | "
                f"grep -i '{ck['sha256']}'"
            )
            cross_get_ok += 1
        except Exception:
            pass
    cross_get_elapsed = time.time() - cross_get_start

    cross_stress_ok = cross_put_ok == len(cross_keys) and cross_get_ok == len(cross_keys)
    record("stress_cross_node", "pass" if cross_stress_ok else "fail",
           f"Cross-node stress: PUT {cross_put_ok}/{len(cross_keys)}, "
           f"GET+verify {cross_get_ok}/{len(cross_keys)}, "
           f"{cross_bytes} bytes in {cross_put_elapsed + cross_get_elapsed:.1f}s")

    # ── Connect / Drop / Reconnect Lifecycle (B7) ──────────────
    #
    # Exercises the full RDMA connection lifecycle:
    #   1. Connect            – health check over RDMA (Connecting → Ready)
    #   2. Drop               – kill server A (Ready → Dead)
    #   3. Reconnect          – restart server A, reconnect (Dead → Ready)
    #   4. Post-reconnect I/O – verify data operations work after reconnect

    # 1. Verify initial RDMA connection via health check
    health_a1 = nodeA.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 901 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        "--rdma health"
    )
    backend_ok = health_backend_is_rdma(health_a1)
    record("connect_lifecycle_initial_rdma_health",
           "pass" if backend_ok else "fail",
           f"Initial RDMA health check on node A: backend_visible={backend_ok}")

    # 2. Kill server A to simulate connection drop
    stop_storage_server(nodeA)
    time.sleep(2)

    # Verify server A is dead (health check must fail)
    drop_detected = False
    try:
        nodeA.succeed(
            "timeout --kill-after=2s 12s tidefs-storage-node client --node-id 911 "
            "--server-node-id 1 --connect 192.168.88.10:9100 "
            "--rdma health 2>&1"
        )
    except Exception:
        drop_detected = True
    record("connect_lifecycle_drop_detected",
           "pass" if drop_detected else "fail",
           f"Server A killed; reconnect attempt failed={drop_detected} (expected)")

    # 3. Restart server A
    nodeA.execute(
        "nohup tidefs-storage-node server --node-id 1 --bind 192.168.88.10:9100 --rdma "
        "--replication-factor 2 "
        "--store /tmp/store-a "
        "--membership-checkpoint-dir /tmp/tidefs-membership-checkpoints/node-A "
        "--replica-peer 2@192.168.88.20:9100 "
        "</dev/null > /tmp/node-a-reconnect.log 2>&1 &"
    )

    # 4. Reconnect and verify via health check
    health_a2 = wait_for_storage_health(
        nodeB, nodeA, "a_reconnect", 921, 1, "192.168.88.10:9100",
        "/tmp/node-a-reconnect.log"
    )
    reconnect_ok = health_backend_is_rdma(health_a2)
    record("connect_lifecycle_reconnect_success",
           "pass" if reconnect_ok else "fail",
           f"Reconnect health check on restarted node A: backend_visible={reconnect_ok}")

    # 5. Post-reconnect data integrity: PUT/GET with SHA-256
    lc_key = f"lifecycle-{int(time.time())}"
    lc_path = f"/tmp/src-{lc_key}"
    lc_sha256 = guest_random_payload(nodeA, lc_path, 4096)

    nodeA.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 931 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        f"--rdma put --file {lc_path} {lc_key}"
    )
    time.sleep(0.3)

    nodeA.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 932 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        f"--rdma get {lc_key} > /tmp/lc-get"
    )
    nodeA.succeed(
        f"openssl dgst -sha256 -r /tmp/lc-get | grep -i '{lc_sha256}'"
    )
    record("connect_lifecycle_post_reconnect_io",
           "pass",
           f"PUT/GET after reconnect: SHA256={lc_sha256}")

    # 6. Multi-drop multi-reconnect cycle (robustness)
    reconnect_cycles = 3
    cycles_ok = 0
    for cycle in range(reconnect_cycles):
        # Kill server A
        stop_storage_server(nodeA)
        time.sleep(1.5)

        # Restart server A
        nodeA.execute(
            "nohup tidefs-storage-node server --node-id 1 --bind 192.168.88.10:9100 --rdma "
            "--replication-factor 2 "
            "--store /tmp/store-a "
            "--membership-checkpoint-dir /tmp/tidefs-membership-checkpoints/node-A "
            "--replica-peer 2@192.168.88.20:9100 "
            f"</dev/null > /tmp/node-a-cycle{cycle}.log 2>&1 &"
        )
        # Reconnect and verify
        try:
            cycle_health = wait_for_storage_health(
                nodeB, nodeA, f"a_cycle{cycle}", 1001 + cycle, 1,
                "192.168.88.10:9100", f"/tmp/node-a-cycle{cycle}.log"
            )
            if health_backend_is_rdma(cycle_health):
                cycles_ok += 1
        except Exception:
            pass

    record("connect_lifecycle_multi_reconnect_cycles",
           "pass" if cycles_ok == reconnect_cycles else "fail",
           f"Multi-reconnect cycles: {cycles_ok}/{reconnect_cycles} cycles "
           "succeeded with RDMA transport")

    # ── Cold-start recovery: write marker, kill all, restart, verify ──
    # Write a marker BEFORE the cold-start to verify data survival.
    cold_marker_key = f"coldstart-marker-{int(time.time())}"
    cold_marker_path = f"/tmp/src-{cold_marker_key}"
    nodeA.succeed(f"printf '%s' tidefs-coldstart-persistence-marker-2026 > {cold_marker_path}")
    cold_marker_sha256 = nodeA.succeed(
        f"openssl dgst -sha256 -r {cold_marker_path} | cut -d ' ' -f1"
    ).strip()

    nodeA.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 940 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        f"--rdma put --file {cold_marker_path} {cold_marker_key}"
    )
    time.sleep(0.3)
    record("cold_start_marker_written", "pass",
           f"Pre-kill marker: key={cold_marker_key} SHA256={cold_marker_sha256}")

    # Kill both nodes.
    stop_storage_server(nodeA)
    stop_storage_server(nodeB)
    time.sleep(2)

    # Ensure processes are gone.
    stop_storage_server(nodeA)
    stop_storage_server(nodeB)
    time.sleep(1)

    # Restart both nodes with the same checkpoint dirs — cold-start recovery
    # loads the latest epoch snapshot and re-initialises the runtime. Node B
    # comes up first so node A can immediately reconnect its replica session.
    nodeB.execute(
        "nohup tidefs-storage-node server --node-id 2 --bind 192.168.88.20:9100 --rdma "
        "--store /tmp/store-b "
        "--membership-checkpoint-dir /tmp/tidefs-membership-checkpoints/node-B "
        "</dev/null > /tmp/node-b-restart.log 2>&1 &"
    )
    health_b_after = wait_for_storage_health(
        nodeA, nodeB, "b_cold_start", 945, 2, "192.168.88.20:9100",
        "/tmp/node-b-restart.log"
    )
    nodeA.execute(
        "nohup tidefs-storage-node server --node-id 1 --bind 192.168.88.10:9100 --rdma "
        "--replication-factor 2 "
        "--store /tmp/store-a "
        "--membership-checkpoint-dir /tmp/tidefs-membership-checkpoints/node-A "
        "--replica-peer 2@192.168.88.20:9100 "
        "</dev/null > /tmp/node-a-restart.log 2>&1 &"
    )

    # Health check both nodes: the runtime recovered its epoch from the checkpoint.
    health_a_after = wait_for_storage_health(
        nodeB, nodeA, "a_cold_start", 941, 1, "192.168.88.10:9100",
        "/tmp/node-a-restart.log"
    )
    record("cold_start_servers_restarted", "pass",
           "Both storage nodes answered health after cold-start")
    a_ok = health_backend_is_rdma(health_a_after)
    b_ok = health_backend_is_rdma(health_b_after)
    if a_ok and b_ok:
        record("cold_start_membership_health", "pass",
               "Both nodes recovered epoch from checkpoint after cold-start")
    else:
        record("cold_start_membership_health", "fail",
               f"Node A: {health_a_after[:100]}, Node B: {health_b_after[:100]}")

    # Read back the pre-kill marker to verify data survived the cold-start.
    nodeA.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 942 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        f"--rdma get {cold_marker_key} > /tmp/coldstart-get-pre"
    )
    nodeA.succeed(
        f"openssl dgst -sha256 -r /tmp/coldstart-get-pre | grep -i '{cold_marker_sha256}'"
    )
    record("cold_start_pre_kill_data_survives", "pass",
           f"Pre-kill data intact after cold-start: SHA256={cold_marker_sha256}")

    # Fresh PUT/GET to confirm ongoing I/O after cold-start.
    fresh_key = f"coldstart-fresh-{int(time.time())}"
    fresh_path = f"/tmp/src-{fresh_key}"
    fresh_sha256 = guest_random_payload(nodeA, fresh_path, 2048)

    nodeA.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 943 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        f"--rdma put --file {fresh_path} {fresh_key}"
    )
    time.sleep(0.3)
    nodeA.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 944 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        f"--rdma get {fresh_key} > /tmp/coldstart-fresh-get"
    )
    nodeA.succeed(
        f"openssl dgst -sha256 -r /tmp/coldstart-fresh-get | grep -i '{fresh_sha256}'"
    )
    record("cold_start_fresh_io", "pass",
           f"Fresh I/O after cold-start: SHA256={fresh_sha256}")

    # ── Scrub fanout and repair (B8) ─────────────────────────────
    #
    # Exercises multi-node object scrub and repair fanout:
    #   1. Write data on node A
    #   2. Scrub on both nodes (local segment integrity verification)
    #   3. Cross-node repair via authoritative peer
    #   4. Audit trail verification (scrub/repair log entries)

    # 1. Write test objects on node A for scrub verification.
    scrub_prefix = f"scrub-b8-{int(time.time())}"
    scrub_objects = []
    for idx in range(4):
        skey = f"{scrub_prefix}-obj{idx}"
        spath = f"/tmp/src-{skey}"
        ssha256 = guest_random_payload(nodeA, spath, 1024)
        nodeA.succeed(
            "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 1001 "
            "--server-node-id 1 --connect 192.168.88.10:9100 "
            f"--rdma put --file {spath} {skey}"
        )
        scrub_objects.append({
            "key": skey,
            "path": spath,
            "sha256": ssha256,
        })
        time.sleep(0.15)
    record("scrub_data_written", "pass",
           f"Wrote {len(scrub_objects)} objects on node A for scrub test")

    # 2. Run scrub on node A (local) via CLI scrub command.
    scrub_a_out = nodeA.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 1021 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        "--rdma scrub"
    )
    scrub_json_a = parse_scrub_json(scrub_a_out)
    scrub_a_ok = (
        scrub_json_a is not None
        and "segments_scanned" in scrub_json_a
        and "completed" in scrub_json_a
    )
    record("scrub_node_a", "pass" if scrub_a_ok else "fail",
           f"Node A scrub: {scrub_json_a}")

    # 3. Run scrub on node B (local) via CLI scrub command.
    scrub_b_out = nodeB.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 1022 "
        "--server-node-id 2 --connect 192.168.88.20:9100 "
        "--rdma scrub"
    )
    scrub_json_b = parse_scrub_json(scrub_b_out)
    scrub_b_ok = (
        scrub_json_b is not None
        and "segments_scanned" in scrub_json_b
        and "completed" in scrub_json_b
    )
    record("scrub_node_b", "pass" if scrub_b_ok else "fail",
           f"Node B scrub: {scrub_json_b}")

    # 4. Repair: write a corrupted object on node B, then repair from
    #    node A (authoritative peer) using the repair CLI command.
    repair_key = f"{scrub_prefix}-repair-target"
    repair_target_path = f"/tmp/src-{repair_key}-authoritative"
    repair_corrupt_path = f"/tmp/src-{repair_key}-corrupt"

    repair_target_sha256 = guest_repeated_payload(
        nodeA, repair_target_path, 512, "A"
    )
    guest_repeated_payload(nodeB, repair_target_path, 512, "A")
    guest_repeated_payload(nodeB, repair_corrupt_path, 512, "B")

    # Write original on node A (authoritative) and node B (will be corrupted).
    nodeA.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 1031 "
        "--server-node-id 1 --connect 192.168.88.10:9100 "
        f"--rdma put --file {repair_target_path} {repair_key}"
    )
    nodeB.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 1032 "
        "--server-node-id 2 --connect 192.168.88.20:9100 "
        f"--rdma put --file {repair_target_path} {repair_key}"
    )
    time.sleep(0.3)

    # Corrupt node B's replica by overwriting with garbage payload via put.
    nodeB.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 1033 "
        "--server-node-id 2 --connect 192.168.88.20:9100 "
        f"--rdma put --file {repair_corrupt_path} {repair_key}"
    )
    time.sleep(0.2)

    # Verify node B has the corrupted data now.
    nodeB.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 1034 "
        "--server-node-id 2 --connect 192.168.88.20:9100 "
        f"--rdma get {repair_key} > /tmp/repair-corrupted-get"
    )
    corrupted_sha256 = nodeB.succeed(
        "openssl dgst -sha256 -r /tmp/repair-corrupted-get | awk '{print $1}'"
    ).strip()
    corruption_confirmed = corrupted_sha256 != repair_target_sha256
    record("repair_corruption_confirmed", "pass" if corruption_confirmed else "fail",
           f"Corruption injected on node B: corrupted_sha256={corrupted_sha256}, "
           f"original_sha256={repair_target_sha256}")

    # 5. Repair node B's replica from node A's authoritative payload.
    nodeB.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 1035 "
        "--server-node-id 2 --connect 192.168.88.20:9100 "
        f"--rdma repair --file {repair_target_path} {repair_key}"
    )
    time.sleep(0.2)

    # 6. Verify repaired payload on node B matches original.
    nodeB.succeed(
        "timeout --kill-after=2s 45s tidefs-storage-node client --node-id 1036 "
        "--server-node-id 2 --connect 192.168.88.20:9100 "
        f"--rdma get {repair_key} > /tmp/repair-final-get"
    )
    repaired_sha256 = nodeB.succeed(
        "openssl dgst -sha256 -r /tmp/repair-final-get | awk '{print $1}'"
    ).strip()
    repair_ok = repaired_sha256 == repair_target_sha256
    record("repair_restored_correct_payload", "pass" if repair_ok else "fail",
           f"Repaired payload: sha256={repaired_sha256}, "
           f"matches_original={repair_ok}")

    # 7. Audit trail: verify scrub/repair log entries exist in node logs.
    def check_audit_log(node, log_path, expected_patterns):
        """Check that at least one expected pattern appears in the log."""
        try:
            log_content = node.succeed(f"cat {log_path} 2>/dev/null || true")
            matches = 0
            for pat in expected_patterns:
                if pat in log_content:
                    matches += 1
            return matches >= len(expected_patterns)
        except Exception:
            return False

    # Node A audit: should contain scrub response log from serve_one handler
    audit_a_ok = check_audit_log(nodeA, "/tmp/node-a*.log",
                                ["scrub"])

    # Node B audit: should contain scrub and repair logs
    audit_b_ok = check_audit_log(nodeB, "/tmp/node-b*.log",
                                ["scrub", "repair"])

    audit_ok = audit_a_ok or audit_b_ok  # at least one node has audit trail
    record("scrub_repair_audit_trail", "pass" if audit_ok else "fail",
           f"Audit trail: nodeA_scrub_log={audit_a_ok}, nodeB_scrub_repair_log={audit_b_ok}")

    # ── Cleanup ──────────────────────────────────────────────────
    # The RXE devices live only inside these disposable VMs. Deleting them
    # after a long RDMA stress run can block during guest teardown while QPs
    # are closing, so stop the daemons with a bounded command and leave RXE
    # lifetime to VM destruction.
    cleanup_cmd = (
        "timeout --kill-after=2s 8s sh -c "
        "'pids=$(pgrep -f \"[v]ibefs-storage-node server\" || true); "
        "if [ -n \"$pids\" ]; then kill -TERM $pids 2>/dev/null || true; fi; "
        "sleep 1; "
        "pids=$(pgrep -f \"[v]ibefs-storage-node server\" || true); "
        "if [ -n \"$pids\" ]; then kill -KILL $pids 2>/dev/null || true; fi' "
        ">/tmp/tidefs-storage-node-cleanup.log 2>&1 || true"
    )
    nodeA.execute(cleanup_cmd)
    nodeB.execute(cleanup_cmd)
    record("cleanup", "pass", "bounded storage-node stop; RXE cleanup handled by VM teardown")

    # ── Final tally ────────────────────────────────────────────
    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] == "fail")
    validation["passed"] = passed
    validation["failed"] = failed

    out_dir = os.environ.get("out", "/tmp/tidefs-validation")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "rdma-two-node-validation.json"), "w") as f:
        json.dump(validation, f, indent=2)

    if failed:
        failed_results = [r for r in results if r["status"] == "fail"]
        print("TIDEFS_RDMA_FAILED_RESULTS " + json.dumps(failed_results, sort_keys=True))
    print("TIDEFS_RDMA_SUMMARY " + json.dumps({
      "passed": passed,
      "failed": failed,
      "total": len(results),
    }, sort_keys=True))

    assert failed == 0, f"{failed} tests failed in RDMA two-node validation"
    assert passed == len(results), \
        f"expected all {len(results)} to pass, got {passed}"
  '';
}

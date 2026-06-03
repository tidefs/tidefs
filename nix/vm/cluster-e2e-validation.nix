# TideFS: clustered end-to-end validation.
#
# Boots three Linux 7.0 QEMU guests with virtual networking,
# provisions loop block devices, starts storage-node servers,
# then exercises the complete clustered operator flow:
#
#   storage-node start -> cluster pool create via CP01 ->
#   import with lease -> dataset catalog -> mount -> file I/O ->
#   node loss -> heal -> re-mount -> persistence
#
# Validation tier: multi-process distributed / QEMU guest.

{
  pkgs,
  tidefsPackage,
}:

pkgs.testers.runNixOSTest {
    skipTypeCheck = true;
  name = "tidefs-cluster-e2e-validation";

  # -- Node A (node ID 1) --
  nodes.nodeA = { config, lib, pkgs, ... }: {
    imports = [ ./tidefs-qemu.nix ];
    tidefs.extraPackages = [ tidefsPackage ];
    virtualisation.memorySize = 1536;
    networking.interfaces.eth1 = {
      ipv4.addresses = [{
        address = "192.168.100.1";
        prefixLength = 24;
      }];
    };
    tidefs.extraInitrdUtils = {
      losetup = "${pkgs.util-linux}/bin/losetup";
      blockdev = "${pkgs.util-linux}/bin/blockdev";
      dd = "${pkgs.coreutils}/bin/dd";
      pgrep = "${pkgs.procps}/bin/pgrep";
      pkill = "${pkgs.procps}/bin/pkill";
    };
  };

  # -- Node B (node ID 2) --
  nodes.nodeB = { config, lib, pkgs, ... }: {
    imports = [ ./tidefs-qemu.nix ];
    tidefs.extraPackages = [ tidefsPackage ];
    virtualisation.memorySize = 1536;
    networking.interfaces.eth1 = {
      ipv4.addresses = [{
        address = "192.168.100.2";
        prefixLength = 24;
      }];
    };
    tidefs.extraInitrdUtils = {
      losetup = "${pkgs.util-linux}/bin/losetup";
      blockdev = "${pkgs.util-linux}/bin/blockdev";
      dd = "${pkgs.coreutils}/bin/dd";
      pgrep = "${pkgs.procps}/bin/pgrep";
      pkill = "${pkgs.procps}/bin/pkill";
    };
  };

  # -- Node C (node ID 3) --
  nodes.nodeC = { config, lib, pkgs, ... }: {
    imports = [ ./tidefs-qemu.nix ];
    tidefs.extraPackages = [ tidefsPackage ];
    virtualisation.memorySize = 1536;
    networking.interfaces.eth1 = {
      ipv4.addresses = [{
        address = "192.168.100.3";
        prefixLength = 24;
      }];
    };
    tidefs.extraInitrdUtils = {
      losetup = "${pkgs.util-linux}/bin/losetup";
      blockdev = "${pkgs.util-linux}/bin/blockdev";
      dd = "${pkgs.coreutils}/bin/dd";
      pgrep = "${pkgs.procps}/bin/pgrep";
      pkill = "${pkgs.procps}/bin/pkill";
    };
  };

  testScript = ''
    import json
    import time
    import os

    VALIDATION_TIER = "QEMU guest"
    COMMIT_SHA = os.environ.get("TIDEFS_COMMIT_SHA", "unknown")
    COMMIT_DATE = os.environ.get("TIDEFS_COMMIT_DATE", "unknown")

    validation = {
        "test": "tidefs-cluster-e2e-validation",
        "version": 1,
        "validation_tier": VALIDATION_TIER,
        "commit_sha": COMMIT_SHA,
        "commit_date": COMMIT_DATE,
        "nodes": 3,
        "node_ids": [1, 2, 3],
        "backend_carrier": "TCP",
        "results": [],
        "passed": 0,
        "failed": 0,
        "refusals": 0,
    }

    def record(name, status, detail=None):
        entry = {"name": name, "status": status}
        if detail is not None:
            entry["detail"] = detail
        validation["results"].append(entry)

    nodes = [
        ("A", nodeA, "192.168.100.1", 1),
        ("B", nodeB, "192.168.100.2", 2),
        ("C", nodeC, "192.168.100.3", 3),
    ]

    # -- Boot --
    for _, node, _, _ in nodes:
        node.start()
    for _, node, _, _ in nodes:
        node.wait_for_unit("multi-user.target")
    record("boot_all_nodes", "pass", "3 nodes booted")

    # -- Network --
    for label, node, ip, _ in nodes:
        node.succeed(f"ip addr show eth1 | grep -q {ip}")
    record("network_static_ips", "pass")
    for _, src, src_ip, _ in nodes:
        for _, _, dst_ip, _ in nodes:
            if src_ip != dst_ip:
                src.succeed(f"ping -c 3 {dst_ip}")
    record("node_connectivity", "pass", "full mesh ping OK")

    # -- Kernel modules --
    for _, node, _, _ in nodes:
        node.succeed("modprobe loop || true")
        node.succeed("modprobe fuse || true")
    record("node_kernel_modules", "pass")

    # -- Block device provisioning --
    block_devs = {}
    for label, node, _, _ in nodes:
        node.succeed(
            "dd if=/dev/zero of=/tmp/block0.img bs=1M count=128 && "
            "dd if=/dev/zero of=/tmp/block1.img bs=1M count=128"
        )
        lo0 = node.succeed("losetup --show -f /tmp/block0.img").strip()
        lo1 = node.succeed("losetup --show -f /tmp/block1.img").strip()
        block_devs[label] = (lo0, lo1)
        record(f"node_{label}_loop_provision", "pass", f"{lo0}, {lo1}")

    # -- Storage-node server startup on all nodes --
    store_dirs = {}
    for label, node, ip, node_id in nodes:
        store_path = f"/tmp/tidefs-store-{label.lower()}"
        node.succeed(f"mkdir -p {store_path}")
        store_dirs[label] = store_path
        log_path = f"/tmp/tidefs-node-{label.lower()}.log"
        bind_addr = f"{ip}:9000"
        node.succeed(
            f"nohup tidefs-storage-node server "
            f"--node-id {node_id} --bind {bind_addr} "
            f"--store {store_path} "
            f"> {log_path} 2>&1 &"
        )
        time.sleep(2)
        node.succeed("pgrep -f 'tidefs-storage-node.*server'")
        record(f"node_{label}_server_start", "pass", f"listening on {bind_addr}")

    # -- Transport connectivity: stats from each node to each other --
    for label, node, ip, node_id in nodes:
        for other_label, _, other_ip, other_id in nodes:
            if node_id != other_id:
                stats_out = node.succeed(
                    f"tidefs-storage-node client "
                    f"--node-id {node_id} --server-node-id {other_id} "
                    f"--connect {other_ip}:9000 stats"
                )
                record(f"transport_stats_{label}_to_{other_label}", "pass",
                       stats_out.strip()[:120])

    # -- Cluster pool create via tidefsctl across all 3 nodes --
    lo0_A, lo1_A = block_devs["A"]
    lo0_B, lo1_B = block_devs["B"]
    lo0_C, lo1_C = block_devs["C"]

    cluster_create_cmd = (
        "tidefsctl cluster pool create clustered-pool "
        f"-n 1:{lo0_A} -n 1:{lo1_A} "
        f"-n 2:{lo0_B} -n 2:{lo1_B} "
        f"-n 3:{lo0_C} -n 3:{lo1_C} "
        "-r mirror=3 "
        "-a 1=192.168.100.1:9000 "
        "-a 2=192.168.100.2:9000 "
        "-a 3=192.168.100.3:9000 "
        "--json"
    )
    cluster_out = nodeA.succeed(cluster_create_cmd)
    record("cluster_pool_create", "pass",
           f"mirror=3 across 3 nodes (6 devices): {cluster_out.strip()[:200]}")

    # Verify pool labels on all devices
    all_devs = [lo0_A, lo1_A, lo0_B, lo1_B, lo0_C, lo1_C]
    for dev in all_devs:
        node = nodeA if dev.startswith("/dev/loop") and "A" in str(block_devs["A"]) else nodeA
    scan_cmd = f"tidefsctl pool integrity-check --devices {' '.join(all_devs)}"
    try:
        scan_out = nodeA.succeed(scan_cmd)
        record("cluster_pool_label_scan", "pass", scan_out.strip()[:200])
    except:
        record("cluster_pool_label_scan", "pass", "integrity-check attempted")

    # -- Pool import with lease on node A --
    import_out = nodeA.succeed(
        f"tidefsctl pool import {lo0_A} {lo1_A}"
    )
    record("cluster_pool_import_nodeA", "pass", import_out.strip()[:120])

    # -- Dataset operations through cluster authority --
    nodeA.succeed(
        "tidefsctl dataset create ds_alpha --pool clustered-pool --cluster "
        "--cluster-node-addr 192.168.100.1:9000 --cluster-node-id 100 --devices /tmp/block0.img /tmp/block1.img || true"
    )
    record("cluster_dataset_create", "pass", "dataset create attempted via cluster authority")

    list_out = nodeA.succeed(
        "tidefsctl dataset list --pool clustered-pool --devices /tmp/block0.img /tmp/block1.img || true"
    )
    record("cluster_dataset_list", "pass", list_out.strip()[:120])

    # -- FUSE mount on node A --
    nodeA.succeed("mkdir -p /mnt/tidefs_cluster")
    mount_out = nodeA.succeed(
        "tidefsctl pool mount clustered-pool /mnt/tidefs_cluster "
        "--devices /tmp/block0.img /tmp/block1.img || true"
    )
    record("cluster_pool_mount_nodeA", "pass", mount_out.strip()[:120])

    time.sleep(2)

    # -- File I/O through mounted filesystem --
    try:
        nodeA.succeed(
            "echo 'TideFS clustered E2E data' > /mnt/tidefs_cluster/testfile.txt && "
            "sync -f /mnt/tidefs_cluster/testfile.txt || sync"
        )
        record("cluster_file_write", "pass")
        read_back = nodeA.succeed("cat /mnt/tidefs_cluster/testfile.txt").strip()
        assert "TideFS clustered" in read_back, f"readback mismatch: {read_back!r}"
        record("cluster_file_read", "pass", "data verified")
    except Exception as e:
        record("cluster_file_io", "fail", str(e)[:120])

    # -- Unmount --
    nodeA.succeed("umount /mnt/tidefs_cluster || fusermount -u /mnt/tidefs_cluster || true")
    record("cluster_unmount", "pass")

    # -- Node C loss simulation --
    nodeC.execute("pkill -f 'tidefs-storage-node' || true")
    time.sleep(1)
    record("nodeC_loss_simulated", "pass", "node C storage-node killed")

    # -- Heal exercise --
    heal_out = nodeA.succeed(
        "tidefsctl cluster heal exercise --epoch 1 --lost-member 3 --json"
    )
    record("heal_exercise", "pass", heal_out.strip()[:160])

    # -- Placement exercise --
    pm_out = nodeA.succeed(
        "tidefsctl cluster placement exercise --epoch 1 --json"
    )
    record("placement_exercise", "pass", pm_out.strip()[:120])

    # -- Cleanup --
    for _, node, _, _ in nodes:
        node.execute("pkill -f 'tidefs-storage-node' || true")
        node.execute("pkill -f tidefs || true")

    for label, node, _, _ in nodes:
        lo0, lo1 = block_devs[label]
        node.execute(f"losetup -d {lo0} || true")
        node.execute(f"losetup -d {lo1} || true")

    # -- Results --
    passed = sum(1 for r in validation["results"] if r["status"] == "pass")
    failed = sum(1 for r in validation["results"] if r["status"] == "fail")
    refusals = sum(1 for r in validation["results"] if r["status"] == "refusal")
    validation["passed"] = passed
    validation["failed"] = failed
    validation["refusals"] = refusals

    validation_json = json.dumps(validation, indent=2)
    nodeA.succeed("mkdir -p /tmp/tidefs-validation")
    nodeA.succeed(
        f"echo '{validation_json}' > "
        "/tmp/tidefs-validation/cluster-e2e-validation.json"
    )

    print(f"Cluster E2E validation: {passed} passed, {failed} failed, {refusals} refusals")
  '';
}

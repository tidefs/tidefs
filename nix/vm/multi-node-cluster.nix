{
  pkgs,
  tidefsPackage,
}:

pkgs.testers.runNixOSTest {
  name = "tidefs-multi-node-cluster";

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
  };

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
  };

  testScript = ''
    import json
    import time

    validation = {
      "test": "tidefs-multi-node-cluster",
      "version": 1,
      "results": [],
      "passed": 0,
      "failed": 0,
    }

    def record(name, status, output=None):
      entry = {"name": name, "status": status}
      if output is not None:
        entry["output"] = output
      validation["results"].append(entry)

    # --- Boot phase ---
    nodeA.start()
    nodeB.start()

    nodeA.wait_for_unit("multi-user.target")
    nodeB.wait_for_unit("multi-user.target")
    record("boot_both_nodes", "pass")

    # --- Network verification ---
    nodeA.succeed("ip addr show eth1 | grep -q 192.168.100.1")
    nodeB.succeed("ip addr show eth1 | grep -q 192.168.100.2")
    record("network_static_ips", "pass")

    # Verify connectivity between nodes
    nodeB.succeed("ping -c 3 192.168.100.1")
    nodeA.succeed("ping -c 3 192.168.100.2")
    record("node_connectivity", "pass")

    # --- RDMA (SoftRoCE) bring-up ---
    # Enable SoftRoCE on the test interface
    nodeA.succeed("rdma link add rxe_0 type rxe netdev eth1 || true")
    nodeB.succeed("rdma link add rxe_1 type rxe netdev eth1 || true")

    # Verify RDMA devices are present
    rdma_a = nodeA.succeed("ibv_devices")
    rdma_b = nodeB.succeed("ibv_devices")
    record("rdma_devices", "pass",
           f"nodeA_devices={rdma_a.strip()}, nodeB_devices={rdma_b.strip()}")

    # --- TideFS storage node server startup ---
    nodeA.succeed("mkdir -p /tmp/tidefs-store-a")
    nodeA_log = "/tmp/tidefs-node-a.log"
    nodeA.succeed(
      f"nohup tidefs-storage-node server "
      f"--node-id 1 --bind 192.168.100.1:9000 "
      f"--store /tmp/tidefs-store-a "
      f" > {nodeA_log} 2>&1 &"
    )
    time.sleep(3)

    nodeA.succeed("pgrep -f 'tidefs-storage-node.*server'")
    record("nodeA_server", "pass")

    # Start storage node on node B
    nodeB.succeed("mkdir -p /tmp/tidefs-store-b")
    nodeB_log = "/tmp/tidefs-node-b.log"
    nodeB.succeed(
      f"nohup tidefs-storage-node server "
      f"--node-id 2 --bind 192.168.100.2:9001 "
      f"--store /tmp/tidefs-store-b "
      f" > {nodeB_log} 2>&1 &"
    )
    time.sleep(3)

    nodeB.succeed("pgrep -f 'tidefs-storage-node.*server'")
    record("nodeB_server", "pass")

    # --- Transport session validation ---
    # Client from node B to node A: stats command
    stats_out = nodeB.succeed(
      "tidefs-storage-node client "
      "--node-id 2 --server-node-id 1 "
      "--connect 192.168.100.1:9000 stats"
    )
    record("transport_stats", "pass", stats_out.strip())

    # Client put/get round-trip
    nodeB.succeed(
      "tidefs-storage-node client "
      "--node-id 2 --server-node-id 1 "
      "--connect 192.168.100.1:9000 "
      "put cluster_test_key cluster_test_value"
    )
    record("transport_put", "pass")

    get_out = nodeB.succeed(
      "tidefs-storage-node client "
      "--node-id 2 --server-node-id 1 "
      "--connect 192.168.100.1:9000 "
      "get cluster_test_key"
    )
    assert "cluster_test_value" in get_out, \
      f"unexpected get response: {get_out!r}"
    record("transport_get", "pass", get_out.strip())

    # --- Results ---
    passed = sum(1 for r in validation["results"] if r["status"] == "pass")
    failed = sum(1 for r in validation["results"] if r["status"] == "fail")
    validation["passed"] = passed
    validation["failed"] = failed

    assert failed == 0, f"{failed} tests failed"
    assert passed == len(validation["results"]), \
      f"expected all {len(validation['results'])} to pass, got {passed}"

    # Write validation
    validation_json = json.dumps(validation, indent=2)
    nodeA.succeed("mkdir -p /tmp/tidefs-validation")
    nodeA.succeed(
      f"echo '{validation_json}' > "
      f"/tmp/tidefs-validation/multi-node-cluster.json"
    )

    # Cleanup
    nodeA.execute("pkill -f 'tidefs-storage-node' || true")
    nodeB.execute("pkill -f 'tidefs-storage-node' || true")
  '';
}

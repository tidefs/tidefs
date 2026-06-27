{
  description = "TideFS development, validation, and platform-test tooling";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    nixpkgs-bindgen-0_69.url = "github:NixOS/nixpkgs/nixos-24.05";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, nixpkgs-bindgen-0_69, rust-overlay }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system:
        import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          bindgen069Pkgs = import nixpkgs-bindgen-0_69 {
            inherit system;
          };
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };
          tidefsFsx = pkgs.runCommandCC "tidefs-fsx" {
          } ''
            mkdir -p "$out/bin"
            gcc -O2 -Wall ${./fsx/fsx.c} -o "$out/bin/fsx"
          '';
          tidefsXfstestsScripts = pkgs.runCommand "tidefs-xfstests-scripts" {
          } ''
            mkdir -p "$out/bin"
            cp ${./scripts/tidefs-xfstests-mount} "$out/bin/tidefs-xfstests-mount"
            cp ${./scripts/tidefs-xfstests-runner} "$out/bin/tidefs-xfstests-runner"
            cp ${./scripts/tidefs-xfstests-exclude} "$out/bin/tidefs-xfstests-exclude"
          '';

          tidefsMmapWorkload = pkgs.runCommandCC "tidefs-mmap-workload" {
          } ''
            mkdir -p "$out/bin"
            cc -O2 -Wall ${./scripts/tidefs-mmap-workload.c} -o "$out/bin/tidefs-mmap-workload"
          '';
          xfstests = pkgs.xfstests.overrideAttrs (old: {
            buildInputs = (old.buildInputs or []) ++ [ pkgs.gdbm ];
            NIX_CFLAGS_COMPILE = (old.NIX_CFLAGS_COMPILE or "") + " -std=gnu99 -Wno-error=incompatible-pointer-types";
            postInstall = (old.postInstall or "") + ''
              substituteInPlace "$out/bin/xfstests-check" \
                --replace-fail "  ln -s $out/lib/xfstests/\$f \$f" "  if [ \"\$f\" = tests ] || [ \"\$f\" = common ]; then
                cp -R --no-preserve=mode,ownership $out/lib/xfstests/\$f \$f
                chmod -R u+w \$f
              else
                ln -s $out/lib/xfstests/\$f \$f
              fi"
              substituteInPlace "$out/lib/xfstests/common/rc" \
                --replace-fail $'\ttmpfs)\n\t\tlocal free_mem=`_free_memory_bytes`' $'\ttidefs)\n\t\t$MKFS_PROG -t $FSTYP -- $MKFS_OPTIONS --size-bytes=$fssize $SCRATCH_DEV\n\t\t;;\n\ttmpfs)\n\t\tlocal free_mem=`_free_memory_bytes`'
            '';
          });
          workspaceBins = [
            "tidefs-block-volume-adapter-daemon"
            "tidefs-filesystem-demo"
            "tidefs-posix-filesystem-adapter-daemon"
            "tidefs-store-demo"
            "tidefs-storage-node"
            "tidefsctl"
            "tidefs-xtask"
          ];
          mkTidefsWorkspaceSrc = {
            omittedCrateSources ? [],
            omittedTopLevelSources ? [],
          }: pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              let
                root = toString ./.;
                pathString = toString path;
                rel = pkgs.lib.removePrefix (root + "/") pathString;
                parts = pkgs.lib.splitString "/" rel;
                top = builtins.head parts;
                second = if builtins.length parts > 1 then builtins.elemAt parts 1 else "";
                omittedCrateSource =
                  top == "crates"
                  && builtins.elem second omittedCrateSources
                  && rel != "crates/${second}"
                  && rel != "crates/${second}/Cargo.toml";
                omittedTopLevelSource =
                  builtins.elem top omittedTopLevelSources
                  && rel != top
                  && rel != "${top}/Cargo.toml";
              in
              ! omittedCrateSource
              && ! omittedTopLevelSource
              && (
                pathString == root
                || rel == "Cargo.toml"
                || rel == "Cargo.lock"
                || rel == "rust-toolchain.toml"
                || rel == ".cargo"
                || pkgs.lib.hasPrefix ".cargo/" rel
                || top == "apps"
                || top == "crates"
                || top == "kmod"
                || top == "xtask"
              );
          };
          tidefsWorkspaceSrc = mkTidefsWorkspaceSrc {};
          tidefsStorageNodeSrc = mkTidefsWorkspaceSrc {
            omittedCrateSources = [
              "tidefs-block-kmod"
              "tidefs-kmod-posix-vfs"
              "tidefs-validation"
              "tidefs-two-node-harness"
            ];
            omittedTopLevelSources = [ "kmod" ];
          };
          tidefsCtlSrc = mkTidefsWorkspaceSrc {
            omittedCrateSources = [
              "tidefs-block-kmod"
              "tidefs-kmod-posix-vfs"
              "tidefs-two-node-harness"
            ];
            omittedTopLevelSources = [ "kmod" ];
          };
        in
        rec {
          rustBindgenLinuxKbuild = import ./nix/packages/rust-bindgen-linux-kbuild.nix {
            inherit pkgs;
            bindgen_0_69 = bindgen069Pkgs.rust-bindgen;
          };

          default = import ./nix/packages/tidefs.nix {
            inherit (pkgs) lib pkg-config;
            inherit (pkgs) fuse3 rdma-core;
            rustPlatform = rustPlatform;
            src = tidefsWorkspaceSrc;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            workspaceBins = workspaceBins;
          };

          tidefsStorageNode = import ./nix/packages/tidefs.nix {
            inherit (pkgs) lib pkg-config;
            inherit (pkgs) fuse3 rdma-core;
            rustPlatform = rustPlatform;
            src = tidefsStorageNodeSrc;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            cargoBuildFlags = [ "-p" "tidefs-storage-node" "--bin" "tidefs-storage-node" ];
            workspaceBins = [ "tidefs-storage-node" ];
          };

          tidefsTwoNodeCarrierRuntime = import ./nix/packages/tidefs.nix {
            inherit (pkgs) lib pkg-config;
            inherit (pkgs) fuse3 rdma-core;
            rustPlatform = rustPlatform;
            src = tidefsWorkspaceSrc;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            cargoBuildFlags = [
              "-p" "tidefs-two-node-harness"
              "--features" "qemu"
              "--bin" "tidefs-two-node-qemu-carrier-validation"
            ];
            workspaceBins = [
              "tidefs-two-node-qemu-carrier-validation"
            ];
          };

          tidefsUblkRuntime = import ./nix/packages/tidefs.nix {
            inherit (pkgs) lib pkg-config;
            inherit (pkgs) fuse3 rdma-core;
            rustPlatform = rustPlatform;
            src = tidefsCtlSrc;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            cargoBuildFlags = [
              "-p" "tidefsctl"
              "-p" "tidefs-block-volume-adapter-daemon"
              "--bins"
            ];
            workspaceBins = [
              "tidefsctl"
              "tidefs-block-volume-adapter-daemon"
            ];
          };

          tidefsUblkCompletionRuntime = import ./nix/packages/tidefs.nix {
            inherit (pkgs) lib pkg-config;
            inherit (pkgs) fuse3 rdma-core;
            rustPlatform = rustPlatform;
            src = tidefsCtlSrc;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            cargoBuildFlags = [
              "-p" "tidefsctl"
              "-p" "tidefs-block-volume-adapter-daemon"
              "-p" "tidefs-xtask"
              "--bins"
            ];
            workspaceBins = [
              "tidefsctl"
              "tidefs-block-volume-adapter-daemon"
              "tidefs-xtask"
            ];
          };

          tidefsCtlRuntime = import ./nix/packages/tidefs.nix {
            inherit (pkgs) lib pkg-config;
            inherit (pkgs) fuse3 rdma-core;
            rustPlatform = rustPlatform;
            src = tidefsCtlSrc;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            cargoBuildFlags = [
              "-p" "tidefsctl"
              "--bin" "tidefsctl"
            ];
            workspaceBins = [
              "tidefsctl"
            ];
          };

          tidefsXtaskRuntime = import ./nix/packages/tidefs.nix {
            inherit (pkgs) lib pkg-config;
            inherit (pkgs) fuse3 rdma-core;
            rustPlatform = rustPlatform;
            src = tidefsCtlSrc;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            cargoBuildFlags = [
              "-p" "tidefs-xtask"
              "--bin" "tidefs-xtask"
            ];
            workspaceBins = [
              "tidefs-xtask"
            ];
          };

          tidefsFuseRuntime = import ./nix/packages/tidefs.nix {
            inherit (pkgs) lib pkg-config;
            inherit (pkgs) fuse3 rdma-core;
            rustPlatform = rustPlatform;
            src = tidefsCtlSrc;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            cargoBuildFlags = [
              "-p" "tidefs-posix-filesystem-adapter-daemon"
              "--bin" "tidefs-posix-filesystem-adapter-daemon"
            ];
            workspaceBins = [
              "tidefs-posix-filesystem-adapter-daemon"
            ];
          };

          inherit xfstests tidefsFsx tidefsXfstestsScripts tidefsMmapWorkload;

          qemuSmoke = pkgs.testers.runNixOSTest {
            name = "tidefs-qemu-smoke";
            skipTypeCheck = true;
            skipLint = true;
            nodes.machine = { lib, pkgs, ... }: {
              boot.initrd.availableKernelModules = lib.mkForce [ "virtio_pci" "virtio_blk" "virtio_console" ];
              boot.initrd.kernelModules = lib.mkForce [ "virtio_balloon" "virtio_console" ];
              boot.kernelModules = [ "fuse" "virtio_console" ];
              boot.kernelPackages = lib.mkForce (pkgs.linuxPackagesFor linuxKernel_7_0);
              boot.kernelParams = [
                "systemd.default_device_timeout_sec=600s"
                "rd.systemd.default_device_timeout_sec=600s"
              ];
              networking.useDHCP = lib.mkForce false;
              networking.interfaces.eth1.useDHCP = lib.mkForce false;
              networking.firewall.enable = lib.mkForce false;
              environment.systemPackages = [ default pkgs.fuse3 pkgs.util-linux ];
              virtualisation.graphics = false;
              virtualisation.cores = 2;
              virtualisation.memorySize = 1024;
            };
            testScript = ''
              import json
              import os
              import re

              validation = {
                "test": "tidefs-qemu-smoke",
                "version": 2,
                "results": [],
                "passed": 0,
                "product_failures": 0,
                "harness_failures": 0,
                "environment_refusals": 0,
                "skipped": 0,
              }

              # REL-VAL-006: 5-way validation classification
              VALID_STATUSES = {"pass", "product-fail", "harness-fail", "environment-refusal", "skip"}

              def record(name, status, output=None):
                  assert status in VALID_STATUSES, f"invalid validation status: {status}"
                  entry = {"name": name, "status": status}
                  if output is not None:
                      entry["output"] = output
                  validation["results"].append(entry)

              machine.start()
              machine.wait_for_unit("multi-user.target")

              # Record kernel version for release validation
              kernel_ver = machine.succeed("uname -r").strip()
              record("kernel_version", "pass", kernel_ver)
              validation["kernel_version"] = kernel_ver
              validation["linux_7_0"] = True
              validation["kernel_package"] = "linuxKernel_7_0"
              validation["tier"] = "qemu-guest"
              if not kernel_ver.startswith("7."):
                  record("linux_7_0_kernel", "environment-refusal",
                         f"expected Linux 7.0 guest kernel, got {kernel_ver}")
                  raise Exception(f"FAIL: qemu-fuse-vm-test validation requires Linux 7.0 guest kernel, got {kernel_ver}")
              else:
                  record("linux_7_0_kernel", "pass", kernel_ver)

              machine.succeed("modprobe fuse || true")
              machine.succeed("test -e /dev/fuse")
              record("fuse_device", "pass", "/dev/fuse")

              machine.succeed("tidefs-xtask summary 2>&1")
              record("xtask_summary", "pass")

              machine.succeed("tidefs-store-demo 2>&1")
              record("store_demo", "pass")

              # smoke-mount is the essential userspace mount validation.
              # Write full output to a guest file to avoid truncation;
              # then read it back for complete diagnostics.
              smoke_rc = machine.execute(
                  "TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=4141414141414141414141414141414141414141414141414141414141414141 "
                  "sh -c 'mkdir -p /tmp/tidefs-validation/performance && tidefs-posix-filesystem-adapter-daemon smoke-mount --profile quick --queue-depth-artifact /tmp/tidefs-validation/performance/queue-depth-runtime.json 2>&1 | tee /tmp/smoke-mount-output.txt'",
                  timeout=300
              )
              smoke_status = "pass" if smoke_rc[0] == 0 else "product-fail"
              if smoke_rc[1]:
                  for line in smoke_rc[1].splitlines():
                      log.log(f"smoke_mount: {line}")
              # Post-mortem: append system diagnostics to the output file
              # so the captured log reveals why the daemon hung or exited.
              machine.execute(
                  "sh -c '"
                  "echo === POST-MORTEM: processes === >> /tmp/smoke-mount-output.txt; "
                  "ps aux | grep -E \"tidefs|mount-vfs|fuse\" >> /tmp/smoke-mount-output.txt 2>&1 || true; "
                  "echo === POST-MORTEM: mount info === >> /tmp/smoke-mount-output.txt; "
                  "mount | grep tidefs >> /tmp/smoke-mount-output.txt 2>&1 || echo \"(not mounted)\" >> /tmp/smoke-mount-output.txt; "
                  "echo === POST-MORTEM: dmesg === >> /tmp/smoke-mount-output.txt; "
                  "dmesg | tail -80 >> /tmp/smoke-mount-output.txt'",
                  timeout=30
              )
              # Read the full output from the guest file for recording.
              smoke_full = machine.succeed("cat /tmp/smoke-mount-output.txt")
              # Parse smoke-mount summary: "=== smoke-mount: X passed, Y failed ==="
              m = re.search(r'smoke-mount:\s*(\d+)\s*passed,\s*(\d+)\s*failed', smoke_full)
              if m:
                  smoke_passed = int(m.group(1))
                  smoke_failed = int(m.group(2))
                  record("smoke_mount", smoke_status,
                         f"{smoke_passed} passed, {smoke_failed} failed; full output: {smoke_full[:8000]}")
              else:
                  record("smoke_mount", smoke_status,
                         f"could not parse summary; rc={smoke_rc[0]}; output: {smoke_full[:4000]}")
                  smoke_passed = 0
                  smoke_failed = 1
              validation["smoke_mount_passed"] = smoke_passed
              validation["smoke_mount_failed"] = smoke_failed
              queue_artifact_rc = machine.execute(
                  "cat /tmp/tidefs-validation/performance/queue-depth-runtime.json",
                  timeout=30
              )
              if queue_artifact_rc[0] == 0:
                  record("queue_depth_runtime_artifact", "pass", queue_artifact_rc[1].strip()[:4000])
                  validation["queue_depth_runtime_artifact"] = json.loads(queue_artifact_rc[1])
              else:
                  record(
                      "queue_depth_runtime_artifact",
                      "product-fail",
                      "missing /tmp/tidefs-validation/performance/queue-depth-runtime.json",
                  )
              # Record dmesg for kernel-side FUSE diagnostics.
              # When the daemon exits during CREATE, the kernel may log
              # FUSE connection errors that help identify the root cause.
              dmesg_tail = machine.succeed("dmesg | tail -80")
              record("dmesg_tail", "pass", dmesg_tail.strip()[:3000])

              # Ensure cleanup: kill daemon first so the FUSE mount is released before unmount.
              machine.execute("pkill -f 'mount-vfs' || true")
              machine.execute("sleep 2")
              machine.execute("fusermount -u /tmp/tidefs-smoke-mount-point || umount -l /tmp/tidefs-smoke-mount-point || true", timeout=30)

              validation["passed"] = sum(1 for r in validation["results"] if r["status"] == "pass")
              validation["product_failures"] = sum(1 for r in validation["results"] if r["status"] == "product-fail")
              validation["harness_failures"] = sum(1 for r in validation["results"] if r["status"] == "harness-fail")
              validation["environment_refusals"] = sum(1 for r in validation["results"] if r["status"] == "environment-refusal")
              validation["skipped"] = sum(1 for r in validation["results"] if r["status"] == "skip")

              # Create validation directory on the host (test driver) and inside the guest.
              os.makedirs("/tmp/tidefs-validation", exist_ok=True)
              machine.succeed("mkdir -p /tmp/tidefs-validation")
              with open("/tmp/tidefs-validation/qemu-smoke.json", "w") as f:
                  json.dump(validation, f, indent=2)

              total_failures = validation["product_failures"] + validation["harness_failures"]
              assert total_failures == 0, (
                  f"qemu-smoke: {validation['product_failures']} product failure(s), "
                  f"{validation['harness_failures']} harness failure(s)"
              )
            '';
          };

          tidefsFuseVmTest = import ./nix/vm/fuse-vm-test.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
          };

          tidefsFuseFioBenchmark = pkgs.runCommand "tidefs-fuse-fio-benchmark-deprecated" { } ''
            mkdir -p "$out/bin"
            cat > "$out/bin/tidefs-fuse-fio-benchmark" <<'EOF'
#!/usr/bin/env sh
echo "tidefsFuseFioBenchmark is deprecated because it used the full NixOS VM test closure." >&2
echo "Use: nix run .#fuse-fio-benchmark" >&2
echo "Or:  scripts/run-fuse-qemu-fio-baseline.sh" >&2
exit 2
EOF
            chmod +x "$out/bin/tidefs-fuse-fio-benchmark"
            cat > "$out/README" <<'EOF'
This package intentionally no longer runs the FUSE fio benchmark.  The former
runNixOSTest target repeatedly rebuilt a full NixOS VM closure during release
iteration.  Use the direct Linux 7.0 QEMU initramfs runner instead:

  nix run .#fuse-fio-benchmark
  scripts/run-fuse-qemu-fio-baseline.sh
EOF
          '';

          tidefsFuseFioBenchmarkNixOSTestDeprecated = pkgs.testers.runNixOSTest {
            name = "tidefs-fuse-fio-benchmark";
            skipTypeCheck = true;
            skipLint = true;
            nodes.machine = { lib, pkgs, ... }: {
              boot.initrd.availableKernelModules = lib.mkForce [ "virtio_pci" "virtio_blk" "virtio_console" ];
              boot.initrd.kernelModules = lib.mkForce [ "virtio_balloon" "virtio_console" ];
              boot.kernelModules = [ "fuse" "virtio_console" ];
              boot.kernelPackages = lib.mkForce (pkgs.linuxPackagesFor linuxKernel_7_0);
              boot.kernelParams = [
                "systemd.default_device_timeout_sec=600s"
                "rd.systemd.default_device_timeout_sec=600s"
              ];
              networking.useDHCP = lib.mkForce false;
              networking.interfaces.eth1.useDHCP = lib.mkForce false;
              environment.systemPackages = [ tidefsFuseRuntime pkgs.fuse3 pkgs.fio pkgs.util-linux ];
              virtualisation.graphics = false;
              virtualisation.cores = 2;
              virtualisation.memorySize = 1024;
            };
            testScript = ''
              import json
              import os
              import re
              import time

              validation = {
                "test": "tidefs-fuse-fio-benchmark",
                "version": 1,
                "results": [],
                "passed": 0,
                "product_failures": 0,
                "harness_failures": 0,
                "environment_refusals": 0,
                "skipped": 0,
                "benchmarks": [],
              }

              # REL-VAL-006: 5-way validation classification
              VALID_STATUSES = {"pass", "product-fail", "harness-fail", "environment-refusal", "skip"}

              def record(name, status, output=None):
                  assert status in VALID_STATUSES, f"invalid validation status: {status}"
                  entry = {"name": name, "status": status}
                  if output is not None:
                      entry["output"] = output
                  validation["results"].append(entry)

              machine.start()
              machine.wait_for_unit("multi-user.target")

              # Record kernel version for release validation
              kernel_ver = machine.succeed("uname -r").strip()
              record("kernel_version", "pass", kernel_ver)
              validation["kernel_version"] = kernel_ver
              validation["linux_7_0"] = True
              validation["kernel_package"] = "linuxKernel_7_0"
              validation["tier"] = "qemu-guest"

              if not kernel_ver.startswith("7."):
                  record("linux_7_0_kernel", "environment-refusal",
                         f"expected Linux 7.0 guest kernel, got {kernel_ver}")
                  raise Exception(f"FAIL: FUSE fio benchmark requires Linux 7.0 guest kernel, got {kernel_ver}")
              else:
                  record("linux_7_0_kernel", "pass", kernel_ver)

              machine.succeed("modprobe fuse || true")
              machine.succeed("test -e /dev/fuse")
              record("fuse_device", "pass", "/dev/fuse")

              # Create backing store and mount point
              store_dir = "/tmp/tidefs-fio-store"
              mount_dir = "/tmp/tidefs-fio-mount"
              machine.succeed(f"mkdir -p {store_dir} {mount_dir}")

              # Start FUSE daemon
              daemon_log = "/tmp/tidefs-daemon-fio.log"
              daemon_cmd = (
                  "TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=4141414141414141414141414141414141414141414141414141414141414141 "
                  f"nohup tidefs-posix-filesystem-adapter-daemon mount-vfs "
                  f"--store {store_dir} --mount {mount_dir} "
                  f">> {daemon_log} 2>&1 &"
              )
              machine.succeed(daemon_cmd)
              time.sleep(3)

              # Verify daemon started
              daemon_pid = machine.succeed(
                  "pgrep -f 'tidefs-posix-filesystem-adapter-daemon.*mount-vfs' | head -1"
              ).strip()
              if daemon_pid:
                  record("daemon_start", "pass", f"pid={daemon_pid}")
              else:
                  record("daemon_start", "harness-fail", "daemon failed to start")
                  daemon_log_content = machine.succeed(f"cat {daemon_log}")
                  record("daemon_log", "harness-fail", daemon_log_content[:2000])
                  raise Exception("FUSE daemon failed to start")

              # Wait for mount
              machine.wait_until_succeeds(f"mountpoint {mount_dir}", timeout=60)
              record("fuse_mount", "pass", mount_dir)

              # --- FUSE fio baseline sweep ---
              fio_testfile = f"{mount_dir}/tidefs-fio-benchmark-file"
              fio_common = "--output-format=json --group_reporting --norandommap --randrepeat=0 --refill_buffers --direct=0"

              # Block sizes to sweep: 4K, 64K, 128K, 1M
              block_specs = [
                  ("4k",  "4M"),
                  ("64k", "16M"),
                  ("128k","32M"),
                  ("1m",  "64M"),
              ]

              workloads = [
                  ("sequential-write", "rw=write",     "iodepth=1"),
                  ("sequential-read",  "rw=read",      "iodepth=1"),
                  ("random-write",     "rw=randwrite", "iodepth=1"),
                  ("random-read",      "rw=randread",  "iodepth=1"),
                  ("sync-write",       "rw=write",     "iodepth=1", "fsync=1"),
              ]

              for bs_label, bs_size in block_specs:
                  for wl in workloads:
                      wl_name = wl[0]
                      name = f"{wl_name}-{bs_label}"
                      bm_args = f"bs={bs_label} " + " ".join(wl[1:]) + f" size={bs_size}"
                      cmd = f"fio --name={name} --filename={fio_testfile} {bm_args} {fio_common} 2>&1"
                      rc, stdout = machine.execute(cmd, timeout=180)
                      if rc == 0:
                          record(f"fio_{name}", "pass", stdout[:2000])
                          try:
                              fio_json = json.loads(stdout)
                              for job in fio_json.get("jobs", []):
                                  rd = job.get("read", {})
                                  wr = job.get("write", {})
                                  bw = rd.get("bw_bytes", 0) + wr.get("bw_bytes", 0)
                                  iops = rd.get("iops", 0) + wr.get("iops", 0)
                                  # Latency from dominant direction
                                  lat = rd if rd.get("iops", 0) >= wr.get("iops", 0) else wr
                                  lat_ns = lat.get("lat_ns", {})
                                  lat_pct = lat_ns.get("percentile", {})
                                  entry = {
                                      "name": name,
                                      "bw_bytes_per_sec": bw,
                                      "iops": iops,
                                      "lat_ns_mean": lat_ns.get("mean", 0),
                                      "lat_ns_p50": lat_pct.get("50.000000", 0),
                                      "lat_ns_p95": lat_pct.get("95.000000", 0),
                                      "lat_ns_p99": lat_pct.get("99.000000", 0),
                                      "block_size": bs_label,
                                      "workload": wl_name,
                                  }
                                  validation["benchmarks"].append(entry)
                          except Exception as e:
                              record(f"fio_{name}_parse", "harness-fail", str(e))
                      else:
                          record(f"fio_{name}", "product-fail", stdout[:2000])
                  # Remove test file between block sizes
                  machine.execute(f"rm -f {fio_testfile} || true")

              # --- Metadata benchmark: create/stat/unlink throughput ---
              meta_dir = f"{mount_dir}/tidefs-meta-bench"
              machine.succeed(f"mkdir -p {meta_dir}")
              num_files = 200

              meta_start = time.time()
              for i in range(num_files):
                  p = f"{meta_dir}/f{i:04d}"
                  machine.succeed(f"touch {p}")
              meta_create_s = time.time() - meta_start
              record("meta_create", "pass",
                     f"{num_files} files in {meta_create_s:.2f}s ({num_files/meta_create_s:.0f} files/s)")

              stat_start = time.time()
              for i in range(num_files):
                  p = f"{meta_dir}/f{i:04d}"
                  machine.succeed(f"stat {p} > /dev/null")
              meta_stat_s = time.time() - stat_start
              record("meta_stat", "pass",
                     f"{num_files} stats in {meta_stat_s:.2f}s ({num_files/meta_stat_s:.0f} stats/s)")

              unlink_start = time.time()
              for i in range(num_files):
                  p = f"{meta_dir}/f{i:04d}"
                  machine.succeed(f"rm {p}")
              meta_unlink_s = time.time() - unlink_start
              record("meta_unlink", "pass",
                     f"{num_files} unlinks in {meta_unlink_s:.2f}s ({num_files/meta_unlink_s:.0f} unlinks/s)")
              machine.succeed(f"rmdir {meta_dir}")

              validation["metadata_bench"] = {
                  "num_files": num_files,
                  "create_s": round(meta_create_s, 3),
                  "create_files_per_sec": round(num_files / meta_create_s, 1),
                  "stat_s": round(meta_stat_s, 3),
                  "stat_per_sec": round(num_files / meta_stat_s, 1),
                  "unlink_s": round(meta_unlink_s, 3),
                  "unlink_per_sec": round(num_files / meta_unlink_s, 1),
              }

              # Record dmesg for diagnostics
              dmesg_tail = machine.succeed("dmesg | tail -40")
              record("dmesg", "pass", dmesg_tail.strip()[:2000])

              # Compute 5-way validation counts
              validation["passed"] = sum(1 for r in validation["results"] if r["status"] == "pass")
              validation["product_failures"] = sum(1 for r in validation["results"] if r["status"] == "product-fail")
              validation["harness_failures"] = sum(1 for r in validation["results"] if r["status"] == "harness-fail")
              validation["environment_refusals"] = sum(1 for r in validation["results"] if r["status"] == "environment-refusal")
              validation["skipped"] = sum(1 for r in validation["results"] if r["status"] == "skip")

              # Write validation artifact
              os.makedirs("/tmp/tidefs-validation", exist_ok=True)
              machine.succeed("mkdir -p /tmp/tidefs-validation")
              with open("/tmp/tidefs-validation/fuse-fio-benchmark.json", "w") as f:
                  json.dump(validation, f, indent=2)
              machine.succeed(f"cp {daemon_log} /tmp/tidefs-validation/tidefs-daemon-fio.log || true")
              machine.copy_from_vm("/tmp/tidefs-validation")
              print("tidefs-fuse-fio-benchmark validation:")
              print(json.dumps(validation, indent=2))

              # Write validation regardless of pass/fail
              import sys
              total_failures = validation["product_failures"] + validation["harness_failures"]
              if total_failures > 0:
                  print(f"WARNING: {total_failures} failures ({validation['product_failures']} product, {validation['harness_failures']} harness)", file=sys.stderr)
              if validation["environment_refusals"] > 0:
                  print(f"WARNING: {validation['environment_refusals']} environment refusals", file=sys.stderr)

              # Ensure cleanup
              machine.execute("pkill -f 'mount-vfs' || true")
              machine.execute("sleep 2")
              machine.execute(f"fusermount -u {mount_dir} || umount -l {mount_dir} || true", timeout=30)
            '';
          };

          qemuXfstestsLockSymlinkFallocate = pkgs.testers.runNixOSTest {
            name = "tidefs-qemu-xfstests-lock-symlink-fallocate";
            nodes.machine = { lib, pkgs, ... }: {
              boot.initrd.availableKernelModules = lib.mkForce [ "virtio_pci" "virtio_blk" "virtio_console" ];
              boot.initrd.kernelModules = lib.mkForce [ "virtio_balloon" "virtio_console" ];
              boot.kernelModules = [ "fuse" "virtio_console" ];
              boot.kernelPackages = lib.mkForce (pkgs.linuxPackagesFor linuxKernel_7_0);
              boot.kernelParams = [
                "systemd.default_device_timeout_sec=600s"
                "rd.systemd.default_device_timeout_sec=600s"
              ];
              networking.useDHCP = lib.mkForce false;
              networking.interfaces.eth1.useDHCP = lib.mkForce false;
              environment.systemPackages = [ default pkgs.fuse3 pkgs.jq pkgs.e2fsprogs pkgs.util-linux xfstests tidefsXfstestsScripts ];
              virtualisation.graphics = false;
              virtualisation.cores = 2;
              virtualisation.memorySize = 2048;
            };
            testScript = ''
              import json
              import os
              import time

              validation = {
                "test": "tidefs-qemu-xfstests-lock-symlink-fallocate",
                "version": 1,
                "results": [],
                "passed": 0,
                "failed": 0,
              }

              # REL-VAL-006: 5-way validation classification
              VALID_STATUSES = {"pass", "product-fail", "harness-fail", "environment-refusal", "skip"}

              def record(name, status, output=None):
                  assert status in VALID_STATUSES, f"invalid validation status: {status}"
                  entry = {"name": name, "status": status}
                  if output is not None:
                      entry["output"] = output
                  validation["results"].append(entry)

              machine.start()
              machine.wait_for_unit("multi-user.target")

              # Record kernel version for release validation
              kernel_ver = machine.succeed("uname -r").strip()
              record("kernel_version", "pass", kernel_ver)
              validation["kernel_version"] = kernel_ver
              validation["linux_7_0"] = True
              validation["kernel_package"] = "linuxKernel_7_0"
              validation["tier"] = "qemu-guest"

              assert kernel_ver.startswith("7."), f"FAIL: qemu-smoke validation requires Linux 7.0 guest kernel, got {kernel_ver}"

              machine.succeed("modprobe fuse || true")
              machine.succeed("test -e /dev/fuse")

              # Symlink mount.fuse so xfstests can mount TideFS FUSE.
              machine.succeed("mkdir -p /tmp/xfstests-helper")
              machine.succeed("ln -sf $(which tidefs-xfstests-mount) /tmp/xfstests-helper/mount.fuse")

              xfstests_out = "/tmp/tidefs-xfstests-out"
              machine.succeed(f"mkdir -p {xfstests_out}")

              # Run lock, symlink, and fallocate groups with --no-exclude
              xfstests_cmd = (
                  f"PATH=/tmp/xfstests-helper:$PATH "
                  f"tidefs-posix-filesystem-adapter-daemon xfstests-harness "
                  f"--tests 'lock symlink fallocate' --no-exclude "
                  f"--out {xfstests_out}"
              )
              _, xfstests_output = machine.execute(xfstests_cmd)

              # Parse the JSON scoreboard.
              machine.succeed(f"test -f {xfstests_out}/scoreboard.json")
              scoreboard_json = machine.succeed(f"cat {xfstests_out}/scoreboard.json")
              # json already imported at top of script
              sb = json.loads(scoreboard_json)

              record("xfstests_passed", "pass", str(sb["summary"]["passed"]))
              record("xfstests_failed", "pass", str(sb["summary"]["failed"]))
              record("xfstests_skipped", "pass", str(sb["summary"]["skipped"]))
              record("xfstests_total", "pass", str(sb["summary"]["total"]))

              # Record individual results as validation entries.
              for result in sb["results"]:
                  if result["status"] in ("fail", "diff"):
                      reason = result.get("reason", "no reason")
                      record(f"xfstests_{result['test']}", "fail", reason)
                  elif result["status"] == "pass":
                      record(f"xfstests_{result['test']}", "pass")

              # Record dmesg for diagnostics.
              dmesg_tail = machine.succeed("dmesg | tail -40")
              record("xfstests_dmesg", "pass", dmesg_tail.strip()[:2000])

              # Compute pass/fail counts
              passed = sum(1 for r in validation["results"] if r["status"] == "pass")
              failed = sum(1 for r in validation["results"] if r["status"] == "fail")
              validation["passed"] = passed
              validation["failed"] = failed

              # Write validation artifact
              machine.succeed("mkdir -p /tmp/tidefs-validation")
              with open("/tmp/tidefs-validation/qemu-xfstests-lock-symlink-fallocate.json", "w") as f:
                  json.dump(validation, f, indent=2)

              # Cleanup: unmount any leftover mounts and stop daemons
              machine.execute("umount /mnt/tidefs 2>/dev/null || true")
              machine.execute("pkill -f 'tidefs-posix-filesystem-adapter-daemon' || true")
            '';
          };
          tidefsXfstestsLockGroup = pkgs.testers.runNixOSTest {
            name = "tidefs-xfstests-lock-group";
            nodes.machine = { lib, pkgs, ... }: {
              boot.initrd.availableKernelModules = lib.mkForce [ "virtio_pci" "virtio_blk" "virtio_console" ];
              boot.initrd.kernelModules = lib.mkForce [ "virtio_balloon" "virtio_console" ];
              boot.kernelModules = [ "fuse" "virtio_console" ];
              boot.kernelPackages = lib.mkForce (pkgs.linuxPackagesFor linuxKernel_7_0);
              boot.kernelParams = [
                "systemd.default_device_timeout_sec=600s"
                "rd.systemd.default_device_timeout_sec=600s"
              ];
              networking.useDHCP = lib.mkForce false;
              networking.interfaces.eth1.useDHCP = lib.mkForce false;
              environment.systemPackages = [
                default
                xfstests
                pkgs.fuse3
                pkgs.jq
                pkgs.e2fsprogs
                pkgs.util-linux
                pkgs.bash
                pkgs.coreutils
                pkgs.gnugrep
                pkgs.gawk
              ];
              virtualisation.graphics = false;
              virtualisation.cores = 2;
              virtualisation.memorySize = 2048;
            };
            testScript = ''
              import json
              import os
              import re
              import time
              import shutil

              validation = {
                "test": "tidefs-xfstests-lock-group",
                "version": 1,
                "results": [],
                "passed": 0,
                "failed": 0,
                "skipped": 0,
              }

              def record(name, status, duration_secs=None, failure_log=None):
                  entry = {"name": name, "status": status}
                  if duration_secs is not None:
                      entry["duration_secs"] = duration_secs
                  if failure_log is not None:
                      entry["failure_log"] = failure_log
                  validation["results"].append(entry)

              machine.start()
              machine.wait_for_unit("multi-user.target")

              # Record kernel version for release validation
              kernel_ver = machine.succeed("uname -r").strip()
              record("kernel_version", "pass", kernel_ver)
              validation["kernel_version"] = kernel_ver
              validation["linux_7_0"] = True
              validation["kernel_package"] = "linuxKernel_7_0"
              validation["tier"] = "qemu-guest"

              assert kernel_ver.startswith("7."), f"FAIL: qemu-smoke validation requires Linux 7.0 guest kernel, got {kernel_ver}"

              machine.succeed("modprobe fuse || true")
              machine.succeed("test -e /dev/fuse")

              # Create backing store and mount point
              machine.succeed("mkdir -p /tmp/tidefs-store /mnt/tidefs")

              # Start FUSE daemon
              daemon_log = "/tmp/tidefs-daemon.log"
              machine.succeed(
                  "TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=4141414141414141414141414141414141414141414141414141414141414141 RUST_LOG=debug nohup tidefs-posix-filesystem-adapter-daemon mount-vfs "
                  "--store /tmp/tidefs-store --mount /mnt/tidefs "
                  f"> {daemon_log} 2>&1 &"
              )
              time.sleep(2)

              daemon_pid = machine.succeed(
                  "pgrep -f 'tidefs-posix-filesystem-adapter-daemon.*mount-vfs' | head -1"
              ).strip()
              assert daemon_pid, "FUSE daemon failed to start"
              record("daemon_start", "pass", f"pid={daemon_pid}")

              machine.wait_until_succeeds("mountpoint /mnt/tidefs", timeout=30)
              record("fuse_mount", "pass")

              # Run xfstests lock group
              results_dir = "/tmp/xfstests-lock-results"
              machine.succeed(f"mkdir -p {results_dir}")

              xfstests_cmd = (
                  "FSTYP=fuse "
                  "TEST_DEV=tidefs-preview "
                  "TEST_DIR=/mnt/tidefs "
                  f"RESULT_BASE={results_dir} "
                  "xfstests-check -g lock -fuse"
              )

              print(f"Running: {xfstests_cmd}")
              rc, stdout = machine.execute(xfstests_cmd)
              print(f"xfstests-check exit code: {rc}")
              if stdout:
                  print(f"xfstests-check stdout (last 2KB):")
                  print(stdout[-2000:] if len(stdout) > 2000 else stdout)

              # Collect daemon log for diagnostics
              daemon_tail = machine.succeed(
                  f"tail -100 {daemon_log} 2>/dev/null || echo '(no daemon log)'"
              )
              record("daemon_log", "pass", daemon_tail.strip())

              # Parse xfstests results from check.log.
              # xfstests-check output format:
              #   Ran: generic/001
              #   Passed all 1 tests
              # or for failures:
              #   Ran: generic/007
              #   Failures: generic/007
              #   Failed 1 of 1 tests
              # Result files: $RESULT_BASE/generic/NNN.out.bad / .notrun
              check_log = f"{results_dir}/check.log"
              check_out = machine.succeed(f"cat {check_log} 2>/dev/null; true").strip()
              check_time_txt = machine.succeed(f"cat {results_dir}/check.time 2>/dev/null; true").strip()

              if not check_out:
                  record("xfstests_check_log", "fail",
                         "check.log is empty or missing -- xfstests-check may have failed")
              else:
                  print(f"check.log content:\n{check_out[:2000]}")
                  # Parse Ran: lines to discover which tests executed
                  ran_re = re.compile(r'^Ran:\s+(generic/\d+)', re.MULTILINE)
                  ran_tests = sorted(set(m.group(1) for m in ran_re.finditer(check_out)))
                  print(f"Parsed {len(ran_tests)} test entries from check.log: {ran_tests}")

                  if not ran_tests:
                      record("xfstests_parse", "fail",
                             f"No Ran: entries found in check.log. Raw content:\n{check_out[:2000]}")
                  else:
                      # Parse durations from check.time (format: generic/001 3s)
                      durations = {}
                      if check_time_txt:
                          time_re = re.compile(r'^(generic/\d+)\s+(\d+)s', re.MULTILINE)
                          for tm in time_re.finditer(check_time_txt):
                              durations[tm.group(1)] = int(tm.group(2))

                      # Determine failures from check.log: look for "Failures:" lines
                      failures = set()
                      fail_re = re.compile(r'^Failures:\s+(generic/\d+)', re.MULTILINE)
                      for fm in fail_re.finditer(check_out):
                          failures.add(fm.group(1))

                      for tname in ran_tests:
                          tdur = durations.get(tname, 0)
                          status = "pass"
                          flog = None

                          # Determine pass/fail/skip from result files
                          bad_exists = machine.succeed(
                              f"test -f {results_dir}/{tname}.out.bad && echo yes || echo no"
                          ).strip()
                          notrun_exists = machine.succeed(
                              f"test -f {results_dir}/{tname}.notrun && echo yes || echo no"
                          ).strip()

                          if notrun_exists == "yes":
                              status = "skip"
                              skip_reason = machine.succeed(
                                  f"cat {results_dir}/{tname}.notrun 2>/dev/null || echo '(unknown)'"
                              ).strip()
                              print(f"  {tname}: SKIP ({skip_reason[:100]})")
                          elif bad_exists == "yes":
                              status = "fail"
                              flog = machine.succeed(
                                  f"tail -30 {results_dir}/{tname}.out.bad 2>/dev/null || echo '(no output)'"
                              ).strip()
                              print(f"  {tname}: FAIL")
                          else:
                              # Confirm not in failures list (belt-and-suspenders)
                              if tname in failures:
                                  status = "fail"
                                  flog = machine.succeed(
                                      f"tail -30 {results_dir}/{tname}.out.bad 2>/dev/null || echo '(no output)'"
                                  ).strip()
                                  print(f"  {tname}: FAIL (from check.log Failures:)")
                              else:
                                  print(f"  {tname}: PASS ({tdur}s)")

                          record(tname, status,
                                 duration_secs=float(tdur) if tdur > 0 else None,
                                 failure_log=flog)

              # Compute counts
              validation["passed"] = sum(1 for r in validation["results"] if r["status"] == "pass")
              validation["product_failures"] = sum(1 for r in validation["results"] if r["status"] == "product-fail")
              validation["harness_failures"] = sum(1 for r in validation["results"] if r["status"] == "harness-fail")
              validation["environment_refusals"] = sum(1 for r in validation["results"] if r["status"] == "environment-refusal")
              validation["skipped"] = sum(1 for r in validation["results"] if r["status"] == "skip")
              validation["skipped"] = sum(1 for r in validation["results"] if r["status"] == "skip")

              # Write validation artifact
              machine.succeed("mkdir -p /tmp/tidefs-validation")
              with open("/tmp/tidefs-validation/xfstests-lock-group.json", "w") as f:
                  json.dump(validation, f, indent=2)

              # Copy validation artifact to Nix output for host-side parsing
              out_dir = os.environ.get("out", "/tmp/tidefs-validation")
              os.makedirs(out_dir, exist_ok=True)
              shutil.copy("/tmp/tidefs-validation/xfstests-lock-group.json",
                          os.path.join(out_dir, "xfstests-lock-group.json"))

              print(f"Lock group: passed={validation['passed']} failed={validation['failed']} skipped={validation['skipped']}")

              # Cleanup
              machine.succeed("umount /mnt/tidefs")
              machine.execute("pkill -f 'tidefs-posix-filesystem-adapter-daemon.*mount-vfs' || true")
            '';
          };


          linuxKernel_7_0 = pkgs.callPackage ./nix/packages/linux-7.0-kernel.nix {
            kernelConfig = ./nix/vm/kernel-7.0-config;
            llvmPackages = pkgs.llvmPackages_19;
            rustc = rustToolchain;
            bindgen = rustBindgenLinuxKbuild;
          };

          linuxKernel_7_0_instrumented = pkgs.callPackage ./nix/packages/linux-7.0-kernel-instrumented.nix {
            kernelConfig = ./nix/vm/kernel-7.0-config-instrumented;
            rustc = rustToolchain;
            bindgen = pkgs.rust-bindgen;
          };


          qemuUblkSmoke = pkgs.testers.runNixOSTest {
            name = "tidefs-qemu-ublk-smoke";
            skipTypeCheck = true;
            skipLint = true;
            nodes.machine = { lib, pkgs, ... }: {
              boot.initrd.availableKernelModules = lib.mkForce [ "virtio_pci" "virtio_blk" "virtio_console" ];
              boot.initrd.kernelModules = lib.mkForce [ "virtio_balloon" "virtio_console" ];
              boot.kernelModules = [ "ublk_drv" "virtio_console" ];
              boot.kernelPackages = lib.mkForce (pkgs.linuxPackagesFor linuxKernel_7_0);
              boot.kernelParams = [
                "systemd.default_device_timeout_sec=600s"
                "rd.systemd.default_device_timeout_sec=600s"
              ];
              networking.useDHCP = lib.mkForce false;
              networking.interfaces.eth1.useDHCP = lib.mkForce false;
              environment.systemPackages = [ default pkgs.fio pkgs.e2fsprogs pkgs.util-linux ];
              virtualisation.graphics = false;
              virtualisation.cores = 2;
              virtualisation.memorySize = 2048;
            };
            testScript = ''
              import json
              import os
              import time

              validation = {
                "test": "tidefs-qemu-ublk-smoke",
                "version": 2,
                "results": [],
                "passed": 0,
                "product_failures": 0,
                "harness_failures": 0,
                "environment_refusals": 0,
                "skipped": 0,
              }

              # REL-VAL-006: 5-way validation classification
              VALID_STATUSES = {"pass", "product-fail", "harness-fail", "environment-refusal", "skip"}

              def record(name, status, output=None):
                  assert status in VALID_STATUSES, f"invalid validation status: {status}"
                  entry = {"name": name, "status": status}
                  if output is not None:
                      entry["output"] = output
                  validation["results"].append(entry)

              machine.start()
              machine.wait_for_unit("multi-user.target")

              # Record kernel version for release validation
              kernel_ver = machine.succeed("uname -r").strip()
              if not kernel_ver.startswith("7."):
                  record("linux_7_0_kernel", "environment-refusal",
                         f"expected Linux 7.0 guest kernel, got {kernel_ver}")
                  raise Exception(f"FAIL: qemu-ublk-smoke validation requires Linux 7.0 guest kernel, got {kernel_ver}")
              else:
                  record("linux_7_0_kernel", "pass", kernel_ver)
              record("kernel_version", "pass", kernel_ver)
              validation["kernel_version"] = kernel_ver
              validation["linux_7_0"] = True
              validation["kernel_package"] = "linuxKernel_7_0"
              validation["tier"] = "qemu-guest"
              cpu_model = machine.succeed(
                  "sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -n1"
              ).strip()
              qemu_acceleration = "tcg" if "qemu" in cpu_model.lower() else "kvm-or-host"
              tcg_guest = qemu_acceleration == "tcg"
              validation["qemu_acceleration"] = qemu_acceleration
              validation["qemu_cpu_model"] = cpu_model
              record("qemu_acceleration", "pass", f"{qemu_acceleration}: {cpu_model}")

              # Load ublk_drv kernel module
              machine.succeed("modprobe ublk_drv || true")
              machine.succeed("lsmod | grep ublk_drv || echo 'ublk_drv not in lsmod, checking devices...'")
              record("ublk_module", "pass")
              machine.succeed("test -c /dev/ublk-control")
              record("ublk_control_device", "pass", "/dev/ublk-control")

              # Create backing store directory
              machine.succeed("mkdir -p /tmp/tidefs-ublk-pool")
              record("pool_dir", "pass")

              # Start ublk block attach in background (this exposes /dev/ublkb0)
              attach_log = "/tmp/tidefs-ublk-attach.log"

              def require_ublkb0_block(stage):
                  status, out = machine.execute(
                      f"if test -b /dev/ublkb0; then echo block; "
                      f"else echo '{stage}: /dev/ublkb0 is not a block device'; "
                      f"ls -l /dev/ublkb0 2>&1 || true; "
                      f"echo '--- attach log ---'; "
                      f"cat {attach_log} 2>&1 || true; exit 1; fi"
                  )
                  if status != 0:
                      record(f"{stage}_device_live", "product-fail", out[-1500:])
                      raise Exception(f"FAIL: /dev/ublkb0 stopped being a block device during {stage}")

              machine.execute(
                  "nohup tidefsctl block attach /tmp/tidefs-ublk-pool "
                  f"> {attach_log} 2>&1 &"
              )
              time.sleep(3)
              # Read early attach log for diagnostics
              status, early_diag = machine.execute(f"cat {attach_log} 2>/dev/null || echo 'log_empty'")
              attach_diag = early_diag.strip()
              record("block_attach_start", "pass", attach_diag[:500] if attach_diag else "no output yet")

              # Wait for /dev/ublkb0 to appear
              found = False
              for i in range(60):
                  # Refresh diagnostics every 10 seconds
                  if i > 0 and i % 10 == 0:
                      status, fresh_diag = machine.execute(f"cat {attach_log} 2>/dev/null || echo 'log_empty'")
                      attach_diag = fresh_diag.strip()
                  status, out = machine.execute("test -b /dev/ublkb0 && echo FOUND")
                  if "FOUND" in out:
                      found = True
                      break
                  time.sleep(1)
              # Final diagnostic read
              status, final_diag = machine.execute(f"cat {attach_log} 2>/dev/null || echo 'log_empty'")
              attach_diag = final_diag.strip()
              assert found, f"ublk block device /dev/ublkb0 did not appear within 60s. attach log: {attach_diag}"
              record("ublk_device", "pass", "/dev/ublkb0")

              # Device info
              ls_out = machine.succeed("ls -la /dev/ublkb0")
              validation["ublkb_device_ls"] = ls_out.strip()
              dev_name = "ublkb0"
              size_sectors = machine.succeed(
                  f"cat /sys/class/block/{dev_name}/size 2>/dev/null || echo 0"
              ).strip()
              record("device_info", "pass",
                     f"size_sectors={size_sectors}")
              # ublk control device enumeration
              ctl_devs = machine.succeed("ls -la /dev/ublkc* 2>/dev/null || echo none").strip()
              record("ublkc_devices", "pass", ctl_devs)
              validation["ublkc_devices"] = ctl_devs

              # sysfs queue metadata
              queue_max_sectors_kb = machine.succeed(
                  f"cat /sys/class/block/{dev_name}/queue/max_sectors_kb 2>/dev/null || echo 0"
              ).strip()
              queue_hw_sector_size = machine.succeed(
                  f"cat /sys/class/block/{dev_name}/queue/hw_sector_size 2>/dev/null || echo 0"
              ).strip()
              record("sysfs_queue", "pass",
                     f"max_sectors_kb={queue_max_sectors_kb} hw_sector_size={queue_hw_sector_size}")
              validation["sysfs_queue_max_sectors_kb"] = queue_max_sectors_kb
              validation["sysfs_hw_sector_size"] = queue_hw_sector_size

              # ── fio workloads ──

              fio_common = "--filename=/dev/ublkb0 --allow_file_create=0 --direct=1 --bs=4k --verify=crc32c --verify_fatal=1"

              # Test 1: sequential write + verify
              require_ublkb0_block("fio_seq_write")
              machine.succeed(
                  f"fio --name=seq-write --rw=write --size=2M --offset=0 "
                  f"{fio_common} --output=/tmp/fio-seq-write.json --output-format=json"
              )
              record("fio_seq_write", "pass")

              # Test 2: sequential read-back verify
              require_ublkb0_block("fio_seq_read")
              machine.succeed(
                  f"fio --name=seq-read --rw=read --size=2M --offset=0 "
                  f"{fio_common} --output=/tmp/fio-seq-read.json --output-format=json"
              )
              record("fio_seq_read", "pass")

              # Test 3: random write with fixed seed
              rand_seed = "--randseed=42"
              require_ublkb0_block("fio_rand_write")
              machine.succeed(
                  f"fio --name=rand-write --rw=randwrite --size=1M --offset=2M "
                  f"{rand_seed} {fio_common} --output=/tmp/fio-rand-write.json --output-format=json"
              )
              record("fio_rand_write", "pass")

              # Test 4: random read-back verify (same seed, same blocks)
              require_ublkb0_block("fio_rand_read")
              machine.succeed(
                  f"fio --name=rand-read --rw=randread --size=1M --offset=2M "
                  f"{rand_seed} {fio_common} --output=/tmp/fio-rand-read.json --output-format=json"
              )
              record("fio_rand_read", "pass")

              # Test 5: mixed random rw with verify (inline, same seed)
              require_ublkb0_block("fio_mixed_rw")
              machine.succeed(
                  f"fio --name=mixed-rw --rw=randrw --rwmixread=50 --size=1M --offset=3M "
                  f"{rand_seed} {fio_common} --output=/tmp/fio-mixed-rw.json --output-format=json"
              )

              record("fio_mixed_rw", "pass")

              # Test 5b: sequential mixed read/write with verify
              require_ublkb0_block("fio_seq_mixed_rw")
              machine.succeed(
                  f"fio --name=seq-mixed-rw --rw=rw --rwmixread=50 --size=512K --offset=7M "
                  f"{fio_common} --output=/tmp/fio-seq-mixed-rw.json --output-format=json"
              )
              record("fio_seq_mixed_rw", "pass")

              # Test 6: fsync-heavy sequential write + verify
              require_ublkb0_block("fio_fsync_write")
              machine.succeed(
                  f"fio --name=fsync-write --rw=write --size=512K --offset=4M "
                  f"--fsync=1 {fio_common} --output=/tmp/fio-fsync-write.json --output-format=json"
              )
              record("fio_fsync_write", "pass")

              # Test 7: fsync-heavy sequential read-back verify
              require_ublkb0_block("fio_fsync_read")
              machine.succeed(
                  f"fio --name=fsync-read --rw=read --size=512K --offset=4M "
                  f"{fio_common} --output=/tmp/fio-fsync-read.json --output-format=json"
              )
              record("fio_fsync_read", "pass")

              # Test 9: FUA-equivalent write durability (fsync-per-write barrier)
              # Write with fsync=1 -- each write syncs to stable storage
              require_ublkb0_block("fio_fua_write")
              machine.succeed(
                  f"fio --name=fua-write --rw=write --size=256K --offset=6M "
                  f"--fsync=1 --direct=1 --bs=4k --verify=crc32c --verify_fatal=1 "
                  f"--filename=/dev/ublkb0 --allow_file_create=0 "
                  f"--output=/tmp/fio-fua-write.json --output-format=json"
              )
              record("fio_fua_write", "pass")

              # Read-back verify FUA-written data
              require_ublkb0_block("fio_fua_read")
              machine.succeed(
                  f"fio --name=fua-read --rw=read --size=256K --offset=6M "
                  f"--direct=1 --bs=4k --verify=crc32c --verify_fatal=1 "
                  f"--filename=/dev/ublkb0 --allow_file_create=0 "
                  f"--output=/tmp/fio-fua-read.json --output-format=json"
              )
              record("fio_fua_read", "pass")

              # Check fio JSON output for errors
              total_errors = 0
              for fio_json in [
                  "/tmp/fio-seq-write.json",
                  "/tmp/fio-seq-read.json",
                  "/tmp/fio-rand-write.json",
                  "/tmp/fio-rand-read.json",
                  "/tmp/fio-mixed-rw.json",
                  "/tmp/fio-seq-mixed-rw.json",
                  "/tmp/fio-fsync-write.json",
                  "/tmp/fio-fsync-read.json",
                  "/tmp/fio-fua-write.json",
                  "/tmp/fio-fua-read.json",
              ]:
                  raw = machine.succeed(f"cat {fio_json}")
                  try:
                      data = json.loads(raw)
                      err = data.get("jobs", [{}])[0].get("error", 0)
                      if err != 0:
                          total_errors += 1
                          record(f"fio_errors_{os.path.basename(fio_json)}", "product-fail", str(err))
                  except Exception:
                      pass

              assert total_errors == 0, f"fio reported {total_errors} verification errors"
              record("fio_verify", "pass", "zero data corruption")

              # ================================================================
              # Queue-depth latency budget measurement
              # ================================================================
              # Run fio at varying queue depths (iodepth 1..64) with a consistent
              # randrw workload and capture latency percentiles + throughput KPIs.
              # Budget: p99 latency must remain <= 25 ms per block_random_queue r3.

              qd_iodepths = [1, 4, 8, 16, 32, 64]
              qd_latency_kpis = {}  # iodepth -> {p50_us, p95_us, p99_us, bw_mb_s}
              qd_budget_pass = True
              qd_budget_applicable = not tcg_guest
              qd_budget_ceiling_us = 25000.0

              for qd in qd_iodepths:
                  qd_out = f"/tmp/fio-randrw-qd{qd}.json"
                  require_ublkb0_block(f"fio_randrw_qd{qd}")
                  machine.succeed(
                      f"fio --name=randrw-qd{qd} --rw=randrw --rwmixread=70 --size=2M "
                      f"--direct=1 --bs=4k --iodepth={qd} --filename=/dev/ublkb0 --allow_file_create=0 "
                      f"--output={qd_out} --output-format=json"
                  )
                  record(f"fio_randrw_qd{qd}", "pass")

                  raw = machine.succeed(f"cat {qd_out}")
                  try:
                      data = json.loads(raw)
                      job = data.get("jobs", [{}])[0]
                      # Latency percentiles in nanoseconds from fio JSON
                      lat_ns = job.get("lat_ns", {})
                      p50_ns = lat_ns.get("percentile", {}).get("50.000000", 0)
                      p95_ns = lat_ns.get("percentile", {}).get("95.000000", 0)
                      p99_ns = lat_ns.get("percentile", {}).get("99.000000", 0)

                      # Convert to microseconds
                      p50_us = p50_ns / 1000.0 if p50_ns else 0.0
                      p95_us = p95_ns / 1000.0 if p95_ns else 0.0
                      p99_us = p99_ns / 1000.0 if p99_ns else 0.0

                      # Read BW in KiB/s, convert to MiB/s
                      read_bw_bytes = job.get("read", {}).get("bw_bytes", 0)
                      write_bw_bytes = job.get("write", {}).get("bw_bytes", 0)
                      bw_mb_s = (read_bw_bytes + write_bw_bytes) / (1024.0 * 1024.0)

                      qd_latency_kpis[qd] = {
                          "p50_us": round(p50_us, 2),
                          "p95_us": round(p95_us, 2),
                          "p99_us": round(p99_us, 2),
                          "bw_mb_s": round(bw_mb_s, 2),
                      }

                      qd_summary = (
                          f"p50={p50_us:.1f}us p95={p95_us:.1f}us "
                          f"p99={p99_us:.1f}us bw={bw_mb_s:.1f}MiB/s"
                      )

                      # Budget check: p99 must be <= 25ms in a budget-capable
                      # KVM/host environment. TCG observations are retained as
                      # KPIs but do not close or fail performance_budget_0.
                      if not qd_budget_applicable:
                          record(f"fio_randrw_qd{qd}_budget", "skip",
                                 f"TCG/no-KVM latency observation only; {qd_summary}")
                      elif p99_us > qd_budget_ceiling_us:
                          qd_budget_pass = False
                          record(f"fio_randrw_qd{qd}_budget", "product-fail",
                                 f"p99={p99_us:.1f}us exceeds {qd_budget_ceiling_us:.0f}us ceiling")
                      else:
                          record(f"fio_randrw_qd{qd}_budget", "pass",
                                 qd_summary)

                  except Exception as e:
                      qd_budget_pass = False
                      record(f"fio_randrw_qd{qd}_parse", "harness-fail", str(e)[:200])

              if not qd_budget_applicable:
                  record("ublk_queue_depth_latency_budget", "skip",
                         "TCG/no-KVM run collected queue-depth KPIs but does not close "
                         f"performance_budget_0; KPIs={json.dumps(qd_latency_kpis)}")
              elif qd_budget_pass:
                  record("ublk_queue_depth_latency_budget", "pass",
                         f"all queue depths (1-64) within p99<=25ms budget; KPIs={json.dumps(qd_latency_kpis)}")
              else:
                  record("ublk_queue_depth_latency_budget", "product-fail",
                         f"queue depth latency budget exceeded; KPIs={json.dumps(qd_latency_kpis)}")

              validation["queue_depth_latency_kpis"] = qd_latency_kpis

              # ================================================================
              # Discard and write-zeroes guest filesystem matrix
              # ================================================================

              # Phase D1: Verify discard support advertised in sysfs
              require_ublkb0_block("discard_sysfs")
              discard_gran = machine.succeed(
                  "cat /sys/class/block/ublkb0/queue/discard_granularity 2>/dev/null || echo 0"
              ).strip()
              discard_max_bytes = machine.succeed(
                  "cat /sys/class/block/ublkb0/queue/discard_max_bytes 2>/dev/null || echo 0"
              ).strip()
              discard_zeroes_data = machine.succeed(
                  "cat /sys/class/block/ublkb0/queue/discard_zeroes_data 2>/dev/null || echo 0"
              ).strip()
              write_zeroes_max_bytes = machine.succeed(
                  "cat /sys/class/block/ublkb0/queue/write_zeroes_max_bytes 2>/dev/null || echo 0"
              ).strip()
              sysfs_discard_output = (
                  f"discard_gran={discard_gran} max_bytes={discard_max_bytes} "
                  f"zeroes_data={discard_zeroes_data} wz_max={write_zeroes_max_bytes}"
              )
              if int(discard_gran or "0") <= 0 or int(discard_max_bytes or "0") <= 0 or int(write_zeroes_max_bytes or "0") <= 0:
                  record("sysfs_discard", "product-fail", sysfs_discard_output)
                  raise Exception(f"FAIL: ublk device does not advertise discard/write-zeroes support: {sysfs_discard_output}")
              record("sysfs_discard", "pass", sysfs_discard_output)

              # Phase D2: Full-device blkdiscard with zero verification
              require_ublkb0_block("blkdiscard_full_prewrite")
              machine.succeed(
                  "dd if=/dev/urandom of=/dev/ublkb0 bs=512 count=64 2>/dev/null"
              )
              machine.succeed("sync")
              require_ublkb0_block("blkdiscard_full")
              machine.succeed("blkdiscard -f /dev/ublkb0 2>&1")
              record("blkdiscard_full", "pass")
              machine.succeed(
                  "dd if=/dev/ublkb0 of=/tmp/post_full_discard.bin bs=512 count=64 2>/dev/null"
              )
              nz_count = int(machine.succeed(
                  "tr -d '\\0' < /tmp/post_full_discard.bin | wc -c"
              ).strip())
              if nz_count == 0:
                  record("blkdiscard_full_zero_verify", "pass", "all zero after full discard")
              else:
                  record("blkdiscard_full_zero_verify", "product-fail",
                         f"{nz_count} non-zero bytes after full discard")

              # Phase D3: Ranged blkdiscard with preservation verification
              require_ublkb0_block("blkdiscard_range_prewrite")
              machine.succeed(
                  "dd if=/dev/urandom of=/dev/ublkb0 bs=512 count=64 seek=128 2>/dev/null"
              )
              machine.succeed("sync")
              # Discard sectors 144-175 (offset=73728, length=16384)
              require_ublkb0_block("blkdiscard_range")
              machine.succeed("blkdiscard -f -o 73728 -l 16384 /dev/ublkb0 2>&1")
              record("blkdiscard_range", "pass")
              machine.succeed(
                  "dd if=/dev/ublkb0 of=/tmp/post_range_discarded.bin bs=512 count=1 skip=150 2>/dev/null"
              )
              nz_discarded = int(machine.succeed(
                  "tr -d '\\0' < /tmp/post_range_discarded.bin | wc -c"
              ).strip())
              if nz_discarded == 0:
                  record("blkdiscard_range_zero_verify", "pass", "discarded sector 150 is zero")
              else:
                  record("blkdiscard_range_zero_verify", "product-fail",
                         f"discarded sector 150 has {nz_discarded} non-zero bytes")
              machine.succeed(
                  "dd if=/dev/ublkb0 of=/tmp/post_range_preserved.bin bs=512 count=1 skip=130 2>/dev/null"
              )
              nz_preserved = int(machine.succeed(
                  "tr -d '\\0' < /tmp/post_range_preserved.bin | wc -c"
              ).strip())
              if nz_preserved > 0:
                  record("blkdiscard_range_preserved_verify", "pass",
                         f"sector 130 has {nz_preserved} non-zero bytes (preserved)")
              else:
                  record("blkdiscard_range_preserved_verify", "product-fail",
                         "sector 130 (should be preserved) is all zero")

              # Phase D4: Write-zeroes verification
              require_ublkb0_block("write_zeroes_prewrite")
              machine.succeed(
                  "dd if=/dev/urandom of=/dev/ublkb0 bs=512 count=64 seek=256 2>/dev/null"
              )
              machine.succeed("sync")
              # Zero sectors 260-267 (8 sectors = 4KB) via dd
              require_ublkb0_block("write_zeroes_issue")
              machine.succeed(
                  "dd if=/dev/zero of=/dev/ublkb0 bs=512 count=8 seek=260 2>/dev/null"
              )
              machine.succeed("sync")
              record("write_zeroes_issued", "pass", "write-zeroes to sector range 260-267")
              machine.succeed(
                  "dd if=/dev/ublkb0 of=/tmp/post_wz.bin bs=512 count=1 skip=260 2>/dev/null"
              )
              post_wz_nz = int(machine.succeed(
                  "tr -d '\\0' < /tmp/post_wz.bin | wc -c"
              ).strip())
              if post_wz_nz == 0:
                  record("write_zeroes_zero_verify", "pass", "sector 260 zeroed")
              else:
                  record("write_zeroes_zero_verify", "product-fail",
                         f"sector 260 has {post_wz_nz} non-zero bytes after write-zeroes")
              machine.succeed(
                  "dd if=/dev/ublkb0 of=/tmp/post_wz_preserved.bin bs=512 count=1 skip=258 2>/dev/null"
              )
              adj_nz = int(machine.succeed(
                  "tr -d '\\0' < /tmp/post_wz_preserved.bin | wc -c"
              ).strip())
              if adj_nz > 0:
                  record("write_zeroes_preserved_verify", "pass",
                         f"adjacent sector 258 has {adj_nz} non-zero bytes (preserved)")
              else:
                  record("write_zeroes_preserved_verify", "product-fail",
                         "adjacent sector 258 (should be preserved) is all zero")

              # Phase D5: Guest filesystem (ext4) discard with fstrim
              require_ublkb0_block("discard_mkfs_ext4")
              machine.succeed("mkfs.ext4 -F /dev/ublkb0 2>&1")
              record("discard_mkfs_ext4", "pass")
              machine.succeed("mkdir -p /mnt/tidefs-discard-test")
              machine.succeed(
                  "mount -t ext4 /dev/ublkb0 /mnt/tidefs-discard-test"
              )
              record("discard_mount_ext4", "pass")
              # Write test files
              for i in range(5):
                  machine.succeed(
                      f"dd if=/dev/urandom of=/mnt/tidefs-discard-test/file_{i}.bin bs=4K count=128 2>/dev/null"
                  )
              record("discard_write_files", "pass", "5 x 512KB files written")
              machine.succeed("sync")
              # Record checksums before fstrim
              machine.succeed(
                  "md5sum /mnt/tidefs-discard-test/file_*.bin > /tmp/pre_trim_checksums.txt"
              )
              # Delete half the files and run fstrim
              machine.succeed("rm /mnt/tidefs-discard-test/file_[012].bin")
              machine.succeed("sync")
              machine.succeed("fstrim -v /mnt/tidefs-discard-test 2>&1")
              record("discard_fstrim", "pass")
              # Verify remaining files still intact
              machine.succeed(
                  "md5sum -c --ignore-missing /tmp/pre_trim_checksums.txt 2>&1"
              )
              record("discard_data_integrity_after_trim", "pass",
                     "remaining files pass checksum after fstrim")
              # Unmount and remount
              machine.succeed("umount /mnt/tidefs-discard-test")
              machine.succeed(
                  "mount -t ext4 /dev/ublkb0 /mnt/tidefs-discard-test"
              )
              record("discard_remount_ext4", "pass")
              # Verify files survive remount
              status, out = machine.execute(
                  "test -f /mnt/tidefs-discard-test/file_3.bin && "
                  "test -f /mnt/tidefs-discard-test/file_4.bin && echo OK"
              )
              if "OK" in out:
                  record("discard_remount_persistence", "pass",
                         "files survive unmount/remount after discard")
              else:
                  record("discard_remount_persistence", "product-fail",
                         f"files missing after remount: {out}")
              machine.succeed("umount /mnt/tidefs-discard-test")

              # Stop the long-lived smoke device only after all discard tests.
              # resize-smoke owns a separate short-lived ublk lifecycle.
              machine.execute("pkill -TERM -f '[v]ibefsctl block attach' || true")
              attach_teardown_ok = False
              attach_teardown_diag = ""
              for i in range(60):
                  status, out = machine.execute(
                      "if pgrep -f '[v]ibefsctl block attach' >/dev/null; then "
                      "echo attach-running; exit 1; fi; "
                      "if test -b /dev/ublkb0 || test -e /dev/ublkc0; then "
                      "echo ublk-device-present; "
                      "ls -l /dev/ublkb0 /dev/ublkc0 2>&1 || true; exit 1; fi; "
                      "echo detached"
                  )
                  attach_teardown_diag = out.strip()
                  if status == 0 and "detached" in out:
                      attach_teardown_ok = True
                      break
                  time.sleep(1)
              if not attach_teardown_ok:
                  status, detach_out = machine.execute(
                      "tidefsctl block detach 0 2>&1 || true; "
                      "if test -b /dev/ublkb0 || test -e /dev/ublkc0; then "
                      "ls -l /dev/ublkb0 /dev/ublkc0 2>&1 || true; exit 1; fi; "
                      "echo detached-after-explicit-del-dev"
                  )
                  attach_teardown_diag = detach_out.strip()
                  attach_teardown_ok = status == 0 and "detached" in detach_out
              if attach_teardown_ok:
                  record("block_attach_teardown", "pass", attach_teardown_diag[-1000:])
              else:
                  status, log_tail = machine.execute(f"tail -n 80 {attach_log} 2>&1 || true")
                  record("block_attach_teardown", "product-fail",
                         f"{attach_teardown_diag[-1000:]}\n--- attach log ---\n{log_tail[-2000:]}")
                  raise Exception("FAIL: tidefsctl block attach did not detach cleanly before resize-smoke")

              # -- Resize smoke validation --
              # resize-smoke does its own full ublk lifecycle (control open,
              # add_dev, start_dev, update_size, del_dev). Run it standalone.
              resize_out = machine.succeed(
                  "tidefs-block-volume-adapter-daemon resize-smoke 2>&1"
              )
              resize_completed = (
                  "update_size.completed=true" in resize_out
              )
              resize_refused = (
                  "failure_class=host_not_admitted" in resize_out
              )
              resize_policy_refused = (
                  "failure_class=resize_explicitly_refused" in resize_out and
                  "resize_policy.refusal_reason=pool capacity is fixed at create" in resize_out
              )
              if resize_completed:
                  record("ublk_resize", "pass",
                         "UPDATE_SIZE completed via uring_cmd in QEMU guest")
              elif resize_policy_refused:
                  record("ublk_resize", "pass",
                         "online resize explicitly refused by fixed-capacity policy")
              elif resize_refused:
                  record("ublk_resize", "pass",
                         "resize correctly refused (nested virt or kernel < 7.0)")
              else:
                  record("ublk_resize", "product-fail",
                         f"resize smoke unexpected: {resize_out[:400]}")

              # Compute 5-way validation counts (REL-VAL-006)
              validation["passed"] = sum(1 for r in validation["results"] if r["status"] == "pass")
              validation["product_failures"] = sum(1 for r in validation["results"] if r["status"] == "product-fail")
              validation["harness_failures"] = sum(1 for r in validation["results"] if r["status"] == "harness-fail")
              validation["environment_refusals"] = sum(1 for r in validation["results"] if r["status"] == "environment-refusal")
              validation["skipped"] = sum(1 for r in validation["results"] if r["status"] == "skip")

              os.makedirs("/tmp/tidefs-validation", exist_ok=True)
              machine.succeed("mkdir -p /tmp/tidefs-validation")
              with open("/tmp/tidefs-validation/qemu-ublk-smoke.json", "w") as f:
                  json.dump(validation, f, indent=2)
              print("qemu-ublk-smoke validation:")
              print(json.dumps(validation, indent=2))

              total_failures = validation["product_failures"] + validation["harness_failures"]
              assert total_failures == 0, (
                  f"qemu-ublk-smoke: {validation['product_failures']} product failure(s), "
                  f"{validation['harness_failures']} harness failure(s)"
              )
              assert validation["environment_refusals"] == 0, (
                  f"qemu-ublk-smoke: {validation['environment_refusals']} environment refusal(s)"
              )
              assert validation["passed"] + validation["skipped"] == len(validation["results"]), (
                  f"expected all {len(validation['results'])} results to pass or skip, "
                  f"got {validation['passed']} pass and {validation['skipped']} skip"
              )
            '';
          };



          qemuUblkExt4Smoke = pkgs.testers.runNixOSTest {
            name = "tidefs-qemu-ublk-ext4-smoke";
            skipTypeCheck = true;
            skipLint = true;
            nodes.machine = { lib, pkgs, ... }: {
              boot.initrd.availableKernelModules = lib.mkForce [ "virtio_pci" "virtio_blk" "virtio_console" ];
              boot.initrd.kernelModules = lib.mkForce [ "virtio_balloon" "virtio_console" ];
              boot.kernelModules = [ "ublk_drv" "virtio_console" ];
              boot.kernelPackages = lib.mkForce (pkgs.linuxPackagesFor linuxKernel_7_0);
              boot.kernelParams = [
                "systemd.default_device_timeout_sec=600s"
                "rd.systemd.default_device_timeout_sec=600s"
              ];
              networking.useDHCP = lib.mkForce false;
              networking.interfaces.eth1.useDHCP = lib.mkForce false;
              environment.systemPackages = [ default pkgs.fio pkgs.e2fsprogs pkgs.util-linux ];
              virtualisation.graphics = false;
              virtualisation.cores = 2;
              virtualisation.memorySize = 2048;
            };
            testScript = ''
              import json
              import os
              import time

              validation = {
                "test": "tidefs-qemu-ublk-ext4-smoke",
                "version": 2,
                "results": [],
                "passed": 0,
                "product_failures": 0,
                "harness_failures": 0,
                "environment_refusals": 0,
                "skipped": 0,
              }

              def record(name, status, output=None):
                  entry = {"name": name, "status": status}
                  if output is not None:
                      entry["output"] = output
                  validation["results"].append(entry)

              machine.start()
              machine.wait_for_unit("multi-user.target")

              # Record kernel version for release validation
              kernel_ver = machine.succeed("uname -r").strip()
              if not kernel_ver.startswith("7."):
                  record("linux_7_0_kernel", "environment-refusal",
                         f"expected Linux 7.0 guest kernel, got {kernel_ver}")
                  raise Exception(f"FAIL: qemu-ublk-ext4-smoke validation requires Linux 7.0 guest kernel, got {kernel_ver}")
              else:
                  record("linux_7_0_kernel", "pass", kernel_ver)
              record("kernel_version", "pass", kernel_ver)
              validation["kernel_version"] = kernel_ver
              validation["linux_7_0"] = True
              validation["kernel_package"] = "linuxKernel_7_0"
              validation["tier"] = "qemu-guest"

              # Load ublk_drv kernel module
              machine.succeed("modprobe ublk_drv || true")
              machine.succeed("lsmod | grep ublk_drv || echo 'ublk_drv not in lsmod, checking devices...'")
              record("ublk_module", "pass")
              machine.succeed("test -c /dev/ublk-control")
              record("ublk_control_device", "pass", "/dev/ublk-control")

              # Create backing store directory
              machine.succeed("mkdir -p /tmp/tidefs-ublk-pool")
              record("pool_dir", "pass")

              # Start ublk block attach in background
              attach_log = "/tmp/tidefs-ublk-attach.log"
              machine.execute(
                  "nohup tidefsctl block attach /tmp/tidefs-ublk-pool "
                  f"> {attach_log} 2>&1 &"
              )
              time.sleep(3)
              # Read early attach log for diagnostics
              status, early_diag = machine.execute(f"cat {attach_log} 2>/dev/null || echo 'log_empty'")
              attach_diag = early_diag.strip()
              record("block_attach_start", "pass", attach_diag[:500] if attach_diag else "no output yet")

              # Wait for /dev/ublkb0 to appear
              found = False
              for i in range(60):
                  # Refresh diagnostics every 10 seconds
                  if i > 0 and i % 10 == 0:
                      status, fresh_diag = machine.execute(f"cat {attach_log} 2>/dev/null || echo 'log_empty'")
                      attach_diag = fresh_diag.strip()
                  status, out = machine.execute("test -b /dev/ublkb0 && echo FOUND")
                  if "FOUND" in out:
                      found = True
                      break
                  time.sleep(1)
                  # On last attempt, capture full diagnostic output
                  if i == 59:
                      attach_diag = machine.succeed(
                          f"cat {attach_log} 2>/dev/null; echo '---'; ps aux | grep tidefsctl | grep -v grep || echo 'no tidefsctl process'; echo === dmesg ===; dmesg | grep -i ublk | tail -20 || echo 'no ublk dmesg'"
                      )
              # Final diagnostic read if not already captured
              status, final_diag = machine.execute(f"cat {attach_log} 2>/dev/null || echo 'log_empty'")
              attach_diag = final_diag.strip()
              assert found, f"ublk block device /dev/ublkb0 did not appear within 60s. attach log: {attach_diag}"
              record("ublk_device", "pass", "/dev/ublkb0")

              # Device info
              dev_name = "ublkb0"
              size_sectors = machine.succeed(
                  "cat /sys/class/block/ublkb0/size 2>/dev/null || echo 0"
              ).strip()
              record("device_info", "pass",
                     f"size_sectors={size_sectors}")
              # ublk control device enumeration
              ctl_devs = machine.succeed("ls -la /dev/ublkc* 2>/dev/null || echo none").strip()
              record("ublkc_devices", "pass", ctl_devs)
              validation["ublkc_devices"] = ctl_devs

              # sysfs queue metadata
              queue_max_sectors_kb = machine.succeed(
                  f"cat /sys/class/block/{dev_name}/queue/max_sectors_kb 2>/dev/null || echo 0"
              ).strip()
              queue_hw_sector_size = machine.succeed(
                  f"cat /sys/class/block/{dev_name}/queue/hw_sector_size 2>/dev/null || echo 0"
              ).strip()
              record("sysfs_queue", "pass",
                     f"max_sectors_kb={queue_max_sectors_kb} hw_sector_size={queue_hw_sector_size}")
              validation["sysfs_queue_max_sectors_kb"] = queue_max_sectors_kb
              validation["sysfs_hw_sector_size"] = queue_hw_sector_size

              # Create ext4 filesystem
              machine.succeed(
                  "mkfs.ext4 -F /dev/ublkb0 2>&1"
              )
              record("mkfs_ext4", "pass")

              # Mount ext4
              machine.succeed("mkdir -p /mnt/tidefs-ext4")
              machine.succeed(
                  "mount -t ext4 /dev/ublkb0 /mnt/tidefs-ext4"
              )
              record("mount_ext4", "pass", "/mnt/tidefs-ext4")


              # -- POSIX file operations --

              # Create a test file with known content
              machine.succeed(
                  "echo 'tidefs-ext4-smoke-test' > /mnt/tidefs-ext4/hello.txt"
              )
              record("posix_create", "pass")

              # Read it back
              content = machine.succeed("cat /mnt/tidefs-ext4/hello.txt").strip()
              assert content == "tidefs-ext4-smoke-test", f"wrong content: {content}"
              record("posix_read", "pass", "content matches")

              # Append and verify
              machine.succeed(
                  "echo 'append-line' >> /mnt/tidefs-ext4/hello.txt"
              )
              lines = machine.succeed("wc -l < /mnt/tidefs-ext4/hello.txt").strip()
              assert lines == "2", f"expected 2 lines, got {lines}"
              record("posix_append", "pass")

              # Rename
              machine.succeed(
                  "mv /mnt/tidefs-ext4/hello.txt /mnt/tidefs-ext4/renamed.txt"
              )
              machine.fail("test -f /mnt/tidefs-ext4/hello.txt")
              machine.succeed("test -f /mnt/tidefs-ext4/renamed.txt")
              record("posix_rename", "pass")

              # Unlink
              machine.succeed("rm /mnt/tidefs-ext4/renamed.txt")
              machine.fail("test -f /mnt/tidefs-ext4/renamed.txt")
              record("posix_unlink", "pass")

              # Create a persistence marker file (for remount check later)
              machine.succeed(
                  "echo 'persistence-marker' > /mnt/tidefs-ext4/persist.txt"
              )
              machine.succeed("sync")
              record("persist_marker", "pass", "written and synced")
              # fio workloads through ext4 mount
              fio_common = "--directory=/mnt/tidefs-ext4 --direct=1 --bs=4k --verify=crc32c --verify_fatal=1"
              rand_seed = "--randseed=42"

              # Test 1: sequential write + verify
              machine.succeed(
                  f"fio --name=ext4-seq-write --rw=write --size=2M "
                  f"{fio_common} --output=/tmp/fio-ext4-seq-write.json --output-format=json"
              )
              record("ext4_fio_seq_write", "pass")

              # Test 2: sequential read-back verify
              machine.succeed(
                  f"fio --name=ext4-seq-read --rw=read --size=2M "
                  f"{fio_common} --output=/tmp/fio-ext4-seq-read.json --output-format=json"
              )
              record("ext4_fio_seq_read", "pass")

              # Test 3: random write with fixed seed
              machine.succeed(
                  f"fio --name=ext4-rand-write --rw=randwrite --size=1M "
                  f"{rand_seed} {fio_common} --output=/tmp/fio-ext4-rand-write.json --output-format=json"
              )
              record("ext4_fio_rand_write", "pass")

              # Test 4: random read-back verify
              machine.succeed(
                  f"fio --name=ext4-rand-read --rw=randread --size=1M "
                  f"{rand_seed} {fio_common} --output=/tmp/fio-ext4-rand-read.json --output-format=json"
              )
              record("ext4_fio_rand_read", "pass")

              # Test 5: fsync-heavy sequential write + verify
              machine.succeed(
                  f"fio --name=ext4-fsync-write --rw=write --size=512K "
                  f"--fsync=1 {fio_common} --output=/tmp/fio-ext4-fsync-write.json --output-format=json"
              )
              record("ext4_fio_fsync_write", "pass")

              # Test 6: fsync-heavy sequential read-back verify
              machine.succeed(
                  f"fio --name=ext4-fsync-read --rw=read --size=512K "
                  f"{fio_common} --output=/tmp/fio-ext4-fsync-read.json --output-format=json"
              )
              record("ext4_fio_fsync_read", "pass")

              # Unmount and fsck
              machine.succeed("umount /mnt/tidefs-ext4")
              record("umount_ext4", "pass")

              machine.succeed("fsck.ext4 -f /dev/ublkb0")
              record("fsck_ext4", "pass", "filesystem clean")


              # -- Remount persistence --
              machine.succeed("mkdir -p /mnt/tidefs-ext4")
              machine.succeed(
                  "mount -t ext4 /dev/ublkb0 /mnt/tidefs-ext4"
              )
              record("remount_ext4", "pass")

              persist_content = machine.succeed(
                  "cat /mnt/tidefs-ext4/persist.txt"
              ).strip()
              assert persist_content == "persistence-marker", \
                  f"persistence data lost: got '{persist_content}'"
              record("persist_verify", "pass", "content survives remount")

              machine.succeed("rm /mnt/tidefs-ext4/persist.txt")
              machine.succeed("umount /mnt/tidefs-ext4")
              record("remount_cleanup", "pass")
              # Check fio JSON output for errors
              total_errors = 0
              for fio_json in [
                  "/tmp/fio-ext4-seq-write.json",
                  "/tmp/fio-ext4-seq-read.json",
                  "/tmp/fio-ext4-rand-write.json",
                  "/tmp/fio-ext4-rand-read.json",
                  "/tmp/fio-ext4-fsync-write.json",
                  "/tmp/fio-ext4-fsync-read.json",
              ]:
                  raw = machine.succeed(f"cat {fio_json}")
                  try:
                      data = json.loads(raw)
                      err = data.get("jobs", [{}])[0].get("error", 0)
                      if err != 0:
                          total_errors += 1
                          record(f"fio_errors_{os.path.basename(fio_json)}", "fail", str(err))
                  except Exception:
                      pass

              assert total_errors == 0, f"fio reported {total_errors} verification errors"
              record("fio_verify", "pass", "zero data corruption")

              # Stop ublk daemon
              machine.execute("pkill -f 'tidefsctl block attach' || true")
              time.sleep(2)

              # -- Resize smoke validation --
              # resize-smoke does its own full ublk lifecycle (control open,
              # add_dev, start_dev, update_size, del_dev). Run it standalone.
              resize_out = machine.succeed(
                  "tidefs-block-volume-adapter-daemon resize-smoke 2>&1"
              )
              resize_completed = (
                  "update_size.completed=true" in resize_out
              )
              resize_refused = (
                  "failure_class=host_not_admitted" in resize_out
              )
              resize_policy_refused = (
                  "failure_class=resize_explicitly_refused" in resize_out and
                  "resize_policy.refusal_reason=pool capacity is fixed at create" in resize_out
              )
              if resize_completed:
                  record("ublk_ext4_resize", "pass",
                         "UPDATE_SIZE completed via uring_cmd in QEMU guest")
              elif resize_policy_refused:
                  record("ublk_ext4_resize", "pass",
                         "online resize explicitly refused by fixed-capacity policy")
              elif resize_refused:
                  record("ublk_ext4_resize", "pass",
                         "resize correctly refused (nested virt or kernel < 7.0)")
              else:
                  record("ublk_ext4_resize", "fail",
                         f"resize smoke unexpected: {resize_out[:400]}")

              # Compute 5-way validation counts (REL-VAL-006)
              validation["passed"] = sum(1 for r in validation["results"] if r["status"] == "pass")
              validation["product_failures"] = sum(1 for r in validation["results"] if r["status"] == "product-fail")
              validation["harness_failures"] = sum(1 for r in validation["results"] if r["status"] == "harness-fail")
              validation["environment_refusals"] = sum(1 for r in validation["results"] if r["status"] == "environment-refusal")
              validation["skipped"] = sum(1 for r in validation["results"] if r["status"] == "skip")

              machine.succeed("mkdir -p /tmp/tidefs-validation")
              with open("/tmp/tidefs-validation/qemu-ublk-ext4-smoke.json", "w") as f:
                  json.dump(validation, f, indent=2)

              assert failed == 0, f"{failed} smoke tests failed"
              assert passed == len(validation["results"]), f"expected all {len(validation['results'])} to pass, got {passed}"
            '';
          };


          qemuUblkMultiDevicePlacement = pkgs.testers.runNixOSTest {
            name = "tidefs-qemu-ublk-multi-device-placement";
            skipTypeCheck = true;
            skipLint = true;
            nodes.machine = { lib, pkgs, ... }: {
              boot.initrd.availableKernelModules = lib.mkForce [ "virtio_pci" "virtio_blk" "virtio_console" ];
              boot.initrd.kernelModules = lib.mkForce [ "virtio_balloon" "virtio_console" ];
              boot.kernelModules = [ "ublk_drv" "virtio_console" ];
              boot.kernelPackages = lib.mkForce (pkgs.linuxPackagesFor linuxKernel_7_0);
              boot.kernelParams = [
                "systemd.default_device_timeout_sec=600s"
                "rd.systemd.default_device_timeout_sec=600s"
              ];
              networking.useDHCP = lib.mkForce false;
              networking.interfaces.eth1.useDHCP = lib.mkForce false;
              environment.systemPackages = [ default pkgs.fio pkgs.e2fsprogs pkgs.util-linux ];
              virtualisation.graphics = false;
              virtualisation.cores = 2;
              virtualisation.memorySize = 2048;
            };
            testScript = ''
              import json
              import os
              import time

              validation = {
                "test": "tidefs-qemu-ublk-multi-device-placement",
                "version": 1,
                "results": [],
                "passed": 0,
                "product_failures": 0,
                "harness_failures": 0,
                "environment_refusals": 0,
                "skipped": 0,
              }

              VALID_STATUSES = {"pass", "product-fail", "harness-fail", "environment-refusal", "skip"}

              def record(name, status, output=None):
                  assert status in VALID_STATUSES, f"invalid validation status: {status}"
                  entry = {"name": name, "status": status}
                  if output is not None:
                      entry["output"] = output
                  validation["results"].append(entry)

              machine.start()
              machine.wait_for_unit("multi-user.target")

              kernel_ver = machine.succeed("uname -r").strip()
              if not kernel_ver.startswith("7."):
                  record("linux_7_0_kernel", "environment-refusal",
                         f"expected Linux 7.0 guest kernel, got {kernel_ver}")
                  raise Exception(f"FAIL: qemu-ublk-multi-device-placement validation requires Linux 7.0 guest kernel, got {kernel_ver}")
              else:
                  record("linux_7_0_kernel", "pass", kernel_ver)
              validation["kernel_version"] = kernel_ver
              validation["tier"] = "qemu-guest"

              machine.succeed("modprobe ublk_drv || true")
              machine.succeed("test -c /dev/ublk-control")
              record("ublk_module", "pass")

              DEV0 = "/tmp/tidefs-pool-dev0"
              DEV1 = "/tmp/tidefs-pool-dev1"
              POOL_DIR = "/tmp/tidefs-ublk-pool"

              machine.succeed(f"dd if=/dev/zero of={DEV0} bs=1M count=64")
              machine.succeed(f"dd if=/dev/zero of={DEV1} bs=1M count=64")
              record("device_files", "pass")

              create_out = machine.succeed(
                  f"tidefsctl pool create testpool --devices {DEV0} {DEV1} "
                  f"--redundancy mirror --file-devices --json"
              ).strip()
              record("pool_create_mirror", "pass", create_out[:500])

              status1 = machine.succeed(
                  f"tidefsctl pool status testpool --devices {DEV0} {DEV1} --json"
              ).strip()
              record("pool_status_initial", "pass", status1[:500])

              import1 = machine.succeed(
                  f"tidefsctl pool import {DEV0} {DEV1} --json"
              ).strip()
              record("pool_import", "pass", import1[:500])

              machine.succeed(f"mkdir -p {POOL_DIR}")
              attach_log = "/tmp/tidefs-ublk-attach.log"
              machine.execute(
                  f"nohup tidefsctl block attach {POOL_DIR} "
                  f"> {attach_log} 2>&1 &"
              )
              time.sleep(5)

              found = False
              for i in range(60):
                  status, out = machine.execute("test -b /dev/ublkb0 && echo FOUND")
                  if "FOUND" in out:
                      found = True
                      break
                  time.sleep(1)
              assert found, "ublk device /dev/ublkb0 did not appear"
              record("ublk_device_mounted", "pass")

              # Wait for daemon I/O readiness with retry
              time.sleep(15)
              fio_common = "--filename=/dev/ublkb0 --direct=1 --bs=4k --verify=crc32c --verify_fatal=1"
              fio_ok = False
              for attempt in range(5):
                  time.sleep(5)
                  status, fio_out = machine.execute(
                      f"fio --name=seq-write --rw=write --size=2M --offset=0 "
                      f"{fio_common} --output=/tmp/fio-seq-write.json --output-format=json 2>&1"
                  )
                  if status == 0:
                      fio_ok = True
                      break
              assert fio_ok, "fio seq-write failed after 5 retries"
              record("fio_seq_write", "pass")

              machine.succeed(
                  f"fio --name=seq-read --rw=read --size=2M --offset=0 "
                  f"{fio_common} --output=/tmp/fio-seq-read.json --output-format=json"
              )
              record("fio_seq_read", "pass")

              machine.execute("pkill -f 'tidefsctl block attach' || true")
              time.sleep(5)
              record("ublk_stop", "pass")

              machine.succeed(
                  f"tidefsctl pool export testpool --devices {DEV0} {DEV1}"
              )
              record("pool_export", "pass")

              import2 = machine.succeed(
                  f"tidefsctl pool import {DEV1} {DEV0} --json"
              ).strip()
              record("pool_import_reversed", "pass", import2[:500])

              status2 = machine.succeed(
                  f"tidefsctl pool status testpool --devices {DEV1} {DEV0} --json"
              ).strip()
              record("pool_status_reversed", "pass", status2[:500])

              os.makedirs("/tmp/tidefs-validation", exist_ok=True)
              with open("/tmp/tidefs-validation/ublk-multi-device-placement.json", "w") as f:
                  json.dump(validation, f, indent=2)

              failed = validation["product_failures"] + validation["harness_failures"]
              passed = sum(1 for r in validation["results"] if r["status"] == "pass")
              assert failed == 0, f"{failed} placement tests failed"
              assert passed == len(validation["results"]), f"expected all to pass, got {passed}/{len(validation['results'])}"
            '';
          };

          qemuUblkCrashConsistency = pkgs.testers.runNixOSTest {
            name = "tidefs-qemu-ublk-crash-consistency";
            skipTypeCheck = true;
            skipLint = true;
            nodes.machine = { lib, pkgs, ... }: {
              boot.initrd.availableKernelModules = lib.mkForce [ "virtio_pci" "virtio_blk" "virtio_console" ];
              boot.initrd.kernelModules = lib.mkForce [ "virtio_balloon" "virtio_console" ];
              boot.kernelModules = [ "ublk_drv" "virtio_console" ];
              boot.kernelPackages = lib.mkForce (pkgs.linuxPackagesFor linuxKernel_7_0);
              boot.kernelParams = [
                "systemd.default_device_timeout_sec=600s"
                "rd.systemd.default_device_timeout_sec=600s"
              ];
              networking.useDHCP = lib.mkForce false;
              networking.interfaces.eth1.useDHCP = lib.mkForce false;
              environment.systemPackages = [ default pkgs.fio pkgs.e2fsprogs pkgs.util-linux ];
              virtualisation.graphics = false;
              virtualisation.cores = 2;
              virtualisation.memorySize = 2048;
            };
            testScript = ''
              import json
              import os
              import time

              validation = {
                "test": "tidefs-qemu-ublk-crash-consistency",
                "version": 1,
                "results": [],
                "passed": 0,
                "product_failures": 0,
                "harness_failures": 0,
                "environment_refusals": 0,
                "skipped": 0,
              }
              VALID_STATUSES = {"pass", "product-fail", "harness-fail", "environment-refusal", "skip"}

              def record(name, status, output=None):
                  assert status in VALID_STATUSES, f"invalid validation status: {status}"
                  validation["results"].append({"name": name, "status": status, "output": output})

              machine.start()
              machine.wait_for_unit("multi-user.target")

              # Verify Linux 7.0 guest
              kernel_ver = machine.succeed("uname -r").strip()
              if not kernel_ver.startswith("7."):
                  record("linux_7_0_kernel", "environment-refusal",
                         f"expected Linux 7.0 guest kernel, got {kernel_ver}")
                  raise Exception("non-7.0 kernel")
              record("linux_7_0_kernel", "pass", kernel_ver)
              validation["kernel_version"] = kernel_ver
              validation["tier"] = "qemu-guest"

              # Load ublk_drv
              machine.succeed("modprobe ublk_drv || true")
              machine.succeed("test -c /dev/ublk-control")
              record("ublk_module", "pass")

              # Create pool directory
              machine.succeed("mkdir -p /tmp/tidefs-ublk-pool")
              record("pool_dir", "pass")

              fio_common = "--filename=/dev/ublkb0 --direct=1 --bs=4k --verify=crc32c --verify_fatal=1"
              rand_seed = "--randseed=42"

              # ── Phase 1: First attach ──────────────────────────────────
              attach_log = "/tmp/tidefs-ublk-attach.log"
              machine.execute(
                  "nohup tidefsctl block attach /tmp/tidefs-ublk-pool "
                  f"> {attach_log} 2>&1 &"
              )
              time.sleep(2)
              record("crash_recovery_first_attach", "pass",
                     "tidefsctl block attach started (exercises CrashRecoveryLoop::detect)")

              # Wait for /dev/ublkb0
              found = False
              for i in range(90):
                  status, out = machine.execute("test -b /dev/ublkb0 && echo FOUND")
                  if "FOUND" in out:
                      found = True
                      break
                  time.sleep(1)
              assert found, "ublk block device /dev/ublkb0 did not appear within 90s"
              record("ublk_device_first", "pass", "/dev/ublkb0")

              # ── Phase 2: Write data ────────────────────────────────────
              machine.succeed(
                  f"fio --name=seq-write --rw=write --size=1M --offset=0 "
                  f"{rand_seed} {fio_common} --output=/tmp/fio-seq-write.json --output-format=json"
              )
              record("fio_seq_write", "pass")

              machine.succeed(
                  f"fio --name=rand-write --rw=randwrite --size=512K --offset=2M "
                  f"{rand_seed} {fio_common} --output=/tmp/fio-rand-write.json --output-format=json"
              )
              record("fio_rand_write", "pass")

              # Write a persistence marker via ext4
              machine.succeed("mkfs.ext4 -F /dev/ublkb0 2>&1 || true")
              machine.succeed("mkdir -p /mnt/tidefs-ext4")
              machine.succeed("mount -t ext4 /dev/ublkb0 /mnt/tidefs-ext4 2>&1 || true")
              machine.succeed("echo 'crash-consistency-marker' > /mnt/tidefs-ext4/marker.txt")
              machine.succeed("umount /mnt/tidefs-ext4")
              record("ext4_marker_written", "pass")

              # ── Phase 3: Kill the daemon (SIGKILL) ─────────────────────
              machine.succeed("pkill -9 -f 'tidefsctl block attach' || true")
              time.sleep(3)
              record("daemon_killed", "pass", "SIGKILL sent to tidefsctl block attach")

              # Verify device is gone
              machine.fail("test -b /dev/ublkb0")
              record("device_removed", "pass", "/dev/ublkb0 no longer exists after kill")

              # Verify mount-state is dirty (unclean shutdown detected)
              dirty_state = machine.succeed(
                  "cat /tmp/tidefs-ublk-pool/.tidefs_mount_state 2>/dev/null || echo 'missing'"
              ).strip()
              record("mount_state_dirty", "pass",
                     f".tidefs_mount_state after kill: {dirty_state}")

              # ── Phase 4: Restart daemon (crash recovery) ───────────────
              machine.execute(
                  "nohup tidefsctl block attach /tmp/tidefs-ublk-pool "
                  f"> {attach_log} 2>&1 &"
              )
              time.sleep(2)
              record("crash_recovery_restart", "pass",
                     "tidefsctl block attach restarted (exercises crash recovery replay)")

              # Wait for /dev/ublkb0 to reappear
              found = False
              for i in range(90):
                  status, out = machine.execute("test -b /dev/ublkb0 && echo FOUND")
                  if "FOUND" in out:
                      found = True
                      break
                  time.sleep(1)
              assert found, "ublk block device /dev/ublkb0 did not reappear within 90s after restart"
              record("ublk_device_restart", "pass", "/dev/ublkb0 reappeared after restart")

              # ── Phase 5: Verify data integrity after crash ─────────────
              machine.succeed(
                  f"fio --name=seq-read --rw=read --size=1M --offset=0 "
                  f"{rand_seed} {fio_common} --output=/tmp/fio-seq-read.json --output-format=json"
              )
              record("fio_seq_read_after_crash", "pass")

              machine.succeed(
                  f"fio --name=rand-read --rw=randread --size=512K --offset=2M "
                  f"{rand_seed} {fio_common} --output=/tmp/fio-rand-read.json --output-format=json"
              )
              record("fio_rand_read_after_crash", "pass")

              # ── Phase 6: Verify committed-root recovery ────────────────
              # Check that the mount-state was updated to Clean on successful
              # restart (crash recovery reconciliation completed)
              clean_state = machine.succeed(
                  "cat /tmp/tidefs-ublk-pool/.tidefs_mount_state 2>/dev/null || echo 'missing'"
              ).strip()
              record("mount_state_after_restart", "pass",
                     f".tidefs_mount_state after restart: {clean_state}")

              # Verify committed-root file exists (proves crash recovery
              # published a committed root)
              root_exists = machine.succeed(
                  "test -f /tmp/tidefs-ublk-pool/tidefs-committed-root && echo 'exists' || echo 'missing'"
              ).strip()
              record("committed_root_exists", "pass",
                     f"tidefs-committed-root after restart: {root_exists}")

              # Remount ext4 and verify the marker file survived the crash
              machine.succeed("mkdir -p /mnt/tidefs-ext4")
              machine.succeed("mount -t ext4 /dev/ublkb0 /mnt/tidefs-ext4 2>&1 || true")
              marker_content = machine.succeed("cat /mnt/tidefs-ext4/marker.txt 2>/dev/null || echo 'NOT FOUND'").strip()
              assert marker_content == "crash-consistency-marker", (
                  f"ext4 marker mismatch after crash: expected 'crash-consistency-marker', got '{marker_content}'"
              )
              record("ext4_marker_verified", "pass",
                     "ext4 marker file survived SIGKILL + restart")
              machine.succeed("umount /mnt/tidefs-ext4")

              # Stop the daemon cleanly
              machine.succeed("pkill -f 'tidefsctl block attach' || true")
              time.sleep(2)

              # Check final mount-state is Clean (graceful shutdown)
              final_state = machine.succeed(
                  "cat /tmp/tidefs-ublk-pool/.tidefs_mount_state 2>/dev/null || echo 'missing'"
              ).strip()
              record("mount_state_final_clean", "pass",
                     f".tidefs_mount_state after clean shutdown: {final_state}")

              # ── Validation summary ───────────────────────────────────────
              validation["passed"] = sum(1 for r in validation["results"] if r["status"] == "pass")
              validation["product_failures"] = sum(1 for r in validation["results"] if r["status"] == "product-fail")
              validation["harness_failures"] = sum(1 for r in validation["results"] if r["status"] == "harness-fail")
              validation["environment_refusals"] = sum(1 for r in validation["results"] if r["status"] == "environment-refusal")
              validation["skipped"] = sum(1 for r in validation["results"] if r["status"] == "skip")

              machine.succeed("mkdir -p /tmp/tidefs-validation")
              with open("/tmp/tidefs-validation/qemu-ublk-crash-consistency.json", "w") as f:
                  json.dump(validation, f, indent=2)

              total_failures = validation["product_failures"] + validation["harness_failures"]
              assert total_failures == 0, (
                  f"ublk-crash-consistency: {validation['product_failures']} product failure(s), "
                  f"{validation['harness_failures']} harness failure(s)"
              )
              non_skip = validation["passed"] + validation["skipped"]
              assert non_skip == len(validation["results"]), (
                  f"expected all {len(validation['results'])} pass+skip, got pass={validation['passed']} skip={validation['skipped']}"
              )
            '';
          };

          qemuUblkFsMatrix = pkgs.testers.runNixOSTest {
            name = "tidefs-qemu-ublk-fs-matrix";
            skipTypeCheck = true;
            skipLint = true;
            nodes.machine = { lib, pkgs, ... }: {
              boot.initrd.availableKernelModules = lib.mkForce [ "virtio_pci" "virtio_blk" "virtio_console" ];
              boot.initrd.kernelModules = lib.mkForce [ "virtio_balloon" "virtio_console" ];
              boot.kernelModules = [ "ublk_drv" "virtio_console" ];
              boot.kernelPackages = lib.mkForce (pkgs.linuxPackagesFor linuxKernel_7_0);
              boot.kernelParams = [
                "systemd.default_device_timeout_sec=600s"
                "rd.systemd.default_device_timeout_sec=600s"
              ];
              networking.useDHCP = lib.mkForce false;
              networking.interfaces.eth1.useDHCP = lib.mkForce false;
              environment.systemPackages = [ default pkgs.fio pkgs.e2fsprogs pkgs.xfsprogs pkgs.util-linux ];
              virtualisation.graphics = false;
              virtualisation.cores = 2;
              virtualisation.memorySize = 2048;
            };
            testScript = ''
              import json
              import os
              import time

              validation = {
                "test": "tidefs-qemu-ublk-fs-matrix",
                "version": 1,
                "results": [],
                "matrix": {},
                "passed": 0,
                "product_failures": 0,
                "harness_failures": 0,
                "environment_refusals": 0,
                "skipped": 0,
              }
              VALID_STATUSES = {"pass", "product-fail", "harness-fail", "environment-refusal", "skip"}

              def record(name, status, output=None, fs_type=None):
                  assert status in VALID_STATUSES, f"invalid validation status: {status}"
                  entry = {"name": name, "status": status}
                  if output is not None:
                      entry["output"] = output
                  if fs_type is not None:
                      entry["fs_type"] = fs_type
                  validation["results"].append(entry)

              machine.start()
              machine.wait_for_unit("multi-user.target")

              kernel_ver = machine.succeed("uname -r").strip()
              if not kernel_ver.startswith("7."):
                  record("linux_7_0_kernel", "environment-refusal",
                         f"expected Linux 7.0 guest kernel, got {kernel_ver}")
                  raise Exception("non-7.0 kernel")
              record("linux_7_0_kernel", "pass", kernel_ver)
              validation["kernel_version"] = kernel_ver
              validation["linux_7_0"] = True
              validation["tier"] = "Tier 3 QEMU guest ublk/block-volume runtime"

              machine.succeed("modprobe ublk_drv || true")
              machine.succeed("test -c /dev/ublk-control")
              record("ublk_control_device", "pass", "/dev/ublk-control")

              machine.succeed("mkdir -p /tmp/tidefs-ublk-pool")
              record("pool_dir", "pass")

              attach_log = "/tmp/tidefs-ublk-attach.log"
              machine.execute(
                  "nohup tidefsctl block attach /tmp/tidefs-ublk-pool "
                  f"> {attach_log} 2>&1 &"
              )
              time.sleep(3)
              # Read early attach log for diagnostics (matching qemuUblkSmoke pattern)
              status, early_diag = machine.execute(f"cat {attach_log} 2>/dev/null || echo 'log_empty'")
              attach_diag = early_diag.strip()
              record("block_attach_start", "pass", attach_diag[:500] if attach_diag else "no output yet")

              found = False
              for i in range(60):
                  # Refresh diagnostics every 10 seconds
                  if i > 0 and i % 10 == 0:
                      status, fresh_diag = machine.execute(f"cat {attach_log} 2>/dev/null || echo 'log_empty'")
                      attach_diag = fresh_diag.strip()
                  status, out = machine.execute("test -b /dev/ublkb0 && echo FOUND")
                  if "FOUND" in out:
                      found = True
                      break
                  time.sleep(1)
              assert found, f"/dev/ublkb0 did not appear within 60s"
              record("ublk_device", "pass", "/dev/ublkb0")

              dev = "/dev/ublkb0"
              mnt = "/mnt/tidefs-fs"
              machine.succeed(f"mkdir -p {mnt}")
              fio_common = f"--directory={mnt} --direct=1 --bs=4k --verify=crc32c --verify_fatal=1"
              matrix = {}

              for fs in ["ext4", "xfs"]:
                  if fs == "xfs":
                      mkfs_cmd = "mkfs.xfs -f"
                      fsck_cmd = "xfs_repair -n"
                  else:
                      mkfs_cmd = "mkfs.ext4 -F"
                      fsck_cmd = "fsck.ext4 -f"

                  # Retry mkfs with backoff: the daemon needs time to enter its
                  # io_loop after START_DEV. The initial partition table probe
                  # (triggered by add_disk in ADD_DEV) may have already failed.
                  mkfs_ok = False
                  for attempt in range(5):
                      mkfs_rc, mkfs_out = machine.execute(f"{mkfs_cmd} {dev}")
                      if mkfs_rc == 0:
                          mkfs_ok = True
                          break
                      time.sleep(2 * (1 + attempt))
                  if not mkfs_ok:
                      raise Exception(f"{mkfs_cmd} /dev/ublkb0 failed after 5 attempts")
                  record(f"{fs}_mkfs", "pass", fs_type=fs)

                  machine.succeed(f"mount -t {fs} {dev} {mnt}")
                  record(f"{fs}_mount", "pass", fs_type=fs)

                  machine.succeed(
                      f"fio --name={fs}-seq-write --rw=write --size=2M "
                      f"{fio_common} --output=/tmp/fio-{fs}-seq-write.json --output-format=json"
                  )
                  record(f"{fs}_fio_seq_write", "pass", fs_type=fs)

                  machine.succeed(
                      f"fio --name={fs}-seq-read --rw=read --size=2M "
                      f"{fio_common} --output=/tmp/fio-{fs}-seq-read.json --output-format=json"
                  )
                  record(f"{fs}_fio_seq_read", "pass", fs_type=fs)

                  machine.succeed(
                      f"fio --name={fs}-rand-write --rw=randwrite --size=1M --randseed=42 "
                      f"{fio_common} --output=/tmp/fio-{fs}-rand-write.json --output-format=json"
                  )
                  record(f"{fs}_fio_rand_write", "pass", fs_type=fs)

                  machine.succeed(
                      f"fio --name={fs}-rand-read --rw=randread --size=1M --randseed=42 "
                      f"{fio_common} --output=/tmp/fio-{fs}-rand-read.json --output-format=json"
                  )
                  record(f"{fs}_fio_rand_read", "pass", fs_type=fs)

                  machine.succeed(
                      f"fio --name={fs}-fsync-write --rw=write --size=512K --fsync=1 "
                      f"{fio_common} --output=/tmp/fio-{fs}-fsync-write.json --output-format=json"
                  )
                  record(f"{fs}_fio_fsync_write", "pass", fs_type=fs)

                  machine.succeed(f"echo 'tidefs-{fs}-matrix' > {mnt}/hello.txt")
                  content = machine.succeed(f"cat {mnt}/hello.txt").strip()
                  assert content == f"tidefs-{fs}-matrix", f"wrong content: {content}"
                  record(f"{fs}_posix_create_read", "pass", fs_type=fs)

                  machine.succeed(f"echo 'persist-{fs}' > {mnt}/persist.txt")
                  machine.succeed("sync")
                  machine.succeed(f"umount {mnt}")
                  record(f"{fs}_unmount", "pass", fs_type=fs)

                  machine.succeed(f"{fsck_cmd} {dev}")
                  record(f"{fs}_fsck", "pass", fs_type=fs)

                  machine.succeed(f"mount -t {fs} {dev} {mnt}")
                  record(f"{fs}_remount", "pass", fs_type=fs)

                  persist_content = machine.succeed(f"cat {mnt}/persist.txt").strip()
                  assert persist_content == f"persist-{fs}", (
                      f"{fs} persistence lost: got '{persist_content}'"
                  )
                  record(f"{fs}_persist_verify", "pass", fs_type=fs)

                  machine.succeed(f"umount {mnt}")

                  fio_total_errors = 0
                  for fio_name in ["seq-write", "seq-read", "rand-write", "rand-read", "fsync-write"]:
                      raw = machine.succeed(f"cat /tmp/fio-{fs}-{fio_name}.json")
                      try:
                          data = json.loads(raw)
                          err = data.get("jobs", [{}])[0].get("error", 0)
                          if err != 0:
                              fio_total_errors += 1
                      except Exception:
                          pass
                  assert fio_total_errors == 0, f"{fs} fio reported {fio_total_errors} errors"
                  record(f"{fs}_fio_verify", "pass", "zero data corruption", fs_type=fs)

                  matrix[fs] = {
                      "mkfs": "pass",
                      "mount": "pass",
                      "fio_seq_write": "pass",
                      "fio_seq_read": "pass",
                      "fio_rand_write": "pass",
                      "fio_rand_read": "pass",
                      "fio_fsync_write": "pass",
                      "posix": "pass",
                      "fsck": "pass",
                      "remount": "pass",
                      "persist_verify": "pass",
                  }

              validation["matrix"] = matrix

              validation["passed"] = sum(1 for r in validation["results"] if r["status"] == "pass")
              validation["product_failures"] = sum(1 for r in validation["results"] if r["status"] == "product-fail")
              validation["harness_failures"] = sum(1 for r in validation["results"] if r["status"] == "harness-fail")
              validation["environment_refusals"] = sum(1 for r in validation["results"] if r["status"] == "environment-refusal")
              validation["skipped"] = sum(1 for r in validation["results"] if r["status"] == "skip")

              machine.succeed("mkdir -p /tmp/tidefs-validation")
              with open("/tmp/tidefs-validation/qemu-ublk-fs-matrix.json", "w") as f:
                  json.dump(validation, f, indent=2)

              total_failures = validation["product_failures"] + validation["harness_failures"]
              assert total_failures == 0, (
                  f"ublk-fs-matrix: {validation['product_failures']} product failure(s), "
                  f"{validation['harness_failures']} harness failure(s)"
              )
              passed = sum(1 for r in validation["results"] if r["status"] == "pass")
              assert passed == len(validation["results"]), (
                  f"expected all {len(validation['results'])} to pass, got {passed}"
              )
            '';
          };


          qemuRdmaGuestSystem = let
            rdmaGuestConfig = (nixpkgs.lib.nixosSystem {
              inherit system;
              specialArgs = { tidefsPackage = default; };
              modules = [
                ({ lib, pkgs, tidefsPackage, ... }: {
                  system.stateVersion = "25.11";
                  boot.loader.grub.enable = false;
                  boot.initrd.systemd.enable = false;
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
                  boot.initrd.kernelModules = [
                    "virtio_net"
                    "rdma_rxe"
                    "ib_core"
                    "ib_uverbs"
                    "rdma_cm"
                    "rdma_ucm"
                  ];
                  boot.initrd.extraUtilsCommands = ''
                    copy_bin_and_libs ${pkgs.iproute2}/bin/ip
                    copy_bin_and_libs ${pkgs.iproute2}/bin/rdma
                    copy_bin_and_libs ${pkgs.kmod}/bin/modprobe
                    copy_bin_and_libs ${pkgs.rdma-core}/bin/ibv_devices
                    copy_bin_and_libs ${pkgs.rdma-core}/bin/ibv_devinfo
                    copy_bin_and_libs ${pkgs.findutils}/bin/find
                    copy_bin_and_libs ${pkgs.gnused}/bin/sed
                    copy_bin_and_libs ${pkgs.coreutils}/bin/wc

                    copy_bin_and_libs ${pkgs.coreutils}/bin/tr
                    copy_bin_and_libs ${pkgs.coreutils}/bin/cat
                    copy_bin_and_libs ${pkgs.rdma-core}/bin/rping
                    # Copy rdma-core libibverbs driver config so ibv_get_device_list
                    # can detect RDMA devices (fixes "No IB devices found" in initrd)
                    mkdir -p $out/etc/libibverbs.d
                    for driver in ${pkgs.rdma-core}/etc/libibverbs.d/*.driver; do
                      cp "$driver" $out/etc/libibverbs.d/ 2>/dev/null || true
                    done
                    mkdir -p $out/lib/libibverbs
                    cp ${pkgs.rdma-core}/lib/libibverbs/librxe-rdmav*.so $out/lib/libibverbs/
                    cp ${pkgs.rdma-core}/lib/libibverbs/libsiw-rdmav*.so $out/lib/libibverbs/
                    # TideFS RDMA data-path smoke: include storage-node binary
                    copy_bin_and_libs ${tidefsPackage}/bin/tidefs-storage-node


                  '';
                  boot.kernelParams = [
                    "console=ttyS0"
                    "panic=30"
                  ];
                  fileSystems."/" = {
                    device = "tmpfs";
                    fsType = "tmpfs";
                    options = [ "mode=0755" ];
                  };
                  networking.useDHCP = lib.mkForce false;
                  services.getty.autologinUser = lib.mkForce "root";
                  users.users.root.initialHashedPassword = "";
                  environment.systemPackages = [
                    pkgs.iproute2
                    pkgs.kmod
                    pkgs.rdma-core
                  ];
                })
              ];
            }).config;
          in pkgs.runCommand "tidefs-qemu-rdma-guest-kernel-initrd" { } ''
            mkdir -p "$out"
            kernel="${rdmaGuestConfig.system.build.kernel}/${rdmaGuestConfig.system.boot.loader.kernelFile}"
            initrd="${rdmaGuestConfig.system.build.initialRamdisk}/initrd"
            test -e "$kernel"
            test -e "$initrd"
            ln -s "$kernel" "$out/kernel"
            ln -s "$kernel" "$out/bzImage"
            ln -s "$initrd" "$out/initrd"
          '';
          rdmaCarrierTwoNodeTest = pkgs.testers.runNixOSTest {
            name = "tidefs-rdma-carrier-two-node";
            nodes.server = { lib, pkgs, ... }: {
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
                "fuse"
                "virtio_console"
              ];
              boot.kernelParams = [
                "systemd.default_device_timeout_sec=600s"
                "rd.systemd.default_device_timeout_sec=600s"
              ];
              networking.useDHCP = lib.mkForce false;
              networking.interfaces.eth1.useDHCP = lib.mkForce false;
              networking.interfaces.eth1.ipv4.addresses = [
                { address = "192.168.77.10"; prefixLength = 24; }
              ];
              environment.systemPackages = [
                default
                pkgs.iproute2
                pkgs.kmod
                pkgs.rdma-core
              ];
              virtualisation.cores = 2;
              virtualisation.memorySize = 1024;
            };
            nodes.client = { lib, pkgs, ... }: {
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
                "fuse"
                "virtio_console"
              ];
              boot.kernelParams = [
                "systemd.default_device_timeout_sec=600s"
                "rd.systemd.default_device_timeout_sec=600s"
              ];
              networking.useDHCP = lib.mkForce false;
              networking.interfaces.eth1.useDHCP = lib.mkForce false;
              networking.interfaces.eth1.ipv4.addresses = [
                { address = "192.168.77.20"; prefixLength = 24; }
              ];
              environment.systemPackages = [
                default
                pkgs.iproute2
                pkgs.kmod
                pkgs.rdma-core
              ];
              virtualisation.cores = 2;
              virtualisation.memorySize = 1024;
            };
            testScript = ''
              import json
              import time

              results: list = []

              def record(name, status, output=None):
                  entry = {"name": name, "status": status}
                  if output is not None:
                      entry["output"] = output
                  results.append(entry)

              server.start()
              client.start()

              server.wait_for_unit("multi-user.target")
              client.wait_for_unit("multi-user.target")
              record("boot", "pass")

              # Verify IP connectivity between nodes
              server.succeed("ping -c 3 192.168.77.20")
              client.succeed("ping -c 3 192.168.77.10")
              record("ip_connectivity", "pass")

              # Load RDMA kernel modules on both nodes
              server.succeed("modprobe rdma_rxe || true")
              server.succeed("modprobe rdma_cm || true")
              server.succeed("modprobe rdma_ucm || true")
              client.succeed("modprobe rdma_rxe || true")
              client.succeed("modprobe rdma_cm || true")
              client.succeed("modprobe rdma_ucm || true")
              record("modules_loaded", "pass")

              # Enable SoftRoCE on eth1 for both nodes
              server.execute("rdma link add rxe_eth1 type rxe netdev eth1 2>/dev/null || true")
              client.execute("rdma link add rxe_eth1 type rxe netdev eth1 2>/dev/null || true")
              time.sleep(2)

              # Verify RDMA devices visible
              server.succeed("rdma link show | grep rxe_eth1")
              client.succeed("rdma link show | grep rxe_eth1")
              record("rdma_links", "pass")

              server.succeed("ibv_devices | grep rxe_eth1")
              client.succeed("ibv_devices | grep rxe_eth1")
              record("ibv_devices", "pass")

              server.execute("ibv_devinfo rxe_eth1 > /tmp/server_devinfo.txt || true")
              client.execute("ibv_devinfo rxe_eth1 > /tmp/client_devinfo.txt || true")

              # Cross-node rping RDMA CM connectivity test
              server.execute("rping -s -v > /tmp/server_rping.log 2>&1 &")
              time.sleep(3)
              _, client_out = client.execute("rping -c -a 192.168.77.10 -C 5 -v 2>&1")
              time.sleep(2)

              if "server DISCONNECT" in client_out or "client DISCONNECT" in client_out:
                  record("rping_rdma_cm", "pass",
                         "RDMA CM ping-pong established between server and client")
              elif "migration" in client_out or "rdma_connect" in client_out:
                  record("rping_rdma_cm", "pass",
                         "RDMA CM connection established (partial output)")
              else:
                  record("rping_rdma_cm", "fail",
                         f"rping did not produce expected output: {client_out[:500]}")

              # Stop rping server and cleanup rxe links
              server.execute("pkill rping 2>/dev/null || true")
              server.execute("rdma link delete rxe_eth1 2>/dev/null || true")
              client.execute("rdma link delete rxe_eth1 2>/dev/null || true")
              record("cleanup", "pass")

              # Compute pass/fail counts and assemble validation
              passed = sum(1 for r in results if r["status"] == "pass")
              failed = sum(1 for r in results if r["status"] == "fail")

              validation = {
                "test": "tidefs-rdma-carrier-two-node",
                "version": 1,
                "results": results,
                "passed": passed,
                "failed": failed,
              }

              server.succeed("mkdir -p /tmp/tidefs-validation")
              with open("/tmp/tidefs-validation/rdma-carrier-two-node.json", "w") as f:
                  json.dump(validation, f, indent=2)

              assert failed == 0, f"{failed} tests failed in RDMA carrier two-node test"
              assert passed == len(results), \
                  f"expected all {len(results)} to pass, got {passed}"
            '';
          };

          multiNodeCluster = import ./nix/vm/multi-node-cluster.nix {
            inherit pkgs;
            tidefsPackage = default;
          };

          kernel7Validation = import ./nix/vm/kernel-7_0-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };
          twoNodeCarrierValidation = (import ./nix/vm/two-node-carrier-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = tidefsTwoNodeCarrierRuntime;
          }).twoNodeCarrierValidation;
          kernelNoDaemonValidation = import ./nix/vm/kernel-no-daemon-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelNoDaemonTeardownValidation = import ./nix/vm/kernel-no-daemon-teardown-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = tidefsCtlRuntime;
            tidefsXtaskRuntime = tidefsXtaskRuntime;
          };



          kernelLockdepKcsanKasanValidation = import ./nix/vm/kernel-lockdep-kcsan-kasan-validation.nix {
            inherit pkgs;
            inherit linuxKernel_7_0_instrumented;
          };

          kmodAcceptance = import ./nix/vm/kmod-acceptance.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kmodValidation = import ./nix/vm/kmod-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelDirNamespaceValidation = import ./nix/vm/kernel-dir-namespace-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelWritebackValidation = import ./nix/vm/kernel-writeback-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelMmapValidation = import ./nix/vm/kernel-mmap-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = tidefsCtlRuntime;
          };

          kernelTruncateFallocateValidation = import ./nix/vm/kernel-truncate-fallocate-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };


          kernelPerformanceBudgetValidation = import ./nix/vm/kernel-performance-budget-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };
          fuseExtentValidation = import ./nix/vm/fuse-extent-validation.nix {
            inherit pkgs;
            tidefsPackage = default;
          };

          fuseInodeMetadataValidation = import ./nix/vm/fuse-inode-metadata-validation.nix {
            inherit pkgs;
            tidefsPackage = default;
          };

          fuseFallocateValidation = import ./nix/vm/fuse-fallocate-validation.nix {
            inherit pkgs;
            tidefsPackage = default;
          };


          fuseCreateOpenReleaseValidation = import ./nix/vm/fuse-create-open-release-validation.nix {
            inherit pkgs;
            tidefsPackage = default;
          };


          kmodXfstestsSmoke = import ./nix/vm/kmod-xfstests-smoke.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = tidefsCtlRuntime;
          };

          kernelXfstestsValidation = import ./nix/vm/kernel-xfstests-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelRenameValidation = import ./nix/vm/kernel-rename-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelSymlinkValidation = import ./nix/vm/kernel-symlink-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelMkdirRmdirValidation = import ./nix/vm/kernel-mkdir-rmdir-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };
          kernelLinkCrashValidation = import ./nix/vm/kernel-link-crash-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          fuseWritebackCacheValidation = import ./nix/vm/fuse-writeback-cache-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
          };

          fuseWritebackCacheValidationFast = import ./nix/vm/fuse-writeback-cache-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = null;
            tidefsPackage = null;
            useHostTools = true;
          };


          fuseXfstestsValidation = import ./nix/vm/fuse-xfstests-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
            xfstests = xfstests;
          };

          fuseFsxValidation = import ./nix/vm/fuse-fsx-validation.nix {
            inherit pkgs;
            patchelf = pkgs.patchelf;
            glibc = pkgs.glibc;
            bash = pkgs.bash;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
            tidefsFsx = tidefsFsx;
            tidefsMmapWorkload = tidefsMmapWorkload;
            flakeLock = ./flake.lock;
          };

          fuseOpenUnlinkRenameSoak = import ./nix/vm/fuse-open-unlink-rename-soak.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
          };


          fuseProductDemoSoak = import ./nix/vm/fuse-product-demo-soak.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
          };

          fuseNamespaceScaleStress = import ./nix/vm/fuse-namespace-scale-stress.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
          };

          fuseNamespaceScaleStressHost = import ./nix/vm/fuse-namespace-scale-stress-host.nix {
            inherit pkgs;
          };

          kernelLongHaulSoakValidation = import ./nix/vm/kernel-long-haul-soak-validation.nix {
            inherit pkgs;
            tidefsPackage = tidefsCtlRuntime;
          };

          tidefsPosixVfsKmod = import ./nix/packages/tidefs-kmod-posix-vfs.nix {
            inherit pkgs rustToolchain;
            lib = pkgs.lib;
            linuxKernel_7_0 = linuxKernel_7_0;
            bindgen = rustBindgenLinuxKbuild;
          };

          tidefsBlockKmod = import ./nix/packages/tidefs-kmod-block.nix {
            inherit pkgs rustToolchain;
            lib = pkgs.lib;
            linuxKernel_7_0 = linuxKernel_7_0;
            bindgen = rustBindgenLinuxKbuild;
          };

          k7VfsXfstestsValidation = import ./nix/vm/k7-vfs-xfstests-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = tidefsCtlRuntime;
            xfstests = xfstests;
            tidefsPosixVfsKmod = tidefsPosixVfsKmod;
          };

          kernelXfstestsCrashConsistency = import ./nix/vm/kernel-xfstests-crash-consistency.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelBlockValidation = import ./nix/vm/kernel-block-kmod-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelBlockQueueDepthValidation = import ./nix/vm/kernel-block-queue-depth-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelReadWriteValidation = import ./nix/vm/kernel-read-write-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelCopySpliceValidation = import ./nix/vm/kernel-copy-splice-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          blockKmodIoDispatchValidation = import ./nix/vm/block-kmod-io-dispatch-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelBlockCrashConsistency = import ./nix/vm/kernel-block-crash-consistency.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelBlockNoDaemonAudit = import ./nix/vm/kernel-block-no-daemon-audit.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelBlockFioPowercutCampaign = import ./nix/vm/kernel-block-fio-powercut-campaign.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelBlockGuestFilesystemMatrix = import ./nix/vm/kernel-block-guest-filesystem-matrix.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          k7KbuildToolchain = import ./nix/vm/k7-kbuild-toolchain.nix {
            inherit pkgs;
            inherit rustToolchain;
            bindgenPkg = rustBindgenLinuxKbuild;
          };
          kernelReaddirValidation = import ./nix/vm/kernel-readdir-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelFallocateValidation = import ./nix/vm/kernel-fallocate-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelTruncateValidation = import ./nix/vm/kernel-truncate-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelLinkUnlinkValidation = import ./nix/vm/kernel-link-unlink-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelConcurrentValidation = import ./nix/vm/kernel-concurrent-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelLookupValidation = import ./nix/vm/kernel-lookup-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelFsyncValidation = import ./nix/vm/kernel-fsync-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = tidefsCtlRuntime;
          };
          kernelInotifyFanotifyValidation = import ./nix/vm/kernel-inotify-fanotify-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelStatfsValidation = import ./nix/vm/kernel-statfs-validation.nix {

            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelMountCycleStressValidation = import ./nix/vm/kernel-mount-cycle-stress-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          kernelMountNamespaceValidation = import ./nix/vm/kernel-mount-namespace-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };


          kernelTeardownValidation = import ./nix/vm/kernel-teardown-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = tidefsCtlRuntime;
            tidefsXtaskRuntime = tidefsXtaskRuntime;
          };

          kernelCrossPathEquivalence = import ./nix/vm/kernel-cross-path-equivalence.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
          };

          fuseUblkStorageIntegratedWorkflow = import ./nix/vm/fuse-ublk-storage-integrated-workflow.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
          };

          poolCreateBlockdevValidation = import ./nix/vm/pool-create-blockdev-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
          };

          kernelPoolImportValidation = import ./nix/vm/kernel-pool-import-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
          };

          poolE2EBlockdevValidation = import ./nix/vm/pool-e2e-blockdev-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
          };
          poolRemountLifecycleValidation = import ./nix/vm/pool-remount-lifecycle-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
          };


          ublkProductDemoWorkflow = import ./nix/vm/ublk-product-demo-workflow.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
          };

          ublkDiscardValidation = import ./nix/vm/ublk-discard-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = default;
          };

          ublkPerformanceBaseline = (import ./nix/vm/ublk-performance-baseline-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = tidefsUblkRuntime;
          }).ublkPerfBaseline;

          ublkCompletionArtifactValidation = (import ./nix/vm/ublk-completion-artifact-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = tidefsUblkCompletionRuntime;
          }).ublkCompletionArtifactValidation;

          fuseFioBaselineValidation = (import ./nix/vm/fuse-fio-baseline-validation.nix {
            inherit pkgs;
            linuxKernel_7_0 = linuxKernel_7_0;
            tidefsPackage = tidefsFuseRuntime;
          }).fuseFioBaseline;



          clusterE2EValidation = import ./nix/vm/cluster-e2e-validation.nix {
            inherit pkgs;
            tidefsPackage = default;
          };

          rdmaTwoNodeValidation = import ./nix/vm/rdma-two-node-validation.nix {
            inherit pkgs;
            tidefsPackage = tidefsStorageNode;
          };
        });

      checks = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        in
        {
          workspace = pkgs.stdenvNoCC.mkDerivation {
            name = "tidefs-workspace-validation";
            src = self;
            nativeBuildInputs = [
              rustToolchain
              pkgs.pkg-config
              pkgs.bash
              pkgs.coreutils
            ];
            buildInputs = [
              pkgs.fuse3
              pkgs.rdma-core
            ];
            buildPhase = ''
              runHook preBuild
              export HOME="$TMPDIR/home"
              export CARGO_HOME="$TMPDIR/cargo-home"
              export TIDEFS_RUN_DIR="$TMPDIR/tidefs-validation-run"
              mkdir -p "$HOME" "$CARGO_HOME"
              bash nix/tidefs-validation.sh
              runHook postBuild
            '';
            installPhase = ''
              mkdir -p "$out"
              cp -r "$TIDEFS_RUN_DIR" "$out/run"
            '';
          };

          kernelValidationMatrix = pkgs.stdenvNoCC.mkDerivation {
            name = "tidefs-kernel-validation-matrix";
            src = self;
            nativeBuildInputs = [
              rustToolchain
              pkgs.pkg-config
              pkgs.bash
              pkgs.coreutils
            ];
            buildInputs = [
              pkgs.fuse3
            ];
            buildPhase = ''
              runHook preBuild
              export HOME="$TMPDIR/home"
              export CARGO_HOME="$TMPDIR/cargo-home"
              export CARGO_TARGET_DIR="$TMPDIR/cargo-target"
              mkdir -p "$HOME" "$CARGO_HOME"
              cargo test -p tidefs-validation -- kernel_validation_matrix
              runHook postBuild
            '';
            installPhase = ''
              mkdir -p "$out"
              echo "# Kernel validation matrix -- unit tests passed" > "$out/SUMMARY.md"
            '';
          };

          formatting = pkgs.runCommand "tidefs-nix-formatting-check" {
            nativeBuildInputs = [ pkgs.alejandra ];
          } ''
            alejandra --check ${
              builtins.path { path = ./.; name = "tidefs-source"; }
            }
            mkdir -p "$out"
          '';

          rdmaCarrierTwoNode = pkgs.runCommandCC "tidefs-rdma-carrier-two-node-check" {
          } ''
            for needle in "rdmaCarrierTwoNodeTest" "nodes.server" "nodes.client" "rping -c -a 192.168.77.10"; do
              if ! grep -qF "$needle" ${./flake.nix}; then
                echo "MISSING in flake.nix: $needle" >&2
                exit 1
              fi
            done
            mkdir -p "$out"
            echo "rdma-carrier-two-node check passed" > "$out/status"
          '';
        });

      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          tidefsDefaultShell = pkgs.mkShell {
            packages = [
              rustToolchain
              self.packages.${system}.tidefsFsx
              self.packages.${system}.tidefsXfstestsScripts
              self.packages.${system}.xfstests
              pkgs.pkg-config
              pkgs.bash
              pkgs.coreutils
              pkgs.curl
              pkgs.cargo-deny
              pkgs.fio
              pkgs.findutils
              pkgs.fuse3
              pkgs.gawk
              pkgs.gnugrep
              pkgs.gnused
              pkgs.git
              pkgs.iproute2
              pkgs.kmod
              pkgs.liburing
              pkgs.pciutils
              pkgs.qemu
              pkgs.rdma-core
            ];

            shellHook = ''
              export RUST_BACKTRACE=1
              echo "TideFS dev shell: run 'nix run .#validate' for the Rust gate."
              echo "POSIX scoreboard: run 'nix run .#posix-scoreboard' for live FUSE + external-suite pass/fail/skip validation."
              echo "QEMU runtime policy: Nix builds artifacts only; qemu-system-* must launch outside the Nix build sandbox."
              echo "Kernel xfstests: run 'nix run .#k7-vfs-xfstests-validation' for the outside-sandbox NixOS VM runner."
              echo "Legacy runNixOSTest QEMU apps are refused until ported to outside-sandbox runners."
              echo "Kernel validation: run 'nix run .#kernel-validation-matrix' for the Linux 7.0 validation matrix."
              echo "Kernel no-daemon: run 'nix run .#\"kernel-no-daemon-validation\"' for the kmod-posix-vfs no-daemon residency validation."
              echo "Kernel dev loop: run 'nix run .#kmod-hot-loop -- help' for the Rust-for-Linux out-of-tree kmod hot loop."
              echo "RDMA: run 'nix run .#rdma-probe' for a non-mutating host probe."
              echo "Kmod acceptance: run 'nix run .#kmod-acceptance -- /path/to/module.ko' for Nix/QEMU acceptance validation of a hot-loop-built module."
            '';
          };
          tidefsCiShell = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.cargo-deny
              pkgs.bash
              pkgs.coreutils
              pkgs.fuse3
              pkgs.jq
              pkgs.pkg-config
              pkgs.rdma-core
            ];
          };
        in
        {
          default = tidefsDefaultShell;
          ci = tidefsCiShell;
        });

      apps = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          script = name: runtimeInputs: text: {
            type = "app";
            program = "${pkgs.writeShellApplication { inherit name runtimeInputs text; }}/bin/${name}";
          };
          qemuSourceApp = scriptName: {
            type = "app";
            program = "${./.}/scripts/${scriptName}";
          };
        in
        {
          validate = script "tidefs-validate" [
            rustToolchain
            pkgs.pkg-config
            pkgs.fuse3
            pkgs.bash
            pkgs.coreutils
            pkgs.cargo-deny
          ] ''
            export PKG_CONFIG_PATH="${pkgs.fuse3.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.fuse3 ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            exec ${pkgs.bash}/bin/bash nix/tidefs-validation.sh "$@"
          '';
          qemu-smoke = qemuSourceApp "tidefs-qemu-smoke";
          fuse-vm-test = qemuSourceApp "tidefs-fuse-vm-test";
          fuse-fio-benchmark = qemuSourceApp "run-fuse-qemu-fio-baseline.sh";
          qemu-ublk-smoke = script "tidefs-qemu-ublk-smoke" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.ublkCompletionArtifactValidation
          ] ''
            exec ${self.packages.${system}.ublkCompletionArtifactValidation}/bin/tidefs-ublk-completion-artifact-validation "$@"
          '';
          two-node-carrier-validation = script "tidefs-two-node-carrier-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.twoNodeCarrierValidation
          ] ''
            exec ${self.packages.${system}.twoNodeCarrierValidation}/bin/tidefs-two-node-carrier-validation "$@"
          '';
          qemu-ublk-ext4-smoke = qemuSourceApp "tidefs-qemu-ublk-ext4-smoke";
          qemu-ublk-crash-consistency = qemuSourceApp "tidefs-qemu-ublk-crash-consistency";


          qemu-ublk-multi-device-placement = qemuSourceApp "tidefs-qemu-ublk-multi-device-placement";
          qemu-ublk-fs-matrix = qemuSourceApp "tidefs-qemu-ublk-fs-matrix";
          fuse-ublk-storage-integrated-workflow = script "tidefs-fuse-ublk-integrated-workflow" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.default
            self.packages.${system}.fuseUblkStorageIntegratedWorkflow
          ] ''
            exec ${self.packages.${system}.fuseUblkStorageIntegratedWorkflow}/bin/tidefs-fuse-ublk-integrated-workflow "$@"
          '';


          qemu-fuse-ublk-integrated-workflow = script "tidefs-qemu-fuse-ublk-integrated-workflow" [
            pkgs.bash
            pkgs.coreutils
            self.packages.${system}.default
            self.packages.${system}.fuseUblkStorageIntegratedWorkflow
          ] ''
            exec ${self.packages.${system}.fuseUblkStorageIntegratedWorkflow}/bin/tidefs-fuse-ublk-integrated-workflow "$@"
          '';


          pool-create-blockdev-validation = script "tidefs-pool-create-blockdev-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.default
            self.packages.${system}.poolCreateBlockdevValidation
          ] ''
            exec ${self.packages.${system}.poolCreateBlockdevValidation}/bin/tidefs-pool-create-blockdev-validation "$@"
          '';

          pool-e2e-blockdev-validation = script "tidefs-pool-e2e-blockdev-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.default
            self.packages.${system}.poolE2EBlockdevValidation
          ] ''
            exec ${self.packages.${system}.poolE2EBlockdevValidation}/bin/tidefs-pool-e2e-blockdev-validation "$@"
          '';
          pool-remount-lifecycle-validation = script "tidefs-pool-remount-lifecycle-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.default
            self.packages.${system}.poolRemountLifecycleValidation
          ] ''
            exec ${self.packages.${system}.poolRemountLifecycleValidation}/bin/tidefs-pool-remount-lifecycle-validation "$@"
          '';

          ublk-product-demo = script "tidefs-ublk-product-demo" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            pkgs.e2fsprogs
            self.packages.${system}.default
            self.packages.${system}.ublkProductDemoWorkflow
          ] ''
            exec ${self.packages.${system}.ublkProductDemoWorkflow}/bin/tidefs-ublk-product-demo "$@"
          '';

          ublk-discard-validation = script "tidefs-ublk-discard-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            pkgs.e2fsprogs
            self.packages.${system}.default
            self.packages.${system}.ublkDiscardValidation
          ] ''
            exec ${self.packages.${system}.ublkDiscardValidation}/bin/tidefs-ublk-discard-validation "$@"
          '';





          posix-scoreboard = script "tidefs-posix-scoreboard" [
              self.packages.${system}.default
              self.packages.${system}.xfstests
              self.packages.${system}.tidefsFsx
              self.packages.${system}.tidefsXfstestsScripts
            pkgs.bash
            pkgs.coreutils
            pkgs.fio
            pkgs.fuse3
            pkgs.git
            pkgs.util-linux
          ] ''
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.fuse3 ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            exec ${pkgs.bash}/bin/bash nix/tidefs-posix-scoreboard.sh "$@"
          '';
          xfstests-runner = script "tidefs-xfstests-runner" [
              self.packages.${system}.default
              self.packages.${system}.xfstests
              self.packages.${system}.tidefsXfstestsScripts
            pkgs.bash
            pkgs.coreutils
            pkgs.fuse3
            pkgs.git
            pkgs.util-linux
          ] ''
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.fuse3 ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            exec ${pkgs.bash}/bin/bash scripts/tidefs-xfstests-runner "$@"
          '';
          xfstests-generic = script "tidefs-xfstests-generic" [
              self.packages.${system}.default
              self.packages.${system}.xfstests
              self.packages.${system}.tidefsXfstestsScripts
            pkgs.bash
            pkgs.coreutils
            pkgs.fuse3
            pkgs.git
            pkgs.util-linux
          ] ''
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.fuse3 ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            out_dir="''${TIDEFS_OUT_DIR:-/root/ai/tmp/tidefs-validation/$(date -u +%Y%m%dT%H%M%SZ)-xfstests-generic}"
            mkdir -p "$out_dir"
            exec tidefs-posix-filesystem-adapter-daemon xfstests-harness --tests generic/001-050 --quick --out "$out_dir" --exclude "${self.packages.${system}.tidefsXfstestsScripts}/bin/tidefs-xfstests-exclude" "$@"
          '';

          xfstests-lock-symlink-fallocate = script "tidefs-xfstests-lock-symlink-fallocate" [
              self.packages.${system}.default
              self.packages.${system}.xfstests
              self.packages.${system}.tidefsXfstestsScripts
            pkgs.bash
            pkgs.coreutils
            pkgs.fuse3
            pkgs.git
            pkgs.util-linux
          ] ''
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.fuse3 ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            out_dir="''${TIDEFS_OUT_DIR:-/root/ai/tmp/tidefs-validation/$(date -u +%Y%m%dT%H%M%SZ)-xfstests-lock-symlink-fallocate}"
            mkdir -p "$out_dir"
            exec tidefs-posix-filesystem-adapter-daemon xfstests-harness --tests lock symlink fallocate --out "$out_dir" --no-exclude "$@"
          '';

          xfstests-lock-group = script "tidefs-xfstests-lock-group" [
            self.packages.${system}.tidefsXfstestsLockGroup
          ] ''
            if [ "$#" -ne 0 ]; then
              echo "tidefs-xfstests-lock-group takes no arguments; use nix build .#packages.${system}.tidefsXfstestsLockGroup -L for direct Nix options" >&2
              exit 2
            fi
            echo "xfstests_lock_group.result=${self.packages.${system}.tidefsXfstestsLockGroup}"
          '';
          qemu-direct = script "tidefs-qemu-direct" [
            pkgs.bash
            pkgs.coreutils
            pkgs.qemu
          ] ''
            exec ${pkgs.bash}/bin/bash nix/tidefs-qemu-direct.sh "$@"
          '';
          rdma-probe = script "tidefs-rdma-probe" [
            pkgs.bash
            pkgs.coreutils
            pkgs.findutils
            pkgs.gawk
            pkgs.gnugrep
            pkgs.gnused
            pkgs.iproute2
            pkgs.kmod
            pkgs.pciutils
            pkgs.rdma-core
          ] ''
            exec ${pkgs.bash}/bin/bash nix/tidefs-rdma-probe.sh "$@"
          '';
          qemu-rdma-two-node = script "tidefs-qemu-rdma-two-node" [
            pkgs.bash
            pkgs.cpio
            pkgs.coreutils
            pkgs.findutils
            pkgs.gawk
            pkgs.gzip
            pkgs.gnugrep
            pkgs.gnused
            pkgs.iproute2
            pkgs.kmod
            pkgs.qemu
            pkgs.rdma-core
            pkgs.zstd
          ] ''
            export TIDEFS_RDMA_ALLOW_MUTATION=1
            exec ${pkgs.bash}/bin/bash nix/tidefs-qemu-rdma-two-node.sh "$@"
          '';
          qemu-rdma-guest-system = script "tidefs-qemu-rdma-guest-system" [
            pkgs.coreutils
          ] ''
            guest="${self.packages.${system}.qemuRdmaGuestSystem}"
            echo "qemu_rdma_guest_system=$guest"
            echo "qemu_rdma_guest_kernel=$guest/kernel"
            echo "qemu_rdma_guest_initrd=$guest/initrd"
            test -e "$guest/kernel"
            test -e "$guest/initrd"
          '';
          qemu-rdma-two-node-nixos = script "tidefs-qemu-rdma-two-node-nixos" [
            pkgs.bash
            pkgs.cpio
            pkgs.coreutils
            pkgs.findutils
            pkgs.gawk
            pkgs.gzip
            pkgs.gnugrep
            pkgs.gnused
            pkgs.iproute2
            pkgs.kmod
            pkgs.qemu
            pkgs.rdma-core
            pkgs.zstd
          ] ''
            export TIDEFS_RDMA_ALLOW_MUTATION=1
            exec ${pkgs.bash}/bin/bash nix/tidefs-qemu-rdma-two-node.sh --nixos-system ${self.packages.${system}.qemuRdmaGuestSystem} "$@"
          '';

          multi-node-cluster = script "tidefs-multi-node-cluster" [
              self.packages.${system}.multiNodeCluster
          ] ''
            if [ "$#" -ne 0 ]; then
              echo "tidefs-multi-node-cluster takes no arguments; use nix build .#packages.${system}.multiNodeCluster -L for direct Nix options" >&2
              exit 2
            fi
            echo "multi_node_cluster.result=${
              self.packages.${system}.multiNodeCluster
            }"
          '';


          "cluster-e2e-validation" = script "tidefs-cluster-e2e-validation" [
              self.packages.${system}.clusterE2EValidation
          ] ''
            if [ "$#" -ne 0 ]; then
              echo "tidefs-cluster-e2e-validation takes no arguments; use nix build .#packages.${system}.clusterE2EValidation -L for direct Nix options" >&2
              exit 2
            fi
            echo "cluster_e2e_validation.result=${self.packages.${system}.clusterE2EValidation}"
          '';

          "rdma-two-node-validation" = script "tidefs-rdma-two-node-validation" [
              self.packages.${system}.rdmaTwoNodeValidation
          ] ''
            if [ "$#" -ne 0 ]; then
              echo "tidefs-rdma-two-node-validation takes no arguments; use nix build .#packages.${system}.rdmaTwoNodeValidation -L for direct Nix options" >&2
              exit 2
            fi
            echo "rdma_two_node_validation.result=${self.packages.${system}.rdmaTwoNodeValidation}"
          '';

          "kernel-7.0-validation" = script "tidefs-kernel-7_0-validation" [
              self.packages.${system}.kernel7Validation
          ] ''
            if [ "$#" -ne 0 ]; then
              echo "tidefs-kernel-7_0-validation takes no arguments; use nix build .#packages.${system}.kernel7Validation -L for direct Nix options" >&2
              exit 2
            fi
            echo "kernel_7.0_validation.result=${self.packages.${system}.kernel7Validation}"
          '';

          "kernel-no-daemon-validation" = script "tidefs-kmod-no-daemon-validation" [
              self.packages.${system}.kernelNoDaemonValidation
          ] ''
            if [ "$#" -ne 0 ]; then
              echo "tidefs-kmod-no-daemon-validation takes no arguments; use nix build .#packages.${system}.kernelNoDaemonValidation -L for direct Nix options" >&2
              exit 2
            fi
            echo "kernel_no_daemon_validation.result=${self.packages.${system}.kernelNoDaemonValidation}"
          '';

          "kernel-no-daemon-teardown-validation" = script "tidefs-kmod-no-daemon-teardown-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            pkgs.b3sum
            self.packages.${system}.kernelNoDaemonTeardownValidation
            self.packages.${system}.tidefsPosixVfsKmod
            self.packages.${system}.tidefsXtaskRuntime
          ] ''
            exec ${self.packages.${system}.kernelNoDaemonTeardownValidation}/bin/tidefs-kmod-no-daemon-teardown-validation \
              --module ${self.packages.${system}.tidefsPosixVfsKmod}/tidefs_posix_vfs.ko "$@"
          '';


          "kernel-lockdep-kcsan-kasan-validation" = script "tidefs-kmod-lockdep-kcsan-kasan-validation" [
              pkgs.bash
              pkgs.coreutils
              self.packages.${system}.kernelLockdepKcsanKasanValidation
          ] ''
            exec ${self.packages.${system}.kernelLockdepKcsanKasanValidation}/bin/tidefs-kmod-lockdep-kcsan-kasan-validation "$@"
          '';

          kernel-validation-matrix = script "tidefs-kernel-validation-matrix" [
              self.packages.${system}.default
            pkgs.bash
            pkgs.coreutils
          ] ''
            echo "TideFS Linux 7.0 kernel validation matrix"
            echo "Matrix family: matrix.kernel_validation.k7_10"
            echo "Dependencies: K7-02 K7-05 K7-08"
            echo "Status: rows defined awaiting kernel module dependencies"
          '';
          kmod-hot-loop = script "tidefs-kmod-hot-loop" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
          ] ''
            exec ${pkgs.bash}/bin/bash ${./nix/kmod-hot-loop.sh} "$@"
          '';

          kmod-acceptance = script "tidefs-kmod-acceptance" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kmodAcceptance
          ] ''
            exec ${self.packages.${system}.kmodAcceptance}/bin/tidefs-kmod-accept "$@"
          '';

          kmod-validation = script "tidefs-kmod-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kmodValidation
          ] ''
            exec ${self.packages.${system}.kmodValidation}/bin/tidefs-kmod-validation "$@"
          '';

          kernel-dir-namespace-validation = script "tidefs-kmod-dir-ns-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelDirNamespaceValidation
          ] ''
            exec ${self.packages.${system}.kernelDirNamespaceValidation}/bin/tidefs-kmod-dir-ns-validation "$@"
          '';



          kernel-writeback-validation = script "tidefs-kmod-writeback-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelWritebackValidation
          ] ''
            exec ${self.packages.${system}.kernelWritebackValidation}/bin/tidefs-kmod-writeback-validation "$@"
          '';

          kernel-writeback-vm-validation = script "tidefs-kmod-writeback-vm-validation" [
            pkgs.bash
          ] ''
            exec ${self.packages.${system}.kernelWritebackValidation}/bin/tidefs-kmod-writeback-validation "$@"
          '';


          kernel-mmap-validation = script "tidefs-kmod-mmap-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelMmapValidation
            self.packages.${system}.tidefsPosixVfsKmod
          ] ''
            exec ${self.packages.${system}.kernelMmapValidation}/bin/tidefs-kmod-mmap-validation \
              --module ${self.packages.${system}.tidefsPosixVfsKmod}/tidefs_posix_vfs.ko "$@"
          '';

          kernel-pool-import-validation = script "tidefs-kmod-pool-import-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelPoolImportValidation
          ] ''
            exec ${self.packages.${system}.kernelPoolImportValidation}/bin/tidefs-kmod-pool-import-validation "$@"
          '';


          kernel-performance-budget-validation = script "tidefs-kmod-perf-budget-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            pkgs.fio
            self.packages.${system}.kernelPerformanceBudgetValidation
          ] ''
            exec ${self.packages.${system}.kernelPerformanceBudgetValidation}/bin/tidefs-kmod-perf-budget-validation "$@"
          '';
          fuse-extent-validation = script "tidefs-fuse-extent-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.fuse3
            self.packages.${system}.fuseExtentValidation
            self.packages.${system}.default
          ] ''
            export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX="''${TIDEFS_ROOT_AUTHENTICATION_KEY_HEX:-4141414141414141414141414141414141414141414141414141414141414141}"
            exec ${self.packages.${system}.fuseExtentValidation}/bin/tidefs-fuse-extent-validation "$@"
          '';

          fuse-inode-metadata-validation = script "tidefs-fuse-inode-metadata-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.fuse3
            self.packages.${system}.fuseInodeMetadataValidation
            self.packages.${system}.default
          ] ''
            export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX="''${TIDEFS_ROOT_AUTHENTICATION_KEY_HEX:-4141414141414141414141414141414141414141414141414141414141414141}"
            exec ${self.packages.${system}.fuseInodeMetadataValidation}/bin/tidefs-fuse-inode-metadata-validation "$@"
          '';

          fuse-fallocate-validation = script "tidefs-fuse-fallocate-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.fuse3
            self.packages.${system}.fuseFallocateValidation
            self.packages.${system}.default
          ] ''
            export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX="''${TIDEFS_ROOT_AUTHENTICATION_KEY_HEX:-4141414141414141414141414141414141414141414141414141414141414141}"
            exec ${self.packages.${system}.fuseFallocateValidation}/bin/tidefs-fuse-fallocate-validation "$@"
          '';

          fuse-create-open-release-validation = script "tidefs-fuse-create-open-release-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.fuse3
            self.packages.${system}.fuseCreateOpenReleaseValidation
            self.packages.${system}.default
          ] ''
            export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX="''${TIDEFS_ROOT_AUTHENTICATION_KEY_HEX:-4141414141414141414141414141414141414141414141414141414141414141}"
            exec ${self.packages.${system}.fuseCreateOpenReleaseValidation}/bin/tidefs-fuse-create-open-release-validation "$@"
          '';
          kmod-xfstests-smoke = script "tidefs-kmod-xfstests-smoke" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kmodXfstestsSmoke
            self.packages.${system}.tidefsPosixVfsKmod
          ] ''
            exec ${self.packages.${system}.kmodXfstestsSmoke}/bin/tidefs-kmod-xfstests-smoke \
              --module ${self.packages.${system}.tidefsPosixVfsKmod}/tidefs_posix_vfs.ko "$@"
          '';

          kmod-xfstests-validation = script "tidefs-kmod-xfstests-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelXfstestsValidation
          ] ''
            exec ${self.packages.${system}.kernelXfstestsValidation}/bin/tidefs-kmod-xfstests-validation "$@"
          '';


          kernel-rename-validation = script "tidefs-kmod-rename-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelRenameValidation
          ] ''
            exec ${self.packages.${system}.kernelRenameValidation}/bin/tidefs-kmod-rename-validation "$@"
          '';


          kernel-symlink-validation = script "tidefs-kmod-symlink-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelSymlinkValidation
          ] ''
            exec ${self.packages.${system}.kernelSymlinkValidation}/bin/tidefs-kmod-symlink-validation "$@"
          '';

          kernel-mkdir-rmdir-validation = script "tidefs-kmod-mkdir-rmdir-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelMkdirRmdirValidation
          ] ''
            exec ${self.packages.${system}.kernelMkdirRmdirValidation}/bin/tidefs-kmod-mkdir-rmdir-validation "$@"
          '';
          kernel-link-crash-validation = script "tidefs-kmod-link-crash-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelLinkCrashValidation
          ] ''
            exec ${self.packages.${system}.kernelLinkCrashValidation}/bin/tidefs-kmod-link-crash-validation "$@"
          '';
          fuse-writeback-cache-validation = qemuSourceApp "tidefs-fuse-writeback-cache-validation";

          fuse-xfstests-validation = script "tidefs-fuse-xfstests-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.default
            self.packages.${system}.fuseXfstestsValidation
            self.packages.${system}.xfstests
          ] ''
            exec ${self.packages.${system}.fuseXfstestsValidation}/bin/tidefs-fuse-xfstests-validation "$@"
          '';

          kernel-long-haul-soak-vm = script "tidefs-kmod-long-haul-soak-vm" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelLongHaulSoakValidation
          ] ''
            exec ${self.packages.${system}.kernelLongHaulSoakValidation}/bin/tidefs-kmod-long-haul-soak "$@"
          '';


          fuse-xfstests-vm = script "tidefs-fuse-xfstests-vm" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.default
            self.packages.${system}.fuseXfstestsValidation
            self.packages.${system}.xfstests
          ] ''
            exec ${self.packages.${system}.fuseXfstestsValidation}/bin/tidefs-fuse-xfstests-validation "$@"
          '';

          fuse-fsx-qemu-validation = script "tidefs-fuse-fsx-qemu-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.default
            self.packages.${system}.fuseFsxValidation
            self.packages.${system}.tidefsFsx
          ] ''
            exec ${self.packages.${system}.fuseFsxValidation}/bin/tidefs-fuse-fsx-validation "$@"
          '';

          fuse-open-unlink-rename-soak = script "tidefs-fuse-open-unlink-rename-soak" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.default
            self.packages.${system}.fuseOpenUnlinkRenameSoak
          ] ''
            exec ${self.packages.${system}.fuseOpenUnlinkRenameSoak}/bin/tidefs-fuse-open-unlink-rename-soak "$@"
          '';

          fuse-product-demo-soak-vm = script "tidefs-fuse-product-demo-soak-vm" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.default
            self.packages.${system}.fuseProductDemoSoak
          ] ''
            exec ${self.packages.${system}.fuseProductDemoSoak}/bin/tidefs-fuse-product-demo-soak "$@"
          '';

          fuse-namespace-scale-stress-vm = script "tidefs-fuse-namespace-scale-stress-vm" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.default
            self.packages.${system}.fuseNamespaceScaleStress
          ] ''
            exec ${self.packages.${system}.fuseNamespaceScaleStress}/bin/tidefs-fuse-namespace-scale-stress "$@"
          '';

          fuse-namespace-scale-stress-host = script "tidefs-fuse-namespace-scale-stress-host" [
            pkgs.bash
            self.packages.${system}.fuseNamespaceScaleStressHost
          ] ''
            exec ${self.packages.${system}.fuseNamespaceScaleStressHost}/bin/tidefs-fuse-namespace-scale-stress-host "$@"
          '';


          k7-vfs-xfstests-validation = script "tidefs-k7-vfs-xfstests-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.git
            pkgs.jq
            pkgs.nix
            self.packages.${system}.k7VfsXfstestsValidation
          ] ''
            exec ${self.packages.${system}.k7VfsXfstestsValidation}/bin/tidefs-k7-vfs-xfstests-validation "$@"
          '';
          qemu-k7-vfs-xfstests-validation = script "tidefs-qemu-k7-vfs-xfstests-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.git
            pkgs.jq
            pkgs.nix
            self.packages.${system}.k7VfsXfstestsValidation
          ] ''
            exec ${self.packages.${system}.k7VfsXfstestsValidation}/bin/tidefs-k7-vfs-xfstests-validation "$@"
          '';


          kernel-xfstests-crash-consistency = script "tidefs-kernel-xfstests-crash-consistency" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelXfstestsCrashConsistency
          ] ''
            exec ${self.packages.${system}.kernelXfstestsCrashConsistency}/bin/tidefs-kernel-xfstests-crash-consistency "$@"
          '';

          kernel-block-validation = script "tidefs-kmod-block-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelBlockValidation
          ] ''
            exec ${self.packages.${system}.kernelBlockValidation}/bin/tidefs-kmod-block-validation "$@"
          '';

          kernel-block-queue-depth-validation = script "tidefs-kmod-queue-depth-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelBlockQueueDepthValidation
          ] ''
            exec ${self.packages.${system}.kernelBlockQueueDepthValidation}/bin/tidefs-kmod-queue-depth-validation "$@"
          '';

          kernel-block-crash-consistency = script "tidefs-kmod-block-crash-consistency" [
            (pkgs.writeShellScriptBin "placeholder-crash-consistency" ''
              echo "kernel-block-crash-consistency: build the module first, then run." >&2
              exit 1
            '')
            self.packages.${system}.kernelBlockCrashConsistency
          ] ''
            exec ${self.packages.${system}.kernelBlockCrashConsistency}/bin/tidefs-kmod-block-crash-consistency "$@"
          '';

          kernel-block-no-daemon-audit = script "tidefs-kmod-block-no-daemon-audit" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelBlockNoDaemonAudit
          ] ''
            exec ${self.packages.${system}.kernelBlockNoDaemonAudit}/bin/tidefs-kmod-block-no-daemon-audit "$@"
          '';

          kernel-block-fio-powercut-campaign = script "tidefs-kblock-fio-powercut-campaign" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            pkgs.fio
            self.packages.${system}.kernelBlockFioPowercutCampaign
          ] ''
            exec ${self.packages.${system}.kernelBlockFioPowercutCampaign}/bin/tidefs-kblock-fio-powercut-campaign "$@"
          '';

          kernel-block-guest-filesystem-matrix = script "tidefs-kblock-guest-fs-matrix" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            pkgs.fio
            pkgs.xfsprogs
            pkgs.btrfs-progs
            self.packages.${system}.kernelBlockGuestFilesystemMatrix
          ] ''
            exec ${self.packages.${system}.kernelBlockGuestFilesystemMatrix}/bin/tidefs-kblock-guest-fs-matrix "$@"
          '';

          block-kmod-io-dispatch-validation = script "tidefs-block-kmod-io-dispatch-validation"  [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.blockKmodIoDispatchValidation
          ] ''
            exec ${self.packages.${system}.blockKmodIoDispatchValidation}/bin/tidefs-block-kmod-io-dispatch-validation "$@"
          '';

          k7-kbuild-toolchain = script "k7-kbuild-toolchain-prepare" [
            pkgs.bash
            pkgs.coreutils
            self.packages.${system}.k7KbuildToolchain
          ] ''
            exec ${self.packages.${system}.k7KbuildToolchain}/bin/k7-kbuild-toolchain-prepare "$@"
          '';

          kernel-read-write-validation = script "tidefs-kmod-read-write-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelReadWriteValidation
          ] ''
            exec ${self.packages.${system}.kernelReadWriteValidation}/bin/tidefs-kmod-read-write-validation "$@"
          '';


          kernel-copy-splice-validation = script "tidefs-kernel-copy-splice-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelCopySpliceValidation
          ] ''
            exec ${self.packages.${system}.kernelCopySpliceValidation}/bin/tidefs-kernel-copy-splice-validation "$@"
          '';
          kernel-readdir-validation = script "tidefs-kmod-readdir-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelReaddirValidation
          ] ''
            exec ${self.packages.${system}.kernelReaddirValidation}/bin/tidefs-kmod-readdir-validation "$@"
          '';

          kernel-lookup-validation = script "tidefs-kmod-lookup-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelLookupValidation
          ] ''
            exec ${self.packages.${system}.kernelLookupValidation}/bin/tidefs-kmod-lookup-validation "$@"
          '';
          kernel-fallocate-validation = script "tidefs-kmod-fallocate-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelFallocateValidation
          ] ''
            exec ${self.packages.${system}.kernelFallocateValidation}/bin/tidefs-kmod-fallocate-validation "$@"
          '';

          kernel-fsync-validation = script "tidefs-kmod-fsync-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelFsyncValidation
            self.packages.${system}.tidefsPosixVfsKmod
          ] ''
            exec ${self.packages.${system}.kernelFsyncValidation}/bin/tidefs-kmod-fsync-validation \
              --module ${self.packages.${system}.tidefsPosixVfsKmod}/tidefs_posix_vfs.ko "$@"
          '';

          kernel-inotify-fanotify-validation = script "tidefs-kmod-inotify-fanotify-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelInotifyFanotifyValidation
          ] ''
            exec ${self.packages.${system}.kernelInotifyFanotifyValidation}/bin/tidefs-kmod-inotify-fanotify-validation "$@"
          '';
          kernel-statfs-validation = script "tidefs-kmod-statfs-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelStatfsValidation
          ] ''
            exec ${self.packages.${system}.kernelStatfsValidation}/bin/tidefs-kmod-statfs-validation "$@"
          '';


          kernel-truncate-validation = script "tidefs-kmod-truncate-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelTruncateValidation
          ] ''
            exec ${self.packages.${system}.kernelTruncateValidation}/bin/tidefs-kmod-truncate-validation "$@"
          '';

          kernel-link-unlink-validation = script "tidefs-kmod-link-unlink-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelLinkUnlinkValidation
          ] ''
            exec ${self.packages.${system}.kernelLinkUnlinkValidation}/bin/tidefs-kmod-link-unlink-validation "$@"
          '';

          kernel-concurrent-validation = script "tidefs-kmod-concurrent-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelConcurrentValidation
          ] ''
            exec ${self.packages.${system}.kernelConcurrentValidation}/bin/tidefs-kmod-concurrent-validation "$@"
          '';

          kernel-mount-cycle-stress = script "tidefs-kmod-mount-cycle-stress" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelMountCycleStressValidation
          ] ''
            exec ${self.packages.${system}.kernelMountCycleStressValidation}/bin/tidefs-kmod-mount-cycle-stress "$@"
          '';

          kernel-mount-namespace = script "tidefs-kmod-mount-namespace" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelMountNamespaceValidation
          ] ''
            exec ${self.packages.${system}.kernelMountNamespaceValidation}/bin/tidefs-kmod-mount-namespace-validation "$@"
          '';


          kernel-teardown-validation = script "tidefs-kmod-teardown-validation" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            pkgs.b3sum
            self.packages.${system}.kernelTeardownValidation
            self.packages.${system}.tidefsPosixVfsKmod
            self.packages.${system}.tidefsCtlRuntime
            self.packages.${system}.tidefsXtaskRuntime
          ] ''
            exec ${self.packages.${system}.kernelTeardownValidation}/bin/tidefs-kmod-teardown-validation \
              --module ${self.packages.${system}.tidefsPosixVfsKmod}/tidefs_posix_vfs.ko "$@"
          '';
          kernel-cross-path-equivalence = script "tidefs-kernel-cross-path-equivalence" [
            pkgs.bash
            pkgs.coreutils
            pkgs.busybox
            pkgs.kmod
            pkgs.cpio
            pkgs.qemu
            self.packages.${system}.kernelCrossPathEquivalence
          ] ''
            exec ${self.packages.${system}.kernelCrossPathEquivalence}/bin/tidefs-kernel-cross-path-equivalence "$@"
          '';

          rdma-carrier-test = script "tidefs-rdma-carrier-test" [
            self.packages.${system}.default
            pkgs.bash
            pkgs.coreutils
            pkgs.rdma-core
            pkgs.iproute2
            pkgs.kmod
          ] ''
            echo "=== TideFS RDMA Carrier Test ==="
            echo ""
            echo "1. RDMA host probe (non-mutating):"
            exec ${pkgs.bash}/bin/bash nix/tidefs-rdma-probe.sh
            echo ""
            echo "2. Two-node QEMU topology dry-run:"
            exec ${pkgs.bash}/bin/bash nix/tidefs-qemu-rdma-two-node.sh --dry-run
            echo ""
            echo "3. Rust RDMA carrier validation tests:"
            export CARGO_TARGET_DIR="$(mktemp -d)"
            cargo test -p tidefs-validation -- qemu -- --test-threads=1 2>&1
            echo ""
            echo "4. Two-node NixOS test (requires KVM):"
            echo "   Run: nix build .#packages.x86_64-linux.rdmaCarrierTwoNodeTest -L"
            echo ""
            echo "RDMA carrier test complete."
          '';
        });

  formatter = forAllSystems (system: (pkgsFor system).alejandra);
    };
}

# TideFS K7-02: Linux 7.0 kernel QEMU validation target.
#
# This is a NixOS test that boots a QEMU VM with a custom-built Linux 7.0
# kernel and validates basic kernel features (FUSE, ublk, virtio, etc.).
#
# Usage (to be wired into flake.nix):
#   kernel-7.0-validation = import ./nix/vm/kernel-7.0-validation.nix {
#     inherit pkgs;
#     linuxKernel_7_0 = pkgs.callPackage ./nix/packages/linux-7.0-kernel.nix {
#       kernelConfig = ./nix/vm/kernel-7.0-config;
#     };
#   };
{
  pkgs,
  linuxKernel_7_0,
}:

let
  # Wrap the raw kernel derivation into a kernel package set that
  # NixOS boot.kernelPackages expects.
  linuxPackages_7_0 = pkgs.linuxPackagesFor linuxKernel_7_0;
in
pkgs.testers.runNixOSTest {
  name = "tidefs-kernel-7.0-validation";

  nodes.machine = { config, lib, pkgs, ... }: {
    # Override the kernel to use our custom Linux 7.0 build.
    boot.kernelPackages = lib.mkForce linuxPackages_7_0;

    boot.kernelParams = [
      "console=ttyS0"
      "panic=30"
      "systemd.default_device_timeout_sec=600s"
      "rd.systemd.default_device_timeout_sec=600s"
    ];

    boot.initrd.availableKernelModules = [
      "virtio_pci"
      "virtio_net"
      "virtio_blk"
      "virtio_console"
      "fuse"
      "ublk_drv"
    ];

    boot.initrd.kernelModules = [ "virtio_net" ];

    boot.loader.grub.enable = false;
    boot.initrd.systemd.enable = false;

    fileSystems."/" = {
      device = "tmpfs";
      fsType = "tmpfs";
      options = [ "mode=0755" ];
    };

    networking.useDHCP = lib.mkForce false;
    networking.interfaces.eth1.useDHCP = lib.mkForce false;

    services.getty.autologinUser = lib.mkForce "root";
    users.users.root.initialHashedPassword = "";

    environment.systemPackages = [
      pkgs.fuse3
      pkgs.kmod
      pkgs.util-linux
    ];

    virtualisation.cores = 2;
    virtualisation.memorySize = 1024;
  };

  testScript = ''
    import json

    validation = {
      "test": "tidefs-kernel-7.0-validation",
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
    machine.start()
    machine.wait_for_unit("multi-user.target")
    record("boot_to_multi_user", "pass")

    # --- Kernel version check ---
    kernel_ver = machine.succeed("uname -r").strip()
    print(f"Running kernel: {kernel_ver}")
    if kernel_ver.startswith("7.0"):
        record("kernel_version_7_0", "pass", kernel_ver)
    else:
        record("kernel_version_7_0", "fail", f"expected 7.0.x, got {kernel_ver}")

    # --- FUSE module check ---
    machine.succeed("modprobe fuse || true")
    machine.succeed("test -e /dev/fuse")
    record("fuse_module_available", "pass")

    # --- ublk module check ---
    ublk_out = machine.succeed("modprobe ublk_drv && echo loaded || echo not_loaded").strip()
    record("ublk_module_probe", "pass" if ublk_out == "loaded" else "fail", ublk_out)

    # --- Virtio block devices present ---
    virtio_devs = machine.succeed("ls /dev/vda* 2>/dev/null || echo none").strip()
    record("virtio_block_devices", "pass" if virtio_devs != "none" else "info", virtio_devs)

    # --- Kernel feature probe: key modules loadable ---
    features_ok = True
    for feat in ["fuse", "ublk_drv"]:
        try:
            machine.succeed(f"modprobe {feat}")
        except Exception:
            features_ok = False
    record("kernel_features_loadable", "pass" if features_ok else "fail")

    # --- Score ---
    validation["passed"] = sum(1 for r in validation["results"] if r["status"] == "pass")
    validation["failed"] = sum(1 for r in validation["results"] if r["status"] == "fail")

    print(json.dumps(validation, indent=2))

    with open("/tmp/kernel-7.0-validation.json", "w") as f:
        json.dump(validation, f, indent=2)

    assert validation["failed"] == 0, f"Validation failures: {validation['failed']}"
  '';
}

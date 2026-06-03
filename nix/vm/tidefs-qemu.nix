{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.tidefs;
  sn = cfg.storageNode;
in
{
  options.tidefs = {
    extraPackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
      description = "Extra packages to install in the VM system environment.";
    };
    extraKernelModules = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Extra kernel modules for the VM initrd.";
    };
    extraInitrdUtils = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = "Extra binaries to copy into the initrd (dest -> src attrset). Key is destination name, value is source binary store path.";
    };

    storageNode = {
      enable = lib.mkEnableOption "TideFS storage node systemd service";

      nodeId = lib.mkOption {
        type = lib.types.ints.u64;
        default = 1;
        description = "Node ID for the storage node.";
      };

      bindAddr = lib.mkOption {
        type = lib.types.str;
        default = "0.0.0.0:9000";
        description = "Address the storage node binds to.";
      };

      storePath = lib.mkOption {
        type = lib.types.str;
        default = "/var/lib/tidefs/store";
        description = "Path to the storage node backing store.";
      };

      package = lib.mkOption {
        type = lib.types.nullOr lib.types.package;
        default = null;
        description = "TideFS package providing tidefs-storage-node binary.";
      };

      extraArgs = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "Extra arguments passed to tidefs-storage-node server.";
      };
    };
  };

  config = lib.mkMerge [
    {
      system.stateVersion = "25.11";

      boot.loader.grub.enable = false;
      boot.initrd.systemd.enable = false;

      boot.initrd.availableKernelModules = [
        "virtio_pci"
        "virtio_net"
        "virtio_blk"
        "virtio_console"
        "rdma_rxe"
        "fuse"
        "ublk_drv"
        "siw"
        "ib_core"
        "ib_uverbs"
      ] ++ cfg.extraKernelModules;

      boot.initrd.kernelModules = [
        "virtio_net"
        "rdma_rxe"
        "ib_core"
        "ib_uverbs"
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
      '' + lib.concatStringsSep "\n" (
        lib.mapAttrsToList (dest: src: "copy_bin_and_libs ${src} ${dest}")
          cfg.extraInitrdUtils
      );

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
        pkgs.fuse3
      ] ++ cfg.extraPackages;

      virtualisation.cores = lib.mkDefault 2;
      virtualisation.memorySize = lib.mkDefault 1024;
    }

    (lib.mkIf (sn.enable && sn.package != null) {
      systemd.services.tidefs-storage-node = {
        description = "TideFS Storage Node";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          ExecStart = "${sn.package}/bin/tidefs-storage-node server --node-id ${toString sn.nodeId} --bind ${sn.bindAddr} --store ${sn.storePath} ${lib.concatStringsSep " " sn.extraArgs}";
          Restart = "on-failure";
          RestartSec = 3;
          User = "root";
          StandardOutput = "journal";
          StandardError = "journal";
        };
      };
    })
  ];
}

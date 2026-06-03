{
  lib,
  # Derive version from workspace Cargo.toml so the package and artifact
  # metadata always match the source tree that produced them.
  cargoToml ? builtins.fromTOML (builtins.readFile ../../Cargo.toml),
  rustPlatform,
  pkg-config,
  fuse3,
  rdma-core,
  src,
  cargoLock,
  cargoBuildFlags ? [ "--workspace" ],
  workspaceBins ? [
    "tidefs-block-volume-adapter-daemon"
    "tidefs-storage-node"
    "tidefs-filesystem-demo"
    "tidefs-posix-filesystem-adapter-daemon"
    "tidefs-store-demo"
    "tidefsctl"
    "tidefs-xtask"
  ],
  version ? cargoToml.workspace.package.version or cargoToml.package.version or "0.0.0-unknown",
}:

rustPlatform.buildRustPackage {
  pname = "tidefs-workspace";
  inherit version src cargoLock;

  inherit cargoBuildFlags;
  doCheck = false;
  cargoTestFlags = [ "--workspace" "--all-targets" ];
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ fuse3 rdma-core ];

  installPhase = ''
    runHook preInstall
    mkdir -p "$out/bin"
    for bin in ${lib.concatStringsSep " " workspaceBins}; do
      installed=
      for candidate in "target/release/$bin" target/*/release/"$bin"; do
        if [ -x "$candidate" ]; then
          install -Dm755 "$candidate" "$out/bin/$bin"
          installed=1
          break
        fi
      done
      if [ -z "$installed" ]; then
        echo "missing expected workspace binary: $bin" >&2
        exit 1
      fi
    done
    runHook postInstall
  '';
}

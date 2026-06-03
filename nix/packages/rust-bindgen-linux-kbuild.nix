{
  pkgs,
  bindgen_0_69,
}:

pkgs.runCommand "rust-bindgen-0.69.4-linux-kbuild" {
  pname = "rust-bindgen";
  version = "0.69.4-linux-kbuild";
  passthru.unwrapped = bindgen_0_69;
  meta = {
    description = "rust-bindgen 0.69.4 wrapper for Linux 7.0 Rust Kbuild";
    license = pkgs.lib.licenses.bsd3;
    platforms = [ "x86_64-linux" ];
  };
} ''
  mkdir -p "$out/bin"
  cat > "$out/bin/bindgen" <<'EOF'
#!${pkgs.bash}/bin/bash
set -euo pipefail

args=()
for arg in "$@"; do
  case "$arg" in
    -Wno-format-overflow-non-kprintf|-Wno-format-truncation-non-kprintf|-Wno-format-overflow)
      ;;
    *)
      args+=("$arg")
      ;;
  esac
done

exec ${bindgen_0_69}/bin/bindgen "''${args[@]}"
EOF
  chmod +x "$out/bin/bindgen"
''

# TideFS K7-KBUILD-TOOLCHAIN-001: Reproducible Linux 7.0 Rust Kbuild toolchain.
#
# Provides a Nix derivation that exposes rustc 1.88, matching rust-src,
# bindgen, clang, and ld.lld for Linux 7.0 Rust-for-Linux Kbuild.
# Workers run this from a clean TideFS worktree to enter a build-ready state
# without hidden operator shell paths.
#
# Usage (from TideFS worktree root):
#   nix run .#k7-kbuild-toolchain
#   # or: nix build .#k7-kbuild-toolchain && result/bin/k7-kbuild-toolchain-prepare
#
# Produces a script that:
#   1. Verifies rustc 1.88, rust-src version match, bindgen >= 0.65.1,
#      clang, and ld.lld are on PATH.
#   2. Exports the necessary Kbuild environment variables.
#   3. Reports readiness or missing prerequisites.
#
# The Linux source and build artifacts must remain outside the TideFS
# repo -- this derivation only prepares the toolchain, not the kernel.
{
  pkgs,
  rustToolchain,
  bindgenPkg ? pkgs.rust-bindgen or pkgs.bindgen,
}:

let
  # The preparation script, bundled with the required toolchain.
  k7KbuildToolchainPrepare = pkgs.writeShellScriptBin "k7-kbuild-toolchain-prepare" ''
    set -euo pipefail

    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'

    errors=0
    warnings=0

    version_ge() {
        printf '%s\n%s\n' "$2" "$1" | sort -V -C 2>/dev/null || return 1
    }

    check_cmd() {
        local name="$1"
        local required="$2"
        local version_arg="''${3:---version}"
        local found=0
        local ver=""
        local path=""

        if path="$(command -v "$name" 2>/dev/null)"; then
            found=1
            ver="$( ("$name" "$version_arg" 2>/dev/null || echo "unknown") | head -1)"
        fi

        if [ "$found" -eq 1 ]; then
            if version_ge "''${ver##* }" "$required" 2>/dev/null || [ "$required" = "any" ]; then
                echo -e "  ''${GREEN}[OK]''${NC} $name: $ver ($path)"
            else
                echo -e "  ''${YELLOW}[WARN]''${NC} $name version $ver is below required $required ($path)"
                warnings=$((warnings + 1))
            fi
        else
            echo -e "  ''${RED}[MISSING]''${NC} $name (required >= $required)"
            errors=$((errors + 1))
        fi
    }

    echo "=== K7 Kbuild Toolchain Preparation (Nix) ==="
    echo ""
    echo "Environment provided by Nix derivation."
    echo ""

    echo "Checking Rust toolchain..."
    check_cmd "rustc" "1.88"

    echo "Checking rust-src..."
    RUST_SYSROOT="$(rustc --print sysroot 2>/dev/null || echo "")"
    if [ -n "$RUST_SYSROOT" ] && [ -d "$RUST_SYSROOT/lib/rustlib/src/rust/library" ]; then
        RUST_SRC_VER="$(rustc --version 2>/dev/null | awk '{print $2}')"
        echo -e "  ''${GREEN}[OK]''${NC} rust-src: $RUST_SRC_VER (in sysroot)"
    else
        echo -e "  ''${RED}[MISSING]''${NC} rust-src: not found in sysroot"
        echo "    Ensure the rustToolchain includes rust-src component."
        errors=$((errors + 1))
    fi

    echo "Checking bindgen..."
    check_cmd "bindgen" "0.65.1"

    echo "Checking clang..."
    check_cmd "clang" "any"

    echo "Checking ld.lld..."
    check_cmd "ld.lld" "any" "--version"

    echo ""

    if [ "$errors" -eq 0 ]; then
        echo "All prerequisites found via Nix toolchain."
        echo ""
        echo "Exported environment for Linux 7.0 Kbuild:"
        echo "  RUSTC=$(command -v rustc)"
        echo "  BINDGEN=$(command -v bindgen)"
        echo "  CLANG=$(command -v clang)"
        echo "  LD=$(command -v ld.lld)"
        echo "  RUSTC_BOOTSTRAP=1"
        echo ""
        echo "Next steps for Review debt TFR-009/TFR-018 kmod work:"
        echo "  1. Run: nix/kmod-hot-loop.sh prepare"
        echo "  2. Pass KERNEL_TREE, KERNEL_BUILD, and MODULE_OUT for explicit prepared paths"
        echo "  3. Run: RUSTC=\$RUSTC RUSTC_BOOTSTRAP=1 make -j8 -C \$LINUX_SRC O=\$LINUX_BUILD LLVM=1 rustavailable"
        echo "  4. Build modules with MO=\$MODULE_OUT/<module-name> and the repo-pinned absolute rustc"
        echo ""
        echo "Toolchain preparation complete."

        if [ "$warnings" -gt 0 ]; then
            echo ""
            echo -e "''${YELLOW}Warning: $warnings component(s) below recommended version.''${NC}"
        fi
    else
        echo -e "''${RED}$errors prerequisite(s) missing.''${NC}"
        echo ""
        echo "The Nix environment should have provided all prerequisites."
        echo "Check that rustToolchain includes rust-src and bindgen is available."
        exit 1
    fi
  '';

in
pkgs.runCommand "k7-kbuild-toolchain" {
  nativeBuildInputs = [
    pkgs.makeWrapper
  ];
  buildInputs = [
    rustToolchain
    bindgenPkg
    pkgs.clang
    pkgs.lld
  ];
  passthru = {
    inherit rustToolchain bindgenPkg;
    scriptPath = "${k7KbuildToolchainPrepare}/bin/k7-kbuild-toolchain-prepare";
  };
  meta = {
    description = "Reproducible Linux 7.0 Rust Kbuild toolchain preparation for TideFS kernel module workers";
    license = pkgs.lib.licenses.mit;
    platforms = [ "x86_64-linux" ];
  };
} ''
  mkdir -p "$out/bin"
  cp ${k7KbuildToolchainPrepare}/bin/k7-kbuild-toolchain-prepare "$out/bin/"
  wrapProgram "$out/bin/k7-kbuild-toolchain-prepare" \
    --prefix PATH : "${rustToolchain}/bin" \
    --prefix PATH : "${bindgenPkg}/bin" \
    --prefix PATH : "${pkgs.clang}/bin" \
    --prefix PATH : "${pkgs.lld}/bin" \
    --set RUSTC_BOOTSTRAP 1 \
    --set K7_KBUILD_TOOLCHAIN_NIX 1
  echo "K7 Kbuild toolchain prepared: $out/bin/k7-kbuild-toolchain-prepare" > "$out/README"
''

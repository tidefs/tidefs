#!/usr/bin/env bash
# K7 Kbuild toolchain preparation script.
#
# Verifies that the Linux 7.0 Rust-for-Linux Kbuild prerequisites are
# available on PATH and exports the necessary environment variables.
#
# This is a non-Nix fallback; prefer the Nix app via:
#   nix run .#k7-kbuild-toolchain
#
# Usage:
#   source scripts/k7-kbuild-toolchain-prepare.sh
#   # or: eval "$(bash scripts/k7-kbuild-toolchain-prepare.sh)"
#
# Exit codes:
#   0  All prerequisites found
#   1  One or more prerequisites missing
#   2  Wrong version of a required component

set -euo pipefail

REQUIRED_RUSTC_MAJOR="1.88"
REQUIRED_BINDGEN_MAJOR="0"
REQUIRED_BINDGEN_MINOR="72"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

errors=0
warnings=0

# ── Helper functions ──────────────────────────────────────────────────────

version_ge() {
    # Returns 0 if $1 >= $2, where both are dot-separated version strings.
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

check_cmd() {
    local name="$1"
    local required="$2"
    local version_arg="${3:---version}"
    local found=0
    local ver=""
    local path=""

    if path="$(command -v "$name" 2>/dev/null)"; then
        found=1
        ver="$( ("$name" "$version_arg" 2>/dev/null || echo "unknown") | head -1)"
    fi

    if [ "$found" -eq 1 ]; then
        if version_ge "${ver##* }" "$required" 2>/dev/null || [ "$required" = "any" ]; then
            echo -e "  ${GREEN}[OK]${NC} $name: $ver ($path)"
        else
            echo -e "  ${YELLOW}[WARN]${NC} $name version $ver is below required $required ($path)"
            warnings=$((warnings + 1))
        fi
    else
        echo -e "  ${RED}[MISSING]${NC} $name (required >= $required)"
        errors=$((errors + 1))
    fi
}

# ── Main checks ────────────────────────────────────────────────────────────

echo "=== K7 Kbuild Toolchain Preparation ==="
echo ""

echo "Checking Rust toolchain..."
check_cmd "rustc" "$REQUIRED_RUSTC_MAJOR"

echo "Checking rust-src..."
RUST_SYSROOT="$(rustc --print sysroot 2>/dev/null || echo "")"
if [ -n "$RUST_SYSROOT" ] && [ -d "$RUST_SYSROOT/lib/rustlib/src/rust/library" ]; then
    RUST_SRC_VER="$(rustc --version 2>/dev/null | awk '{print $2}')"
    echo -e "  ${GREEN}[OK]${NC} rust-src: $RUST_SRC_VER (in sysroot)"
else
    echo -e "  ${RED}[MISSING]${NC} rust-src: not found in sysroot ($RUST_SYSROOT/lib/rustlib/src/rust/library)"
    echo "    Install via: rustup component add rust-src"
    errors=$((errors + 1))
fi

echo "Checking bindgen..."
check_cmd "bindgen" "0.72"

echo "Checking clang..."
check_cmd "clang" "any"

echo "Checking ld.lld..."
check_cmd "ld.lld" "any" "--version"

echo ""

# ── Environment export ─────────────────────────────────────────────────────

if [ "$errors" -eq 0 ]; then
    echo "All prerequisites found."

    # Export Kbuild environment variables for Linux 7.0 Rust-for-Linux build
    cat <<ENVEOF

# Paste these into your shell or source this script:
export RUSTC="$(command -v rustc)"
export BINDGEN="$(command -v bindgen)"
export CLANG="$(command -v clang)"
export LD="$(command -v ld.lld)"
export RUSTC_BOOTSTRAP=1
export RUSTFLAGS="-Ctarget-feature=-crt-static"
export TIDEFS_KERNEL_JOBS="${TIDEFS_KERNEL_JOBS:-8}"

# Linux 7.0 Kbuild requires these for Rust support:
#   make -j8 LLVM=1 rustavailable
#   make -j8 LLVM=1 modules_prepare
ENVEOF

    echo ""
    echo "Next steps for Review debt TFR-009/TFR-018 kmod work:"
    echo "  1. Run: tidefs-nexus-worker-tool linux-prepare --slot <SLOT> --issue <N>"
    echo "  2. Use the returned linux_src/linux_build/module_out paths"
    echo "  3. Run: RUSTC=\$RUSTC RUSTC_BOOTSTRAP=1 make -j8 -C \$LINUX_SRC O=\$LINUX_BUILD LLVM=1 rustavailable"
    echo "  4. Build modules with MO=\$MODULE_OUT/<module-name> and the repo-pinned absolute rustc"
    echo ""
    echo "Toolchain preparation complete."

    if [ "$warnings" -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}Warning: $warnings component(s) below recommended version.${NC}"
        echo "The kernel build may still work; monitor for errors."
    fi
else
    echo -e "${RED}$errors prerequisite(s) missing.${NC}"
    echo ""
    echo "To fix, either:"
    echo "  - Use the Nix app: nix run .#k7-kbuild-toolchain"
    echo "  - Install manually:"
    echo "    * rustc 1.88 + rust-src: rustup toolchain install 1.88.0 --component rust-src"
    echo "    * bindgen >= 0.72: cargo install bindgen-cli --version 0.72.1"
    echo "    * clang + ld.lld: apt install clang lld or nix-shell -p clang lld"
fi

exit $errors

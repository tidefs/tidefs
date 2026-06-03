#!/usr/bin/env bash
# TideFS benchmark runner
# Usage: ./nix/benchmarks.sh [CRATE]
#   CRATE: object-store | filesystem | all (default: all)

set -euo pipefail

cd "$(dirname "$0")/.."

run_bench() {
    local crate="$1"
    echo "==> Running benchmarks for: $crate"
    cargo bench -p "tidefs-local-${crate}" --bench "${crate//-/_}"
}

case "${1:-all}" in
    object-store)
        run_bench "object-store"
        ;;
    filesystem)
        run_bench "filesystem"
        ;;
    all)
        run_bench "object-store"
        run_bench "filesystem"
        ;;
    *)
        echo "Usage: $0 {object-store|filesystem|all}"
        exit 1
        ;;
esac

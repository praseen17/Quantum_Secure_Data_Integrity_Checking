#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 OUTPUT_DIR SIZE_MB [REPETITIONS=30] [ROUNDS=10] [PATTERN=localized] [SEED=20261112] [SAMPLE_FRACTIONS='0.01 0.05 0.1']" >&2
  exit 2
fi
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output_dir=$(realpath -m "$1")
size_mb=$2
repetitions=${3:-30}
rounds=${4:-10}
pattern=${5:-localized}
seed=${6:-20261112}
fractions=${7:-"0.01 0.05 0.1"}
build_dir=${QSAFE_BUILD_DIR:-"$repo_root/build/current"}
export QSAFE_BENCH_BINARY="$build_dir/qsafe_audit_experiment"
"$repo_root/scripts/run_audit_sweep.sh" "$output_dir" "$size_mb" \
  "$repetitions" "$rounds" "$pattern" "$seed" "$fractions"

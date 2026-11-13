#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 OUTPUT_DIR SIZE_MB [REPETITIONS=30] [ROUNDS=10] [PATTERN=localized] [SEED=20261112] [SAMPLE_FRACTION=0.05] [CORRUPTION_FRACTION=0.02]" >&2
  exit 2
fi

output_dir=$(realpath -m "$1")
size_mb=$2
repetitions=${3:-30}
rounds=${4:-10}
pattern=${5:-localized}
seed=${6:-20261112}
sample_fraction=${7:-0.05}
corruption_fraction=${8:-0.02}
repo_root=$(cd "$(dirname "$0")/.." && pwd)
binary=${QSAFE_BENCH_BINARY:-"$repo_root/build/clean/qsafe_audit_experiment"}
mkdir -p "$output_dir"
if [[ ! -x "$binary" ]]; then
  echo "benchmark executable not found: $binary" >&2
  exit 2
fi

export QSAFE_MANIFEST_OUT="$output_dir/run_manifest.json"
export QSAFE_SOURCE_REVISION="$(git -C "$repo_root" rev-parse HEAD)"
export QSAFE_SOURCE_DIRTY="$(git -C "$repo_root" status --porcelain | wc -l | tr -d ' ')"
export QSAFE_BUILD_MODE="$(sed -n 's/^CMAKE_BUILD_TYPE:STRING=//p' "$repo_root/build/clean/CMakeCache.txt" | head -1)"
export QSAFE_COMPILER="$(c++ --version | head -1)"
export QSAFE_OS="$(uname -a)"
export QSAFE_CPU="$(lscpu | awk -F: '/Model name/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')"
export QSAFE_LIBOQS="liboqs 0.16.0"
export QSAFE_ISAL="$(dpkg-query -W -f='${Version}' libisal-dev 2>/dev/null || echo unknown)"
export QSAFE_OPENSSL="$(openssl version)"
export QSAFE_SIZE_MB="$size_mb"
export QSAFE_REPETITIONS="$repetitions"
export QSAFE_ROUNDS="$rounds"
export QSAFE_PATTERN="$pattern"
export QSAFE_SEED="$seed"
export QSAFE_SAMPLE_FRACTION="$sample_fraction"
export QSAFE_CORRUPTION_FRACTION="$corruption_fraction"
export QSAFE_ALGORITHM="ML-DSA-44"
export QSAFE_PYTHON="$(python3 --version)"
export QSAFE_RISK_CONFIG_SHA256="$(sha256sum "$repo_root/config/risk.conf" | awk '{print $1}')"

python3 - <<'PY'
import json
import os

fields = {
    "source_revision": "QSAFE_SOURCE_REVISION",
    "source_dirty_file_count": "QSAFE_SOURCE_DIRTY",
    "build_mode": "QSAFE_BUILD_MODE",
    "compiler": "QSAFE_COMPILER",
    "os": "QSAFE_OS",
    "cpu": "QSAFE_CPU",
    "liboqs": "QSAFE_LIBOQS",
    "isa_l": "QSAFE_ISAL",
    "openssl": "QSAFE_OPENSSL",
    "ml_dsa_algorithm": "QSAFE_ALGORITHM",
    "python": "QSAFE_PYTHON",
    "size_mb": "QSAFE_SIZE_MB",
    "repetitions": "QSAFE_REPETITIONS",
    "rounds": "QSAFE_ROUNDS",
    "fault_pattern": "QSAFE_PATTERN",
    "seed": "QSAFE_SEED",
    "sample_fraction": "QSAFE_SAMPLE_FRACTION",
    "random_corruption_fraction": "QSAFE_CORRUPTION_FRACTION",
    "risk_config_sha256": "QSAFE_RISK_CONFIG_SHA256",
}
manifest = {key: os.environ.get(value, "") for key, value in fields.items()}
for field in ("size_mb", "repetitions", "rounds", "seed", "source_dirty_file_count"):
    manifest[field] = int(manifest[field])
for field in ("sample_fraction", "random_corruption_fraction"):
    manifest[field] = float(manifest[field])
with open(os.environ["QSAFE_MANIFEST_OUT"], "w", encoding="utf-8") as output:
    json.dump(manifest, output, indent=2)
    output.write("\n")
PY

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/qsafe-bench.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT
"$binary" --size-mb "$size_mb" --repetitions "$repetitions" --rounds "$rounds" \
  --pattern "$pattern" --seed "$seed" --sample-fraction "$sample_fraction" \
  --corruption-fraction "$corruption_fraction" --risk-config "$repo_root/config/risk.conf" \
  --work "$work_dir" > "$output_dir/benchmark.csv"

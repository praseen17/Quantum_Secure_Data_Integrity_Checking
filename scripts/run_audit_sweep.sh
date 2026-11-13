#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 5 ]]; then
  echo "usage: $0 OUTPUT_DIR SIZE_MB REPETITIONS ROUNDS PATTERN [SEED=20261112] [SAMPLE_FRACTIONS='0.01 0.025 0.05 0.1']" >&2
  exit 2
fi

output_dir=$(realpath -m "$1")
size_mb=$2
repetitions=$3
rounds=$4
pattern=$5
seed=${6:-20261112}
fractions=${7:-"0.01 0.025 0.05 0.1"}
mkdir -p "$output_dir"
combined="$output_dir/benchmark.csv"
first=1

for fraction in $fractions; do
  token=${fraction//./p}
  cell_dir="$output_dir/sample-$token"
  scripts/run_audit_benchmark.sh "$cell_dir" "$size_mb" "$repetitions" "$rounds" \
    "$pattern" "$seed" "$fraction" 0.02
  if [[ $first -eq 1 ]]; then
    cp "$cell_dir/benchmark.csv" "$combined"
    first=0
  else
    tail -n +2 "$cell_dir/benchmark.csv" >> "$combined"
  fi
done

python3 - "$output_dir/sweep_manifest.json" "$size_mb" "$repetitions" "$rounds" \
  "$pattern" "$seed" "$fractions" <<'PY'
import json
import sys

path, size, repetitions, rounds, pattern, seed, fractions = sys.argv[1:]
manifest = {
    "size_mb": int(size),
    "repetitions_per_cell": int(repetitions),
    "rounds_per_repetition": int(rounds),
    "fault_pattern": pattern,
    "seed": int(seed),
    "sample_fractions": [float(value) for value in fractions.split()],
    "cell_manifests": [
        f"sample-{value.replace('.', 'p')}/run_manifest.json"
        for value in fractions.split()
    ],
}
with open(path, "w", encoding="utf-8") as output:
    json.dump(manifest, output, indent=2)
    output.write("\n")
PY

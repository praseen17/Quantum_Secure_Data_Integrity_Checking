#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${QSAFE_BUILD_DIR:-"$repo_root/build/current"}
output_dir=${1:-"$(mktemp -d "${TMPDIR:-/tmp}/qsafe-demo.XXXXXX")"}
if [[ ! -x "$build_dir/qsafe_demo" ]]; then
  echo "Demo executable not found at $build_dir/qsafe_demo; run scripts/build.sh first." >&2
  exit 2
fi
exec "$build_dir/qsafe_demo" "$output_dir"

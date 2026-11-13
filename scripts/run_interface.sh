#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${QSAFE_BUILD_DIR:-"$repo_root/build/current"}
if [[ ! -x "$build_dir/qsafe_vault" ]]; then
  echo "Vault executable not found at $build_dir/qsafe_vault; run scripts/build.sh first." >&2
  exit 2
fi
exec python3 "$repo_root/interface/server.py" --binary "$build_dir/qsafe_vault" "$@"

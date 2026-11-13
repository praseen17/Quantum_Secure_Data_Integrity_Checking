#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${QSAFE_BUILD_DIR:-"$repo_root/build/current"}
cmake -S "$repo_root" -B "$build_dir" -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$repo_root/build/liboqs-install"
cmake --build "$build_dir" --parallel "${QSAFE_JOBS:-4}"
printf 'Build complete: %s\n' "$build_dir"

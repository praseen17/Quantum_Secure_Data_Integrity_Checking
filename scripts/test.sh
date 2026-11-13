#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${QSAFE_BUILD_DIR:-"$repo_root/build/current"}
if [[ ! -f "$build_dir/CTestTestfile.cmake" ]]; then
  echo "No configured build at $build_dir; run scripts/build.sh first." >&2
  exit 2
fi
cmake --build "$build_dir" --parallel "${QSAFE_JOBS:-4}"
ctest --test-dir "$build_dir" --output-on-failure

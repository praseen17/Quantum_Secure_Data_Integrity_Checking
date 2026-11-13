#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_prefix="${1:-${repo_root}/build/liboqs-install}"
source_dir="${repo_root}/build/liboqs-src"
build_dir="${repo_root}/build/liboqs-build"
version="0.16.0"

if [[ ! -d "${source_dir}/.git" ]]; then
  git clone --depth 1 --branch "${version}" https://github.com/open-quantum-safe/liboqs.git "${source_dir}"
fi

cmake -S "${source_dir}" -B "${build_dir}" -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="${install_prefix}" \
  -DOQS_DIST_BUILD=ON \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65"
cmake --build "${build_dir}" --parallel
cmake --install "${build_dir}"

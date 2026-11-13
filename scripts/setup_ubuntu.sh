#!/usr/bin/env bash
set -euo pipefail

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
else
  echo "Cannot identify Linux distribution (/etc/os-release missing)." >&2
  exit 1
fi
if [[ "${ID:-}" != ubuntu ]]; then
  echo "This setup helper supports Ubuntu; detected ${PRETTY_NAME:-unknown}." >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build git pkg-config \
  libssl-dev libsqlite3-dev libisal-dev python3 python3-venv python3-pip \
  python3-dev curl ca-certificates

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
"$repo_root/scripts/build_liboqs.sh"
python3 -m venv "$repo_root/analysis/.venv"
"$repo_root/analysis/.venv/bin/python" -m pip install \
  -r "$repo_root/requirements-analysis.txt"

echo "Dependencies installed. Configure and build with scripts/build.sh."

#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd -P)"
exec bash "$script_dir/check-daemon-network-boundary.sh" "$@"

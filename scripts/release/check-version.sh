#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
source "$root/scripts/release/common.sh"
[[ $# -le 1 ]] || { release_fail 'usage: check-version.sh [v<version>]'; exit 2; }
release_version "$root" "${1:-}"

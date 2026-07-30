#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd -P)"
runner="$repo_root/scripts/run-relay-web-companion-e2e.sh"

bash -n "$runner"

if "$runner" --unknown >/dev/null 2>&1; then
  printf 'runner accepted an unknown mode\n' >&2
  exit 1
fi

if "$runner" >/dev/null 2>&1; then
  printf 'runner accepted a missing mode\n' >&2
  exit 1
fi

printf 'run-relay-web-companion-e2e contract: PASS\n'

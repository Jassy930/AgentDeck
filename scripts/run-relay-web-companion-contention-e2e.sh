#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
AGENTDECK_W3_CONTENTION=1 \
  exec bash "$repo_root/scripts/run-relay-web-companion-pairing-e2e.sh" --durable

#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
runner="$repo_root/scripts/run-relay-web-companion-pairing-e2e.sh"

for network_fault in disconnect delay relayRestart; do
  AGENTDECK_W3_NETWORK_FAULT="$network_fault" bash "$runner" --durable
done

printf '%s\n' '{"schemaVersion":1,"gate":"relay-web-companion-w3.5","status":"PASS","networkFaults":["disconnect","delay","relayRestart"],"byteTransparentProxy":true,"externalPhysicalPublicEvidence":"BLOCKED"}'

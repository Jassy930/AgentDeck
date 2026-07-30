#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
runner="$repo_root/scripts/run-relay-web-companion-pairing-e2e.sh"

for browser_kill_cut in prompt approval reconnect; do
  AGENTDECK_W3_BROWSER_KILL_CUT="$browser_kill_cut" bash "$runner" --durable
done

printf '%s\n' '{"schemaVersion":1,"gate":"relay-web-companion-w3.4","status":"PASS","browserKillCuts":["prompt","approval","reconnect"],"killSignal":"SIGKILL","sameProfileColdRecovered":true,"externalPhysicalPublicEvidence":"BLOCKED"}'

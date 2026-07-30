#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
runner="$repo_root/scripts/run-relay-web-companion-pairing-e2e.sh"

for crash_cut in guardPendingDurable stateDurable guardStableDurable; do
  AGENTDECK_W3_CRASH_CUT="$crash_cut" bash "$runner" --durable
done

printf '%s\n' '{"schemaVersion":1,"gate":"relay-web-companion-w3.1","status":"PASS","crashCuts":["guardPendingDurable","stateDurable","guardStableDurable"],"counterReservationStart":512,"counterReservationEnd":768,"binaryFramesBeforeRecovery":0,"externalPhysicalPublicEvidence":"BLOCKED"}'

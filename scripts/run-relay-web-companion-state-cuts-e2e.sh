#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
runner="$repo_root/scripts/run-relay-web-companion-pairing-e2e.sh"
web_root="$repo_root/web/relay-test-companion"

for state_cut in stateGuardPendingDurable stateDurable guardStableDurable; do
  AGENTDECK_W3_STATE_CUT="$state_cut" bash "$runner" --durable
done

(
  cd "$web_root"
  AGENTDECK_WEB_CORE_FEATURES=w2-test-fixture \
    bun run test:browser:built -- --grep 'W3.2 statePending sibling'
)

printf '%s\n' '{"schemaVersion":1,"gate":"relay-web-companion-w3.2","status":"PASS","stateCuts":["stateGuardPendingDurable","stateDurable","guardStableDurable"],"recovery":["statePendingPreviousRetried","statePendingNextFinalized","stableExact"],"siblingForkQuarantined":true,"binaryFramesBeforeRecovery":0,"externalPhysicalPublicEvidence":"BLOCKED"}'

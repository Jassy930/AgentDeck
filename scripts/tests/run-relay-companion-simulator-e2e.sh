#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
runner="$repo_root/scripts/run-relay-companion-simulator-e2e.sh"
ui_test="$repo_root/ios/AgentDeckMobileUITests/RelayCompanionUITests.swift"

fail() {
  printf 'relay companion simulator E2E contract: FAIL: %s\n' "$1" >&2
  exit 1
}

[[ -x "$runner" ]] || fail "missing executable runner: $runner"
[[ -f "$ui_test" ]] || fail "missing UI test: $ui_test"
command -v jq >/dev/null 2>&1 || fail "missing command: jq"

before_status="$(git -C "$repo_root" status --short --untracked-files=all)"
record="$(bash "$runner" --contract)"
after_status="$(git -C "$repo_root" status --short --untracked-files=all)"
[[ "$before_status" == "$after_status" ]] || fail "--contract mutated the repository"
[[ "$(printf '%s\n' "$record" | wc -l | tr -d ' ')" == "1" ]] \
  || fail "--contract must emit exactly one JSON line"
printf '%s\n' "$record" | jq -e '
  .schemaVersion == 1
  and .gate == "relay-companion-simulator-e2e"
  and .mode == "contract"
  and .status == "READY"
  and .mutations == 0
  and .topology == [
    "temp-direct-tls-relay",
    "single-agentdeckd-remotelink",
    "synthetic-vendor-adapter",
    "same-uid-local-pairing",
    "production-swift-relay-client",
    "ios-simulator"
  ]
  and (keys | sort) == ([
    "gate", "mode", "mutations", "schemaVersion", "status", "topology"
  ] | sort)
' >/dev/null || fail "--contract JSON does not match the frozen topology"

set +e
bash "$runner" --unsupported-contract-argument >/dev/null 2>&1
unsupported_rc=$?
set -e
[[ "$unsupported_rc" -eq 2 ]] || fail "unknown arguments must exit 2"

printf 'relay companion simulator E2E contract: PASS\n'

#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$repo_root"

if [[ $# -ne 1 || "$1" != 'p0' ]]; then
  printf 'usage: scripts/verify-relay-companion-mvp.sh p0\n' >&2
  exit 2
fi

run_gate() {
  local label="$1"
  shift
  printf 'RUN: %s\n' "$label"
  "$@"
  printf 'PASS: %s\n' "$label"
}

verify_ios() (
  cd "$repo_root/ios"
  xcodegen generate
  xcodebuild \
    -project AgentDeckMobile.xcodeproj \
    -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' \
    test
)

verify_schema_snapshot() {
  cargo run -q -p agentdeck-cli -- protocol schema \
    | diff - protocol/agentdeck/agentdeck-protocol.schema.json
}

verify_relay_data_not_in_status() {
  local status
  status="$(git status --short --untracked-files=all)"
  if printf '%s\n' "$status" | grep -F 'agentdeck-relay-data/' >/dev/null; then
    printf '%s\n' "$status" >&2
    printf 'agentdeck-relay-data/ must not appear in git status\n' >&2
    return 1
  fi
}

run_gate 'cargo test' cargo test
run_gate 'agentdeck-relay server,tls tests' \
  cargo test -p agentdeck-relay --features server,tls
run_gate 'Relay R1b hardening E2E' \
  cargo test -p agentdeck-relay --features server \
    --test r1b_hardening_e2e -- --test-threads=1
run_gate 'agentdeck-relay selfcheck' \
  cargo run -p agentdeck-relay --features server -- \
    --selfcheck --bootstrap-secret x
run_gate 'swift test' swift test
run_gate 'iOS Simulator tests' verify_ios
run_gate 'daemon no-net guard' bash scripts/check-daemon-no-net.sh
run_gate 'agent docs gate' scripts/verify-agent-docs.sh
run_gate 'local IPC schema snapshot' verify_schema_snapshot
run_gate 'agentdeck-relay-data git-status guard' verify_relay_data_not_in_status

printf 'verify-relay-companion-mvp p0: PASS\n'

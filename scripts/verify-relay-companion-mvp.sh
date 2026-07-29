#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$repo_root"

if [[ $# -ne 1 ]]; then
  printf 'usage: scripts/verify-relay-companion-mvp.sh <p0|p2|p3|p4-auto|p5>\n' >&2
  exit 2
fi

phase="$1"
case "$phase" in
  p0|p2|p3|p4-auto|p5) ;;
  *)
    printf 'usage: scripts/verify-relay-companion-mvp.sh <p0|p2|p3|p4-auto|p5>\n' >&2
    exit 2
    ;;
esac

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

verify_production_signed_slot() {
  local record
  record="$(scripts/verify-daemon-install.sh production-signed-slot)"
  [[ "$(printf '%s\n' "$record" | wc -l | tr -d ' ')" == 1 ]]
  printf '%s\n' "$record" | jq -e '
    .schemaVersion == 1
    and .gate == "production-signed-launchagent-roundtrip"
    and .phase == "post-MVP"
    and .status == "BLOCKED"
    and .reasonCode == "missing_external_signing_prerequisites"
    and .missingInputs == [
      "matching-provisioning-profile",
      "disposable-signed-test-account"
    ]
    and .mutations == 0
    and .evidence == []
    and .summaryGenerated == false
    and (keys | sort) == ([
      "evidence", "gate", "missingInputs", "mutations", "phase",
      "reasonCode", "schemaVersion", "status", "summaryGenerated"
    ] | sort)
  ' >/dev/null
}

verify_external_blocked_slot() {
  local label="$1"
  local runner="$2"
  local expected_gate="$3"
  local expected_reason="$4"
  local record external_rc

  printf 'RUN: %s\n' "$label"
  set +e
  record="$("$runner" 2>&1)"
  external_rc=$?
  set -e
  if [[ "$external_rc" -ne 78 ]]; then
    printf '%s\n' "$record" >&2
    printf '%s must exit 78, got %s\n' "$label" "$external_rc" >&2
    return 1
  fi
  if [[ "$(printf '%s\n' "$record" | wc -l | tr -d ' ')" != '1' ]]; then
    printf '%s must emit exactly one JSON line\n' "$label" >&2
    return 1
  fi
  if ! printf '%s\n' "$record" | jq -e \
    --arg gate "$expected_gate" \
    --arg reasonCode "$expected_reason" '
      .schemaVersion == 1
      and .gate == $gate
      and .phase == "post-MVP"
      and .status == "BLOCKED"
      and .reasonCode == $reasonCode
      and (.missingInputs | type) == "array"
      and (.missingInputs | length) > 0
      and (.missingInputs | all(type == "string" and length > 0))
      and (.missingInputs | length) == (.missingInputs | unique | length)
      and .mutations == 0
      and .evidence == []
      and .summaryGenerated == false
      and .cleanup == {processesRemaining: 0, artifactsRemaining: 0}
      and (keys | sort) == ([
        "cleanup", "evidence", "gate", "missingInputs", "mutations", "phase",
        "reasonCode", "schemaVersion", "status", "summaryGenerated"
      ] | sort)
    ' >/dev/null; then
    printf '%s\n' "$record" >&2
    printf '%s emitted an invalid BLOCKED record\n' "$label" >&2
    return 1
  fi

  printf 'BLOCKED: %s (%s)\n' "$label" "$expected_reason"
}

verify_schema_snapshots() {
  cargo run -q -p agentdeck-cli -- protocol schema \
    | diff - protocol/agentdeck/agentdeck-protocol.schema.json
  cargo run -q -p agentdeck-cli -- protocol runtime-schema \
    | diff - protocol/agentdeck/runtime-protocol.schema.json
  cargo run -q -p agentdeck-cli -- protocol relay-schema \
    | diff - protocol/agentdeck/relay-v2.schema.json
  cargo run -q -p agentdeck-cli -- protocol e2ee-schema \
    | diff - protocol/agentdeck/e2ee-v1.schema.json
}

verify_relay_selfcheck() {
  local temp_root temp_dir receipt_signing_key status
  temp_root="${TMPDIR:-/tmp}"
  temp_root="${temp_root%/}"
  temp_dir="$(mktemp -d "$temp_root/agentdeck-relay-selfcheck.XXXXXX")"
  temp_dir="$(cd "$temp_dir" && pwd -P)"
  chmod 0700 "$temp_dir"
  receipt_signing_key="$temp_dir/receipt-signing-key.seed"
  dd if=/dev/urandom of="$receipt_signing_key" bs=32 count=1 2>/dev/null
  chmod 0600 "$receipt_signing_key"
  if cargo run -p agentdeck-relay --features server,tls -- \
    --selfcheck \
    --config agentdeck-relay/tests/fixtures/relay-selfcheck.toml \
    --storage "$temp_dir/relay.db" \
    --receipt-signing-key "$receipt_signing_key"; then
    status=0
  else
    status=$?
  fi
  rm -rf "$temp_dir"
  return "$status"
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

verify_client_dependency_boundaries() {
  local package tree
  for package in agentdeck-cli agentdeck-relay-client; do
    tree="$(cargo tree -p "$package" -e normal)"
    case "$tree" in
      *"agentdeck-relay v"*|*axum*|*rusqlite*)
        printf '%s normal dependency tree includes Relay server/store code:\n' \
          "$package" >&2
        printf '%s\n' "$tree" >&2
        return 1
        ;;
    esac
  done
}

verify_v1_production_symbols_absent() {
  local pattern matches rc
  pattern='DataEnvelope::Plaintext|bootstrap_secret|RelayCredentials|FakeRelay|req_origin'
  if matches="$(rg -n --glob '*.rs' "$pattern" \
    agentdeck-protocol agentdeck-relay agentdeck-relay-client agentdeck-cli agentdeckd)"; then
    printf '%s\n' "$matches" >&2
    printf 'removed Relay v1 production symbol found\n' >&2
    return 1
  else
    rc=$?
    if [[ "$rc" -ne 1 ]]; then
      printf 'Relay v1 production symbol scan failed with status %s\n' "$rc" >&2
      return "$rc"
    fi
  fi
}

run_common_rust_gates() {
  run_gate 'cargo test' cargo test --locked
  run_gate 'agentdeck-relay server,tls complete matrix' \
    cargo test -p agentdeck-relay --features server,tls --locked
  run_gate 'agentdeck-relay v2 config selfcheck' verify_relay_selfcheck
  run_gate 'daemon network boundary guard' bash scripts/check-daemon-network-boundary.sh
  run_gate 'four protocol schema snapshots' verify_schema_snapshots
  run_gate 'agent docs gate' scripts/verify-agent-docs.sh
  run_gate 'agentdeck-relay-data git-status guard' verify_relay_data_not_in_status
}

run_p0() {
  run_common_rust_gates
  run_gate 'swift test' swift test
  run_gate 'iOS Simulator tests' verify_ios
}

run_p2() {
  run_common_rust_gates
  run_gate 'Relay v2 hardening E2E' \
    cargo test -p agentdeck-relay --features server,tls --locked \
      --test relay_v2_hardening_e2e -- --test-threads=1
  run_gate 'Relay v2 production-ingress security sentinel' \
    cargo test -p agentdeck-relay --features server,tls --locked \
      --test relay_v2_security_e2e -- --test-threads=1 --nocapture
  run_gate 'Relay v2 outbound client' \
    cargo test -p agentdeck-relay-client --locked
  run_gate 'Relay v2 CLI DirectTLS/SPKI synthetic' \
    cargo test -p agentdeck-cli --locked \
      --test remote_v2_synthetic -- --test-threads=1
  run_gate 'client-only normal dependency boundaries' \
    verify_client_dependency_boundaries
  run_gate 'removed Relay v1 production symbols' \
    verify_v1_production_symbols_absent
}

run_p3() {
  run_common_rust_gates
  run_gate 'real local-runtime smoke' scripts/run-local-runtime-smoke.sh
  run_gate 'daemon install hermetic harness + signed BLOCKED contract' \
    scripts/verify-daemon-install.sh automatic
  run_gate 'production-signed post-MVP BLOCKED contract' \
    verify_production_signed_slot
  run_gate 'daemon package tests' cargo test -p agentdeckd --locked
  run_gate 'Swift shared-daemon tests' swift test
  run_gate 'AgentDeck diagnostics report' swift run AgentDeck -- --diagnostics-report --json
  run_gate 'iOS Simulator tests' verify_ios
}

run_p4_auto() {
  run_gate 'Relay v2 daemon machine synthetic E2E + persistent CLI high-level path' \
    cargo test -p agentdeckd --locked \
      --test relay_v2_machine_e2e -- --test-threads=1 --nocapture
  run_gate 'remote principal cannot confirm pairing' \
    cargo test -p agentdeckd --lib --locked \
      runtime::core::tests::pairing_administration_is_local_control_only_and_binds_create_owner \
      -- --exact --test-threads=1
  run_gate 'persistent CLI paired-state restart + real-slot contract' \
    cargo test -p agentdeck-cli --locked \
      --test e2e_remote_synthetic -- --test-threads=1 --nocapture
  run_gate 'persistent CLI current V6 signed-frame crash readback' \
    cargo test -p agentdeck-cli --locked \
      --test remote_live_key_update \
      directory_advance_crash_after_replay_commit_recovers_exact_signed_frame \
      -- --exact --test-threads=1
  run_gate 'daemon pairing state machine' \
    cargo test -p agentdeckd --locked \
      --test pairing_state_machine -- --test-threads=1
  run_gate 'daemon machine trust-reset state machine' \
    cargo test -p agentdeckd --locked \
      --test machine_trust_reset -- --test-threads=1
  run_gate 'remote CLI production composition boundary' \
    cargo test -p agentdeck-cli --locked \
      --test remote_production_composition -- --test-threads=1
  run_gate 'Relay v2 outbound client' \
    cargo test -p agentdeck-relay-client --locked
  run_gate 'remote protocol contract' \
    cargo test -p agentdeck-protocol --locked
  run_gate 'daemon network boundary guard' \
    bash scripts/check-daemon-network-boundary.sh
  run_gate 'four protocol schema snapshots' verify_schema_snapshots
  run_gate 'agent docs gate' scripts/verify-agent-docs.sh
}

run_p5() {
  run_gate 'Relay Companion Simulator runner contract' \
    bash scripts/tests/run-relay-companion-simulator-e2e.sh
  run_gate 'Relay Companion external BLOCKED slot contract' \
    bash scripts/tests/run-relay-companion-external-blocked.sh
  run_gate 'Relay Companion fixed-topology Simulator lifecycle' \
    bash scripts/run-relay-companion-simulator-e2e.sh
  run_gate 'Swift shared SessionSource tests' \
    swift test --filter AgentDeckSessionSourceTests
  run_gate 'Swift Relay client tests' \
    swift test --filter AgentDeckRelayClientTests
  run_gate 'agent docs gate' scripts/verify-agent-docs.sh
  verify_external_blocked_slot \
    'physical iPhone post-MVP slot' \
    scripts/run-relay-companion-ios-device-smoke.sh \
    'relay-companion-ios-device-smoke' \
    'missing_external_ios_device_prerequisites'
  verify_external_blocked_slot \
    'second Mac post-MVP slot' \
    scripts/run-relay-companion-macos-e2e.sh \
    'relay-companion-macos-e2e' \
    'missing_external_macos_e2e_prerequisites'
}

case "$phase" in
  p0) run_p0 ;;
  p2) run_p2 ;;
  p3) run_p3 ;;
  p4-auto) run_p4_auto ;;
  p5) run_p5 ;;
esac

if [[ "$phase" == 'p5' ]]; then
  printf 'verify-relay-companion-mvp p5: PASS (automatic scope; external slots remain BLOCKED)\n'
else
  printf 'verify-relay-companion-mvp %s: PASS\n' "$phase"
fi

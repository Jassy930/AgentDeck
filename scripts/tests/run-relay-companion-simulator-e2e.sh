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
command -v sed >/dev/null 2>&1 || fail "missing command: sed"

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

grep -Fq 'run_mode="full"' "$runner" \
  || fail "default entry must select the full lifecycle gate"
grep -Fq -- '--lifecycle-smoke) run_mode="lifecycle-smoke"' "$runner" \
  || fail "focused lifecycle-smoke entry is missing"
restart_command_block="$(
  sed -n '/restart_request="r44-restart-/,/could not send real daemon restart command to host/p' \
    "$runner"
)"
printf '%s\n' "$restart_command_block" | grep -Fq '"markerBeforeReadiness\":true' \
  || fail "daemon restart must commit the marker before base-readiness handoff"
grep -Fq 'testFullLifecycleReconnectAndRevoke' "$ui_test" \
  || fail "full production lifecycle UI test is missing"
grep -Fq 'private static let businessReadyUIWait: TimeInterval = 120' "$ui_test" \
  || fail "UI wait must outlive the 90-second host businessReady authority"
[[ "$(grep -Fc 'Self.businessReadyUIWait' "$ui_test")" == "3" ]] \
  || fail "machine-online, catalog and prompt-readiness waits must share the bounded businessReady UI wait"
grep -Fq 'let promptReady = NSPredicate(format: "enabled == true")' "$ui_test" \
  || fail "production prompt must remain disabled until the conversation snapshot is committed"
read_host_json_body="$(sed -n '/^read_host_json()/,/^}/p' "$runner")"
printf '%s\n' "$read_host_json_body" | grep -Fq 'fail_if_xcode_exited || return 1' \
  || fail "host waits must surface an exited xcodebuild before their own timeout"
cleanup_functions="$(
  for function_name in \
    pid_is_alive pid_is_zombie collect_owned_pid_tree pid_identity_matches \
    terminate_owned_pid wait_until_absent force_stop_host; do
    sed -n "/^${function_name}()/,/^}/p" "$runner"
  done
)"
[[ -n "$cleanup_functions" ]] || fail "runner cleanup functions are missing"
cleanup_probe_parent_pid=""
cleanup_probe_child_pid=""
cleanup_probe_root=""
cleanup_probe() {
  local probe_pid
  for probe_pid in "$cleanup_probe_child_pid" "$cleanup_probe_parent_pid"; do
    [[ "$probe_pid" =~ ^[0-9]+$ ]] || continue
    kill -KILL "$probe_pid" >/dev/null 2>&1 || true
  done
  if [[ "$cleanup_probe_parent_pid" =~ ^[0-9]+$ ]]; then
    wait "$cleanup_probe_parent_pid" >/dev/null 2>&1 || true
  fi
  case "$cleanup_probe_root" in
    /tmp/agentdeck-r4-cleanup-contract.*) rm -rf "$cleanup_probe_root" ;;
  esac
}
run_cleanup_probe() {
  local root_kind="$1"
  local cleanup_child_file
  local cleanup_child_pid
  local cleanup_child_state
  local cleanup_parent_pid
  local probe_cargo_pid=""
  local probe_host_pid=""
  cleanup_probe_root="$(mktemp -d /tmp/agentdeck-r4-cleanup-contract.XXXXXX)"
  cleanup_child_file="$cleanup_probe_root/term-resistant-child.pid"
  bash -c '
    (trap "" TERM; while :; do sleep 1; done) &
    printf "%s\n" "$!" >"$1"
    wait
  ' _ "$cleanup_child_file" 2>/dev/null &
  cleanup_parent_pid=$!
  cleanup_probe_parent_pid="$cleanup_parent_pid"
  for _ in 1 2 3 4 5; do
    [[ -s "$cleanup_child_file" ]] && break
    sleep 0.1
  done
  [[ -s "$cleanup_child_file" ]] || fail "cleanup probe did not expose its child PID"
  cleanup_child_pid="$(cat "$cleanup_child_file")"
  cleanup_probe_child_pid="$cleanup_child_pid"
  case "$root_kind" in
    cargo) probe_cargo_pid="$cleanup_parent_pid" ;;
    host) probe_host_pid="$cleanup_parent_pid" ;;
    *) fail "unknown cleanup probe root: $root_kind" ;;
  esac
  (
    eval "$cleanup_functions"
    cargo_pid="$probe_cargo_pid"
    host_pid="$probe_host_pid"
    force_stop_host
  )
  wait "$cleanup_parent_pid" >/dev/null 2>&1 || true
  cleanup_child_state="$(
    (ps -o stat= -p "$cleanup_child_pid" 2>/dev/null || true) | tr -d '[:space:]'
  )"
  if [[ -n "$cleanup_child_state" && "$cleanup_child_state" != Z* ]]; then
    fail "failure cleanup left a captured TERM-resistant descendant for $root_kind root"
  fi
  cleanup_probe
  cleanup_probe_parent_pid=""
  cleanup_probe_child_pid=""
  cleanup_probe_root=""
}
trap cleanup_probe EXIT
run_cleanup_probe cargo
run_cleanup_probe host
trap - EXIT
temporary_diag_marker='AGENTDECK_'"R44_DIAG"
temporary_artifact_marker='AGENTDECK_'"R44_KEEP_FAILURE_ARTIFACTS"
if grep -Fq "$temporary_diag_marker" "$runner"; then
  fail "completed lifecycle runner must not retain temporary R4.4 diagnostics"
fi
if grep -Fq "$temporary_artifact_marker" "$runner"; then
  fail "completed lifecycle runner must not retain private failure artifacts"
fi
if grep -Fq '"status":"INCOMPLETE"' "$runner"; then
  fail "completed lifecycle runner must not retain an INCOMPLETE success path"
fi

printf 'relay companion simulator E2E contract: PASS\n'

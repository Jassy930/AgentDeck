#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

emit_contract() {
  printf '%s\n' '{"schemaVersion":1,"gate":"relay-companion-simulator-e2e","mode":"contract","status":"READY","mutations":0,"topology":["temp-direct-tls-relay","single-agentdeckd-remotelink","synthetic-vendor-adapter","same-uid-local-pairing","production-swift-relay-client","ios-simulator"]}'
}

emit_incomplete() {
  printf '%s\n' '{"schemaVersion":1,"gate":"relay-companion-simulator-e2e","mode":"full","status":"INCOMPLETE","mutations":0,"availableModes":["contract","host-smoke","business-smoke"],"remaining":["relaunch-reconnect","revoke-terminal"]}'
}

usage_error() {
  printf 'usage: %s [--contract|--host-smoke|--business-smoke]\n' "$0" >&2
  exit 2
}

run_mode=""

case "$#" in
  0)
    emit_incomplete
    exit 1
    ;;
  1)
    case "$1" in
      --contract)
        emit_contract
        exit 0
        ;;
      --host-smoke) run_mode="host-smoke" ;;
      --business-smoke) run_mode="business-smoke" ;;
      *) usage_error ;;
    esac
    ;;
  *) usage_error ;;
esac

fail() {
  printf 'relay companion simulator E2E: FAIL: %s\n' "$1" >&2
  if [[ -n "${host_stderr:-}" && -f "$host_stderr" ]]; then
    printf '%s\n' 'host stderr tail:' >&2
    tail -n 80 "$host_stderr" >&2 || true
  fi
  if [[ -n "${host_transcript:-}" && -f "$host_transcript" ]]; then
    printf '%s\n' 'host stdout tail:' >&2
    tail -n 40 "$host_transcript" >&2 || true
  fi
  if [[ -n "${xcode_log:-}" && -f "$xcode_log" ]]; then
    if [[ -n "${xcode_result:-}" && -d "$xcode_result" ]]; then
      printf '%s\n' 'xcresult failure summary:' >&2
      xcrun xcresulttool get test-results tests --path "$xcode_result" --compact \
        2>/dev/null \
        | jq -r '
            .. | objects
            | select(.nodeType? == "Failure Message")
            | [(.name // "test failure"), (.details // "")]
            | join(": ")
          ' \
        | tail -n 20 >&2 || true
    fi
    printf '%s\n' 'private xcodebuild log removed by cleanup' >&2
  fi
  exit 1
}

for dependency in cargo env grep jq xcodebuild xcodegen xcrun mktemp chmod kill pgrep ps stat tail; do
  command -v "$dependency" >/dev/null 2>&1 \
    || fail "missing required command: $dependency"
done

umask 077
runner_root="$(mktemp -d /tmp/ar4.XXXXXX)"
runner_root="$(cd "$runner_root" && pwd -P)"
chmod 700 "$runner_root"
runner_generation="$(basename "$runner_root")"
host_input="$runner_root/host.stdin"
host_output="$runner_root/host.stdout"
host_stderr="$runner_root/host.stderr"
host_transcript="$runner_root/host-transcript.log"
xcode_log="$runner_root/xcodebuild.log"
xcode_result="$runner_root/RelayCompanionE2E.xcresult"
derived_data="$runner_root/DerivedData"

cargo_pid=""
host_pid=""
xcode_pid=""
host_root=""
host_invite=""
host_socket=""
simulator_udid=""
host_record=""
host_graceful=0
cleanup_started=0

pid_is_alive() {
  local pid="$1"
  [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1
}

pid_is_zombie() {
  local pid="$1"
  local state
  state="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  [[ "$state" == Z* ]]
}

terminate_owned_pid() {
  local pid="$1"
  local child
  [[ "$pid" =~ ^[0-9]+$ ]] || return 0
  for child in $(pgrep -P "$pid" 2>/dev/null || true); do
    terminate_owned_pid "$child"
  done
  if pid_is_alive "$pid"; then
    kill -TERM "$pid" >/dev/null 2>&1 || true
  fi
}

wait_until_absent() {
  local pid="$1"
  local timeout_seconds="$2"
  local deadline
  [[ "$pid" =~ ^[0-9]+$ ]] || return 0
  deadline=$(( $(date +%s) + timeout_seconds ))
  while pid_is_alive "$pid" && ! pid_is_zombie "$pid"; do
    if [[ "$(date +%s)" -ge "$deadline" ]]; then
      return 1
    fi
    sleep 0.1
  done
  return 0
}

force_stop_host() {
  if pid_is_alive "$cargo_pid"; then
    terminate_owned_pid "$cargo_pid"
    if ! wait_until_absent "$cargo_pid" 5; then
      local child
      for child in $(pgrep -P "$cargo_pid" 2>/dev/null || true); do
        kill -KILL "$child" >/dev/null 2>&1 || true
      done
      kill -KILL "$cargo_pid" >/dev/null 2>&1 || true
    fi
  elif pid_is_alive "$host_pid"; then
    terminate_owned_pid "$host_pid"
    if ! wait_until_absent "$host_pid" 5; then
      kill -KILL "$host_pid" >/dev/null 2>&1 || true
    fi
  fi
  if [[ -n "$cargo_pid" ]]; then
    wait "$cargo_pid" >/dev/null 2>&1 || true
  fi
}

force_stop_xcode() {
  if pid_is_alive "$xcode_pid"; then
    terminate_owned_pid "$xcode_pid"
    if ! wait_until_absent "$xcode_pid" 5; then
      kill -KILL "$xcode_pid" >/dev/null 2>&1 || true
    fi
  fi
  if [[ -n "$xcode_pid" ]]; then
    wait "$xcode_pid" >/dev/null 2>&1 || true
  fi
}

wait_for_xcode() {
  local deadline xcode_status
  deadline=$(( $(date +%s) + 300 ))
  while pid_is_alive "$xcode_pid" && ! pid_is_zombie "$xcode_pid"; do
    if [[ "$(date +%s)" -ge "$deadline" ]]; then
      terminate_owned_pid "$xcode_pid"
      wait_until_absent "$xcode_pid" 5 || kill -KILL "$xcode_pid" >/dev/null 2>&1 || true
      wait "$xcode_pid" >/dev/null 2>&1 || true
      fail "xcodebuild exceeded the 300 second hard deadline"
    fi
    sleep 0.1
  done
  set +e
  wait "$xcode_pid"
  xcode_status=$?
  set -e
  [[ "$xcode_status" -eq 0 ]] \
    || fail "production Companion UI test failed with exit $xcode_status"
  xcode_pid=""
}

read_host_json() {
  local expected_kind="$1"
  local expected_request_id="$2"
  local timeout_seconds="$3"
  local deadline line
  deadline=$(( $(date +%s) + timeout_seconds ))
  host_record=""
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    if IFS= read -r -t 1 line <&4; then
      printf '%s\n' "$line" >>"$host_transcript"
      if [[ "$line" == \{* ]] \
        && printf '%s\n' "$line" | jq -e \
          --arg kind "$expected_kind" \
          --arg request "$expected_request_id" \
          '.protocol == "agentdeck-p57-host/v1"
           and .kind == $kind
           and ($request == "" or .requestId == $request)' >/dev/null 2>&1; then
        host_record="$line"
        return 0
      fi
    elif [[ -n "$cargo_pid" ]] && ! pid_is_alive "$cargo_pid"; then
      return 1
    fi
  done
  return 1
}

send_host_command() {
  local command="$1"
  pid_is_alive "$cargo_pid" || return 1
  printf '%s\n' "$command" >&3
}

stop_simulator() {
  if [[ -z "$simulator_udid" ]]; then
    return 0
  fi
  xcrun simctl shutdown "$simulator_udid" >/dev/null 2>&1 || true
  xcrun simctl delete "$simulator_udid" >/dev/null 2>&1 || true
  simulator_udid=""
}

safe_remove_host_root() {
  case "$host_root" in
    "$runner_root"/ad-p57-host-*)
      rm -rf "$host_root"
      ;;
    "") ;;
    *)
      printf 'refusing to remove unexpected host root: %s\n' "$host_root" >&2
      ;;
  esac
}

cleanup() {
  local status=$?
  if [[ "$cleanup_started" -eq 1 ]]; then
    return
  fi
  cleanup_started=1

  force_stop_xcode
  stop_simulator
  if [[ "$host_graceful" -ne 1 ]]; then
    force_stop_host
  elif [[ -n "$cargo_pid" ]]; then
    wait "$cargo_pid" >/dev/null 2>&1 || true
  fi

  exec 3>&- || true
  exec 4>&- || true
  safe_remove_host_root
  rm -rf "$runner_root"
  return "$status"
}

handle_signal() {
  local status="$1"
  trap - EXIT HUP INT TERM
  cleanup
  exit "$status"
}

trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

mkfifo "$host_input" "$host_output"
exec 3<>"$host_input"
exec 4<>"$host_output"

printf '%s\n' "RUN: start existing real Relay/daemon host generation $runner_generation" >&2
host_environment=(
  "AGENTDECK_P57_HOST=1"
  "AGENTDECK_P57_HOST_PARENT=$runner_root"
)
if [[ "$run_mode" == "business-smoke" ]]; then
  host_environment+=("AGENTDECK_P57_HOST_SCENARIO=r43-business")
fi
env -u AGENTDECK_P57_HOST_SCENARIO "${host_environment[@]}" \
  cargo test -p agentdeckd --test relay_v2_machine_e2e \
  p57_real_dual_scope_ndjson_host -- \
  --ignored --exact --nocapture --test-threads=1 \
  <&3 >&4 2>"$host_stderr" &
cargo_pid=$!

read_host_json ready "" 240 \
  || fail "real host did not emit a valid ready record within 240 seconds"
printf '%s\n' "$host_record" >"$runner_root/host-ready.json"

host_pid="$(printf '%s\n' "$host_record" | jq -er '.pid')"
host_root="$(printf '%s\n' "$host_record" | jq -er '.rootPath')"
host_invite="$(printf '%s\n' "$host_record" | jq -er '.invitePath')"
host_socket="$(printf '%s\n' "$host_record" | jq -er '.socketPath')"
host_home="$(printf '%s\n' "$host_record" | jq -er '.homePath')"
runtime_db="$(printf '%s\n' "$host_record" | jq -er '.runtimeDatabasePath')"
relay_db="$(printf '%s\n' "$host_record" | jq -er '.relayDatabasePath')"

if [[ "$run_mode" == "business-smoke" ]]; then
  printf '%s\n' "$host_record" | jq -e '
    .scenario == "r43-business"
    and (.conversationId | type == "string" and length > 0)
    and .conversationTitle == "R4.3 synthetic Codex"
  ' >/dev/null || fail "R4.3 host ready record did not attest the business scenario"
else
  printf '%s\n' "$host_record" | jq -e '
    .scenario == null
    and .conversationId == null
    and .conversationTitle == null
  ' >/dev/null || fail "R4.2 host smoke unexpectedly enabled a business scenario"
fi

[[ "$host_pid" =~ ^[0-9]+$ ]] || fail "host ready PID is not numeric"
pid_is_alive "$cargo_pid" || fail "cargo wrapper exited after host ready"
pid_is_alive "$host_pid" || fail "real host PID exited after ready"
host_parent="$(ps -o ppid= -p "$host_pid" | tr -d '[:space:]')"
[[ "$host_parent" == "$cargo_pid" ]] \
  || fail "real host PID $host_pid is not owned by cargo wrapper $cargo_pid"
case "$host_root" in
  "$runner_root"/ad-p57-host-*) ;;
  *) fail "host root is outside the private host namespace: $host_root" ;;
esac
[[ -d "$host_root" && ! -L "$host_root" ]] || fail "host root is not a real directory"
[[ "$(stat -f '%Lp' "$host_root")" == "700" ]] || fail "host root mode is not 0700"
for owned_path in "$host_invite" "$host_socket" "$host_home" "$runtime_db" "$relay_db"; do
  case "$owned_path" in
    "$host_root"/*) ;;
    *) fail "host path escaped its owned root: $owned_path" ;;
  esac
done
[[ -f "$host_invite" && ! -L "$host_invite" ]] || fail "private invite is not a regular file"
[[ "$(stat -f '%Lp' "$host_invite")" == "600" ]] || fail "private invite mode is not 0600"
[[ "$(printf '%s\n' "$host_record" | jq -er '.inviteFileMode')" == "384" ]] \
  || fail "host ready did not attest invite mode 0600"
[[ -S "$host_socket" && ! -L "$host_socket" ]] || fail "Runtime endpoint is not a Unix socket"
[[ "$(stat -f '%Lp' "$host_socket")" == "600" ]] || fail "Runtime socket mode is not 0600"

device_type="$(xcrun simctl list devicetypes -j | jq -er \
  '.devicetypes[] | select(.name == "iPhone 17") | .identifier' | head -n 1)"
runtime_id="$(xcrun simctl list runtimes -j | jq -er \
  '[.runtimes[] | select(.platform == "iOS" and .isAvailable == true)] | last | .identifier')"
[[ -n "$device_type" && -n "$runtime_id" ]] \
  || fail "available iPhone 17 device type or iOS runtime is missing"
if [[ "$run_mode" == "business-smoke" ]]; then
  simulator_name="AgentDeck Relay R4.3 $runner_generation"
  selected_ui_test="testPairListOpenPromptApproval"
else
  simulator_name="AgentDeck Relay R4.2 $runner_generation"
  selected_ui_test="testPairingReachesLocalConfirmation"
fi
simulator_udid="$(xcrun simctl create "$simulator_name" "$device_type" "$runtime_id")"
[[ "$simulator_udid" =~ ^[0-9A-Fa-f-]{36}$ ]] || fail "simctl returned an invalid UDID"
xcrun simctl boot "$simulator_udid"
xcrun simctl bootstatus "$simulator_udid" -b

printf '%s\n' 'RUN: generate project and launch production Companion pairing UI' >&2
(
  cd "$repo_root/ios"
  xcodegen generate >/dev/null
)

set +e
xcodebuild \
  -project "$repo_root/ios/AgentDeckMobile.xcodeproj" \
  -scheme RelayCompanionE2E \
  -destination "platform=iOS Simulator,id=$simulator_udid" \
  -derivedDataPath "$derived_data" \
  -resultBundlePath "$xcode_result" \
  -parallel-testing-enabled NO \
  -test-timeouts-enabled YES \
  -default-test-execution-time-allowance 120 \
  -maximum-test-execution-time-allowance 180 \
  "-only-testing:AgentDeckMobileUITests/RelayCompanionUITests/$selected_ui_test" \
  AGENTDECK_RELAY_E2E_INVITE_PATH="$host_invite" \
  test >"$xcode_log" 2>&1 &
xcode_pid=$!
set -e

wait_request="pairing-pending-$runner_generation"
send_host_command \
  "{\"op\":\"waitFor\",\"requestId\":\"$wait_request\",\"condition\":\"pendingPairing\",\"timeoutMs\":120000}" \
  || fail "could not send pending-pairing readback to real host"
read_host_json waitFor "$wait_request" 140 \
  || fail "real host did not return pending-pairing readback"
printf '%s\n' "$host_record" | jq -e '
  .satisfied == true
  and .condition == "pendingPairing"
  and .evidence.pendingPairingCount == 1
  and .evidence.relayGrantTotal == 0
  and .evidence.relayGrantActive == 0
  and .evidence.runtimeCommandCount == 0
  and .evidence.socketIsUnix == true
  and .evidence.socketMode == 384
' >/dev/null || fail "pairing waiting state was not exact or authorization mutated early"
pending_record="$host_record"

if [[ "$run_mode" == "business-smoke" ]]; then
  approve_request="r43-approve-$runner_generation"
  send_host_command \
    "{\"op\":\"approvePendingPairing\",\"requestId\":\"$approve_request\"}" \
    || fail "could not send same-UID local pairing approval to real host"
  read_host_json approvePendingPairing "$approve_request" 40 \
    || fail "real host did not return local pairing approval readback"
  printf '%s\n' "$host_record" | jq -e '
    .evidence.pendingPairingCount == 0
    and .evidence.relayGrantTotal == 1
    and .evidence.relayGrantActive == 1
    and .evidence.runtimeCommandCount == 0
  ' >/dev/null || fail "local pairing approval did not create exactly one active grant"

  business_request="r43-business-ready-$runner_generation"
  send_host_command \
    "{\"op\":\"waitFor\",\"requestId\":\"$business_request\",\"condition\":\"businessReady\",\"timeoutMs\":30000}" \
    || fail "could not send business-ready wait to real host"
  read_host_json waitFor "$business_request" 40 \
    || fail "real host did not return business-ready readback"
  printf '%s\n' "$host_record" | jq -e '
    .satisfied == true
    and .condition == "businessReady"
    and .evidence.machineRemoteLifecycle == "active"
    and .evidence.pendingPairingCount == 0
    and .evidence.relayGrantTotal == 1
    and .evidence.relayGrantActive == 1
    and .evidence.activeTransitionCount == 0
    and .evidence.activeCatalogStreamCount == 1
  ' >/dev/null || fail "paired machine did not reach exact business-ready state"
fi

wait_for_xcode

business_record=""
if [[ "$run_mode" == "business-smoke" ]]; then
  status_request="r43-status-$runner_generation"
  send_host_command \
    "{\"op\":\"status\",\"requestId\":\"$status_request\"}" \
    || fail "could not send R4.3 business evidence readback to real host"
  read_host_json status "$status_request" 40 \
    || fail "real host did not return R4.3 business evidence"
  printf '%s\n' "$host_record" | jq -e '
    .evidence.machineRemoteLifecycle == "active"
    and .evidence.runtimeCommandCount == 1
    and .evidence.runtimeCompletedCommandCount == 1
    and .evidence.runtimeApprovalTotal == 1
    and .evidence.runtimeApprovalApplied == 1
  ' >/dev/null || fail "R4.3 prompt/approval did not produce exact Runtime evidence"
  business_record="$host_record"

  for relay_path in "$relay_db" "$relay_db-wal" "$relay_db-shm"; do
    [[ -f "$relay_path" ]] || continue
    for plaintext in \
      "R4.3 UI prompt sentinel" \
      "synthetic Codex response" \
      "synthetic codex approval"; do
      if grep -aFq "$plaintext" "$relay_path"; then
        fail "Relay persistence contains forbidden business plaintext"
      fi
    done
  done
fi

shutdown_request="shutdown-$runner_generation"
send_host_command \
  "{\"op\":\"shutdown\",\"requestId\":\"$shutdown_request\"}" \
  || fail "could not send graceful shutdown to real host"
read_host_json stopped "$shutdown_request" 45 \
  || fail "real host did not emit stopped readback"
printf '%s\n' "$host_record" | jq -e \
  '.inviteRemoved == true and .socketExists == false' >/dev/null \
  || fail "real host stopped without invite/socket cleanup proof"

if ! wait_until_absent "$host_pid" 30; then
  fail "real host PID remained after graceful stopped readback"
fi
set +e
wait "$cargo_pid"
cargo_status=$?
set -e
[[ "$cargo_status" -eq 0 ]] || fail "cargo host wrapper exited $cargo_status"
host_graceful=1
[[ ! -e "$host_invite" ]] || fail "private invite remains after host shutdown"
[[ ! -e "$host_socket" ]] || fail "Runtime socket remains after host shutdown"
[[ ! -e "$host_root" ]] || fail "host temp root remains after cargo host exit"

stop_simulator
simulator_count="$(xcrun simctl list devices -j | jq -r \
  --arg name "$simulator_name" '[.devices[][] | select(.name == $name)] | length')"
[[ "$simulator_count" == "0" ]] || fail "owned Simulator remains after delete"

pending_count="$(printf '%s\n' "$pending_record" | jq -er '.evidence.pendingPairingCount')"
grant_total="$(printf '%s\n' "$pending_record" | jq -er '.evidence.relayGrantTotal')"
grant_active="$(printf '%s\n' "$pending_record" | jq -er '.evidence.relayGrantActive')"

rm -rf "$runner_root"
cleanup_started=1
trap - EXIT HUP INT TERM
if [[ "$run_mode" == "business-smoke" ]]; then
  command_count="$(printf '%s\n' "$business_record" | jq -er '.evidence.runtimeCommandCount')"
  completed_count="$(printf '%s\n' "$business_record" | jq -er '.evidence.runtimeCompletedCommandCount')"
  approval_total="$(printf '%s\n' "$business_record" | jq -er '.evidence.runtimeApprovalTotal')"
  approval_applied="$(printf '%s\n' "$business_record" | jq -er '.evidence.runtimeApprovalApplied')"
  printf '{"schemaVersion":1,"gate":"relay-companion-simulator-e2e","mode":"business-smoke","status":"PASS","runtimeCommandCount":%s,"runtimeCompletedCommandCount":%s,"runtimeApprovalTotal":%s,"runtimeApprovalApplied":%s,"relayPlaintextAbsent":true,"cleanup":{"hostPidAbsent":true,"hostRootAbsent":true,"inviteAbsent":true,"socketAbsent":true,"simulatorAbsent":true}}\n' \
    "$command_count" "$completed_count" "$approval_total" "$approval_applied"
else
  printf '{"schemaVersion":1,"gate":"relay-companion-simulator-e2e","mode":"host-smoke","status":"PASS","pendingPairingCount":%s,"relayGrantTotal":%s,"relayGrantActive":%s,"cleanup":{"hostPidAbsent":true,"hostRootAbsent":true,"inviteAbsent":true,"socketAbsent":true,"simulatorAbsent":true}}\n' \
    "$pending_count" "$grant_total" "$grant_active"
fi

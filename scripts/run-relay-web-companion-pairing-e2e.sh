#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
web_root="$repo_root/web/relay-test-companion"
run_mode="pairing"
case "${1:-}" in
  "") ;;
  --business) run_mode="business" ;;
  --durable) run_mode="durable" ;;
  *) printf 'usage: %s [--business|--durable]\n' "$0" >&2; exit 64 ;;
esac
gate_label="W2a"
[[ "$run_mode" != "business" ]] || gate_label="W2b"
[[ "$run_mode" != "durable" ]] || gate_label="W2c"
crash_cut="${AGENTDECK_W3_CRASH_CUT:-}"
state_cut="${AGENTDECK_W3_STATE_CUT:-}"
contention_mode="${AGENTDECK_W3_CONTENTION:-0}"
browser_kill_cut="${AGENTDECK_W3_BROWSER_KILL_CUT:-}"
[[ "$contention_mode" == "0" || "$contention_mode" == "1" ]] \
  || { printf 'AGENTDECK_W3_CONTENTION must be 0 or 1\n' >&2; exit 64; }
case "$browser_kill_cut" in
  ""|prompt|approval|reconnect) ;;
  *) printf 'invalid AGENTDECK_W3_BROWSER_KILL_CUT: %s\n' "$browser_kill_cut" >&2; exit 64 ;;
esac
if (( (${#crash_cut} > 0) + (${#state_cut} > 0) + (contention_mode == 1) + (${#browser_kill_cut} > 0) > 1 )); then
  printf 'only one W3 fault family may be selected\n' >&2
  exit 64
fi
if [[ -n "$crash_cut" ]]; then
  [[ "$run_mode" == "durable" ]] \
    || { printf 'AGENTDECK_W3_CRASH_CUT requires --durable\n' >&2; exit 64; }
  case "$crash_cut" in
    guardPendingDurable|stateDurable|guardStableDurable) ;;
    *) printf 'invalid AGENTDECK_W3_CRASH_CUT: %s\n' "$crash_cut" >&2; exit 64 ;;
  esac
  gate_label="W3.1/$crash_cut"
fi
if [[ -n "$state_cut" ]]; then
  [[ "$run_mode" == "durable" ]] \
    || { printf 'AGENTDECK_W3_STATE_CUT requires --durable\n' >&2; exit 64; }
  case "$state_cut" in
    stateGuardPendingDurable|stateDurable|guardStableDurable) ;;
    *) printf 'invalid AGENTDECK_W3_STATE_CUT: %s\n' "$state_cut" >&2; exit 64 ;;
  esac
  gate_label="W3.2/$state_cut"
fi
if [[ "$contention_mode" == "1" ]]; then
  [[ "$run_mode" == "durable" ]] \
    || { printf 'AGENTDECK_W3_CONTENTION requires --durable\n' >&2; exit 64; }
  gate_label="W3.3/contention"
fi
if [[ -n "$browser_kill_cut" ]]; then
  [[ "$run_mode" == "durable" ]] \
    || { printf 'AGENTDECK_W3_BROWSER_KILL_CUT requires --durable\n' >&2; exit 64; }
  gate_label="W3.4/$browser_kill_cut"
fi

fail() {
  printf 'relay web companion %s: FAIL: %s\n' "$gate_label" "$1" >&2
  if [[ -n "${browser_log:-}" && -f "$browser_log" ]]; then
    tail -n 80 "$browser_log" >&2 || true
  fi
  if [[ -n "${host_stderr:-}" && -f "$host_stderr" ]]; then
    tail -n 80 "$host_stderr" >&2 || true
  fi
  if [[ -n "${host_transcript:-}" && -f "$host_transcript" ]]; then
    tail -n 40 "$host_transcript" >&2 || true
  fi
  exit 1
}

for dependency in bun cargo chmod date grep jq kill mkdir mkfifo mktemp mv pgrep ps rm sleep stat tail tr; do
  command -v "$dependency" >/dev/null 2>&1 || fail "missing dependency: $dependency"
done

umask 077
runner_root="$(mktemp -d /tmp/ar4.XXXXXX)"
runner_root="$(cd "$runner_root" && pwd -P)"
chmod 700 "$runner_root"
generation="$(basename "$runner_root")"
host_input="$runner_root/host.stdin"
host_output="$runner_root/host.stdout"
host_stderr="$runner_root/host.stderr"
host_transcript="$runner_root/host-transcript.log"
browser_log="$runner_root/browser.log"
coordination_dir="$runner_root/w2c-coordination"
profile_id="w2c-e2e"
mkdir -m 700 "$coordination_dir"

cargo_pid=""
host_pid=""
browser_pid=""
host_root=""
host_invite=""
host_socket=""
host_graceful=0
cleanup_started=0

pid_is_running() {
  local pid="$1"
  local state
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" >/dev/null 2>&1 || return 1
  state="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  [[ "$state" != Z* ]]
}

terminate_tree() {
  local pid="$1"
  local child
  [[ "$pid" =~ ^[0-9]+$ ]] || return 0
  for child in $(pgrep -P "$pid" 2>/dev/null || true); do
    terminate_tree "$child"
  done
  kill -TERM "$pid" >/dev/null 2>&1 || true
}

wait_until_absent() {
  local pid="$1"
  local deadline=$(( $(date +%s) + $2 ))
  while pid_is_running "$pid"; do
    [[ "$(date +%s)" -lt "$deadline" ]] || return 1
    sleep 0.1
  done
}

cleanup() {
  local status=$?
  [[ "$cleanup_started" -eq 0 ]] || return
  cleanup_started=1
  if pid_is_running "$browser_pid"; then
    terminate_tree "$browser_pid"
    wait_until_absent "$browser_pid" 5 || kill -KILL "$browser_pid" >/dev/null 2>&1 || true
  fi
  if [[ "$host_graceful" -ne 1 ]] && pid_is_running "$cargo_pid"; then
    terminate_tree "$cargo_pid"
    wait_until_absent "$cargo_pid" 5 || kill -KILL "$cargo_pid" >/dev/null 2>&1 || true
  fi
  [[ -z "$browser_pid" ]] || wait "$browser_pid" >/dev/null 2>&1 || true
  [[ -z "$cargo_pid" ]] || wait "$cargo_pid" >/dev/null 2>&1 || true
  exec 3>&- || true
  exec 4>&- || true
  case "$host_root" in
    "$runner_root"/ad-p57-host-*) rm -rf "$host_root" ;;
    "") ;;
    *) printf 'refusing unexpected host root cleanup: %s\n' "$host_root" >&2 ;;
  esac
  rm -rf "$web_root/test-results" "$runner_root"
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

read_host_json() {
  local expected_kind="$1"
  local expected_request_id="$2"
  local deadline=$(( $(date +%s) + $3 ))
  local fragment=""
  local pending_line=""
  local line=""
  host_record=""
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    fragment=""
    if IFS= read -r -t 1 fragment <&4; then
      line="$pending_line$fragment"
      pending_line=""
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
    else
      pending_line="$pending_line$fragment"
      if [[ -n "$cargo_pid" ]] && ! pid_is_running "$cargo_pid"; then
        return 1
      fi
      if [[ -n "$browser_pid" ]] && ! pid_is_running "$browser_pid" \
        && [[ "$expected_kind" != "stopped" && "$expected_kind" != "status" ]]; then
        return 1
      fi
    fi
  done
  return 1
}

send_host_command() {
  pid_is_running "$cargo_pid" || return 1
  printf '%s\n' "$1" >&3
}

(
  cd "$web_root"
  bun install --frozen-lockfile
  bun run check
  bun run build:w2
)

mkfifo "$host_input" "$host_output"
exec 3<>"$host_input"
exec 4<>"$host_output"

host_environment=(
  "AGENTDECK_P57_HOST=1"
  "AGENTDECK_P57_HOST_PARENT=$runner_root"
)
if [[ "$run_mode" == "business" ]]; then
  host_environment+=("AGENTDECK_P57_HOST_SCENARIO=r43-business")
elif [[ "$run_mode" == "durable" ]]; then
  host_environment+=("AGENTDECK_P57_HOST_SCENARIO=r44-lifecycle")
fi
env -u AGENTDECK_P57_HOST_SCENARIO "${host_environment[@]}" \
  cargo test -p agentdeckd --test relay_v2_machine_e2e \
  p57_real_dual_scope_ndjson_host -- \
  --ignored --exact --nocapture --test-threads=1 \
  <&3 >&4 2>"$host_stderr" &
cargo_pid=$!

read_host_json ready "" 240 || fail "real host did not emit ready"
host_pid="$(printf '%s\n' "$host_record" | jq -er '.pid')"
host_root="$(printf '%s\n' "$host_record" | jq -er '.rootPath')"
host_invite="$(printf '%s\n' "$host_record" | jq -er '.invitePath')"
host_socket="$(printf '%s\n' "$host_record" | jq -er '.socketPath')"
relay_db="$(printf '%s\n' "$host_record" | jq -er '.relayDatabasePath')"
relay_origin="$(printf '%s\n' "$host_record" | jq -er '.relayWssOrigin')"
relay_spki_pin="$(printf '%s\n' "$host_record" | jq -er '.relaySpkiPinBase64')"
host_parent="$(ps -o ppid= -p "$host_pid" 2>/dev/null | tr -d '[:space:]')"
[[ "$host_parent" == "$cargo_pid" ]] || fail "host PID is not owned by cargo wrapper"
web_port="$(bun -e '
  const server = Bun.serve({ port: 0, fetch() { return new Response("ok"); } });
  console.log(server.port);
  server.stop();
')"
[[ "$web_port" =~ ^[0-9]+$ ]] && [[ "$web_port" -ge 1 && "$web_port" -le 65535 ]] \
  || fail "could not reserve Web test port"

if [[ "$run_mode" == "business" || "$run_mode" == "durable" ]]; then
  expected_scenario="r43-business"
  [[ "$run_mode" != "durable" ]] || expected_scenario="r44-lifecycle"
  printf '%s\n' "$host_record" | jq -e --arg scenario "$expected_scenario" '
    .scenario == $scenario
    and .daemonGeneration == 1
    and (.conversationId | type == "string" and length > 0)
    and .conversationTitle == "R4.3 synthetic Codex"
    and (.relayWssOrigin | test("^wss://localhost:[0-9]+/$"))
    and (.relaySpkiPinBase64 | test("^[A-Za-z0-9+/]{43}=$"))
  ' >/dev/null \
    || fail "business host ready topology is not exact"
else
  printf '%s\n' "$host_record" | jq -e '
    .scenario == null
    and .daemonGeneration == 1
    and .conversationId == null
    and .conversationTitle == null
    and (.relayWssOrigin | test("^wss://localhost:[0-9]+/$"))
    and (.relaySpkiPinBase64 | test("^[A-Za-z0-9+/]{43}=$"))
  ' >/dev/null || fail "pairing host ready topology is not exact"
fi
case "$host_root" in "$runner_root"/ad-p57-host-*) ;; *) fail "host root escaped runner" ;; esac
[[ -f "$host_invite" && ! -L "$host_invite" ]] || fail "invite is not regular"
[[ "$(stat -f '%Lp' "$host_invite")" == "600" ]] || fail "invite mode is not 0600"
[[ -S "$host_socket" && ! -L "$host_socket" ]] || fail "Runtime endpoint is not Unix socket"
[[ "$(stat -f '%Lp' "$host_socket")" == "600" ]] || fail "Runtime socket mode is not 0600"

browser_grep="W2a real browser pairing"
[[ "$run_mode" != "business" ]] || browser_grep="W2b real browser business flow"
[[ "$run_mode" != "durable" ]] || browser_grep="W2c durable reload reconnect backfill and revoke"
[[ -z "$browser_kill_cut" ]] || browser_grep="W3.4 managed Chrome process kill cold-recovers"
(
  cd "$web_root"
  browser_environment=(
    "AGENTDECK_WEB_WSS_ORIGIN=$relay_origin"
    "AGENTDECK_WEB_TEST_SPKI_PIN=$relay_spki_pin"
    "AGENTDECK_W2_INVITE_PATH=$host_invite"
    "AGENTDECK_W2_COORDINATION_DIR=$coordination_dir"
    "AGENTDECK_W2_PROFILE_ID=$profile_id"
    "RELAY_WEB_TEST_PORT=$web_port"
  )
  [[ -z "$crash_cut" ]] || browser_environment+=("AGENTDECK_W3_CRASH_CUT=$crash_cut")
  [[ -z "$state_cut" ]] || browser_environment+=("AGENTDECK_W3_STATE_CUT=$state_cut")
  [[ "$contention_mode" != "1" ]] || browser_environment+=("AGENTDECK_W3_CONTENTION=1")
  if [[ -n "$browser_kill_cut" ]]; then
    browser_environment+=(
      "AGENTDECK_W3_BROWSER_KILL_CUT=$browser_kill_cut"
      "AGENTDECK_W3_BROWSER_PROFILE_ROOT=$runner_root/chrome-profile-$browser_kill_cut"
    )
  fi
  env "${browser_environment[@]}" \
    bun run test:browser:built -- \
    --grep "$browser_grep"
) >"$browser_log" 2>&1 &
browser_pid=$!

pending_request="w2a-pending-$generation"
send_host_command \
  "{\"op\":\"waitFor\",\"requestId\":\"$pending_request\",\"condition\":\"pendingPairing\",\"timeoutMs\":120000}" \
  || fail "could not request pending readback"
read_host_json waitFor "$pending_request" 140 || fail "pending readback failed"
printf '%s\n' "$host_record" | jq -e '
  .satisfied == true
  and .evidence.pendingPairingCount == 1
  and .evidence.relayGrantTotal == 0
  and .evidence.relayGrantActive == 0
  and .evidence.runtimeCommandCount == 0
' >/dev/null || fail "pre-approval state mutated"

approve_request="w2a-approve-$generation"
send_host_command \
  "{\"op\":\"approvePendingPairing\",\"requestId\":\"$approve_request\"}" \
  || fail "could not approve pairing"
read_host_json approvePendingPairing "$approve_request" 45 || fail "approval readback failed"
printf '%s\n' "$host_record" | jq -e '
  .evidence.pendingPairingCount == 0
  and .evidence.relayGrantTotal == 1
  and .evidence.relayGrantActive == 1
  and .evidence.runtimeCommandCount == 0
' >/dev/null || fail "approval did not create exact grant"

if [[ "$run_mode" == "business" || "$run_mode" == "durable" ]] \
  && [[ "$browser_kill_cut" != "prompt" ]]; then
  mutated_request="w2b-mutated-$generation"
  send_host_command \
    "{\"op\":\"waitFor\",\"requestId\":\"$mutated_request\",\"condition\":\"webBusinessMutated\",\"timeoutMs\":120000}" \
    || fail "could not request business mutation readback"
  read_host_json waitFor "$mutated_request" 140 || fail "business mutation readback failed"
  if ! printf '%s\n' "$host_record" | jq -e '
    .satisfied == true
    and .evidence.runtimeCommandCount == 1
    and .evidence.runtimeCompletedCommandCount == 1
    and .evidence.runtimeApprovalTotal == 1
    and .evidence.runtimeApprovalApplied == 1
    and .evidence.runtimeActiveWriterCount == 2
    and .evidence.runtimeLiveSubscriptionCount == 2
    and .evidence.runtimeBarrierSubscriptionCount == 0
    and .evidence.runtimeSnapshotSenderCount == 0
    and .evidence.runtimeSubscriptionJobCount == 2
  ' >/dev/null; then
    printf 'W2b mutation evidence: %s\n' "$host_record" >&2
    fail "browser business flow did not mutate exactly once"
  fi
fi

if [[ "$run_mode" == "durable" ]]; then
  coordination_deadline=$(( $(date +%s) + 150 ))
  while [[ ! -f "$coordination_dir/business.ready" ]]; do
    pid_is_running "$browser_pid" || fail "browser exited before durable checkpoint"
    [[ "$(date +%s)" -lt "$coordination_deadline" ]] \
      || fail "browser did not commit the durable business checkpoint"
    sleep 0.1
  done
  [[ ! -L "$coordination_dir/business.ready" ]] || fail "durable checkpoint is a symlink"
  [[ "$(stat -f '%Lp' "$coordination_dir/business.ready")" == "600" ]] \
    || fail "durable checkpoint mode is not 0600"

  restart_request="w2c-restart-$generation"
  send_host_command \
    "{\"op\":\"restartDaemon\",\"requestId\":\"$restart_request\",\"markerBeforeReadiness\":true}" \
    || fail "could not request daemon restart"
  read_host_json restartReady "$restart_request" 75 || fail "daemon base readiness failed"
  printf '%s\n' "$host_record" | jq -e '
    .evidence.daemonGeneration == 2
    and .metadataEntryRevision == 1
    and .evidence.machineRemoteLifecycle == "active"
    and .evidence.relayGrantActive == 1
  ' >/dev/null || fail "daemon base readiness was not exact"
  printf '%s\n' '{"markerBeforeReadiness":true}' >"$coordination_dir/restart.begin.tmp"
  chmod 600 "$coordination_dir/restart.begin.tmp"
  mv "$coordination_dir/restart.begin.tmp" "$coordination_dir/restart.begin"
  read_host_json restartDaemon "$restart_request" 90 || fail "daemon restart readback failed"
  printf '%s\n' "$host_record" | jq -e '
    .evidence.daemonGeneration == 2
    and .restartMarkerTitle == "R4.4 daemon restart marker"
    and .metadataEntryRevision == 1
    and .evidence.runtimeCommandCount == 1
    and .evidence.runtimeCompletedCommandCount == 1
    and .evidence.runtimeApprovalTotal == 1
    and .evidence.runtimeApprovalApplied == 1
    and .evidence.relayGrantActive == 1
  ' >/dev/null || fail "daemon restart did not preserve exact W2c state"
  restart_tmp="$coordination_dir/restart.done.tmp"
  printf '%s\n' "$host_record" | jq -c '{
    daemonGeneration: .evidence.daemonGeneration,
    restartMarkerTitle,
    metadataEntryRevision
  }' >"$restart_tmp"
  chmod 600 "$restart_tmp"
  mv "$restart_tmp" "$coordination_dir/restart.done"
fi

browser_timeout=150
[[ "$run_mode" != "durable" ]] || browser_timeout=220
browser_deadline=$(( $(date +%s) + browser_timeout ))
while pid_is_running "$browser_pid"; do
  [[ "$(date +%s)" -lt "$browser_deadline" ]] || fail "browser pairing exceeded deadline"
  sleep 0.1
done
set +e
wait "$browser_pid"
browser_status=$?
set -e
browser_pid=""
[[ "$browser_status" -eq 0 ]] || fail "browser pairing failed with exit $browser_status"
grep -Fq "1 passed" "$browser_log" || fail "browser did not report one passing $gate_label test"
if grep -aFq "agentdeck-pair:v1:" "$browser_log"; then
  fail "browser output leaked PairInvite"
fi
if [[ -n "$browser_kill_cut" ]]; then
  browser_kill_evidence="$coordination_dir/browser-kill.evidence.json"
  [[ -f "$browser_kill_evidence" && ! -L "$browser_kill_evidence" ]] \
    || fail "browser kill evidence is missing"
  [[ "$(stat -f '%Lp' "$browser_kill_evidence")" == "600" ]] \
    || fail "browser kill evidence mode is not 0600"
  expected_kill_revision=3
  expected_kill_counter_start=256
  expected_kill_counter_end=512
  if [[ "$browser_kill_cut" == "prompt" || "$browser_kill_cut" == "reconnect" ]]; then
    expected_kill_revision=5
    expected_kill_counter_start=512
    expected_kill_counter_end=768
  fi
  jq -e \
    --arg cut "$browser_kill_cut" \
    --argjson revision "$expected_kill_revision" \
    --argjson counterStart "$expected_kill_counter_start" \
    --argjson counterEnd "$expected_kill_counter_end" '
      .schemaVersion == 1
      and .cut == $cut
      and .signal == "SIGKILL"
      and .mainPidChanged == true
      and .sameProfileColdRecovered == true
      and .finalRevision == $revision
      and .counterReservationStart == $counterStart
      and .counterReservationEnd == $counterEnd
    ' "$browser_kill_evidence" >/dev/null \
    || fail "browser kill evidence is not exact"
fi
if [[ "$run_mode" != "pairing" ]] && grep -aEq \
  'web-w2b-prompt-7fb7f299|synthetic Codex response|synthetic codex approval|R4.4 daemon restart marker' "$browser_log"; then
  fail "browser output leaked business plaintext"
fi

status_request="w2a-status-$generation"
send_host_command "{\"op\":\"status\",\"requestId\":\"$status_request\"}" \
  || fail "could not request final status"
read_host_json status "$status_request" 45 || fail "final status readback failed"
if [[ "$run_mode" == "durable" ]]; then
  revoked_request="w2c-revoked-$generation"
  send_host_command \
    "{\"op\":\"waitFor\",\"requestId\":\"$revoked_request\",\"condition\":\"revoked\",\"timeoutMs\":120000}" \
    || fail "could not request revoke readback"
  read_host_json waitFor "$revoked_request" 140 || fail "revoke readback failed"
  printf '%s\n' "$host_record" | jq -e '
    .satisfied == true
    and .evidence.daemonGeneration == 2
    and .evidence.relayGrantTotal == 1
    and .evidence.relayGrantActive == 0
    and .evidence.runtimeRevokedAuthorizationCount == 1
    and .evidence.runtimeCommandCount == 1
    and .evidence.runtimeCompletedCommandCount == 1
    and .evidence.runtimeApprovalTotal == 1
    and .evidence.runtimeApprovalApplied == 1
  ' >/dev/null || fail "W2c revoke terminal did not settle exact host state"
elif [[ "$run_mode" == "business" ]]; then
  printf '%s\n' "$host_record" | jq -e '
    .evidence.machineRemoteLifecycle == "active"
    and .evidence.pendingPairingCount == 0
    and .evidence.relayGrantTotal == 1
    and .evidence.relayGrantActive == 1
    and .evidence.activeTransitionCount == 0
    and .evidence.activeCatalogStreamCount == 1
    and .evidence.runtimeCommandCount == 1
    and .evidence.runtimeCompletedCommandCount == 1
    and .evidence.runtimeApprovalTotal == 1
    and .evidence.runtimeApprovalApplied == 1
  ' >/dev/null || fail "business terminal did not settle exact host state"
else
  printf '%s\n' "$host_record" | jq -e '
    .evidence.machineRemoteLifecycle == "active"
    and .evidence.pendingPairingCount == 0
    and .evidence.relayGrantTotal == 1
    and .evidence.relayGrantActive == 1
    and .evidence.activeTransitionCount == 0
    and .evidence.activeCatalogStreamCount == 1
    and .evidence.runtimeCommandCount == 0
  ' >/dev/null || fail "paired terminal did not settle exact host state"
fi

for relay_path in "$relay_db" "$relay_db-wal" "$relay_db-shm"; do
  [[ -f "$relay_path" ]] || continue
  if grep -aFq "Relay Web Test Companion" "$relay_path"; then
    fail "Relay persistence contains Web device plaintext"
  fi
  if [[ "$run_mode" != "pairing" ]] && grep -aEq \
    'web-w2b-prompt-7fb7f299|synthetic Codex response|synthetic codex approval|R4.4 daemon restart marker' "$relay_path"; then
    fail "Relay persistence contains business plaintext"
  fi
done

shutdown_request="w2a-shutdown-$generation"
send_host_command "{\"op\":\"shutdown\",\"requestId\":\"$shutdown_request\"}" \
  || fail "could not request host shutdown"
read_host_json stopped "$shutdown_request" 45 || fail "host stopped readback failed"
printf '%s\n' "$host_record" | jq -e \
  '.inviteRemoved == true and .socketExists == false' >/dev/null \
  || fail "host cleanup proof is incomplete"
wait_until_absent "$host_pid" 30 || fail "host PID remains after stopped"
set +e
wait "$cargo_pid"
cargo_status=$?
set -e
[[ "$cargo_status" -eq 0 ]] || fail "host wrapper exited $cargo_status"
cargo_pid=""
host_graceful=1
[[ ! -e "$host_invite" ]] || fail "invite remains after shutdown"
[[ ! -e "$host_socket" ]] || fail "Runtime socket remains after shutdown"
[[ ! -e "$host_root" ]] || fail "host root remains after shutdown"
[[ ! -e "$web_root/test-results" ]] || fail "Playwright artifacts remain after PASS"

rm -rf "$runner_root"
cleanup_started=1
trap - EXIT HUP INT TERM
if [[ "$run_mode" == "durable" ]]; then
  durable_revision=3
  reservation_start=256
  reservation_end=512
  gate="relay-web-companion-w2c"
  if [[ -n "$crash_cut" ]]; then
    durable_revision=4
    reservation_start=512
    reservation_end=768
    gate="relay-web-companion-w3-crash-cut"
  elif [[ -n "$state_cut" ]]; then
    gate="relay-web-companion-w3-state-cut"
  elif [[ "$contention_mode" == "1" ]]; then
    gate="relay-web-companion-w3-contention"
  elif [[ -n "$browser_kill_cut" ]]; then
    gate="relay-web-companion-w3-browser-kill"
    if [[ "$browser_kill_cut" == "prompt" || "$browser_kill_cut" == "reconnect" ]]; then
      durable_revision=5
      reservation_start=512
      reservation_end=768
    fi
  fi
  jq -cn \
    --arg gate "$gate" \
    --arg crashCut "$crash_cut" \
    --arg stateCut "$state_cut" \
    --argjson writerContention "$contention_mode" \
    --arg browserKillCut "$browser_kill_cut" \
    --argjson durableRevision "$durable_revision" \
    --argjson counterReservationStart "$reservation_start" \
    --argjson counterReservationEnd "$reservation_end" \
    '{schemaVersion:1,gate:$gate,status:"PASS",crashCut:(if ($crashCut | length) > 0 then $crashCut else null end),stateCut:(if ($stateCut | length) > 0 then $stateCut else null end),writerContention:($writerContention == 1),browserKillCut:(if ($browserKillCut | length) > 0 then $browserKillCut else null end),daemonGeneration:2,durableRevision:$durableRevision,counterReservationStart:$counterReservationStart,counterReservationEnd:$counterReservationEnd,catalogBackfillObserved:true,runtimeCommandCount:1,runtimeCompletedCommandCount:1,runtimeApprovalTotal:1,runtimeApprovalApplied:1,runtimeRevokedAuthorizationCount:1,relayGrantActive:0,relayPlaintextAbsent:true,browserPlaintextAbsent:true,cleanup:{pairedMaterialAbsent:true,kekAbsent:true,revokedTombstonePresent:true,counterGuardAbsent:true,browserAbsent:true,hostPidAbsent:true,hostRootAbsent:true,inviteAbsent:true,socketAbsent:true,playwrightArtifactsAbsent:true}}'
elif [[ "$run_mode" == "business" ]]; then
  printf '%s\n' '{"schemaVersion":1,"gate":"relay-web-companion-w2b","status":"PASS","preConfirmNetworkLocked":true,"pendingPairingCount":0,"relayGrantTotal":1,"relayGrantActive":1,"activeTransitionCount":0,"activeCatalogStreamCount":1,"runtimeCommandCount":1,"runtimeCompletedCommandCount":1,"runtimeApprovalTotal":1,"runtimeApprovalApplied":1,"relayPlaintextAbsent":true,"browserPlaintextAbsent":true,"cleanup":{"browserAbsent":true,"hostPidAbsent":true,"hostRootAbsent":true,"inviteAbsent":true,"socketAbsent":true,"playwrightArtifactsAbsent":true}}'
else
  printf '%s\n' '{"schemaVersion":1,"gate":"relay-web-companion-w2a","status":"PASS","preConfirmNetworkLocked":true,"pendingPairingCount":0,"relayGrantTotal":1,"relayGrantActive":1,"activeTransitionCount":0,"activeCatalogStreamCount":1,"runtimeCommandCount":0,"relayPlaintextAbsent":true,"cleanup":{"browserAbsent":true,"hostPidAbsent":true,"hostRootAbsent":true,"inviteAbsent":true,"socketAbsent":true,"playwrightArtifactsAbsent":true}}'
fi

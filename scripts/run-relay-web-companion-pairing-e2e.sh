#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
web_root="$repo_root/web/relay-test-companion"

fail() {
  printf 'relay web companion W2a: FAIL: %s\n' "$1" >&2
  if [[ -n "${browser_log:-}" && -f "$browser_log" ]]; then
    tail -n 80 "$browser_log" >&2 || true
  fi
  if [[ -n "${host_stderr:-}" && -f "$host_stderr" ]]; then
    tail -n 80 "$host_stderr" >&2 || true
  fi
  exit 1
}

for dependency in bun cargo chmod date grep jq kill mkfifo mktemp pgrep ps rm sleep stat tail tr; do
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

AGENTDECK_P57_HOST=1 AGENTDECK_P57_HOST_PARENT="$runner_root" \
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

printf '%s\n' "$host_record" | jq -e '
  .scenario == null
  and .daemonGeneration == 1
  and (.relayWssOrigin | test("^wss://localhost:[0-9]+/$"))
  and (.relaySpkiPinBase64 | test("^[A-Za-z0-9+/]{43}=$"))
' >/dev/null || fail "host ready topology is not exact"
case "$host_root" in "$runner_root"/ad-p57-host-*) ;; *) fail "host root escaped runner" ;; esac
[[ -f "$host_invite" && ! -L "$host_invite" ]] || fail "invite is not regular"
[[ "$(stat -f '%Lp' "$host_invite")" == "600" ]] || fail "invite mode is not 0600"
[[ -S "$host_socket" && ! -L "$host_socket" ]] || fail "Runtime endpoint is not Unix socket"
[[ "$(stat -f '%Lp' "$host_socket")" == "600" ]] || fail "Runtime socket mode is not 0600"

(
  cd "$web_root"
  AGENTDECK_WEB_WSS_ORIGIN="$relay_origin" \
  AGENTDECK_WEB_TEST_SPKI_PIN="$relay_spki_pin" \
  AGENTDECK_W2_INVITE_PATH="$host_invite" \
  RELAY_WEB_TEST_PORT="$web_port" \
    bun run test:browser:built -- \
    --grep "W2a real browser pairing"
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

browser_deadline=$(( $(date +%s) + 150 ))
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
grep -Fq "1 passed" "$browser_log" || fail "browser did not report one passing W2a test"
if grep -aFq "agentdeck-pair:v1:" "$browser_log"; then
  fail "browser output leaked PairInvite"
fi

status_request="w2a-status-$generation"
send_host_command "{\"op\":\"status\",\"requestId\":\"$status_request\"}" \
  || fail "could not request final status"
read_host_json status "$status_request" 45 || fail "final status readback failed"
printf '%s\n' "$host_record" | jq -e '
  .evidence.machineRemoteLifecycle == "active"
  and .evidence.pendingPairingCount == 0
  and .evidence.relayGrantTotal == 1
  and .evidence.relayGrantActive == 1
  and .evidence.activeTransitionCount == 0
  and .evidence.activeCatalogStreamCount == 1
  and .evidence.runtimeCommandCount == 0
' >/dev/null || fail "paired terminal did not settle exact host state"

for relay_path in "$relay_db" "$relay_db-wal" "$relay_db-shm"; do
  [[ -f "$relay_path" ]] || continue
  if grep -aFq "Relay Web Test Companion" "$relay_path"; then
    fail "Relay persistence contains Web device plaintext"
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
printf '%s\n' '{"schemaVersion":1,"gate":"relay-web-companion-w2a","status":"PASS","preConfirmNetworkLocked":true,"pendingPairingCount":0,"relayGrantTotal":1,"relayGrantActive":1,"activeTransitionCount":0,"activeCatalogStreamCount":1,"runtimeCommandCount":0,"relayPlaintextAbsent":true,"cleanup":{"browserAbsent":true,"hostPidAbsent":true,"hostRootAbsent":true,"inviteAbsent":true,"socketAbsent":true,"playwrightArtifactsAbsent":true}}'

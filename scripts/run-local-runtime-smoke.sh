#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$repo_root"

fail() {
  printf 'P3.9-D local Runtime smoke: FAIL: %s\n' "$*" >&2
  if [[ -n "${daemon_stderr:-}" && -f "$daemon_stderr" ]]; then
    printf '%s\n' 'agentdeckd stderr:' >&2
    tail -n 80 "$daemon_stderr" >&2 || true
  fi
  exit 1
}

for dependency in cargo swift jq mktemp chmod kill find; do
  command -v "$dependency" >/dev/null 2>&1 \
    || fail "missing required command: $dependency"
done

# macOS sockaddr_un 只允许 103 个路径字节。系统 TMPDIR 本身经常很长，
# daemon 还会追加 `/ad-<UUID>/s`，因此真实 binary smoke 必须使用短的私有根。
smoke_root="$(mktemp -d /tmp/ads.XXXXXX)"
smoke_root="$(cd "$smoke_root" && pwd -P)"
chmod 700 "$smoke_root"
missing_root="$(mktemp -d /tmp/adm.XXXXXX)"
missing_root="$(cd "$missing_root" && pwd -P)"
chmod 700 "$missing_root"
expected_socket="$smoke_root/ad-00000000-0000-4000-8000-000000000000/s"
[[ "${#expected_socket}" -le 103 ]] \
  || fail "canonical smoke socket would exceed the macOS 103-byte limit"
daemon_pid=""
daemon_forced_kill=0
daemon_wait_status=0
daemon_stdout="$smoke_root/agentdeckd.stdout"
daemon_stderr="$smoke_root/agentdeckd.stderr"

stop_daemon() {
  if [[ -z "$daemon_pid" ]]; then
    return 0
  fi
  if kill -0 "$daemon_pid" >/dev/null 2>&1; then
    kill -TERM "$daemon_pid" >/dev/null 2>&1 || true
    local attempts=0
    while kill -0 "$daemon_pid" >/dev/null 2>&1 && [[ "$attempts" -lt 200 ]]; do
      sleep 0.1
      attempts=$((attempts + 1))
    done
    if kill -0 "$daemon_pid" >/dev/null 2>&1; then
      daemon_forced_kill=1
      kill -KILL "$daemon_pid" >/dev/null 2>&1 || true
    fi
  fi
  if wait "$daemon_pid" >/dev/null 2>&1; then
    daemon_wait_status=0
  else
    daemon_wait_status=$?
  fi
  daemon_pid=""
}

cleanup() {
  stop_daemon
  rm -rf "$smoke_root" "$missing_root"
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

assert_daemon_alive() {
  kill -0 "$daemon_pid" >/dev/null 2>&1 \
    || fail "shared daemon PID $daemon_pid exited while a client closed"
}

jsonl_value() {
  local expression="$1"
  local path="$2"
  jq -er "$expression" "$path" | tail -n 1
}

assert_command_ids() {
  local path="$1"
  local rust_command_id="$2"
  local swift_command_id="$3"
  local conversation_id="$4"
  jq -e \
    --arg rust "$rust_command_id" \
    --arg swift "$swift_command_id" \
    --arg conversation "$conversation_id" \
    'select(
       .ok == true
       and .syncComplete == true
       and .conversationId == $conversation
       and .snapshotCount == 1
       and .backfillCount > 0
     )
     | (.commandIds | index($rust)) != null
       and (.commandIds | index($swift)) != null' \
    "$path" >/dev/null 2>&1
}

printf '%s\n' 'RUN: build P3.9-D real binary smoke inputs'
cargo build -p agentdeckd -p agentdeck-cli
swift build

cargo_target="$(cargo metadata --format-version 1 --no-deps | jq -er '.target_directory')"
rust_cli="$cargo_target/debug/agentdeck"
daemon="$cargo_target/debug/agentdeckd"
swift_bin="$(swift build --show-bin-path)/AgentDeck"
for binary in "$rust_cli" "$daemon" "$swift_bin"; do
  [[ -x "$binary" ]] || fail "expected executable is absent: $binary"
done

rust_client() {
  "$rust_cli" --runtime-temp-root-for-test "$smoke_root" "$@"
}

swift_smoke() {
  local operation="$1"
  shift
  "$swift_bin" \
    --runtime-smoke-for-test "$operation" \
    --runtime-temp-root-for-test "$smoke_root" \
    "$@"
}

printf '%s\n' 'RUN: start one real ephemeral/no-remote shared daemon'
TMPDIR="$smoke_root/" "$daemon" \
  --ephemeral --no-remote --profile dev \
  >"$daemon_stdout" 2>"$daemon_stderr" &
daemon_pid=$!

ready_output="$smoke_root/rust-ping.json"
attempts=0
until rust_client ping >"$ready_output" 2>"$smoke_root/rust-ping.stderr"; do
  assert_daemon_alive
  attempts=$((attempts + 1))
  [[ "$attempts" -lt 300 ]] || fail 'shared Runtime UDS did not become ready in 30 seconds'
  sleep 0.1
done
jq -e '.ok == true' "$ready_output" >/dev/null \
  || fail 'Rust ping did not complete exactly one Hello handshake'
assert_daemon_alive

namespace_count="$(find "$smoke_root" -mindepth 1 -maxdepth 1 -type d -name 'ad-*' | wc -l | tr -d '[:space:]')"
[[ "$namespace_count" == "1" ]] \
  || fail "expected one private Runtime namespace, observed $namespace_count"

printf '%s\n' 'RUN: real Rust and Swift selfcheck against the same discovered endpoint'
rust_client selfcheck >"$smoke_root/rust-selfcheck.jsonl"
"$swift_bin" --selfcheck --runtime-temp-root-for-test "$smoke_root" \
  >"$smoke_root/swift-selfcheck.json" 2>"$smoke_root/swift-selfcheck.stderr"
jq -e '.ok == true' "$smoke_root/rust-selfcheck.jsonl" >/dev/null \
  || fail 'Rust selfcheck did not return canonical agents'
jq -e '.ok == true and .reply == "selfcheck"' "$smoke_root/swift-selfcheck.json" >/dev/null \
  || fail 'Swift selfcheck did not return canonical agents'
assert_daemon_alive

printf '%s\n' 'RUN: persist two distinct installation identities across client restarts'
rust_client runtime-smoke-for-test installation >"$smoke_root/rust-installation-1.json"
swift_smoke installation >"$smoke_root/swift-installation-1.json"
rust_installation="$(jsonl_value '.installationId' "$smoke_root/rust-installation-1.json")"
swift_installation="$(jsonl_value '.installationId' "$smoke_root/swift-installation-1.json")"
[[ "$rust_installation" != "$swift_installation" ]] \
  || fail 'Rust and Swift clients reused one installation identity'
assert_daemon_alive

printf '%s\n' 'RUN: prebuild a Ready snapshot before either prompt exists'
missing_cwd="$smoke_root/intentionally-absent-cwd"
prewarm_key="p39d-prewarm-$daemon_pid"
rust_client session run \
  --agent codex \
  --cwd "$missing_cwd" \
  --prompt '' \
  --idempotency-key "$prewarm_key" \
  >"$smoke_root/prewarm.jsonl"
conversation_id="$(jsonl_value 'select(.reply == "conversationStart") | .conversationId' "$smoke_root/prewarm.jsonl")"
configuration_revision="$(jsonl_value 'select(.reply == "configuration") | .configurationRevision' "$smoke_root/prewarm.jsonl")"
[[ "$configuration_revision" == "1" ]] \
  || fail "prewarm configuration revision is $configuration_revision, expected 1"
assert_daemon_alive

printf '%s\n' 'RUN: Rust and Swift owners submit separate commands to one conversation'
rust_prompt_key="p39d-rust-prompt-$daemon_pid"
swift_prompt_key="p39d-swift-prompt-$daemon_pid"
rust_client session continue \
  --conversation-id "$conversation_id" \
  --prompt 'Rust owner smoke prompt' \
  --idempotency-key "$rust_prompt_key" \
  >"$smoke_root/rust-send.jsonl"
rust_command_id="$(jsonl_value 'select(.reply == "command") | .commandId' "$smoke_root/rust-send.jsonl")"
jq -e 'select(.reply == "command" and .status == "accepted")' \
  "$smoke_root/rust-send.jsonl" >/dev/null \
  || fail 'Rust first SendPrompt did not return Accepted'
assert_daemon_alive

swift_smoke send-prompt \
  --conversation-id "$conversation_id" \
  --idempotency-key "$swift_prompt_key" \
  --expected-configuration-revision "$configuration_revision" \
  --prompt 'Swift owner smoke prompt' \
  >"$smoke_root/swift-send.json"
swift_command_id="$(jsonl_value 'select(.reply == "command") | .commandId' "$smoke_root/swift-send.json")"
jq -e '.reply == "command" and .status == "accepted"' \
  "$smoke_root/swift-send.json" >/dev/null \
  || fail 'Swift first SendPrompt did not return Accepted'
[[ "$rust_command_id" != "$swift_command_id" ]] \
  || fail 'Rust and Swift prompt receipts returned the same commandId'
assert_daemon_alive

printf '%s\n' 'RUN: restarted clients recover only their own durable receipt'
rust_client runtime-smoke-for-test query-receipt \
  --conversation-id "$conversation_id" \
  --idempotency-key "$rust_prompt_key" \
  >"$smoke_root/rust-own-receipt.json"
swift_smoke query-receipt \
  --conversation-id "$conversation_id" \
  --idempotency-key "$swift_prompt_key" \
  >"$smoke_root/swift-own-receipt.json"
rust_own_command="$(jq -er \
  --arg conversation "$conversation_id" \
  --argjson revision "$configuration_revision" \
  'select(
     .reply == "commandStatus"
     and .conversationId == $conversation
     and .configurationRevision == $revision
   ) | .commandId' \
  "$smoke_root/rust-own-receipt.json" | tail -n 1)"
swift_own_command="$(jq -er \
  --arg conversation "$conversation_id" \
  --argjson revision "$configuration_revision" \
  'select(
     .reply == "commandStatus"
     and .conversationId == $conversation
     and .configurationRevision == $revision
   ) | .commandId' \
  "$smoke_root/swift-own-receipt.json" | tail -n 1)"
[[ "$rust_own_command" == "$rust_command_id" ]] \
  || fail 'Rust restarted client did not recover its own command receipt'
[[ "$swift_own_command" == "$swift_command_id" ]] \
  || fail 'Swift restarted client did not recover its own command receipt'
assert_daemon_alive

printf '%s\n' 'RUN: restarted owners replay each exact SendPrompt without a second command'
rust_client runtime-smoke-for-test send-prompt \
  --conversation-id "$conversation_id" \
  --idempotency-key "$rust_prompt_key" \
  --expected-configuration-revision "$configuration_revision" \
  --prompt 'Rust owner smoke prompt' \
  >"$smoke_root/rust-replay.json"
swift_smoke send-prompt \
  --conversation-id "$conversation_id" \
  --idempotency-key "$swift_prompt_key" \
  --expected-configuration-revision "$configuration_revision" \
  --prompt 'Swift owner smoke prompt' \
  >"$smoke_root/swift-replay.json"
jq -e --arg command "$rust_command_id" \
  --argjson revision "$configuration_revision" \
  '.reply == "command" and .status == "replayed" and .commandId == $command
   and .configurationRevision == $revision' \
  "$smoke_root/rust-replay.json" >/dev/null \
  || fail 'Rust exact SendPrompt retry did not replay the original commandId'
jq -e --arg command "$swift_command_id" \
  --argjson revision "$configuration_revision" \
  '.reply == "command" and .status == "replayed" and .commandId == $command
   and .configurationRevision == $revision' \
  "$smoke_root/swift-replay.json" >/dev/null \
  || fail 'Swift exact SendPrompt retry did not replay the original commandId'
assert_daemon_alive

printf '%s\n' 'RUN: commandId selectors reject both cross-owner receipt queries'
if rust_client runtime-smoke-for-test query-receipt \
  --conversation-id "$conversation_id" \
  --command-id "$swift_command_id" \
  >"$smoke_root/rust-cross-owner.stdout" 2>"$smoke_root/rust-cross-owner.stderr"; then
  fail 'Rust client queried the Swift-owned receipt'
fi
jq -e '.error.code == "daemon.runtime.invalid_state"' \
  "$smoke_root/rust-cross-owner.stdout" >/dev/null \
  || fail 'Rust cross-owner query did not preserve the typed owner rejection'

if swift_smoke query-receipt \
  --conversation-id "$conversation_id" \
  --command-id "$rust_command_id" \
  >"$smoke_root/swift-cross-owner.stdout" 2>"$smoke_root/swift-cross-owner.stderr"; then
  fail 'Swift client queried the Rust-owned receipt'
fi
jq -e '.reply == "failure" and .code == "daemon.runtime.invalid_state"' \
  "$smoke_root/swift-cross-owner.stderr" >/dev/null \
  || fail 'Swift cross-owner query did not preserve the typed owner rejection'
assert_daemon_alive

printf '%s\n' 'RUN: both restarted clients observe both commands through one canonical stream'
deadline=$((SECONDS + 45))
observed=0
while [[ "$SECONDS" -lt "$deadline" ]]; do
  if rust_client runtime-smoke-for-test subscribe \
      --conversation-id "$conversation_id" \
      >"$smoke_root/rust-subscribe.json" 2>"$smoke_root/rust-subscribe.stderr" \
    && swift_smoke subscribe \
      --conversation-id "$conversation_id" \
      >"$smoke_root/swift-subscribe.json" 2>"$smoke_root/swift-subscribe.stderr" \
    && assert_command_ids "$smoke_root/rust-subscribe.json" "$rust_command_id" "$swift_command_id" "$conversation_id" \
    && assert_command_ids "$smoke_root/swift-subscribe.json" "$rust_command_id" "$swift_command_id" "$conversation_id"; then
    observed=1
    break
  fi
  assert_daemon_alive
  sleep 0.2
done
[[ "$observed" == "1" ]] \
  || fail 'both clients did not converge on the two commandIds within 45 seconds'
assert_daemon_alive

rust_client runtime-smoke-for-test installation >"$smoke_root/rust-installation-2.json"
swift_smoke installation >"$smoke_root/swift-installation-2.json"
[[ "$(jsonl_value '.installationId' "$smoke_root/rust-installation-2.json")" == "$rust_installation" ]] \
  || fail 'Rust installation identity changed across real client processes'
[[ "$(jsonl_value '.installationId' "$smoke_root/swift-installation-2.json")" == "$swift_installation" ]] \
  || fail 'Swift installation identity changed across real client processes'
[[ "$(jsonl_value '.installationId' "$smoke_root/rust-subscribe.json")" == "$rust_installation" ]] \
  || fail 'Rust stream observation used another installation identity'
[[ "$(jsonl_value '.installationId' "$smoke_root/swift-subscribe.json")" == "$swift_installation" ]] \
  || fail 'Swift stream observation used another installation identity'
assert_daemon_alive

printf '%s\n' 'RUN: missing endpoint is typed and never falls back to spawning a daemon'
if "$rust_cli" --runtime-temp-root-for-test "$missing_root" ping \
  >"$missing_root/rust.stdout" 2>"$missing_root/rust.stderr"; then
  fail 'Rust missing-endpoint probe unexpectedly succeeded'
fi
jq -e '.error.code == "daemon.client.socket_missing"' "$missing_root/rust.stdout" >/dev/null \
  || fail 'Rust missing endpoint did not return daemon.client.socket_missing'
if "$swift_bin" --selfcheck --runtime-temp-root-for-test "$missing_root" \
  >"$missing_root/swift.stdout" 2>"$missing_root/swift.stderr"; then
  fail 'Swift missing-endpoint probe unexpectedly succeeded'
fi
jq -e '.code == "daemon.client.socket_missing"' "$missing_root/swift.stderr" >/dev/null \
  || fail 'Swift missing endpoint did not return daemon.client.socket_missing'
missing_namespaces="$(find "$missing_root" -mindepth 1 -maxdepth 1 -type d -name 'ad-*' | wc -l | tr -d '[:space:]')"
[[ "$missing_namespaces" == "0" ]] \
  || fail 'missing-endpoint probes spawned a fallback daemon namespace'
assert_daemon_alive

shared_pid="$daemon_pid"
stop_daemon
[[ "$daemon_forced_kill" == "0" ]] \
  || fail 'shared daemon required SIGKILL instead of graceful SIGTERM shutdown'
[[ "$daemon_wait_status" == "0" ]] \
  || fail "shared daemon exited with status $daemon_wait_status during graceful shutdown"
remaining_sockets="$(find "$smoke_root" -mindepth 2 -maxdepth 2 -type s -name s | wc -l | tr -d '[:space:]')"
[[ "$remaining_sockets" == "0" ]] \
  || fail 'shared daemon left its Runtime socket behind after SIGTERM'

jq -n \
  --arg conversationId "$conversation_id" \
  --arg rustCommandId "$rust_command_id" \
  --arg swiftCommandId "$swift_command_id" \
  --arg rustInstallationId "$rust_installation" \
  --arg swiftInstallationId "$swift_installation" \
  --argjson daemonPid "$shared_pid" \
  '{
    ok: true,
    phase: "P3.9-D",
    daemonPid: $daemonPid,
    conversationId: $conversationId,
    commandIds: [$rustCommandId, $swiftCommandId],
    installationIds: [$rustInstallationId, $swiftInstallationId],
    ownerScopedReceipts: true,
    sharedRuntimeConverged: true,
    fallbackSpawned: false
  }'

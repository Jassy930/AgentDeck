#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$repo_root"

mode="${1:-automatic}"
case "$mode" in
  automatic|production-signed-slot) ;;
  *)
    printf 'usage: scripts/verify-daemon-install.sh [automatic|production-signed-slot]\n' >&2
    exit 2
    ;;
esac

blocked_contract() {
  printf '%s\n' '{"schemaVersion":1,"gate":"production-signed-launchagent-roundtrip","phase":"post-MVP","status":"BLOCKED","reasonCode":"missing_external_signing_prerequisites","missingInputs":["matching-provisioning-profile","disposable-signed-test-account"],"mutations":0,"evidence":[],"summaryGenerated":false}'
}

if [[ "$mode" == 'production-signed-slot' ]]; then
  blocked_contract
  exit 0
fi

for dependency in awk cargo find jq kill mktemp readlink rg shasum; do
  command -v "$dependency" >/dev/null 2>&1 || {
    printf 'verify-daemon-install: missing dependency: %s\n' "$dependency" >&2
    exit 1
  }
done

private_tmp="$(mktemp -d "${TMPDIR:-/tmp}/agentdeck-daemon-install.XXXXXX")"
chmod 700 "$private_tmp"
runtime_root="$(mktemp -d /tmp/adu.XXXXXX)"
restart_root="$(mktemp -d /tmp/adr.XXXXXX)"
chmod 700 "$runtime_root" "$restart_root"
daemon_pid=''
daemon_stderr=''

stop_daemon() {
  if [[ -z "$daemon_pid" ]]; then
    return 0
  fi
  if kill -0 "$daemon_pid" >/dev/null 2>&1; then
    kill -TERM "$daemon_pid" >/dev/null 2>&1 || true
    local attempts=0
    while kill -0 "$daemon_pid" >/dev/null 2>&1 && [[ "$attempts" -lt 200 ]]; do
      sleep 0.05
      attempts=$((attempts + 1))
    done
    if kill -0 "$daemon_pid" >/dev/null 2>&1; then
      kill -KILL "$daemon_pid" >/dev/null 2>&1 || true
    fi
  fi
  wait "$daemon_pid" >/dev/null 2>&1 || true
  daemon_pid=''
}

cleanup() {
  stop_daemon
  rm -rf "$private_tmp" "$runtime_root" "$restart_root"
}
trap cleanup EXIT

fail() {
  printf 'verify-daemon-install: FAIL: %s\n' "$*" >&2
  if [[ -n "$daemon_stderr" && -f "$daemon_stderr" ]]; then
    tail -n 80 "$daemon_stderr" >&2 || true
  fi
  exit 1
}

plist_template='packaging/com.agentdeck.agentdeckd.plist.in'
entitlements_template='packaging/agentdeckd.entitlements.in'

[[ "$(rg -o '@LAUNCH_AGENT_LABEL_XML@' "$plist_template" | wc -l | tr -d ' ')" == '1' ]]
[[ "$(rg -o '@DAEMON_PROGRAM_XML@' "$plist_template" | wc -l | tr -d ' ')" == '1' ]]
[[ "$(rg -o '@DAEMON_KEYCHAIN_ACCESS_GROUP_XML@' "$entitlements_template" | wc -l | tr -d ' ')" == '1' ]]

sed \
  -e 's|@LAUNCH_AGENT_LABEL_XML@|com.agentdeck.agentdeckd|' \
  -e 's|@DAEMON_PROGRAM_XML@|/private/tmp/AgentDeck \&amp; Harness/current/agentdeckd|' \
  "$plist_template" | /usr/bin/plutil -lint - >/dev/null
sed \
  -e 's|@DAEMON_KEYCHAIN_ACCESS_GROUP_XML@|ABCDE12345.com.agentdeck.agentdeckd.stable|' \
  "$entitlements_template" | /usr/bin/plutil -lint - >/dev/null

rg -F 'APP_HELPERS="$APP_CONTENTS/Helpers"' script/build_and_run.sh >/dev/null
rg -F 'cp "$CLI_HELPER" "$APP_HELPERS/agentdeck"' script/build_and_run.sh >/dev/null
rg -F 'cp "$DAEMON_HELPER" "$APP_HELPERS/agentdeckd"' script/build_and_run.sh >/dev/null

AGENTDECK_DIST_DIR="$private_tmp/dist" ./script/build_and_run.sh --package
test -x "$private_tmp/dist/AgentDeck.app/Contents/Helpers/agentdeck"
test -x "$private_tmp/dist/AgentDeck.app/Contents/Helpers/agentdeckd"
"$private_tmp/dist/AgentDeck.app/Contents/Helpers/agentdeckd" --version >/dev/null
"$private_tmp/dist/AgentDeck.app/Contents/Helpers/agentdeck" --help >/dev/null

TMPDIR="$private_tmp" cargo test -p agentdeck-cli --locked daemon:: --lib
TMPDIR="$private_tmp" cargo test -p agentdeck-cli --locked --bin agentdeck daemon_cli_tests
TMPDIR="$private_tmp" cargo test -p agentdeck-cli --locked --test daemon_install -- --test-threads=1
TMPDIR="$private_tmp" cargo test -p agentdeckd --locked --lib \
  pending_upgrade_restart_requires_a_new_exact_flush_ack_before_switch -- --test-threads=1
TMPDIR="$private_tmp" cargo test -p agentdeckd --locked --lib \
  switched_pending_retry_finalizes_idempotently_and_completed_replay_is_inert -- --test-threads=1
TMPDIR="$private_tmp" cargo test -p agentdeckd --locked --lib \
  concurrent_acked_upgrades_switch_only_one_version_before_main_exit -- --test-threads=1
TMPDIR="$private_tmp" cargo test -p agentdeckd --locked --lib \
  stage_upgrade_arms_only_after_exact_flush_ack_and_survives_later_disconnect -- --test-threads=1
TMPDIR="$private_tmp" cargo test -p agentdeckd --locked --lib \
  durable_stage_waits_for_active_turn_then_switches_current_and_requests_main_exit -- --test-threads=1
TMPDIR="$private_tmp" cargo test -p agentdeckd --locked --lib \
  runtime::upgrade::tests:: -- --test-threads=1
TMPDIR="$private_tmp" cargo test -p agentdeckd --locked --test upgrade_idle -- --test-threads=1

printf '%s\n' 'RUN: real ephemeral UDS StageUpgrade through the CLI harness'
cargo build -p agentdeckd -p agentdeck-cli
target_dir="$(cargo metadata --format-version 1 --no-deps | jq -er '.target_directory')"
daemon="$target_dir/debug/agentdeckd"
rust_cli="$target_dir/debug/agentdeck"
test -x "$daemon"
test -x "$rust_cli"

daemon_stderr="$runtime_root/agentdeckd.stderr"
TMPDIR="$runtime_root/" "$daemon" --ephemeral --no-remote --profile dev \
  >"$runtime_root/agentdeckd.stdout" 2>"$daemon_stderr" &
daemon_pid=$!
attempts=0
until "$rust_cli" --runtime-temp-root-for-test "$runtime_root" ping \
  >"$runtime_root/ping.json" 2>"$runtime_root/ping.stderr"; do
  kill -0 "$daemon_pid" >/dev/null 2>&1 || fail 'ephemeral daemon exited before UDS readiness'
  attempts=$((attempts + 1))
  [[ "$attempts" -lt 300 ]] || fail 'ephemeral Runtime UDS was not ready in 15 seconds'
  sleep 0.05
done

namespace="$(find "$runtime_root" -mindepth 1 -maxdepth 1 -type d -name 'ad-*' -print -quit)"
[[ -n "$namespace" ]] || fail 'ephemeral Runtime namespace is absent'
version='p3.10-cli-uds'
mkdir -m 700 "$namespace/bin" "$namespace/bin/$version"
candidate="$namespace/bin/$version/agentdeckd"
cp "$daemon" "$candidate"
chmod 500 "$candidate"
candidate_sha256="$(shasum -a 256 "$candidate" | awk '{print $1}')"
test ! -e "$namespace/bin/current" || fail 'current changed before StageUpgrade request'
kill -0 "$daemon_pid" >/dev/null 2>&1 || fail 'daemon PID changed before StageUpgrade request'

"$rust_cli" --runtime-temp-root-for-test "$runtime_root" \
  runtime-smoke-for-test stage-upgrade \
  --target-version "$version" \
  --candidate-sha256 "$candidate_sha256" \
  --candidate-path "$candidate" \
  >"$runtime_root/stage-upgrade.json"
jq -e --arg version "$version" \
  '.daemon.version == $version
   and .daemon.runtimeAcked == true
   and (.daemon.state == "staged" or .daemon.state == "awaitingIdle")' \
  "$runtime_root/stage-upgrade.json" >/dev/null \
  || fail 'CLI did not read back the exact Runtime StageUpgrade receipt'

attempts=0
while kill -0 "$daemon_pid" >/dev/null 2>&1; do
  attempts=$((attempts + 1))
  [[ "$attempts" -lt 200 ]] || fail 'daemon did not exit after idle upgrade'
  sleep 0.05
done
if wait "$daemon_pid"; then
  daemon_pid=''
else
  status=$?
  daemon_pid=''
  fail "upgrade-triggered daemon exit status was $status"
fi
[[ "$(readlink "$namespace/bin/current")" == "$version" ]] \
  || fail 'bin/current did not switch to the exact staged version'

printf '%s\n' 'RUN: manually restart the daemon through bin/current'
daemon_stderr="$restart_root/agentdeckd.stderr"
TMPDIR="$restart_root/" "$namespace/bin/current/agentdeckd" \
  --ephemeral --no-remote --profile dev \
  >"$restart_root/agentdeckd.stdout" 2>"$daemon_stderr" &
daemon_pid=$!
attempts=0
until "$rust_cli" --runtime-temp-root-for-test "$restart_root" ping \
  >"$restart_root/ping.json" 2>"$restart_root/ping.stderr"; do
  kill -0 "$daemon_pid" >/dev/null 2>&1 || fail 'current-linked daemon exited before UDS readiness'
  attempts=$((attempts + 1))
  [[ "$attempts" -lt 300 ]] || fail 'current-linked Runtime UDS was not ready in 15 seconds'
  sleep 0.05
done
stop_daemon

blocked_contract
printf 'verify-daemon-install automatic: PASS\n'

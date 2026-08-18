#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

offline_root="$(mktemp -d "${TMPDIR:-/tmp}/agentdeck-offline-tests.XXXXXX")"
offline_bin="$offline_root/bin"
offline_home="$offline_root/home"
offline_marker="$offline_root/vendor-invoked"
source_home="${HOME:?HOME must be set before running the offline test gate}"
cargo_home_dir="${CARGO_HOME:-$source_home/.cargo}"
rustup_home_dir="${RUSTUP_HOME:-$source_home/.rustup}"

cleanup() {
  rm -rf "$offline_root"
}
trap cleanup EXIT

mkdir -p "$offline_bin" "$offline_home"

for vendor in codex claude; do
  printf '%s\n' \
    '#!/bin/sh' \
    ': "${AGENTDECK_OFFLINE_MARKER:?AGENTDECK_OFFLINE_MARKER is required}"' \
    'printf "vendor process executed\n" >> "$AGENTDECK_OFFLINE_MARKER"' \
    'exit 97' \
    >"$offline_bin/$vendor"
  chmod +x "$offline_bin/$vendor"
done

fail_if_vendor_ran() {
  local case_name="$1"
  if test -e "$offline_marker"; then
    printf 'verify-offline-tests: FAIL (%s): standard tests executed codex or claude\n' \
      "$case_name" >&2
    return 1
  fi
}

run_workspace_tests() {
  local case_name="$1"
  local e2e_value="$2"
  local -a environment=(
    "HOME=$offline_home"
    "CARGO_HOME=$cargo_home_dir"
    "RUSTUP_HOME=$rustup_home_dir"
    "PATH=$offline_bin:$PATH"
    "AGENTDECK_OFFLINE_MARKER=$offline_marker"
  )

  rm -f "$offline_marker"

  printf 'verify-offline-tests: running workspace tests (%s)\n' "$case_name"
  if test "$e2e_value" = "__unset__"; then
    if ! env -u AGENTDECK_E2E -u AGENTDECK_DAEMON_BIN "${environment[@]}" \
      cargo test --workspace --locked; then
      fail_if_vendor_ran "$case_name" || true
      return 1
    fi
  elif ! env -u AGENTDECK_DAEMON_BIN "${environment[@]}" \
    "AGENTDECK_E2E=$e2e_value" \
    cargo test --workspace --locked; then
    fail_if_vendor_ran "$case_name" || true
    return 1
  fi

  fail_if_vendor_ran "$case_name"
}

run_gated_integration_tests() {
  local case_name="$1"
  local e2e_value="$2"
  local -a environment=(
    "HOME=$offline_home"
    "CARGO_HOME=$cargo_home_dir"
    "RUSTUP_HOME=$rustup_home_dir"
    "PATH=$offline_bin:$PATH"
    "AGENTDECK_OFFLINE_MARKER=$offline_marker"
    "AGENTDECK_E2E=$e2e_value"
  )

  rm -f "$offline_marker"

  printf 'verify-offline-tests: running gated integration tests (%s)\n' "$case_name"
  if ! env -u AGENTDECK_DAEMON_BIN "${environment[@]}" \
    cargo test --locked -p agentdeck-cli \
      --test agent_subcommand_smoke \
      --test diagnostics_report_smoke \
      --test e2e_claude_code \
      --test e2e_codex \
      --test e2e_cross_agent_history \
      --test history_cross_agent_smoke; then
    fail_if_vendor_ran "$case_name" || true
    return 1
  fi

  if ! env -u AGENTDECK_DAEMON_BIN "${environment[@]}" \
    cargo test --locked -p agentdeckd \
      --test cc_adapter_shape \
      --test codex_adapter_shape \
      --test router_both_agents; then
    fail_if_vendor_ran "$case_name" || true
    return 1
  fi

  fail_if_vendor_ran "$case_name"
}

run_workspace_tests unset __unset__
run_workspace_tests zero 0
run_gated_integration_tests empty ""
run_gated_integration_tests false false
run_gated_integration_tests other other

printf 'verify-offline-tests: ok\n'

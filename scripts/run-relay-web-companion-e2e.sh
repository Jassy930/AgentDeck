#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd -P)"
web_root="$repo_root/web/relay-test-companion"

usage() {
  printf 'usage: %s --contract|--transport|--pairing|--business|--durable|--negative|--crash-cuts|--state-cuts|--recovery|--all\n' "$0" >&2
  exit 64
}

run_contract() {
  (
    cd "$web_root"
    bun install --frozen-lockfile
    bun run check
    bun run test:unit
  )
  (
    cd "$repo_root"
    cargo test -p agentdeck-web-core --features w1-test-fixture
    cargo build -p agentdeck-web-core --target wasm32-unknown-unknown \
      --features w1-test-fixture
  )
}

run_transport() {
  (
    cd "$web_root"
    bun install --frozen-lockfile
  )
  (
    cd "$repo_root"
    cargo test -p agentdeck-relay --features server,tls \
      --test relay_web_companion_w1_e2e -- --test-threads=1
  )
}

run_pairing() {
  bash "$repo_root/scripts/run-relay-web-companion-pairing-e2e.sh"
}

run_business() {
  bash "$repo_root/scripts/run-relay-web-companion-business-e2e.sh"
}

run_durable() {
  bash "$repo_root/scripts/run-relay-web-companion-durable-e2e.sh"
}

run_negative() {
  (
    cd "$web_root"
    bun install --frozen-lockfile
    bun run check
  )
  (
    cd "$repo_root"
    cargo test -p agentdeck-web-core --features w2-test-fixture
    cargo test -p agentdeckd --test relay_v2_machine_e2e \
      real_daemon_remote_link_runs_both_synthetic_agents_and_revokes_cleanly \
      -- --exact --test-threads=1
  )
  (
    cd "$web_root"
    AGENTDECK_WEB_CORE_FEATURES=w2-test-fixture \
      bun run test:browser -- --grep 'W2.7'
  )
}

run_crash_cuts() {
  bash "$repo_root/scripts/run-relay-web-companion-crash-cuts-e2e.sh"
}

run_state_cuts() {
  bash "$repo_root/scripts/run-relay-web-companion-state-cuts-e2e.sh"
}

run_recovery() {
  run_crash_cuts
  run_state_cuts
}

test "$#" -eq 1 || usage
case "$1" in
  --contract)
    run_contract
    ;;
  --transport)
    run_transport
    ;;
  --pairing)
    run_pairing
    ;;
  --business)
    run_business
    ;;
  --durable)
    run_durable
    ;;
  --negative)
    run_negative
    ;;
  --crash-cuts)
    run_crash_cuts
    ;;
  --state-cuts)
    run_state_cuts
    ;;
  --recovery)
    run_recovery
    ;;
  --all)
    run_contract
    run_transport
    run_pairing
    run_business
    run_durable
    run_negative
    ;;
  *)
    usage
    ;;
esac

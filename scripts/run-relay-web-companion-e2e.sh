#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd -P)"
web_root="$repo_root/web/relay-test-companion"

usage() {
  printf 'usage: %s --contract|--transport|--pairing|--all\n' "$0" >&2
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
  --all)
    run_contract
    run_transport
    run_pairing
    ;;
  *)
    usage
    ;;
esac

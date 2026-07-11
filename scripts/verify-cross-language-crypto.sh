#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null
command -v swift >/dev/null
test -f protocol/agentdeck/crypto-vectors-v1.json

cargo build -p agentdeck-crypto --example hpke_probe
cargo test -p agentdeck-crypto

swift_log="$(mktemp "${TMPDIR:-/tmp}/agentdeck-swift-crypto.XXXXXX")"
trap 'rm -f "$swift_log"' EXIT
swift test --filter RelayCryptoVectorTests 2>&1 | tee "$swift_log"
grep -Eq 'Executed [1-9][0-9]* tests?' "$swift_log"

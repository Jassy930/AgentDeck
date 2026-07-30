#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  printf 'verify-agent-docs: %s\n' "$*" >&2
  exit 1
}

require_file() {
  local path="$1"
  test -f "$path" || fail "missing required file: $path"
}

require_link() {
  local file="$1"
  local needle="$2"
  rg -q --fixed-strings "$needle" "$file" || fail "$file does not reference $needle"
}

require_absent_string() {
  local needle="$1"
  if rg -n --fixed-strings "$needle" . \
    -g '!target/**' \
    -g '!.build/**' \
    -g '!.git/**' \
    -g '!.worktrees/**' \
    -g '!scripts/verify-agent-docs.sh' >/tmp/agentdeck-doc-check.txt; then
    cat /tmp/agentdeck-doc-check.txt >&2
    rm -f /tmp/agentdeck-doc-check.txt
    fail "forbidden project-level external skill binding found"
  fi
  rm -f /tmp/agentdeck-doc-check.txt
}

require_file AGENTS.md
require_file CLAUDE.md
require_file README.md
require_file NORTH_STAR.md
require_file ARCHITECTURE.md
require_file docs/index.md
require_file docs/AGENT_DIAGNOSTICS.md
require_file docs/QUALITY.md
require_file docs/RUST_BUILD_STORAGE.md
require_file docs/plans/README.md
require_file protocol/SPIKE_FINDINGS.md
require_file protocol/CODEX_VERSION.txt

require_link AGENTS.md NORTH_STAR.md
require_link AGENTS.md README.md
require_link AGENTS.md ARCHITECTURE.md
require_link AGENTS.md docs/index.md
require_link AGENTS.md docs/AGENT_DIAGNOSTICS.md
require_link AGENTS.md docs/QUALITY.md
require_link AGENTS.md docs/plans/README.md
require_link AGENTS.md protocol/SPIKE_FINDINGS.md

require_link README.md ARCHITECTURE.md
require_link README.md docs/index.md
require_link README.md docs/QUALITY.md
require_link docs/index.md QUALITY.md
require_link docs/index.md plans/README.md
require_link docs/index.md RUST_BUILD_STORAGE.md
require_link docs/RUST_BUILD_STORAGE.md scripts/clean-rust-artifacts.sh
require_link docs/QUALITY.md scripts/verify-agent-docs.sh

legacy_tool="g""stack"
legacy_tool_upper="G""STACK"
legacy_owner="garry""tan"
legacy_mcp="mcp__claude-in""-chrome"

require_absent_string "$legacy_tool"
require_absent_string "$legacy_tool_upper"
require_absent_string "~/.claude/skills/$legacy_tool"
require_absent_string "$legacy_owner"
require_absent_string "$legacy_mcp"

printf 'verify-agent-docs: ok\n'

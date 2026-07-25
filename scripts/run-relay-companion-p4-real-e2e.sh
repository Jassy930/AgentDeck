#!/bin/sh
set -eu

# P4 MVP 仅保留 post-MVP 真实链路的只读槽位。执行体、输入覆盖和证据生成均未开放。
printf '%s\n' '{"schemaVersion":1,"gate":"relay-companion-p4-real-e2e","phase":"post-MVP","status":"BLOCKED","reasonCode":"missing_external_real_e2e_prerequisites","missingInputs":["release-signed-agentdeckd","release-signed-agentdeck-cli","matching-team-identifier","daemon-keychain-access-group-entitlement","cli-keychain-access-group-entitlement","public-wss-endpoint","public-wss-ca-and-spki-pin","codex-login","claude-code-login","disposable-destructive-profile"],"mutations":0,"evidence":[],"summaryGenerated":false}'

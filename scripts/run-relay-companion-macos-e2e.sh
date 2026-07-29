#!/bin/sh
set -eu
printf '%s\n' '{"schemaVersion":1,"gate":"relay-companion-macos-e2e","phase":"post-MVP","status":"BLOCKED","reasonCode":"missing_external_macos_e2e_prerequisites","missingInputs":["second-physical-mac","isolated-macos-client-trust-domain","second-mac-ssh-access","release-signed-agentdeck-app","release-signed-agentdeckd","release-signed-agentdeck-cli","matching-team-identifier","keychain-access-group-entitlements","public-wss-endpoint","public-wss-ca-and-spki-pin","codex-login","claude-code-login"],"mutations":0,"evidence":[],"summaryGenerated":false,"cleanup":{"processesRemaining":0,"artifactsRemaining":0}}'
exit 78

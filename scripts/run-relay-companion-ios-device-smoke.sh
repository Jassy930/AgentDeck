#!/bin/sh
set -eu
printf '%s\n' '{"schemaVersion":1,"gate":"relay-companion-ios-device-smoke","phase":"post-MVP","status":"BLOCKED","reasonCode":"missing_external_ios_device_prerequisites","missingInputs":["physical-iphone-udid","apple-development-team","matching-provisioning-profile","release-signed-agentdeck-mobile","release-signed-agentdeckd","public-wss-endpoint","public-wss-ca-and-spki-pin","codex-login","claude-code-login"],"mutations":0,"evidence":[],"summaryGenerated":false,"cleanup":{"processesRemaining":0,"artifactsRemaining":0}}'
exit 78

#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

fail() {
  printf 'relay companion external BLOCKED contract: FAIL: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "missing command: jq"
command -v shasum >/dev/null 2>&1 || fail "missing command: shasum"

probe_root="$(mktemp -d /private/tmp/agentdeck-relay-external-blocked.XXXXXX)"
trap 'find "$probe_root" -depth -delete' EXIT
mkdir -p "$probe_root/home" "$probe_root/tmp" "$probe_root/cwd"
printf 'unchanged\n' >"$probe_root/home/sentinel"
printf 'unchanged\n' >"$probe_root/tmp/sentinel"
printf 'unchanged\n' >"$probe_root/cwd/sentinel"

probe_snapshot() {
  {
    find "$probe_root" -mindepth 1 -print
    find "$probe_root" -type f -exec shasum -a 256 {} \;
  } | LC_ALL=C sort
}

assert_static_blocked_runner() {
  local runner="$1"
  local gate="$2"
  local reason_code="$3"
  local missing_inputs="$4"
  local expected_record source_line record baseline_record
  local before_probe after_probe before_status after_status status

  [[ -x "$runner" ]] || fail "missing executable runner: $runner"
  [[ "$(wc -l <"$runner" | tr -d ' ')" == '4' ]] \
    || fail "$runner must remain a four-line static sentinel"
  [[ "$(sed -n '1p' "$runner")" == '#!/bin/sh' ]] \
    || fail "$runner must use the fixed /bin/sh entry"
  [[ "$(sed -n '2p' "$runner")" == 'set -eu' ]] \
    || fail "$runner must fail closed"
  [[ "$(sed -n '4p' "$runner")" == 'exit 78' ]] \
    || fail "$runner must always exit 78"

  expected_record="$(jq -cn \
    --arg gate "$gate" \
    --arg reasonCode "$reason_code" \
    --argjson missingInputs "$missing_inputs" \
    '{
      schemaVersion: 1,
      gate: $gate,
      phase: "post-MVP",
      status: "BLOCKED",
      reasonCode: $reasonCode,
      missingInputs: $missingInputs,
      mutations: 0,
      evidence: [],
      summaryGenerated: false,
      cleanup: {processesRemaining: 0, artifactsRemaining: 0}
    }')"
  source_line="printf '%s\\n' '$expected_record'"
  [[ "$(sed -n '3p' "$runner")" == "$source_line" ]] \
    || fail "$runner contains behavior beyond its frozen JSON output"

  before_probe="$(probe_snapshot)"
  before_status="$(git -C "$repo_root" status --short --untracked-files=all)"
  set +e
  baseline_record="$(
    cd "$probe_root/cwd"
    env -i \
      PATH='/usr/bin:/bin' \
      HOME="$probe_root/home" \
      TMPDIR="$probe_root/tmp" \
      "$runner" 2>&1
  )"
  status=$?
  set -e
  [[ "$status" -eq 78 ]] || fail "$runner default invocation must exit 78"
  [[ "$baseline_record" == "$expected_record" ]] \
    || fail "$runner default output drifted"

  set +e
  record="$(
    cd "$probe_root/cwd"
    env -i \
      PATH='/usr/bin:/bin' \
      HOME="$probe_root/home" \
      TMPDIR="$probe_root/tmp" \
      AGENTDECK_REAL_E2E=1 \
      AGENTDECK_RELAY_URL='wss://should-not-be-probed.invalid' \
      AGENTDECK_PAIR_INVITE='/must/not/be/read' \
      "$runner" --force --device imaginary 2>&1
  )"
  status=$?
  set -e
  [[ "$status" -eq 78 ]] || fail "$runner hostile invocation must still exit 78"
  [[ "$record" == "$baseline_record" ]] \
    || fail "$runner arguments or environment changed the BLOCKED record"
  [[ "$(printf '%s\n' "$record" | wc -l | tr -d ' ')" == '1' ]] \
    || fail "$runner must emit exactly one JSON line"

  printf '%s\n' "$record" | jq -e \
    --arg gate "$gate" \
    --arg reasonCode "$reason_code" \
    --argjson missingInputs "$missing_inputs" '
      .schemaVersion == 1
      and .gate == $gate
      and .phase == "post-MVP"
      and .status == "BLOCKED"
      and .reasonCode == $reasonCode
      and .missingInputs == $missingInputs
      and .mutations == 0
      and .evidence == []
      and .summaryGenerated == false
      and .cleanup == {processesRemaining: 0, artifactsRemaining: 0}
      and (keys | sort) == ([
        "cleanup", "evidence", "gate", "missingInputs", "mutations", "phase",
        "reasonCode", "schemaVersion", "status", "summaryGenerated"
      ] | sort)
    ' >/dev/null || fail "$runner JSON contract drifted"

  after_probe="$(probe_snapshot)"
  after_status="$(git -C "$repo_root" status --short --untracked-files=all)"
  [[ "$before_probe" == "$after_probe" ]] \
    || fail "$runner changed the isolated HOME/TMPDIR/cwd"
  [[ "$before_status" == "$after_status" ]] \
    || fail "$runner mutated the repository"
}

assert_static_blocked_runner \
  "$repo_root/scripts/run-relay-companion-ios-device-smoke.sh" \
  'relay-companion-ios-device-smoke' \
  'missing_external_ios_device_prerequisites' \
  '["physical-iphone-udid","apple-development-team","matching-provisioning-profile","release-signed-agentdeck-mobile","release-signed-agentdeckd","public-wss-endpoint","public-wss-ca-and-spki-pin","codex-login","claude-code-login"]'

assert_static_blocked_runner \
  "$repo_root/scripts/run-relay-companion-macos-e2e.sh" \
  'relay-companion-macos-e2e' \
  'missing_external_macos_e2e_prerequisites' \
  '["second-physical-mac","isolated-macos-client-trust-domain","second-mac-ssh-access","release-signed-agentdeck-app","release-signed-agentdeckd","release-signed-agentdeck-cli","matching-team-identifier","keychain-access-group-entitlements","public-wss-endpoint","public-wss-ca-and-spki-pin","codex-login","claude-code-login"]'

printf 'relay companion external BLOCKED contract: PASS\n'

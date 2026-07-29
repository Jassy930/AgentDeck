#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
verifier_source="$repo_root/scripts/verify-relay-companion-mvp.sh"

fail() {
  printf 'Relay Companion p5 verifier contract: FAIL: %s\n' "$1" >&2
  exit 1
}

[[ -x "$verifier_source" ]] || fail "missing verifier: $verifier_source"

fixture_root="$(mktemp -d /private/tmp/agentdeck-relay-p5-verifier.XXXXXX)"
trap 'find "$fixture_root" -depth -delete' EXIT

ios_record='{"schemaVersion":1,"gate":"relay-companion-ios-device-smoke","phase":"post-MVP","status":"BLOCKED","reasonCode":"missing_external_ios_device_prerequisites","missingInputs":["physical-iphone-udid"],"mutations":0,"evidence":[],"summaryGenerated":false,"cleanup":{"processesRemaining":0,"artifactsRemaining":0}}'
macos_record='{"schemaVersion":1,"gate":"relay-companion-macos-e2e","phase":"post-MVP","status":"BLOCKED","reasonCode":"missing_external_macos_e2e_prerequisites","missingInputs":["second-physical-mac"],"mutations":0,"evidence":[],"summaryGenerated":false,"cleanup":{"processesRemaining":0,"artifactsRemaining":0}}'

write_exit_stub() {
  local target="$1"
  local exit_code="$2"
  mkdir -p "$(dirname "$target")"
  printf '#!/bin/sh\nexit %s\n' "$exit_code" >"$target"
  chmod +x "$target"
}

write_record_stub() {
  local target="$1"
  local record="$2"
  local exit_code="$3"
  mkdir -p "$(dirname "$target")"
  printf '#!/bin/sh\nprintf '\''%%s\\n'\'' '\''%s'\''\nexit %s\n' \
    "$record" "$exit_code" >"$target"
  chmod +x "$target"
}

make_fixture() {
  local root="$1"
  mkdir -p "$root/scripts/tests" "$root/bin"
  cp "$verifier_source" "$root/scripts/verify-relay-companion-mvp.sh"
  chmod +x "$root/scripts/verify-relay-companion-mvp.sh"
  write_exit_stub "$root/scripts/tests/run-relay-companion-simulator-e2e.sh" 0
  write_exit_stub "$root/scripts/tests/run-relay-companion-external-blocked.sh" 0
  write_exit_stub "$root/scripts/run-relay-companion-simulator-e2e.sh" 0
  write_exit_stub "$root/scripts/verify-agent-docs.sh" 0
  write_exit_stub "$root/bin/swift" 0
  write_record_stub "$root/scripts/run-relay-companion-ios-device-smoke.sh" "$ios_record" 78
  write_record_stub "$root/scripts/run-relay-companion-macos-e2e.sh" "$macos_record" 78
}

run_fixture() {
  local root="$1"
  (
    cd "$root"
    PATH="$root/bin:$PATH" bash scripts/verify-relay-companion-mvp.sh p5
  )
}

expect_failure() {
  local label="$1"
  local root="$2"
  if run_fixture "$root" >/dev/null 2>&1; then
    fail "$label unexpectedly passed"
  fi
}

positive="$fixture_root/positive"
make_fixture "$positive"
positive_output="$(run_fixture "$positive")" \
  || fail "valid automatic gates plus external BLOCKED slots must pass"
[[ "$positive_output" == *'BLOCKED: physical iPhone post-MVP slot (missing_external_ios_device_prerequisites)'* ]] \
  || fail "physical iPhone slot was not reported as BLOCKED"
[[ "$positive_output" == *'BLOCKED: second Mac post-MVP slot (missing_external_macos_e2e_prerequisites)'* ]] \
  || fail "second Mac slot was not reported as BLOCKED"
[[ "$positive_output" != *'PASS: physical iPhone post-MVP slot'* ]] \
  || fail "physical iPhone BLOCKED slot was counted as PASS"
[[ "$positive_output" != *'PASS: second Mac post-MVP slot'* ]] \
  || fail "second Mac BLOCKED slot was counted as PASS"
[[ "$positive_output" == *'verify-relay-companion-mvp p5: PASS (automatic scope; external slots remain BLOCKED)'* ]] \
  || fail "p5 completion did not preserve the automatic/external boundary"

missing_automatic="$fixture_root/missing-automatic"
make_fixture "$missing_automatic"
find "$missing_automatic/scripts/run-relay-companion-simulator-e2e.sh" -delete
expect_failure "missing automatic Simulator runner" "$missing_automatic"

failed_automatic="$fixture_root/failed-automatic"
make_fixture "$failed_automatic"
write_exit_stub "$failed_automatic/scripts/run-relay-companion-simulator-e2e.sh" 1
expect_failure "failed automatic Simulator runner" "$failed_automatic"

wrong_external_exit="$fixture_root/wrong-external-exit"
make_fixture "$wrong_external_exit"
write_record_stub \
  "$wrong_external_exit/scripts/run-relay-companion-ios-device-smoke.sh" \
  "$ios_record" 0
expect_failure "external BLOCKED slot with exit 0" "$wrong_external_exit"

malformed_external="$fixture_root/malformed-external"
make_fixture "$malformed_external"
write_record_stub \
  "$malformed_external/scripts/run-relay-companion-macos-e2e.sh" \
  '{"schemaVersion":1,"gate":"relay-companion-macos-e2e","phase":"post-MVP","status":"PASS"}' \
  78
expect_failure "malformed external BLOCKED record" "$malformed_external"

printf 'Relay Companion p5 verifier contract: PASS\n'

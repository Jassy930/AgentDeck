#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
runner="$repo_root/scripts/run-relay-web-companion-e2e.sh"
temp_root="$(mktemp -d "${TMPDIR:-/tmp}/agentdeck-relay-w3-repeatability.XXXXXX")"

fail() {
  printf 'relay web companion W3.6: FAIL: %s\n' "$1" >&2
  exit 1
}

cleanup() {
  case "$temp_root" in
    "${TMPDIR:-/tmp}"/agentdeck-relay-w3-repeatability.*)
      rm -rf -- "$temp_root"
      ;;
    *)
      printf 'refusing unexpected repeatability temp cleanup: %s\n' "$temp_root" >&2
      ;;
  esac
}
trap cleanup EXIT

require_clean_candidate() {
  local expected_commit="$1"
  local expected_tree="$2"
  local actual_commit actual_tree status

  actual_commit="$(git -C "$repo_root" rev-parse HEAD^{commit})"
  actual_tree="$(git -C "$repo_root" rev-parse HEAD^{tree})"
  [[ "$actual_commit" == "$expected_commit" ]] \
    || fail "candidate commit drifted: expected $expected_commit, got $actual_commit"
  [[ "$actual_tree" == "$expected_tree" ]] \
    || fail "candidate tree drifted: expected $expected_tree, got $actual_tree"

  status="$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)"
  [[ -z "$status" ]] || fail "candidate worktree is not clean: $status"
}

extract_gate() {
  local log_path="$1"
  local gate="$2"

  jq -cR --arg gate "$gate" \
    'fromjson? | select(.schemaVersion == 1 and .gate == $gate)' \
    "$log_path"
}

validate_business() {
  local log_path="$1"
  local evidence

  evidence="$(extract_gate "$log_path" 'relay-web-companion-w2b')"
  [[ "$(printf '%s\n' "$evidence" | sed '/^$/d' | wc -l | tr -d ' ')" == "1" ]] \
    || fail "business run did not emit exactly one W2b terminal"
  printf '%s\n' "$evidence" | jq -e '
    .status == "PASS"
    and .runtimeCommandCount == 1
    and .runtimeCompletedCommandCount == 1
    and .runtimeApprovalTotal == 1
    and .runtimeApprovalApplied == 1
    and .preConfirmNetworkLocked == true
    and .pendingPairingCount == 0
    and .relayGrantActive == 1
    and .activeTransitionCount == 0
    and .activeCatalogStreamCount == 1
    and .relayPlaintextAbsent == true
    and .browserPlaintextAbsent == true
    and .cleanup.browserAbsent == true
    and .cleanup.hostPidAbsent == true
    and .cleanup.hostRootAbsent == true
    and .cleanup.inviteAbsent == true
    and .cleanup.socketAbsent == true
    and .cleanup.playwrightArtifactsAbsent == true
  ' >/dev/null || fail "business terminal violated W2b invariants"
}

validate_recovery() {
  local log_path="$1"
  local detail aggregate

  detail="$(jq -cR '
    fromjson?
    | select(
        .schemaVersion == 1
        and (
          .gate == "relay-web-companion-w3-crash-cut"
          or .gate == "relay-web-companion-w3-state-cut"
        )
      )
  ' "$log_path")"
  [[ "$(printf '%s\n' "$detail" | sed '/^$/d' | wc -l | tr -d ' ')" == "6" ]] \
    || fail "recovery run did not emit exactly six W3 detail terminals"
  printf '%s\n' "$detail" | jq -se '
    length == 6
    and (map(select(.gate == "relay-web-companion-w3-crash-cut")) | length == 3)
    and (map(select(.gate == "relay-web-companion-w3-state-cut")) | length == 3)
    and ([.[] | select(.gate == "relay-web-companion-w3-crash-cut") | .crashCut] | sort
      == ["guardPendingDurable", "guardStableDurable", "stateDurable"])
    and ([.[] | select(.gate == "relay-web-companion-w3-state-cut") | .stateCut] | sort
      == ["guardStableDurable", "stateDurable", "stateGuardPendingDurable"])
    and all(.[ ];
      .status == "PASS"
      and .daemonGeneration == 2
      and .catalogBackfillObserved == true
      and .runtimeCommandCount == 1
      and .runtimeCompletedCommandCount == 1
      and .runtimeApprovalTotal == 1
      and .runtimeApprovalApplied == 1
      and .runtimeRevokedAuthorizationCount == 1
      and .relayGrantActive == 0
      and .relayPlaintextAbsent == true
      and .browserPlaintextAbsent == true
      and .cleanup.pairedMaterialAbsent == true
      and .cleanup.kekAbsent == true
      and .cleanup.revokedTombstonePresent == true
      and .cleanup.counterGuardAbsent == true
      and .cleanup.browserAbsent == true
      and .cleanup.proxyAbsent == true
      and .cleanup.hostPidAbsent == true
      and .cleanup.hostRootAbsent == true
      and .cleanup.inviteAbsent == true
      and .cleanup.socketAbsent == true
      and .cleanup.playwrightArtifactsAbsent == true
    )
  ' >/dev/null || fail "recovery terminal violated W3 invariants"

  aggregate="$(jq -cR '
    fromjson?
    | select(
        .schemaVersion == 1
        and (
          .gate == "relay-web-companion-w3.1"
          or .gate == "relay-web-companion-w3.2"
        )
      )
  ' "$log_path")"
  [[ "$(printf '%s\n' "$aggregate" | sed '/^$/d' | wc -l | tr -d ' ')" == "2" ]] \
    || fail "recovery run did not emit both W3 aggregate terminals"
  printf '%s\n' "$aggregate" | jq -se '
    length == 2
    and (map(.gate) | sort == ["relay-web-companion-w3.1", "relay-web-companion-w3.2"])
    and all(.[ ]; .status == "PASS")
    and (first(.[] | select(.gate == "relay-web-companion-w3.1"))
      | .crashCuts == ["guardPendingDurable", "stateDurable", "guardStableDurable"]
      and .binaryFramesBeforeRecovery == 0)
    and (first(.[] | select(.gate == "relay-web-companion-w3.2"))
      | .stateCuts == ["stateGuardPendingDurable", "stateDurable", "guardStableDurable"]
      and .recovery == ["statePendingPreviousRetried", "statePendingNextFinalized", "stableExact"]
      and .siblingForkQuarantined == true
      and .binaryFramesBeforeRecovery == 0)
  ' >/dev/null || fail "recovery aggregate terminal violated W3 invariants"
}

run_selfcheck() {
  local business_log="$temp_root/selfcheck-business.log"
  local invalid_business_log="$temp_root/selfcheck-business-invalid.log"
  local recovery_log="$temp_root/selfcheck-recovery.log"
  local invalid_recovery_log="$temp_root/selfcheck-recovery-invalid.log"
  local invalid_coverage_log="$temp_root/selfcheck-recovery-coverage-invalid.log"

  printf '%s\n' '{"schemaVersion":1,"gate":"relay-web-companion-w2b","status":"PASS","preConfirmNetworkLocked":true,"pendingPairingCount":0,"activeTransitionCount":0,"activeCatalogStreamCount":1,"runtimeCommandCount":1,"runtimeCompletedCommandCount":1,"runtimeApprovalTotal":1,"runtimeApprovalApplied":1,"relayGrantActive":1,"relayPlaintextAbsent":true,"browserPlaintextAbsent":true,"cleanup":{"browserAbsent":true,"hostPidAbsent":true,"hostRootAbsent":true,"inviteAbsent":true,"socketAbsent":true,"playwrightArtifactsAbsent":true}}' >"$business_log"
  validate_business "$business_log"

  sed 's/"runtimeCommandCount":1/"runtimeCommandCount":2/' \
    "$business_log" >"$invalid_business_log"
  if (validate_business "$invalid_business_log" >/dev/null 2>&1); then
    fail "selfcheck accepted a business terminal with duplicate commands"
  fi

  for cut in guardPendingDurable stateDurable guardStableDurable; do
    jq -cn --arg cut "$cut" '{schemaVersion:1,gate:"relay-web-companion-w3-crash-cut",status:"PASS",crashCut:$cut,stateCut:null,daemonGeneration:2,catalogBackfillObserved:true,runtimeCommandCount:1,runtimeCompletedCommandCount:1,runtimeApprovalTotal:1,runtimeApprovalApplied:1,runtimeRevokedAuthorizationCount:1,relayGrantActive:0,relayPlaintextAbsent:true,browserPlaintextAbsent:true,cleanup:{pairedMaterialAbsent:true,kekAbsent:true,revokedTombstonePresent:true,counterGuardAbsent:true,browserAbsent:true,proxyAbsent:true,hostPidAbsent:true,hostRootAbsent:true,inviteAbsent:true,socketAbsent:true,playwrightArtifactsAbsent:true}}' >>"$recovery_log"
  done
  for cut in stateGuardPendingDurable stateDurable guardStableDurable; do
    jq -cn --arg cut "$cut" '{schemaVersion:1,gate:"relay-web-companion-w3-state-cut",status:"PASS",crashCut:null,stateCut:$cut,daemonGeneration:2,catalogBackfillObserved:true,runtimeCommandCount:1,runtimeCompletedCommandCount:1,runtimeApprovalTotal:1,runtimeApprovalApplied:1,runtimeRevokedAuthorizationCount:1,relayGrantActive:0,relayPlaintextAbsent:true,browserPlaintextAbsent:true,cleanup:{pairedMaterialAbsent:true,kekAbsent:true,revokedTombstonePresent:true,counterGuardAbsent:true,browserAbsent:true,proxyAbsent:true,hostPidAbsent:true,hostRootAbsent:true,inviteAbsent:true,socketAbsent:true,playwrightArtifactsAbsent:true}}' >>"$recovery_log"
  done
  printf '%s\n' \
    '{"schemaVersion":1,"gate":"relay-web-companion-w3.1","status":"PASS","crashCuts":["guardPendingDurable","stateDurable","guardStableDurable"],"binaryFramesBeforeRecovery":0}' \
    '{"schemaVersion":1,"gate":"relay-web-companion-w3.2","status":"PASS","stateCuts":["stateGuardPendingDurable","stateDurable","guardStableDurable"],"recovery":["statePendingPreviousRetried","statePendingNextFinalized","stableExact"],"siblingForkQuarantined":true,"binaryFramesBeforeRecovery":0}' \
    >>"$recovery_log"
  validate_recovery "$recovery_log"

  sed 's/"runtimeRevokedAuthorizationCount":1/"runtimeRevokedAuthorizationCount":0/' \
    "$recovery_log" >"$invalid_recovery_log"
  if (validate_recovery "$invalid_recovery_log" >/dev/null 2>&1); then
    fail "selfcheck accepted recovery terminals without revoke"
  fi

  sed 's/"stateCut":"stateGuardPendingDurable"/"stateCut":"stateDurable"/' \
    "$recovery_log" >"$invalid_coverage_log"
  if (validate_recovery "$invalid_coverage_log" >/dev/null 2>&1); then
    fail "selfcheck accepted duplicate recovery cut coverage"
  fi

  printf '%s\n' '{"schemaVersion":1,"gate":"relay-web-companion-w3.6-selfcheck","status":"PASS","positiveFixturesAccepted":true,"negativeBusinessFixtureRejected":true,"negativeRecoveryFixtureRejected":true,"duplicateCutFixtureRejected":true}'
}

if [[ "$#" -eq 1 && "$1" == "--selfcheck" ]]; then
  run_selfcheck
  exit 0
fi
[[ "$#" -eq 0 ]] || fail "usage: $0 [--selfcheck]"

candidate_commit="$(git -C "$repo_root" rev-parse HEAD^{commit})"
candidate_tree="$(git -C "$repo_root" rev-parse HEAD^{tree})"
require_clean_candidate "$candidate_commit" "$candidate_tree"

for run in 1 2 3; do
  run_root="$temp_root/run-$run"
  mkdir -p "$run_root"

  require_clean_candidate "$candidate_commit" "$candidate_tree"
  bash "$runner" --business | tee "$run_root/business.log"
  validate_business "$run_root/business.log"

  require_clean_candidate "$candidate_commit" "$candidate_tree"
  bash "$runner" --recovery | tee "$run_root/recovery.log"
  validate_recovery "$run_root/recovery.log"
  require_clean_candidate "$candidate_commit" "$candidate_tree"

  jq -cn \
    --argjson run "$run" \
    --arg candidateCommit "$candidate_commit" \
    --arg candidateTree "$candidate_tree" \
    '{schemaVersion:1,gate:"relay-web-companion-w3.6-run",status:"PASS",run:$run,candidateCommit:$candidateCommit,candidateTree:$candidateTree,businessTerminals:1,recoveryDetailTerminals:6,recoveryAggregateTerminals:2,runtimeCommandCompleted:"1/1",runtimeApprovalApplied:"1/1",runtimeRevokedAuthorizationCount:1,relayGrantActive:0,plaintextAbsent:true,cleanupAbsent:true}'
done

jq -cn \
  --arg candidateCommit "$candidate_commit" \
  --arg candidateTree "$candidate_tree" \
  '{schemaVersion:1,gate:"relay-web-companion-w3.6",status:"PASS",freshRuns:3,candidateCommit:$candidateCommit,candidateTree:$candidateTree,businessTerminals:3,recoveryDetailTerminals:18,recoveryAggregateTerminals:6,allRunsConsistent:true,plaintextAbsent:true,cleanupAbsent:true,externalPhysicalPublicEvidence:"BLOCKED"}'

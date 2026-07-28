#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="AgentDeck"
BUNDLE_ID="dev.agentdeck.AgentDeck"
MIN_SYSTEM_VERSION="15.0"
CLI_CODE_IDENTIFIER="${AGENTDECK_CLI_CODE_IDENTIFIER:-}"
CLI_TEAM_IDENTIFIER="${AGENTDECK_CLI_TEAM_IDENTIFIER:-}"
CLI_KEYCHAIN_ACCESS_GROUP="${AGENTDECK_CLI_KEYCHAIN_ACCESS_GROUP:-}"
CLI_CODE_IDENTIFIER_REQUIRED="com.agentdeck.agentdeck-cli"
CLI_KEYCHAIN_ACCESS_GROUP_SUFFIX=".com.agentdeck.remote.cli"

cli_identity_fields=0
[[ -n "$CLI_CODE_IDENTIFIER" ]] && cli_identity_fields=$((cli_identity_fields + 1))
[[ -n "$CLI_TEAM_IDENTIFIER" ]] && cli_identity_fields=$((cli_identity_fields + 1))
[[ -n "$CLI_KEYCHAIN_ACCESS_GROUP" ]] && cli_identity_fields=$((cli_identity_fields + 1))
if [[ "$cli_identity_fields" -ne 0 && "$cli_identity_fields" -ne 3 ]]; then
  echo "CLI production identity must be supplied as an all-or-none triple" >&2
  exit 2
fi
if [[ "$cli_identity_fields" -eq 3 ]]; then
  if [[ "$CLI_CODE_IDENTIFIER" != "$CLI_CODE_IDENTIFIER_REQUIRED" ]]; then
    echo "CLI production code identifier is invalid" >&2
    exit 2
  fi
  if [[ ! "$CLI_TEAM_IDENTIFIER" =~ ^[[:alnum:]]{1,64}$ ]]; then
    echo "CLI production TeamIdentifier is invalid" >&2
    exit 2
  fi
  if [[ "$CLI_KEYCHAIN_ACCESS_GROUP" != "${CLI_TEAM_IDENTIFIER}${CLI_KEYCHAIN_ACCESS_GROUP_SUFFIX}" ]]; then
    echo "CLI production Keychain access group is invalid" >&2
    exit 2
  fi
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${AGENTDECK_DIST_DIR:-$ROOT_DIR/dist}"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_HELPERS="$APP_CONTENTS/Helpers"
APP_BINARY="$APP_MACOS/$APP_NAME"
BUNDLED_CLI="$APP_HELPERS/agentdeck"
BUNDLED_DAEMON="$APP_HELPERS/agentdeckd"
RESOURCE_BUNDLE_NAME="${APP_NAME}_${APP_NAME}.bundle"
BUNDLED_RESOURCE_BUNDLE="$APP_BUNDLE/$RESOURCE_BUNDLE_NAME"
INFO_PLIST="$APP_CONTENTS/Info.plist"
DAEMON_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"

if [[ "$DAEMON_TARGET_DIR" != /* ]]; then
  DAEMON_TARGET_DIR="$ROOT_DIR/$DAEMON_TARGET_DIR"
fi
DAEMON_BINARY="$DAEMON_TARGET_DIR/debug/agentdeckd"

cd "$ROOT_DIR"

process_executable_path() {
  local pid="$1"
  /usr/sbin/lsof -a -p "$pid" -d txt -Fn 2>/dev/null \
    | sed -n 's/^n//p' \
    | sed -n '1p'
}

stop_current_bundle_instances() {
  local candidate_pid=""
  local found="false"

  while IFS= read -r candidate_pid; do
    [[ -n "$candidate_pid" ]] || continue
    if [[ "$(process_executable_path "$candidate_pid")" == "$APP_BINARY" ]]; then
      kill "$candidate_pid" 2>/dev/null || true
      found="true"
    fi
  done < <(pgrep -x "$APP_NAME" || true)

  [[ "$found" == "true" ]] || return 0
  for _ in {1..100}; do
    found="false"
    while IFS= read -r candidate_pid; do
      [[ -n "$candidate_pid" ]] || continue
      if [[ "$(process_executable_path "$candidate_pid")" == "$APP_BINARY" ]]; then
        found="true"
        break
      fi
    done < <(pgrep -x "$APP_NAME" || true)
    [[ "$found" == "false" ]] && return 0
    sleep 0.05
  done

  echo "failed to stop existing bundle process: $APP_BINARY" >&2
  return 1
}

stop_current_bundle_instances

cargo build -p agentdeck-cli -p agentdeckd --target-dir "$DAEMON_TARGET_DIR"
swift build
SWIFT_BIN_DIR="$(swift build --show-bin-path)"
BUILD_BINARY="$SWIFT_BIN_DIR/$APP_NAME"
BUILD_RESOURCE_BUNDLE="$SWIFT_BIN_DIR/$RESOURCE_BUNDLE_NAME"
CLI_BINARY="$DAEMON_TARGET_DIR/debug/agentdeck"

if [[ ! -x "$DAEMON_BINARY" ]]; then
  echo "agentdeckd build output not found: $DAEMON_BINARY" >&2
  exit 1
fi
if [[ ! -d "$BUILD_RESOURCE_BUNDLE" ]]; then
  echo "SwiftPM resource bundle not found: $BUILD_RESOURCE_BUNDLE" >&2
  exit 1
fi
if [[ ! -x "$CLI_BINARY" ]]; then
  echo "agentdeck-cli build output not found: $CLI_BINARY" >&2
  exit 1
fi

rm -rf "$APP_BUNDLE"
mkdir -p "$APP_MACOS" "$APP_HELPERS"
cp "$BUILD_BINARY" "$APP_BINARY"
cp "$CLI_BINARY" "$BUNDLED_CLI"
cp "$DAEMON_BINARY" "$BUNDLED_DAEMON"
cp -R "$BUILD_RESOURCE_BUNDLE" "$BUNDLED_RESOURCE_BUNDLE"
chmod +x "$APP_BINARY" "$BUNDLED_CLI" "$BUNDLED_DAEMON"

cat >"$INFO_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>$APP_NAME</string>
  <key>CFBundleIdentifier</key>
  <string>$BUNDLE_ID</string>
  <key>CFBundleName</key>
  <string>$APP_NAME</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>LSMinimumSystemVersion</key>
  <string>$MIN_SYSTEM_VERSION</string>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
PLIST

open_app() {
  stop_current_bundle_instances
  /usr/bin/open -n "$APP_BUNDLE"
}

verify_running_bundle() {
  local app_pid=""
  local actual_min_system_version=""
  local binary_min_system_version=""
  local candidate_pid=""

  [[ -x "$BUNDLED_DAEMON" ]] || {
    echo "verify failed: bundled agentdeckd is missing or not executable" >&2
    return 1
  }
  [[ -f "$BUNDLED_RESOURCE_BUNDLE/Assets.xcassets/CodexIcon.imageset/codex.svg" ]] || {
    echo "verify failed: bundled Codex icon resource is missing" >&2
    return 1
  }
  [[ -f "$BUNDLED_RESOURCE_BUNDLE/Assets.xcassets/ClaudeCodeIcon.imageset/claudecode.svg" ]] || {
    echo "verify failed: bundled Claude Code icon resource is missing" >&2
    return 1
  }

  actual_min_system_version="$(
    /usr/libexec/PlistBuddy -c "Print :LSMinimumSystemVersion" "$INFO_PLIST" 2>/dev/null || true
  )"
  if [[ "$actual_min_system_version" != "$MIN_SYSTEM_VERSION" ]]; then
    echo "verify failed: LSMinimumSystemVersion=$actual_min_system_version, expected $MIN_SYSTEM_VERSION" >&2
    return 1
  fi

  binary_min_system_version="$(
    /usr/bin/vtool -show-build "$APP_BINARY" 2>/dev/null \
      | /usr/bin/awk '$1 == "minos" { print $2; exit }'
  )"
  if [[ "$binary_min_system_version" != "$MIN_SYSTEM_VERSION" ]]; then
    echo "verify failed: Mach-O minos=$binary_min_system_version, expected $MIN_SYSTEM_VERSION" >&2
    return 1
  fi

  for _ in {1..100}; do
    app_pid=""
    while IFS= read -r candidate_pid; do
      [[ -n "$candidate_pid" ]] || continue
      if [[ "$(process_executable_path "$candidate_pid")" == "$APP_BINARY" ]]; then
        app_pid="$candidate_pid"
        break
      fi
    done < <(pgrep -x "$APP_NAME" || true)

    if [[ -n "$app_pid" ]]; then
      echo "verify OK: $APP_BINARY pid=$app_pid"
      echo "verify OK: helper $BUNDLED_CLI"
      echo "verify OK: helper $BUNDLED_DAEMON"
      echo "verify OK: $BUNDLED_RESOURCE_BUNDLE"
      echo "verify OK: LSMinimumSystemVersion=$actual_min_system_version"
      echo "verify OK: Mach-O minos=$binary_min_system_version"
      return 0
    fi
    sleep 0.1
  done

  echo "verify failed: exact bundle process did not start: $APP_BINARY" >&2
  return 1
}

case "$MODE" in
  --package|package)
    ;;
  run)
    open_app
    ;;
  --debug|debug)
    lldb -- "$APP_BINARY"
    ;;
  --logs|logs)
    open_app
    /usr/bin/log stream --info --style compact --predicate "process == \"$APP_NAME\""
    ;;
  --telemetry|telemetry)
    open_app
    /usr/bin/log stream --info --style compact --predicate "subsystem == \"$BUNDLE_ID\""
    ;;
  --verify|verify)
    test -x "$BUNDLED_CLI"
    test -x "$BUNDLED_DAEMON"
    "$BUNDLED_DAEMON" --version >/dev/null
    "$BUNDLED_CLI" --help >/dev/null
    open_app
    verify_running_bundle
    ;;
  *)
    echo "usage: $0 [run|--package|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac

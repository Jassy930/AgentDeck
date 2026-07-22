#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="AgentDeck"
BUNDLE_ID="dev.agentdeck.AgentDeck"
MIN_SYSTEM_VERSION="15.0"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_BINARY="$APP_MACOS/$APP_NAME"
BUNDLED_DAEMON="$APP_MACOS/agentdeckd"
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

cargo build -p agentdeckd --target-dir "$DAEMON_TARGET_DIR"
swift build
SWIFT_BIN_DIR="$(swift build --show-bin-path)"
BUILD_BINARY="$SWIFT_BIN_DIR/$APP_NAME"
BUILD_RESOURCE_BUNDLE="$SWIFT_BIN_DIR/$RESOURCE_BUNDLE_NAME"

if [[ ! -x "$DAEMON_BINARY" ]]; then
  echo "agentdeckd build output not found: $DAEMON_BINARY" >&2
  exit 1
fi
if [[ ! -d "$BUILD_RESOURCE_BUNDLE" ]]; then
  echo "SwiftPM resource bundle not found: $BUILD_RESOURCE_BUNDLE" >&2
  exit 1
fi

rm -rf "$APP_BUNDLE"
mkdir -p "$APP_MACOS"
cp "$BUILD_BINARY" "$APP_BINARY"
cp "$DAEMON_BINARY" "$BUNDLED_DAEMON"
cp -R "$BUILD_RESOURCE_BUNDLE" "$BUNDLED_RESOURCE_BUNDLE"
chmod +x "$APP_BINARY" "$BUNDLED_DAEMON"

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
  /usr/bin/open -n "$APP_BUNDLE"
}

verify_running_bundle() {
  local app_pid=""
  local daemon_pid=""
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
      daemon_pid=""
      while IFS= read -r candidate_pid; do
        [[ -n "$candidate_pid" ]] || continue
        if [[ "$(process_executable_path "$candidate_pid")" == "$BUNDLED_DAEMON" ]]; then
          daemon_pid="$candidate_pid"
          break
        fi
      done < <(pgrep -P "$app_pid" -x agentdeckd || true)

      if [[ -n "$daemon_pid" ]]; then
        echo "verify OK: $APP_BINARY pid=$app_pid"
        echo "verify OK: $BUNDLED_DAEMON pid=$daemon_pid"
        echo "verify OK: $BUNDLED_RESOURCE_BUNDLE"
        echo "verify OK: LSMinimumSystemVersion=$actual_min_system_version"
        echo "verify OK: Mach-O minos=$binary_min_system_version"
        return 0
      fi
    fi
    sleep 0.1
  done

  echo "verify failed: $APP_NAME did not start a bundled agentdeckd child" >&2
  return 1
}

case "$MODE" in
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
    open_app
    verify_running_bundle
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac

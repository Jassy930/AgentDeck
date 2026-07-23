#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="AgentDeck"
BUNDLE_ID="dev.agentdeck.AgentDeck"
MIN_SYSTEM_VERSION="14.0"
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
INFO_PLIST="$APP_CONTENTS/Info.plist"

cd "$ROOT_DIR"

swift build
BUILD_BINARY="$(swift build --show-bin-path)/$APP_NAME"
cargo build -p agentdeck-cli -p agentdeckd
RUST_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
CLI_HELPER="$RUST_TARGET_DIR/debug/agentdeck"
DAEMON_HELPER="$RUST_TARGET_DIR/debug/agentdeckd"

rm -rf "$APP_BUNDLE"
mkdir -p "$APP_MACOS" "$APP_HELPERS"
cp "$BUILD_BINARY" "$APP_BINARY"
cp "$CLI_HELPER" "$APP_HELPERS/agentdeck"
cp "$DAEMON_HELPER" "$APP_HELPERS/agentdeckd"
chmod +x "$APP_BINARY" "$APP_HELPERS/agentdeck" "$APP_HELPERS/agentdeckd"

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
  pkill -x "$APP_NAME" >/dev/null 2>&1 || true
  /usr/bin/open -n "$APP_BUNDLE"
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
    test -x "$APP_HELPERS/agentdeck"
    test -x "$APP_HELPERS/agentdeckd"
    "$APP_HELPERS/agentdeckd" --version >/dev/null
    "$APP_HELPERS/agentdeck" --help >/dev/null
    open_app
    sleep 1
    pgrep -x "$APP_NAME" >/dev/null
    ;;
  *)
    echo "usage: $0 [run|--package|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac

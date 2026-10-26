#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
source "$root/scripts/release/common.sh"
[[ $# -ge 2 && $# -le 3 ]] || { release_fail 'usage: package.sh <target> <desktop|daemon> [output-dir]'; exit 2; }
target="$1"
kind="$2"
release_target "$target" "$kind"
version="$(release_version "$root" "${AGENTDECK_RELEASE_TAG:-}")"
output_dir="${3:-$root/dist/release}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
# 与 debug 或不同部署基线的 Cargo 缓存隔离，不 touch 用户源文件。
build_dir="$root/target/release-build"
packages=(-p agentdeckd --bin agentdeckd)
[[ "$kind" != desktop ]] || packages+=(-p agentdeck-desktop --bin agentdeck-desktop)
case "$target" in
  *-apple-darwin)
    [[ "$(uname -s)" == Darwin ]] || { release_fail 'macOS packaging requires macOS'; exit 1; }
    export MACOSX_DEPLOYMENT_TARGET=15.0
    ;;
  *-linux-*)
    [[ "$(uname -s)" == Linux ]] || { release_fail 'Linux packaging requires Linux'; exit 1; }
    ;;
esac
cd "$root"
cargo build --release --locked --target "$target" --target-dir "$build_dir" "${packages[@]}"
bin_dir="$build_dir/$target/release"
release_architecture "$bin_dir/agentdeckd" "$target"
release_binary_version "$bin_dir/agentdeckd" agentdeckd "$version"
if [[ "$kind" == desktop ]]; then
  release_architecture "$bin_dir/agentdeck-desktop" "$target"
  release_binary_version "$bin_dir/agentdeck-desktop" agentdeck-desktop "$version"
fi
stage="$(mktemp -d "$output_dir/.package.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/daemon"
cp "$bin_dir/agentdeckd" "$stage/daemon/agentdeckd"
cp "$root/LICENSE" "$stage/daemon/LICENSE"
signing=none
case "$target" in
  *-apple-darwin)
    identity="${AGENTDECK_MACOS_SIGN_IDENTITY:-}"
    if [[ -n "$identity" ]]; then
      [[ "$identity" == 'Developer ID Application: '* ]] \
        || { release_fail 'signing identity must explicitly name an existing Developer ID Application certificate'; exit 1; }
      [[ "${GITHUB_EVENT_NAME:-}" != pull_request && "${GITHUB_EVENT_NAME:-}" != pull_request_target ]] \
        || { release_fail 'credentialed signing is disabled for pull requests'; exit 1; }
      sign_args=(--sign "$identity" --options runtime --timestamp)
      signing=developer-id
    else
      sign_args=(--sign - --timestamp=none)
      signing=ad-hoc
    fi
    /usr/bin/codesign --force "${sign_args[@]}" --identifier dev.agentdeck.AgentDeck.agentdeckd "$stage/daemon/agentdeckd"
    /usr/bin/codesign --verify --strict "$stage/daemon/agentdeckd"
    ;;
esac
printf '%s\n' "$version" > "$stage/daemon/RELEASE-VERSION"
cat > "$stage/daemon/RELEASE-INFO.txt" <<INFO
version=$version
target=$target
commit=$(git rev-parse HEAD)
signing=$signing
notarization=not-notarized
macOS packages are not notarized; ad-hoc signing does not establish developer identity.
INFO
if [[ "$kind" == desktop ]]; then
  if [[ "$target" == *-apple-darwin ]]; then
    bundle="$stage/desktop/AgentDeck.app"
    mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
    cp "$bin_dir/agentdeck-desktop" "$bundle/Contents/MacOS/AgentDeck"
    cp "$stage/daemon/agentdeckd" "$bundle/Contents/MacOS/agentdeckd"
    cp "$root/assets/brand/AgentDeck.icns" "$bundle/Contents/Resources/AgentDeck.icns"
    cp "$stage/daemon/RELEASE-"* "$stage/daemon/LICENSE" "$bundle/Contents/Resources/"
    cat > "$bundle/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>AgentDeck</string>
<key>CFBundleIdentifier</key><string>dev.agentdeck.AgentDeck</string>
<key>CFBundleName</key><string>AgentDeck</string>
<key>CFBundleIconFile</key><string>AgentDeck.icns</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>CFBundleVersion</key><string>${version%%[-+]*}</string>
<key>LSMinimumSystemVersion</key><string>15.0</string>
<key>NSPrincipalClass</key><string>NSApplication</string>
<key>NSLocalNetworkUsageDescription</key><string>AgentDeck 通过 SSH 连接局域网内的远端机器。</string>
</dict></plist>
PLIST
    /usr/bin/plutil -lint "$bundle/Contents/Info.plist"
    /usr/bin/codesign --force "${sign_args[@]}" "$bundle"
    /usr/bin/codesign --verify --deep --strict "$bundle"
    desktop_root=AgentDeck.app
  else
    bundle="$stage/desktop/AgentDeck"
    mkdir -p "$bundle"
    cp "$bin_dir/agentdeck-desktop" "$stage/daemon/agentdeckd" "$bundle/"
    cp "$stage/daemon/RELEASE-"* "$stage/daemon/LICENSE" "$bundle/"
    cp "$root/assets/brand/agentdeck.png" "$bundle/agentdeck.png"
    cat > "$bundle/agentdeck.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=AgentDeck
Comment=Coding Agent desktop client
Exec=agentdeck-desktop
Icon=agentdeck
Terminal=false
Categories=Development;
DESKTOP
    desktop_root=AgentDeck
  fi
  COPYFILE_DISABLE=1 tar -czf "$stage/AgentDeck-$target.tar.gz" -C "$stage/desktop" "$desktop_root"
  mv "$stage/AgentDeck-$target.tar.gz" "$output_dir/"
fi
COPYFILE_DISABLE=1 tar -czf "$stage/agentdeckd-$target.tar.gz" -C "$stage/daemon" agentdeckd RELEASE-VERSION RELEASE-INFO.txt LICENSE
mv "$stage/agentdeckd-$target.tar.gz" "$output_dir/"
printf 'Packaged %s %s (%s); macOS notarization is not performed.\n' "$kind" "$version" "$target"

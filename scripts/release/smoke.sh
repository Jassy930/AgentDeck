#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
source "$root/scripts/release/common.sh"
[[ $# -ge 2 && $# -le 3 ]] || { release_fail 'usage: smoke.sh <target> <desktop|daemon> [output-dir]'; exit 2; }
target="$1"
kind="$2"
release_target "$target" "$kind"
version="$(release_version "$root" "${AGENTDECK_RELEASE_TAG:-}")"
output_dir="${3:-$root/dist/release}"
output_dir="$(cd "$output_dir" && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/agentdeck-release-smoke.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/home" "$scratch/bin" "$scratch/data" "$scratch/runtime" "$scratch/daemon" "$scratch/desktop"
chmod 700 "$scratch/runtime"
for vendor in codex claude; do
  cat > "$scratch/bin/$vendor" <<'SHIM'
#!/bin/sh
printf 'unexpected vendor invocation\n' >> "$AGENTDECK_OFFLINE_MARKER"
exit 97
SHIM
  chmod +x "$scratch/bin/$vendor"
done
smoke_env=(
  "HOME=$scratch/home" "XDG_CONFIG_HOME=$scratch/home/.config"
  "XDG_DATA_HOME=$scratch/home/.local/share" "XDG_RUNTIME_DIR=$scratch/runtime"
  "PATH=$scratch/bin:/usr/bin:/bin:/usr/sbin:/sbin"
  "AGENTDECK_DATA_DIR=$scratch/data" "AGENTDECK_OFFLINE_MARKER=$scratch/vendor-invoked"
  "AGENTDECK_CODEX_BIN=$scratch/bin/codex"
)

run_smoke() {
  local label="$1" status=0
  shift
  # Perl 的 alarm 会保留到 exec 后；只约束这次自检，不查找/终止其它应用进程。
  env -u AGENTDECK_E2E "${smoke_env[@]}" \
    /usr/bin/perl -e 'alarm 60; exec @ARGV or die "exec: $!\n"' "$@" \
    > "$scratch/$label.log" 2>&1 || status=$?
  cat "$scratch/$label.log"
  [[ ! -e "$scratch/vendor-invoked" ]] || { release_fail 'smoke test invoked a vendor'; return 1; }
  [[ "$status" == 0 ]] || { release_fail "$label exited $status (60-second timeout)"; return 1; }
}

verify_metadata() {
  local dir="$1"
  [[ "$(cat "$dir/RELEASE-VERSION")" == "$version" ]] \
    || { release_fail "archive version mismatch in $dir"; return 1; }
  grep -Fxq "target=$target" "$dir/RELEASE-INFO.txt"
  grep -Fxq "version=$version" "$dir/RELEASE-INFO.txt"
}

tar -xzf "$output_dir/agentdeckd-$target.tar.gz" -C "$scratch/daemon"
standalone="$scratch/daemon/agentdeckd"
verify_metadata "$scratch/daemon"
release_architecture "$standalone" "$target"
release_binary_version "$standalone" agentdeckd "$version"
if [[ "$target" == *-apple-darwin ]]; then
  /usr/bin/codesign --verify --strict "$standalone"
fi
run_smoke daemon "$standalone" --selfcheck
grep -Fxq OK "$scratch/daemon.log"
run_smoke diagnostics "$standalone" --diagnostics-report
if [[ "$kind" == desktop ]]; then
  tar -xzf "$output_dir/AgentDeck-$target.tar.gz" -C "$scratch/desktop"
  if [[ "$target" == *-apple-darwin ]]; then
    bundle="$scratch/desktop/AgentDeck.app"
    desktop="$bundle/Contents/MacOS/AgentDeck"
    daemon="$bundle/Contents/MacOS/agentdeckd"
    verify_metadata "$bundle/Contents/Resources"
    /usr/bin/plutil -lint "$bundle/Contents/Info.plist"
    for pair in "CFBundleShortVersionString:$version" 'CFBundleIdentifier:dev.agentdeck.AgentDeck' \
      'CFBundleExecutable:AgentDeck' 'LSMinimumSystemVersion:15.0' 'CFBundleIconFile:AgentDeck.icns'; do
      [[ "$(/usr/libexec/PlistBuddy -c "Print :${pair%%:*}" "$bundle/Contents/Info.plist")" == "${pair#*:}" ]]
    done
    cmp "$root/assets/brand/AgentDeck.icns" "$bundle/Contents/Resources/AgentDeck.icns"
    /usr/bin/codesign --verify --deep --strict "$bundle"
    mount="$scratch/dmg"
    /usr/bin/hdiutil attach -quiet -readonly -nobrowse -mountpoint "$mount" "$output_dir/AgentDeck-$target.dmg"
    dmg_status=0
    /usr/bin/codesign --verify --deep --strict "$mount/AgentDeck.app" \
      && cmp "$desktop" "$mount/AgentDeck.app/Contents/MacOS/AgentDeck" \
      && cmp "$daemon" "$mount/AgentDeck.app/Contents/MacOS/agentdeckd" \
      && [[ "$(readlink "$mount/Applications")" == /Applications ]] \
      || dmg_status=$?
    /usr/bin/hdiutil detach -quiet "$mount"
    [[ "$dmg_status" == 0 ]] || { release_fail 'DMG contents differ from the tar.gz bundle'; exit 1; }
  else
    bundle="$scratch/desktop/AgentDeck"
    desktop="$bundle/agentdeck-desktop"
    daemon="$bundle/agentdeckd"
    verify_metadata "$bundle"
    for binary in "$desktop" "$daemon"; do
      LC_ALL=C ldd "$binary" > "$scratch/ldd.log"
      cat "$scratch/ldd.log"
      if grep -q 'not found' "$scratch/ldd.log"; then
        release_fail "missing shared library: $binary"
        exit 1
      fi
    done
    grep -Fxq Exec=agentdeck-desktop "$bundle/agentdeck.desktop"
    cmp "$root/assets/brand/agentdeck.png" "$bundle/agentdeck.png"
  fi
  release_architecture "$desktop" "$target"
  release_architecture "$daemon" "$target"
  release_binary_version "$desktop" agentdeck-desktop "$version"
  release_binary_version "$daemon" agentdeckd "$version"
  cmp "$standalone" "$daemon"
  run_smoke bundled-daemon "$daemon" --selfcheck
  grep -Fxq OK "$scratch/bundled-daemon.log"
  run_smoke desktop "$desktop" --selfcheck
  grep -Fxq '{"status":"ok","surface":"desktop","ui":"gpui"}' "$scratch/desktop.log"
fi
printf 'Smoke passed: %s %s %s (isolated data, no vendor session).\n' "$version" "$target" "$kind"

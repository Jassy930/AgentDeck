#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/agentdeck-release-set.XXXXXX")"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/assets" "$fixture/stage"
version="$("$root/scripts/release/check-version.sh")"
commit="$(git -C "$root" rev-parse HEAD)"

make_archive() {
  local target="$1" kind="$2" archive_version="${3:-$version}" prefix name extension=
  [[ "$target" != *-pc-windows-msvc ]] || extension=.exe
  rm -rf "$fixture/stage"
  mkdir -p "$fixture/stage"
  if [[ "$kind" == daemon ]]; then
    prefix=
    name=agentdeckd
    touch "$fixture/stage/agentdeckd$extension"
  elif [[ "$target" == *-apple-darwin ]]; then
    prefix=AgentDeck.app/Contents/Resources/
    name=AgentDeck
    mkdir -p "$fixture/stage/AgentDeck.app/Contents/MacOS"
    touch "$fixture/stage/AgentDeck.app/Contents/MacOS/AgentDeck" "$fixture/stage/AgentDeck.app/Contents/MacOS/agentdeckd"
  elif [[ "$target" == *-pc-windows-msvc ]]; then
    prefix=AgentDeck/
    name=AgentDeck
    mkdir -p "$fixture/stage/AgentDeck"
    touch "$fixture/stage/AgentDeck/AgentDeck.exe" "$fixture/stage/AgentDeck/agentdeckd.exe"
  else
    prefix=AgentDeck/
    name=AgentDeck
    mkdir -p "$fixture/stage/AgentDeck"
    touch "$fixture/stage/AgentDeck/agentdeck-desktop" "$fixture/stage/AgentDeck/agentdeckd"
  fi
  mkdir -p "$fixture/stage/$prefix"
  printf '%s\n' "$archive_version" > "$fixture/stage/${prefix}RELEASE-VERSION"
  printf 'target=%s\ncommit=%s\n' "$target" "$commit" > "$fixture/stage/${prefix}RELEASE-INFO.txt"
  if [[ "$target" == *-pc-windows-msvc ]]; then
    rm -f "$fixture/assets/$name-$target.zip"
    (cd "$fixture/stage" && zip -qr "$fixture/assets/$name-$target.zip" .)
  else
    (cd "$fixture/stage" && COPYFILE_DISABLE=1 tar -czf "$fixture/assets/$name-$target.tar.gz" *)
  fi
}

expect_failure() {
  local label="$1"
  shift
  if "$@" > "$fixture/failure.log" 2>&1; then
    echo "test-verify-set: expected failure: $label" >&2
    exit 1
  fi
  printf 'test-verify-set: rejected %s\n' "$label"
}

for target in aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu x86_64-pc-windows-msvc; do
  make_archive "$target" desktop
  make_archive "$target" daemon
done
for target in aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
  make_archive "$target" daemon
done
verify="$root/scripts/release/verify-set.sh"
"$verify" "$fixture/assets"
"$verify" "$fixture/assets" --check

asset=AgentDeck-aarch64-unknown-linux-gnu.tar.gz
mv "$fixture/assets/$asset" "$fixture/$asset"
expect_failure 'a missing target' "$verify" "$fixture/assets"
mv "$fixture/$asset" "$fixture/assets/$asset"
touch "$fixture/assets/AgentDeck-windows.zip"
expect_failure 'an extra target' "$verify" "$fixture/assets"
rm "$fixture/assets/AgentDeck-windows.zip"
make_archive aarch64-unknown-linux-musl daemon 999.0.0
expect_failure 'a mismatched package version' "$verify" "$fixture/assets"
saved_commit="$commit"
commit=0000000000000000000000000000000000000000
make_archive aarch64-unknown-linux-musl daemon
commit="$saved_commit"
expect_failure 'a package from another commit' "$verify" "$fixture/assets"
make_archive aarch64-unknown-linux-musl daemon
make_archive x86_64-pc-windows-msvc desktop 999.0.0
expect_failure 'a mismatched Windows zip version' "$verify" "$fixture/assets"
make_archive x86_64-pc-windows-msvc desktop
zip -qd "$fixture/assets/AgentDeck-x86_64-pc-windows-msvc.zip" AgentDeck/agentdeckd.exe
expect_failure 'a Windows zip missing its bundled daemon' "$verify" "$fixture/assets"
make_archive x86_64-pc-windows-msvc desktop
"$verify" "$fixture/assets"
printf 'broken checksum\n' >> "$fixture/assets/SHA256SUMS"
expect_failure 'a corrupt checksum manifest' "$verify" "$fixture/assets" --check
"$verify" "$fixture/assets"
rm "$fixture/assets/SHA256SUMS"
expect_failure 'a missing checksum manifest' "$verify" "$fixture/assets" --check
printf 'test-verify-set: all checks passed\n'

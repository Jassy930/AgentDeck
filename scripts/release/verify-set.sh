#!/usr/bin/env bash
set -euo pipefail

# 聚合门禁只读归档，不执行来自其他平台的二进制。
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ $# -lt 1 || $# -gt 2 || ( $# == 2 && "$2" != --check ) ]]; then
  echo "usage: $0 <asset-directory> [--check]" >&2
  exit 2
fi
asset_dir="$(cd "$1" && pwd)"
version="$("$root/scripts/release/check-version.sh")"
commit="$(git -C "$root" rev-parse HEAD)"
assets=(
  AgentDeck-aarch64-apple-darwin.tar.gz
  AgentDeck-x86_64-apple-darwin.tar.gz
  AgentDeck-x86_64-unknown-linux-gnu.tar.gz
  agentdeckd-aarch64-apple-darwin.tar.gz
  agentdeckd-aarch64-unknown-linux-musl.tar.gz
  agentdeckd-x86_64-apple-darwin.tar.gz
  agentdeckd-x86_64-unknown-linux-gnu.tar.gz
  agentdeckd-x86_64-unknown-linux-musl.tar.gz
)

fail() { echo "verify-set: $*" >&2; exit 1; }
shopt -s nullglob dotglob
for path in "$asset_dir"/*; do
  name="${path##*/}"
  [[ -f "$path" && ! -L "$path" ]] || fail "unexpected non-file: $name"
  [[ "$name" == SHA256SUMS ]] && continue
  known=false
  for asset in "${assets[@]}"; do
    [[ "$name" == "$asset" ]] && known=true
  done
  [[ "$known" == true ]] || fail "unexpected asset: $name"
done

for asset in "${assets[@]}"; do
  archive="$asset_dir/$asset"
  [[ -f "$archive" && ! -L "$archive" ]] || fail "missing asset: $asset"
  target="${asset#*-}"
  target="${target%.tar.gz}"
  case "$asset" in
    AgentDeck-*-apple-darwin.tar.gz)
      prefix=AgentDeck.app/Contents/Resources/
      binaries=(AgentDeck.app/Contents/MacOS/AgentDeck AgentDeck.app/Contents/MacOS/agentdeckd)
      ;;
    AgentDeck-*-unknown-linux-gnu.tar.gz)
      prefix=AgentDeck/
      binaries=(AgentDeck/agentdeck-desktop AgentDeck/agentdeckd)
      ;;
    agentdeckd-*)
      prefix=
      binaries=(agentdeckd)
      ;;
  esac
  listing="$(tar -tzf "$archive")"
  for entry in "${binaries[@]}" "${prefix}RELEASE-VERSION" "${prefix}RELEASE-INFO.txt"; do
    grep -Fxq "$entry" <<< "$listing" || fail "$asset is missing $entry"
  done
  actual_version="$(tar -xOf "$archive" "${prefix}RELEASE-VERSION")"
  [[ "$actual_version" == "$version" ]] || fail "$asset version $actual_version != $version"
  info="$(tar -xOf "$archive" "${prefix}RELEASE-INFO.txt")"
  grep -Fxq "target=$target" <<< "$info" || fail "$asset target metadata mismatch"
  grep -Fxq "commit=$commit" <<< "$info" || fail "$asset commit metadata mismatch"
done

checksums="$(cd "$asset_dir" && shasum -a 256 "${assets[@]}")"
if [[ "${2:-}" == --check ]]; then
  [[ -f "$asset_dir/SHA256SUMS" ]] || fail "missing SHA256SUMS"
  [[ "$(cat "$asset_dir/SHA256SUMS")" == "$checksums" ]] || fail "SHA256SUMS differs from the complete asset set"
else
  printf '%s\n' "$checksums" > "$asset_dir/SHA256SUMS"
fi
printf 'verify-set: 8 archives, version %s, commit %s, SHA256SUMS OK\n' "$version" "$commit"

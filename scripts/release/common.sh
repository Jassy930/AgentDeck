#!/usr/bin/env bash
# 仅供 release 脚本 source；不启动应用、不修改用户安装。

release_fail() {
  printf 'release: %s\n' "$*" >&2
  return 1
}

release_version() {
  local root="$1" tag="${2:-}" version crate locked
  version="$(awk '
    /^\[workspace.package\]$/ { section=1; next }
    /^\[/ { section=0 }
    section && /^version = "/ { split($0, parts, "\""); print parts[2] }
  ' "$root/Cargo.toml")"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]] \
    || { release_fail "invalid workspace version: $version"; return 1; }
  for crate in agentdeck-desktop agentdeckd agentdeck-protocol agentdeck-cli; do
    grep -Eq '^version\.workspace = true$' "$root/$crate/Cargo.toml" \
      || { release_fail "$crate must inherit workspace version"; return 1; }
    locked="$(awk -v name="$crate" '
      /^\[\[package\]\]$/ { selected=0 }
      $0 == "name = \"" name "\"" { selected=1 }
      selected && /^version = "/ { split($0, parts, "\""); print parts[2] }
    ' "$root/Cargo.lock")"
    [[ "$locked" == "$version" ]] \
      || { release_fail "$crate lock version $locked differs from $version"; return 1; }
  done
  [[ -z "$tag" || "$tag" == "v$version" ]] \
    || { release_fail "tag $tag differs from workspace v$version"; return 1; }
  printf '%s\n' "$version"
}

release_target() {
  case "$1:$2" in
    aarch64-apple-darwin:desktop|x86_64-apple-darwin:desktop|x86_64-unknown-linux-gnu:desktop|aarch64-unknown-linux-gnu:desktop|\
    aarch64-apple-darwin:daemon|x86_64-apple-darwin:daemon|x86_64-unknown-linux-gnu:daemon|aarch64-unknown-linux-gnu:daemon|\
    x86_64-unknown-linux-musl:daemon|aarch64-unknown-linux-musl:daemon) ;;
    *) release_fail "unsupported Unix target/kind: $1 $2"; return 1 ;;
  esac
}

release_architecture() {
  local binary="$1" target="$2" expected actual
  [[ -x "$binary" ]] || { release_fail "missing executable: $binary"; return 1; }
  case "$target" in
    *-apple-darwin)
      expected=x86_64
      [[ "$target" != aarch64-* ]] || expected=arm64
      actual="$(/usr/bin/lipo -archs "$binary")"
      [[ "$actual" == "$expected" ]] \
        || { release_fail "$binary architecture $actual, expected $expected"; return 1; }
      actual="$(/usr/bin/vtool -show-build "$binary" | awk '$1 == "minos" { print $2; exit }')"
      [[ "$actual" == 15.0 ]] \
        || { release_fail "$binary minos $actual, expected 15.0"; return 1; }
      ;;
    *-linux-*)
      expected='Advanced Micro Devices X86-64'
      [[ "$target" != aarch64-* ]] || expected=AArch64
      actual="$(LC_ALL=C readelf -h "$binary" | sed -n 's/^ *Machine: *//p')"
      [[ "$actual" == "$expected" ]] \
        || { release_fail "$binary architecture $actual, expected $expected"; return 1; }
      if [[ "$target" == *-musl ]] && LC_ALL=C readelf -l "$binary" | grep -q INTERP; then
        release_fail "musl daemon has a dynamic interpreter: $binary"
        return 1
      fi
      ;;
  esac
}

release_binary_version() {
  local binary="$1" name="$2" version="$3" actual
  actual="$("$binary" --version)"
  [[ "${actual%%$'\n'*}" == "$name $version" ]] \
    || { release_fail "$binary has unexpected version: $actual"; return 1; }
}

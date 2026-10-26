#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
source "$root/scripts/release/common.sh"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/agentdeck-release-test.XXXXXX")"
trap 'rm -rf "$fixture"' EXIT
printf '[workspace.package]\nversion = "1.2.3"\n' > "$fixture/Cargo.toml"
for crate in agentdeck-desktop agentdeckd agentdeck-protocol agentdeck-cli; do
  mkdir -p "$fixture/$crate"
  printf '[package]\nversion.workspace = true\n' > "$fixture/$crate/Cargo.toml"
  printf '[[package]]\nname = "%s"\nversion = "1.2.3"\n' "$crate" >> "$fixture/Cargo.lock"
done
[[ "$(release_version "$fixture" v1.2.3)" == 1.2.3 ]]
if release_version "$fixture" v1.2.4 > /dev/null 2>&1; then
  release_fail 'accepted mismatched tag'; exit 1
fi
printf '[package]\nversion = "1.2.3"\n' > "$fixture/agentdeck-desktop/Cargo.toml"
if release_version "$fixture" > /dev/null 2>&1; then
  release_fail 'accepted desktop without workspace version'; exit 1
fi
printf '[package]\nversion.workspace = true\n' > "$fixture/agentdeck-desktop/Cargo.toml"
sed 's/version = "1.2.3"/version = "1.2.4"/' "$fixture/Cargo.lock" > "$fixture/changed.lock"
mv "$fixture/changed.lock" "$fixture/Cargo.lock"
if release_version "$fixture" > /dev/null 2>&1; then
  release_fail 'accepted stale lock versions'; exit 1
fi
for target in aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-gnu; do
  release_target "$target" desktop
done
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  release_target "$target" daemon
  if release_target "$target" desktop > /dev/null 2>&1; then
    release_fail 'accepted unsupported desktop'; exit 1
  fi
done
if release_target aarch64-unknown-linux-gnu desktop > /dev/null 2>&1 \
  || release_target x86_64-pc-windows-msvc desktop > /dev/null 2>&1; then
  release_fail 'accepted phase-two target'; exit 1
fi
cat > "$fixture/binary" <<'BINARY'
#!/bin/sh
printf 'agentdeckd 1.2.3\nprotocolVersion 9\n'
BINARY
chmod +x "$fixture/binary"
release_binary_version "$fixture/binary" agentdeckd 1.2.3
if release_binary_version "$fixture/binary" agentdeckd 9.9.9 > /dev/null 2>&1; then
  release_fail 'accepted mismatched binary version'; exit 1
fi
"$root/scripts/release/check-version.sh"
printf 'Release script self-tests passed.\n'

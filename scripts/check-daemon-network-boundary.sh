#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$repo_root"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  if [[ $# -gt 1 && -n "$2" ]]; then
    printf '%s\n' "$2" >&2
  fi
  exit 1
}

# 威胁场景：P4.2 引入唯一 outbound client 后，其他 daemon direct dependency 或
# transitive branch 顺带取得 HTTP/WebSocket client/server 栈，绕过 remote/ 的 typed owner。
# `--no-dedupe --prefix depth` 让每个 transitive occurrence 都能归属到 depth=1 owner；
# 所有受关注网络 crate 的 depth=1 owner 必须精确为 agentdeck-relay-client。
network_dependency_violations() {
  awk '
  function package_name(line, depth_text) {
    depth_text = line
    sub(/[^0-9].*$/, "", depth_text)
    return substr(line, length(depth_text) + 1)
  }
  function is_network(package) {
    return package ~ /^(axum|reqwest|hyper|hyper-util|tokio-tungstenite|tungstenite|quinn|h3)( |$)/
  }
  {
    depth_text = $0
    sub(/[^0-9].*$/, "", depth_text)
    depth = depth_text + 0
    package = package_name($0)
    if (depth == 1) {
      owner = package
    }
    if (is_network(package) && (depth <= 1 || owner !~ /^agentdeck-relay-client( |$)/)) {
      print "owner=" owner " dependency=" package
    }
  }
  '
}

allowed_dependency_sentinel=$'0agentdeckd v0\n1agentdeck-relay-client v0\n2tokio-tungstenite v0\n3tungstenite v0'
direct_dependency_sentinel=$'0agentdeckd v0\n1tokio-tungstenite v0'
wrong_owner_sentinel=$'0agentdeckd v0\n1unrelated-client v0\n2hyper v0'
if [[ -n "$(network_dependency_violations <<<"$allowed_dependency_sentinel")" ]]; then
  fail 'network dependency owner parser rejected its approved Relay client sentinel'
fi
for sentinel in "$direct_dependency_sentinel" "$wrong_owner_sentinel"; do
  if [[ -z "$(network_dependency_violations <<<"$sentinel")" ]]; then
    fail 'network dependency owner parser accepted a forbidden sentinel' "$sentinel"
  fi
done

dependency_tree="$(cargo tree -p agentdeckd -e normal --no-dedupe --prefix depth)"
dependency_violations="$(network_dependency_violations <<<"$dependency_tree" || true)"
if [[ -n "$dependency_violations" ]]; then
  fail 'daemon network dependencies must be owned by agentdeck-relay-client' \
    "$dependency_violations"
fi
if ! rg -q '^1agentdeck-relay-client( |$)' <<<"$dependency_tree"; then
  fail 'agentdeckd must use the single approved agentdeck-relay-client dependency'
fi

if outside_local="$(rg -n 'tokio::net' agentdeckd/src \
  | rg -v '^agentdeckd/src/local/' || true)" && [[ -n "$outside_local" ]]; then
  fail 'tokio::net is only allowed under agentdeckd/src/local; remote must use the Relay client' "$outside_local"
fi

if outside_remote_client="$(rg -n '\bagentdeck_relay_client\b' agentdeckd/src \
  | rg -v '^agentdeckd/src/remote/' || true)" && [[ -n "$outside_remote_client" ]]; then
  fail 'agentdeck-relay-client imports are only allowed under agentdeckd/src/remote' \
    "$outside_remote_client"
fi

# Grouped imports make the owning module ambiguous to line-based path filtering. Keep the
# transport import spelling canonical so the exact allowlist cannot be bypassed by formatting
# or aliases; local/ can always use direct `tokio::net::...` imports.
grouped_unix_pattern='tokio\s*::\s*\{[^}]*\bnet\s*::|std\s*::\s*os\s*::\s*unix\s*::\s*\{[^}]*\bnet\s*::|use\s+(tokio|std::os::unix::net)\s+as\s+'
for sentinel in \
  'use tokio::{net::UnixStream};' \
  'use std::os::unix::{net::UnixStream};' \
  $'use tokio::{\n  net::UnixStream,\n};'
do
  if ! printf '%s\n' "$sentinel" | rg -U -q "$grouped_unix_pattern"; then
    fail 'grouped Unix import pattern does not reject its sentinel' "$sentinel"
  fi
done
if grouped_unix_import="$(rg -n -U "$grouped_unix_pattern" agentdeckd/src || true)" \
  && [[ -n "$grouped_unix_import" ]]; then
  fail 'grouped/aliased Unix transport imports are forbidden; use canonical direct paths' \
    "$grouped_unix_import"
fi

# Pathname networking remains local-only；P4 remote/ 只能消费 typed Relay client，不能直接
# 创建 socket。adapters 和 RuntimeCore 不能取得 transport ownership。Type-token
# scanning deliberately catches rustfmt grouped imports and aliases, not only fully-qualified
# paths. Wildcard net imports and direct socket2/mio use are forbidden because they would
# bypass the file-level allowlist.
banned_transport_pattern='\b(TcpListener|TcpStream|TcpSocket|UdpSocket|UdpFramed)\b|\bnet\s*::\s*\*|socket2::|mio::net::|reqwest::|axum::|hyper::server|tokio_tungstenite|tungstenite::|libc\s*::\s*(socket|socketpair|connect|bind|listen|accept|sendto|recvfrom|getaddrinfo)\b|use\s+(::)?libc(\s+as\s+|\s*::)|use\s*\{[^}]*\blibc\b|extern\s+crate\s+libc\b'
for sentinel in \
  'use tokio::net::{TcpStream, UnixStream};' \
  'use std::net::{TcpListener as Listener, UdpSocket};' \
  'use tokio::{net::TcpSocket};' \
  'use tokio::net::*;' \
  'unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };' \
  'unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };' \
  'unsafe { libc::connect(fd, addr, len) };' \
  'use libc::{socket as open_socket};' \
  'use libc as c; c::socket(c::AF_INET, c::SOCK_STREAM, 0);' \
  'use {libc as c}; c::socket(c::AF_INET, c::SOCK_STREAM, 0);'
do
  if ! printf '%s\n' "$sentinel" | rg -q "$banned_transport_pattern"; then
    fail 'network boundary pattern does not reject a grouped/aliased import sentinel' "$sentinel"
  fi
done

if banned_source="$(rg -n -U "$banned_transport_pattern" \
  agentdeckd/src agentdeckd/Cargo.toml || true)" && [[ -n "$banned_source" ]]; then
  fail 'daemon source contains a banned TCP/UDP/HTTP/WebSocket surface' "$banned_source"
fi

# 威胁场景：local/ 的 pathname allowlist 若顺带放行 datagram/raw Unix socket，
# 就会在批准的 stream/listener 之外新增未建模传输面并绕过 framing/supervisor。
unsupported_unix_pattern='\b(UnixDatagram|UnixSocket)\b'
for sentinel in \
  'use tokio::net::UnixDatagram;' \
  'use tokio::net::UnixSocket;'
do
  if ! printf '%s\n' "$sentinel" | rg -q "$unsupported_unix_pattern"; then
    fail 'unsupported Unix transport pattern does not reject its sentinel' "$sentinel"
  fi
done
if unsupported_unix="$(rg -n "$unsupported_unix_pattern" agentdeckd/src || true)" \
  && [[ -n "$unsupported_unix" ]]; then
  fail 'Unix datagram/raw socket transports are forbidden during P3' "$unsupported_unix"
fi

# P3.7 exec-gate legitimately uses a private inherited AF_UNIX socketpair. Keep the
# allowlist file-exact and forbid any pathname connect/bind call on that private control surface,
# including calls through an imported alias.
if private_pathname="$(rg -n '::(connect|bind)\s*\(' \
  agentdeckd/src/exec_gate.rs agentdeckd/src/exec_gate/parent.rs \
  agentdeckd/src/runtime/execution.rs || true)" && [[ -n "$private_pathname" ]]; then
  fail 'exec-gate private socketpair files must not open pathname Unix sockets' "$private_pathname"
fi

if std_listener_or_datagram="$(rg -n \
  'std::os::unix::net[^\n]*(UnixListener|UnixDatagram)' agentdeckd/src || true)" \
  && [[ -n "$std_listener_or_datagram" ]]; then
  fail 'std UnixListener/UnixDatagram are forbidden during P3' "$std_listener_or_datagram"
fi
if private_listener_or_datagram="$(rg -n '\b(UnixListener|UnixDatagram)\b' \
  agentdeckd/src/exec_gate.rs agentdeckd/src/exec_gate/parent.rs \
  agentdeckd/src/runtime/execution.rs || true)" \
  && [[ -n "$private_listener_or_datagram" ]]; then
  fail 'exec-gate private control surface may only use UnixStream socketpair' \
    "$private_listener_or_datagram"
fi

unix_transport_pattern='\b(UnixListener|UnixStream|UnixDatagram)\b'
for sentinel in \
  'use tokio::{net as n}; n::UnixListener::bind(path);' \
  'use std::os::unix::{net}; net::UnixStream::connect(path);'
do
  if ! printf '%s\n' "$sentinel" | rg -q "$unix_transport_pattern"; then
    fail 'Unix transport pattern does not reject a grouped module alias sentinel' "$sentinel"
  fi
done

while IFS=: read -r path line _; do
  [[ -z "$path" ]] && continue
  case "$path" in
    agentdeckd/src/local/*)
      ;;
    agentdeckd/src/exec_gate.rs|agentdeckd/src/exec_gate/parent.rs)
      ;;
    agentdeckd/src/runtime/execution.rs)
      test_module_boundary="$(rg -n '^mod tests \{' "$path" | head -n 1 | cut -d: -f1)"
      previous_line=''
      if [[ "$line" -gt 1 ]]; then
        previous_line="$(sed -n "$((line - 1))p" "$path")"
      fi
      if [[ "$previous_line" == '#[cfg(test)]' ]]; then
        continue
      fi
      if [[ -z "$test_module_boundary" || "$line" -le "$test_module_boundary" ]]; then
        fail 'runtime/execution.rs may use std UnixStream only below cfg(test)' "$path:$line"
      fi
      ;;
    *)
      fail 'Unix transport type is outside the local/exec-gate file allowlist' "$path:$line"
      ;;
  esac
done < <(rg -n "$unix_transport_pattern" agentdeckd/src || true)

adapter_transport_pattern='crate::(local|remote)|crate\s*::\s*\{[^}]*\b(local|remote)\b|tokio::net|agentdeck_relay|relay_v2'
for sentinel in \
  'use crate::{local};' \
  $'use crate::{\n    remote as transport,\n};'
do
  if ! printf '%s\n' "$sentinel" | rg -U -q "$adapter_transport_pattern"; then
    fail 'adapter transport pattern does not reject its sentinel' "$sentinel"
  fi
done
if adapter_transport="$(rg -n -U \
  "$adapter_transport_pattern" \
  agentdeckd/src/codex agentdeckd/src/claude_code || true)" \
  && [[ -n "$adapter_transport" ]]; then
  fail 'vendor adapters must not import local/remote/Relay transport' "$adapter_transport"
fi

printf 'ok: agentdeckd network boundary is local UDS plus remote/-owned Relay client only\n'

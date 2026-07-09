#!/usr/bin/env bash
set -euo pipefail
if cargo tree -p agentdeckd -e features 2>/dev/null | grep -qiE 'tokio .*\bnet\b|axum'; then
  echo "FAIL: agentdeckd 依赖树含 tokio net / axum（R1a 不变量：daemon 无 net 至 R2）"; exit 1
fi
echo "ok: agentdeckd 无 tokio net / axum"

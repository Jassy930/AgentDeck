#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
target_dir="$repo_root/target"
mode="${1:---dry-run}"

case "$mode" in
  --dry-run)
    clean_args=(--dry-run --profile dev)
    ;;
  --execute)
    clean_args=(--profile dev)
    ;;
  *)
    printf '用法：%s [--dry-run|--execute]\n' "$0" >&2
    exit 64
    ;;
esac

if pgrep -f "$target_dir" >/dev/null; then
  printf 'ERROR: 检测到仍在使用 %s 的构建进程；请等待构建结束后重试\n' "$target_dir" >&2
  exit 2
fi

before="$(du -sh "$target_dir" 2>/dev/null || printf '0B\t%s\n' "$target_dir")"
printf '清理前：%s\n' "$before"

cd "$repo_root"
cargo clean "${clean_args[@]}"

if [[ "$mode" == "--execute" ]]; then
  after="$(du -sh "$target_dir" 2>/dev/null || printf '0B\t%s\n' "$target_dir")"
  printf '清理后：%s\n' "$after"
fi

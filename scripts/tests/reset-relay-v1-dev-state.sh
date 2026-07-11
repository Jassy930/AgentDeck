#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd -P)"
reset_script="$repo_root/scripts/reset-relay-v1-dev-state.sh"

if [[ ! -f "$reset_script" ]]; then
  printf 'reset-relay-v1-dev-state test: FAIL: target script missing: %s\n' "$reset_script" >&2
  exit 1
fi

for command in awk jq openssl realpath sqlite3; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'reset-relay-v1-dev-state test: FAIL: missing command: %s\n' "$command" >&2
    exit 1
  }
done

tmp_root="$(realpath "$(mktemp -d "${TMPDIR:-/tmp}/agentdeck-relay-v1-reset.XXXXXX")")"
flagged_paths=()

restore_test_flags() {
  local path
  for path in "${flagged_paths[@]}"; do
    if [[ -e "$path" || -L "$path" ]]; then
      chflags nouchg "$path" 2>/dev/null || true
    fi
  done
}

cleanup() {
  restore_test_flags
  rm -rf -- "$tmp_root"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

credential='MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY='

credential_hash() {
  printf '%s' "$1" | openssl dgst -sha256 -binary | openssl base64 -A
}

create_v1_state() {
  local root="$1"
  local account_id="${2:-acc-test}"
  local device_id="${3:-device-test}"
  local role="${4:-device}"
  local bearer="${5:-$credential}"
  local hash
  hash="$(credential_hash "$bearer")"

  mkdir -p "$root"
  sqlite3 "$root/relay.db" <<SQL
PRAGMA foreign_keys = ON;
CREATE TABLE accounts (
    account_id TEXT PRIMARY KEY,
    owner_sign_pubkey TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    role TEXT NOT NULL CHECK (role IN ('machine', 'device')),
    credential_hash TEXT NOT NULL UNIQUE,
    sign_pubkey TEXT NOT NULL,
    box_pubkey TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX idx_devices_credential_hash ON devices(credential_hash);
CREATE TABLE challenges (
    device_sign_pubkey TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL
);
CREATE TABLE seq_high_water_marks (
    conversation_id TEXT PRIMARY KEY,
    next_seq INTEGER NOT NULL DEFAULT 0,
    acked_seq INTEGER NOT NULL DEFAULT -1
);
CREATE TABLE conv_events (
    conversation_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    turn_session_id TEXT NOT NULL,
    encryption_version INTEGER NOT NULL DEFAULT 0,
    payload BLOB,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (conversation_id, seq)
);
PRAGMA user_version = 1;
INSERT INTO accounts(account_id, owner_sign_pubkey, created_at_ms)
VALUES ('$account_id', 'owner-key', 1);
INSERT INTO devices(
    device_id, account_id, role, credential_hash, sign_pubkey, box_pubkey, revoked, created_at_ms
) VALUES (
    '$device_id', '$account_id', '$role', '$hash', 'sign-key', 'box-key', 0, 1
);
SQL

  : >"$root/relay.db-wal"
  : >"$root/relay.db-shm"
  jq -n \
    --arg relay_url 'ws://127.0.0.1:8443' \
    --arg account_id "$account_id" \
    --arg device_id "$device_id" \
    --arg credential "$bearer" \
    --arg role "$role" \
    '{relay_url: $relay_url, account_id: $account_id, device_id: $device_id,
      credential: $credential, role: $role}' >"$root/dev.credentials.json"

  printf 'keep\n' >"$root/unrelated.txt"
  printf 'keep-prefix\n' >"$root/relay.db.backup"
  printf 'keep-credential-prefix\n' >"$root/dev.credentials.json.backup"
}

create_real_wal_sidecars() {
  local root="$1"
  local fifo="$root/sqlite-input"
  local ready="$root/wal-ready"
  local sqlite_pid
  local attempt
  local path

  mkfifo "$fifo"
  sqlite3 "$root/relay.db" <"$fifo" >"$root/sqlite.stdout" 2>"$root/sqlite.stderr" &
  sqlite_pid=$!
  exec 9>"$fifo"
  printf '%s\n' \
    'PRAGMA journal_mode = WAL;' \
    'PRAGMA wal_autocheckpoint = 0;' \
    'UPDATE accounts SET created_at_ms = created_at_ms + 1;' \
    'PRAGMA wal_checkpoint(TRUNCATE);' \
    ".shell touch '$ready'" >&9

  for attempt in {1..100}; do
    [[ -f "$ready" ]] && break
    sleep 0.02
  done
  if [[ ! -f "$ready" ]]; then
    kill -9 "$sqlite_pid" 2>/dev/null || true
    exec 9>&-
    wait "$sqlite_pid" 2>/dev/null || true
    printf 'reset-relay-v1-dev-state test: FAIL: could not create real WAL sidecars\n' >&2
    exit 1
  fi

  # 模拟 Relay 已停止但上次进程未清理 sidecar；先 checkpoint，保证 immutable
  # 读取主 DB 仍能看到完整 v1 schema 与 device row。
  kill -9 "$sqlite_pid"
  exec 9>&-
  wait "$sqlite_pid" 2>/dev/null || true
  for path in "$root/relay.db-wal" "$root/relay.db-shm"; do
    [[ -f "$path" ]] || {
      printf 'reset-relay-v1-dev-state test: FAIL: missing real sidecar: %s\n' "$path" >&2
      exit 1
    }
  done

  # 将 mtime 固定到过去，使会写 mmap 的 sqlite3 -readonly 查询可重复改变 stat
  # fingerprint，而不是依赖同一秒内的时间戳粒度。
  touch -t 200001010000 "$root/relay.db-wal" "$root/relay.db-shm"
}

assert_exists() {
  local path="$1"
  [[ -e "$path" || -L "$path" ]] || {
    printf 'reset-relay-v1-dev-state test: FAIL: expected path to remain: %s\n' "$path" >&2
    exit 1
  }
}

assert_absent() {
  local path="$1"
  [[ ! -e "$path" && ! -L "$path" ]] || {
    printf 'reset-relay-v1-dev-state test: FAIL: expected path to be deleted: %s\n' "$path" >&2
    exit 1
  }
}

assert_state_intact() {
  local root="$1"
  assert_exists "$root/relay.db"
  assert_exists "$root/relay.db-wal"
  assert_exists "$root/relay.db-shm"
  assert_exists "$root/dev.credentials.json"
  assert_exists "$root/unrelated.txt"
  assert_exists "$root/relay.db.backup"
  assert_exists "$root/dev.credentials.json.backup"
}

run_reset() {
  local root="$1"
  shift
  bash "$reset_script" \
    --storage "$root/relay.db" \
    --credentials "$root/dev.credentials.json" \
    "$@"
}

expect_rejected_without_deletion() {
  local name="$1"
  local root="$2"
  shift 2
  if "$@" >"$tmp_root/$name.stdout" 2>"$tmp_root/$name.stderr"; then
    printf 'reset-relay-v1-dev-state test: FAIL: %s unexpectedly succeeded\n' "$name" >&2
    exit 1
  fi
  assert_state_intact "$root"
  printf 'PASS: %s rejected with zero deletion\n' "$name"
}

# 缺少精确确认串。
root="$tmp_root/missing-confirm"
create_v1_state "$root"
expect_rejected_without_deletion missing-confirm "$root" run_reset "$root"

# storage / credentials 必须是绝对普通文件，目录不能代替文件。
root="$tmp_root/directory-storage"
create_v1_state "$root"
expect_rejected_without_deletion directory-storage "$root" \
  bash "$reset_script" --storage "$root" --credentials "$root/dev.credentials.json" \
  --confirm DELETE-RELAY-V1-DEV-STATE

root="$tmp_root/directory-credentials"
create_v1_state "$root"
expect_rejected_without_deletion directory-credentials "$root" \
  bash "$reset_script" --storage "$root/relay.db" --credentials "$root" \
  --confirm DELETE-RELAY-V1-DEV-STATE

root="$tmp_root/root-storage"
create_v1_state "$root"
expect_rejected_without_deletion root-storage "$root" \
  bash "$reset_script" --storage / --credentials "$root/dev.credentials.json" \
  --confirm DELETE-RELAY-V1-DEV-STATE

# 输入路径任何组件都不能是 symlink。
real_root="$tmp_root/component-real"
link_root="$tmp_root/component-link"
create_v1_state "$real_root"
ln -s "$real_root" "$link_root"
expect_rejected_without_deletion symlink-component "$real_root" \
  bash "$reset_script" --storage "$link_root/relay.db" \
  --credentials "$link_root/dev.credentials.json" \
  --confirm DELETE-RELAY-V1-DEV-STATE

for link_kind in storage credentials; do
  root="$tmp_root/symlink-$link_kind-file"
  create_v1_state "$root"
  if [[ "$link_kind" == storage ]]; then
    ln -s "$root/relay.db" "$root/relay-link.db"
    expect_rejected_without_deletion symlink-storage-file "$root" \
      bash "$reset_script" --storage "$root/relay-link.db" \
      --credentials "$root/dev.credentials.json" \
      --confirm DELETE-RELAY-V1-DEV-STATE
  else
    ln -s "$root/dev.credentials.json" "$root/credentials-link.json"
    expect_rejected_without_deletion symlink-credentials-file "$root" \
      bash "$reset_script" --storage "$root/relay.db" \
      --credentials "$root/credentials-link.json" \
      --confirm DELETE-RELAY-V1-DEV-STATE
  fi
done

# 两个 sidecar 也属于删除集合，任一个是 symlink 都必须整组拒绝。
for sidecar in wal shm; do
  root="$tmp_root/symlink-$sidecar"
  create_v1_state "$root"
  rm "$root/relay.db-$sidecar"
  ln -s "$root/unrelated.txt" "$root/relay.db-$sidecar"
  expect_rejected_without_deletion "symlink-$sidecar" "$root" run_reset "$root" \
    --confirm DELETE-RELAY-V1-DEV-STATE
done

# macOS immutable flag 必须在第一次 unlink 前被预检发现；即使断言失败，EXIT
# trap 也会先恢复 flag，避免测试 fixture 无法清理。
if [[ "$(uname -s)" == 'Darwin' ]]; then
  command -v chflags >/dev/null 2>&1 || {
    printf 'reset-relay-v1-dev-state test: FAIL: missing command: chflags\n' >&2
    exit 1
  }
  root="$tmp_root/immutable-credentials"
  create_v1_state "$root"
  flagged_paths+=("$root/dev.credentials.json")
  chflags uchg "$root/dev.credentials.json"
  expect_rejected_without_deletion immutable-credentials "$root" run_reset "$root" \
    --confirm DELETE-RELAY-V1-DEV-STATE
  chflags nouchg "$root/dev.credentials.json"
  flagged_paths=()
else
  printf 'SKIP: immutable-credentials requires macOS chflags\n'
fi

# credential JSON 必须是精确 v1 shape；v2 marker/额外字段拒绝。
root="$tmp_root/v2-marker"
create_v1_state "$root"
jq '.version = 2' "$root/dev.credentials.json" >"$root/credentials.tmp"
mv "$root/credentials.tmp" "$root/dev.credentials.json"
expect_rejected_without_deletion v2-marker "$root" run_reset "$root" \
  --confirm DELETE-RELAY-V1-DEV-STATE

# bearer 必须实际解码为 32 bytes，并且逐字等于重新编码的 canonical Base64。
root="$tmp_root/wrong-decoded-credential-length"
short_credential="$(printf '0123456789abcdef0123456789abcde' | openssl base64 -A)"
create_v1_state "$root" acc-test device-test device "$short_credential"
expect_rejected_without_deletion wrong-decoded-credential-length "$root" run_reset "$root" \
  --confirm DELETE-RELAY-V1-DEV-STATE

root="$tmp_root/noncanonical-credential-base64"
noncanonical_credential="${credential:0:${#credential}-2}Z="
create_v1_state "$root" acc-test device-test device "$noncanonical_credential"
expect_rejected_without_deletion noncanonical-credential-base64 "$root" run_reset "$root" \
  --confirm DELETE-RELAY-V1-DEV-STATE

# DB 只能是精确 v1 schema：未知表、额外表、错误 user_version 均拒绝。
for table_kind in unknown-table extra-table; do
  root="$tmp_root/$table_kind"
  create_v1_state "$root"
  if [[ "$table_kind" == unknown-table ]]; then
    sqlite3 "$root/relay.db" 'ALTER TABLE challenges RENAME TO challenge_v2;'
  else
    sqlite3 "$root/relay.db" 'CREATE TABLE relay_v2_marker(version INTEGER NOT NULL);'
  fi
  expect_rejected_without_deletion "$table_kind" "$root" run_reset "$root" \
    --confirm DELETE-RELAY-V1-DEV-STATE
done

root="$tmp_root/wrong-user-version"
create_v1_state "$root"
sqlite3 "$root/relay.db" 'PRAGMA user_version = 2;'
expect_rejected_without_deletion wrong-user-version "$root" run_reset "$root" \
  --confirm DELETE-RELAY-V1-DEV-STATE

root="$tmp_root/wrong-explicit-index-column"
create_v1_state "$root"
sqlite3 "$root/relay.db" \
  'DROP INDEX idx_devices_credential_hash; CREATE INDEX idx_devices_credential_hash ON devices(device_id);'
expect_rejected_without_deletion wrong-explicit-index-column "$root" run_reset "$root" \
  --confirm DELETE-RELAY-V1-DEV-STATE

root="$tmp_root/whitespace-in-check-literal"
create_v1_state "$root"
sqlite3 "$root/relay.db" <<'SQL'
PRAGMA writable_schema = ON;
UPDATE sqlite_schema
SET sql = replace(sql, '''machine''', '''mach ine''')
WHERE type = 'table' AND name = 'devices';
PRAGMA writable_schema = OFF;
SQL
expect_rejected_without_deletion whitespace-in-check-literal "$root" run_reset "$root" \
  --confirm DELETE-RELAY-V1-DEV-STATE

# credential 必须与 DB 中同一 device 行的 account/device/role/hash 全部关联。
for mismatch in account device role hash; do
  root="$tmp_root/mismatch-$mismatch"
  create_v1_state "$root"
  case "$mismatch" in
    account) jq '.account_id = "acc-other"' "$root/dev.credentials.json" >"$root/credentials.tmp" ;;
    device) jq '.device_id = "device-other"' "$root/dev.credentials.json" >"$root/credentials.tmp" ;;
    role) jq '.role = "machine"' "$root/dev.credentials.json" >"$root/credentials.tmp" ;;
    hash) jq '.credential = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="' "$root/dev.credentials.json" >"$root/credentials.tmp" ;;
  esac
  mv "$root/credentials.tmp" "$root/dev.credentials.json"
  expect_rejected_without_deletion "mismatch-$mismatch" "$root" run_reset "$root" \
    --confirm DELETE-RELAY-V1-DEV-STATE
done

# 真实 WAL/SHM 已 checkpoint 且 Relay 已停止时，reset 自己的只读校验不得触碰
# sidecar，否则最终 fingerprint guard 会把自身副作用误报为活动 Relay。
root="$tmp_root/real-wal-sidecars"
create_v1_state "$root"
create_real_wal_sidecars "$root"
if ! run_reset "$root" --confirm DELETE-RELAY-V1-DEV-STATE \
  >"$tmp_root/real-wal-sidecars.stdout" 2>"$tmp_root/real-wal-sidecars.stderr"; then
  sed -n '1,80p' "$tmp_root/real-wal-sidecars.stderr" >&2
  printf 'reset-relay-v1-dev-state test: FAIL: real WAL sidecars caused validation fingerprint drift\n' >&2
  exit 1
fi
assert_absent "$root/relay.db"
assert_absent "$root/relay.db-wal"
assert_absent "$root/relay.db-shm"
assert_absent "$root/dev.credentials.json"
printf 'PASS: real WAL sidecars are not touched by validation\n'

# immutable SQLite URI 只能消除 reset 自己的 sidecar 副作用；外部活动写入仍必须被
# 最终 fingerprint guard 拒绝，且发生在第一次 unlink 前。
root="$tmp_root/active-sidecar-mutation"
create_v1_state "$root"
fake_bin="$root/fake-sqlite-bin"
mkdir -p "$fake_bin"
real_sqlite3="$(command -v sqlite3)"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  '"$REAL_SQLITE3" "$@"' \
  'status=$?' \
  'if [[ -e "$MUTATE_SIDECAR" ]]; then printf x >>"$MUTATE_SIDECAR"; fi' \
  'exit "$status"' >"$fake_bin/sqlite3"
chmod +x "$fake_bin/sqlite3"
expect_rejected_without_deletion active-sidecar-mutation "$root" \
  env \
    PATH="$fake_bin:$PATH" \
    REAL_SQLITE3="$real_sqlite3" \
    MUTATE_SIDECAR="$root/relay.db-shm" \
    bash "$reset_script" \
      --storage "$root/relay.db" \
      --credentials "$root/dev.credentials.json" \
      --confirm DELETE-RELAY-V1-DEV-STATE

# 即使 preflight 后 OS unlink 仍失败，也只能报告 partial deletion；必须非零退出、
# 不打印成功，并逐个列出四个允许目标中仍存在的 exact path。
root="$tmp_root/unlink-stage-failure"
create_v1_state "$root"
fake_bin="$root/fake-bin"
mkdir -p "$fake_bin"
real_rm="$(command -v rm)"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'failed=0' \
  'for operand in "$@"; do' \
  '  case "$operand" in -f|--) continue ;; esac' \
  '  if [[ "$operand" == "$FAIL_UNLINK_PATH" ]]; then' \
  '    printf "simulated unlink failure: %s\\n" "$operand" >&2' \
  '    failed=1' \
  '  else' \
  '    "$REAL_RM" -f -- "$operand"' \
  '  fi' \
  'done' \
  '((failed == 0))' >"$fake_bin/rm"
chmod +x "$fake_bin/rm"
set +e
env \
  PATH="$fake_bin:$PATH" \
  REAL_RM="$real_rm" \
  FAIL_UNLINK_PATH="$root/dev.credentials.json" \
  bash "$reset_script" \
    --storage "$root/relay.db" \
    --credentials "$root/dev.credentials.json" \
    --confirm DELETE-RELAY-V1-DEV-STATE \
    >"$tmp_root/unlink-stage-failure.stdout" \
    2>"$tmp_root/unlink-stage-failure.stderr"
unlink_status=$?
set -e
[[ "$unlink_status" -ne 0 ]] || {
  printf 'reset-relay-v1-dev-state test: FAIL: simulated unlink failure returned zero\n' >&2
  exit 1
}
if grep -F 'deleted exact Relay' "$tmp_root/unlink-stage-failure.stdout" >/dev/null; then
  printf 'reset-relay-v1-dev-state test: FAIL: unlink failure printed success\n' >&2
  exit 1
fi
grep -F "remaining exact path: $root/dev.credentials.json" \
  "$tmp_root/unlink-stage-failure.stderr" >/dev/null || {
    sed -n '1,80p' "$tmp_root/unlink-stage-failure.stderr" >&2
    printf 'reset-relay-v1-dev-state test: FAIL: unlink failure omitted remaining exact path\n' >&2
    exit 1
  }
[[ "$(grep -Fc 'remaining exact path:' "$tmp_root/unlink-stage-failure.stderr")" == '1' ]] || {
  sed -n '1,80p' "$tmp_root/unlink-stage-failure.stderr" >&2
  printf 'reset-relay-v1-dev-state test: FAIL: unlink failure reported a non-exact remaining set\n' >&2
  exit 1
}
grep -F 'no rollback is guaranteed' "$tmp_root/unlink-stage-failure.stderr" >/dev/null || {
  printf 'reset-relay-v1-dev-state test: FAIL: unlink failure promised or omitted rollback boundary\n' >&2
  exit 1
}
grep -F 'manually remove the remaining exact paths, then pair again' \
  "$tmp_root/unlink-stage-failure.stderr" >/dev/null || {
    printf 'reset-relay-v1-dev-state test: FAIL: unlink failure omitted manual cleanup and re-pair guidance\n' >&2
    exit 1
  }
assert_absent "$root/relay.db"
assert_absent "$root/relay.db-wal"
assert_absent "$root/relay.db-shm"
assert_exists "$root/dev.credentials.json"
assert_exists "$root/unrelated.txt"
printf 'PASS: unlink failure reports exact remainder without success or rollback claim\n'

# 精确 v1 输入只删除四个目标，保留所有同前缀及无关文件。
root="$tmp_root/success"
create_v1_state "$root"
run_reset "$root" --confirm DELETE-RELAY-V1-DEV-STATE
assert_absent "$root/relay.db"
assert_absent "$root/relay.db-wal"
assert_absent "$root/relay.db-shm"
assert_absent "$root/dev.credentials.json"
assert_exists "$root/unrelated.txt"
assert_exists "$root/relay.db.backup"
assert_exists "$root/dev.credentials.json.backup"
printf 'PASS: exact v1 state deleted; prefixed and unrelated files preserved\n'
printf 'reset-relay-v1-dev-state test: PASS\n'

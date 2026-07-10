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
trap 'rm -rf -- "$tmp_root"' EXIT

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

# credential JSON 必须是精确 v1 shape；v2 marker/额外字段拒绝。
root="$tmp_root/v2-marker"
create_v1_state "$root"
jq '.version = 2' "$root/dev.credentials.json" >"$root/credentials.tmp"
mv "$root/credentials.tmp" "$root/dev.credentials.json"
expect_rejected_without_deletion v2-marker "$root" run_reset "$root" \
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

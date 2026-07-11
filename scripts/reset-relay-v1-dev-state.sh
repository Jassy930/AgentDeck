#!/usr/bin/env bash
set -euo pipefail

readonly confirmation='DELETE-RELAY-V1-DEV-STATE'

fail() {
  printf 'reset-relay-v1-dev-state: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'usage: reset-relay-v1-dev-state.sh --storage ABSOLUTE_FILE --credentials ABSOLUTE_FILE --confirm DELETE-RELAY-V1-DEV-STATE' >&2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

storage=''
credentials=''
provided_confirmation=''

while (($# > 0)); do
  case "$1" in
    --storage)
      [[ -z "$storage" && $# -ge 2 ]] || { usage; fail 'invalid or duplicate --storage'; }
      storage="$2"
      shift 2
      ;;
    --credentials)
      [[ -z "$credentials" && $# -ge 2 ]] || { usage; fail 'invalid or duplicate --credentials'; }
      credentials="$2"
      shift 2
      ;;
    --confirm)
      [[ -z "$provided_confirmation" && $# -ge 2 ]] || { usage; fail 'invalid or duplicate --confirm'; }
      provided_confirmation="$2"
      shift 2
      ;;
    *)
      usage
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "$storage" && -n "$credentials" ]] || { usage; fail 'both --storage and --credentials are required'; }
[[ "$provided_confirmation" == "$confirmation" ]] || fail "confirmation must be exactly $confirmation"

for command in awk jq openssl realpath sqlite3 stat; do
  require_command "$command"
done

verify_no_symlink_component() {
  local path="$1"
  local current=''
  local component
  local -a components

  IFS='/' read -r -a components <<<"${path#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" ]] || continue
    current="$current/$component"
    [[ ! -L "$current" ]] || fail "path contains a symlink component: $path"
  done
}

validate_required_file() {
  local label="$1"
  local path="$2"
  local resolved

  [[ "$path" == /* && "$path" != '/' ]] || fail "$label must be an absolute non-root file path"
  [[ ! -L "$path" ]] || fail "$label must not be a symlink"
  [[ -f "$path" ]] || fail "$label must name an existing regular file"
  verify_no_symlink_component "$path"
  resolved="$(realpath "$path")" || fail "cannot resolve $label"
  [[ "$resolved" == "$path" ]] || fail "$label must be canonical and contain no symlink component"
}

validate_optional_sidecar() {
  local label="$1"
  local path="$2"

  [[ "$path" == /* && "$path" != '/' ]] || fail "$label must be an absolute non-root file path"
  verify_no_symlink_component "$path"
  if [[ -L "$path" ]]; then
    fail "$label must not be a symlink"
  fi
  if [[ -e "$path" ]]; then
    local resolved
    [[ -f "$path" ]] || fail "$label must be a regular file when present"
    resolved="$(realpath "$path")" || fail "cannot resolve $label"
    [[ "$resolved" == "$path" ]] || fail "$label must be canonical and contain no symlink component"
  fi
}

validate_macos_unlink_flags() {
  local label="$1"
  local path="$2"
  local flags

  [[ "$(uname -s)" == 'Darwin' ]] || return 0
  flags="$(stat -f '%Sf' "$path")" || fail "cannot inspect $label file flags"
  case ",$flags," in
    *,uchg,*|*,uappnd,*|*,schg,*|*,sappnd,*|*,restricted,*)
      fail "$label has a macOS flag that can block unlink: $flags"
      ;;
  esac
}

validate_unlink_preflight() {
  local label="$1"
  local path="$2"
  local parent

  [[ -e "$path" || -L "$path" ]] || return 0
  parent="$(dirname "$path")"
  [[ -d "$parent" ]] || fail "$label parent is not a directory"
  [[ -x "$parent" ]] || fail "$label parent directory is not searchable"
  [[ -w "$parent" ]] || fail "$label parent directory is not writable"
  validate_macos_unlink_flags "$label" "$path"
  validate_macos_unlink_flags "$label parent" "$parent"
}

stat_fingerprint() {
  local path="$1"
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    printf 'absent\n'
  elif stat -f '%d:%i:%z:%m:%c:%p' "$path" >/dev/null 2>&1; then
    stat -f '%d:%i:%z:%m:%c:%p' "$path"
  else
    stat -c '%d:%i:%s:%Y:%Z:%f' "$path"
  fi
}

wal="${storage}-wal"
shm="${storage}-shm"

# 删除集合固定为这四个精确路径；不接受路径重叠，也不使用 glob。
[[ "$credentials" != "$storage" && "$credentials" != "$wal" && "$credentials" != "$shm" ]] || \
  fail 'storage, sidecars, and credentials paths must be distinct'

validate_required_file storage "$storage"
validate_required_file credentials "$credentials"
validate_optional_sidecar storage-wal "$wal"
validate_optional_sidecar storage-shm "$shm"
validate_unlink_preflight storage "$storage"
validate_unlink_preflight storage-wal "$wal"
validate_unlink_preflight storage-shm "$shm"
validate_unlink_preflight credentials "$credentials"

storage_before="$(stat_fingerprint "$storage")"
wal_before="$(stat_fingerprint "$wal")"
shm_before="$(stat_fingerprint "$shm")"
credentials_before="$(stat_fingerprint "$credentials")"

storage_uri="file:$(printf '%s' "$storage" | jq -sRr @uri)?mode=ro&immutable=1"

sqlite_read() {
  sqlite3 -batch -noheader "$storage_uri" "$1"
}

user_version="$(sqlite_read 'PRAGMA user_version;')" || fail 'storage is not a readable SQLite database'
[[ "$user_version" == '1' ]] || fail 'storage PRAGMA user_version is not Relay v1'

expected_tables=$'accounts\nchallenges\nconv_events\ndevices\nseq_high_water_marks'
actual_tables="$(sqlite_read \
  "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name;")" || \
  fail 'cannot inspect storage tables'
[[ "$actual_tables" == "$expected_tables" ]] || fail 'storage table set is not the exact Relay v1 schema'

expected_indexes='idx_devices_credential_hash'
actual_indexes="$(sqlite_read \
  "SELECT name FROM sqlite_schema WHERE type = 'index' AND name NOT LIKE 'sqlite_autoindex_%' ORDER BY name;")" || \
  fail 'cannot inspect storage indexes'
[[ "$actual_indexes" == "$expected_indexes" ]] || fail 'storage index set is not the exact Relay v1 schema'

# 只移除 SQL 字符串字面量之外的空白，并只在字面量之外做小写归一；字面量中的
# 空格、大小写和 SQL 的 '' escape 必须逐字保留，不能把 'mach ine' 误判成
# 'machine'。sqlite_schema 会去掉 IF NOT EXISTS 并规范 CREATE 前缀。
normalize_schema_sql() {
  LC_ALL=C awk '
    BEGIN { ORS = ""; in_string = 0; row_separator = "__AGENTDECK_SCHEMA_ROW__" }
    NR > 1 && in_string { printf "\n" }
    {
      for (i = 1; i <= length($0); i++) {
        c = substr($0, i, 1)
        if (in_string) {
          printf "%s", c
          if (c == "\047") {
            if (substr($0, i + 1, 1) == "\047") {
              printf "%s", substr($0, i + 1, 1)
              i++
            } else {
              in_string = 0
            }
          }
        } else if (c == "\047") {
          in_string = 1
          printf "%s", c
        } else if (substr($0, i, length(row_separator)) == row_separator) {
          printf "\n"
          i += length(row_separator) - 1
        } else if (c !~ /[[:space:]]/) {
          printf "%s", tolower(c)
        }
      }
    }
    END { if (in_string) exit 2 }
  '
}

expected_schema_sql=$'idx_devices_credential_hash|createindexidx_devices_credential_hashondevices(credential_hash)\naccounts|createtableaccounts(account_idtextprimarykey,owner_sign_pubkeytextnotnull,created_at_msintegernotnull)\nchallenges|createtablechallenges(device_sign_pubkeytextprimarykey,noncetextnotnull,expires_at_msintegernotnull)\nconv_events|createtableconv_events(conversation_idtextnotnull,seqintegernotnull,turn_session_idtextnotnull,encryption_versionintegernotnulldefault0,payloadblob,created_at_msintegernotnull,primarykey(conversation_id,seq))\ndevices|createtabledevices(device_idtextprimarykey,account_idtextnotnullreferencesaccounts(account_id),roletextnotnullcheck(rolein(\'machine\',\'device\')),credential_hashtextnotnullunique,sign_pubkeytextnotnull,box_pubkeytextnotnull,revokedintegernotnulldefault0,created_at_msintegernotnull)\nseq_high_water_marks|createtableseq_high_water_marks(conversation_idtextprimarykey,next_seqintegernotnulldefault0,acked_seqintegernotnulldefault-1)'
raw_schema_sql="$(sqlite_read \
  "SELECT name || '|' || sql || '__AGENTDECK_SCHEMA_ROW__' FROM sqlite_schema WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_autoindex_%' ORDER BY type, name;")" || \
  fail 'cannot inspect normalized storage DDL'
actual_schema_sql="$(printf '%s' "$raw_schema_sql" | normalize_schema_sql)" || \
  fail 'cannot normalize storage DDL safely'
[[ "$actual_schema_sql" == "$expected_schema_sql" ]] || fail 'storage DDL is not the exact Relay v1 schema'

extra_objects="$(sqlite_read \
  "SELECT count(*) FROM sqlite_schema WHERE type IN ('view', 'trigger') AND name NOT LIKE 'sqlite_%';")" || \
  fail 'cannot inspect storage schema objects'
[[ "$extra_objects" == '0' ]] || fail 'storage contains non-v1 views or triggers'

expected_columns=$'accounts|0|account_id|TEXT|0|<null>|1\naccounts|1|owner_sign_pubkey|TEXT|1|<null>|0\naccounts|2|created_at_ms|INTEGER|1|<null>|0\nchallenges|0|device_sign_pubkey|TEXT|0|<null>|1\nchallenges|1|nonce|TEXT|1|<null>|0\nchallenges|2|expires_at_ms|INTEGER|1|<null>|0\nconv_events|0|conversation_id|TEXT|1|<null>|1\nconv_events|1|seq|INTEGER|1|<null>|2\nconv_events|2|turn_session_id|TEXT|1|<null>|0\nconv_events|3|encryption_version|INTEGER|1|0|0\nconv_events|4|payload|BLOB|0|<null>|0\nconv_events|5|created_at_ms|INTEGER|1|<null>|0\ndevices|0|device_id|TEXT|0|<null>|1\ndevices|1|account_id|TEXT|1|<null>|0\ndevices|2|role|TEXT|1|<null>|0\ndevices|3|credential_hash|TEXT|1|<null>|0\ndevices|4|sign_pubkey|TEXT|1|<null>|0\ndevices|5|box_pubkey|TEXT|1|<null>|0\ndevices|6|revoked|INTEGER|1|0|0\ndevices|7|created_at_ms|INTEGER|1|<null>|0\nseq_high_water_marks|0|conversation_id|TEXT|0|<null>|1\nseq_high_water_marks|1|next_seq|INTEGER|1|0|0\nseq_high_water_marks|2|acked_seq|INTEGER|1|-1|0'
actual_columns="$(sqlite_read \
  "SELECT m.name || '|' || p.cid || '|' || p.name || '|' || upper(p.type) || '|' || p.\"notnull\" || '|' || ifnull(p.dflt_value, '<null>') || '|' || p.pk FROM sqlite_schema AS m JOIN pragma_table_info(m.name) AS p WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%' ORDER BY m.name, p.cid;")" || \
  fail 'cannot inspect storage columns'
[[ "$actual_columns" == "$expected_columns" ]] || fail 'storage columns are not the exact Relay v1 schema'

expected_index_shapes=$'accounts|sqlite_autoindex_accounts_1|1|pk|0\nchallenges|sqlite_autoindex_challenges_1|1|pk|0\nconv_events|sqlite_autoindex_conv_events_1|1|pk|0\ndevices|idx_devices_credential_hash|0|c|0\ndevices|sqlite_autoindex_devices_1|1|pk|0\ndevices|sqlite_autoindex_devices_2|1|u|0\nseq_high_water_marks|sqlite_autoindex_seq_high_water_marks_1|1|pk|0'
actual_index_shapes="$(sqlite_read \
  "SELECT table_name || '|' || name || '|' || \"unique\" || '|' || origin || '|' || partial FROM (SELECT 'accounts' AS table_name, * FROM pragma_index_list('accounts') UNION ALL SELECT 'challenges', * FROM pragma_index_list('challenges') UNION ALL SELECT 'conv_events', * FROM pragma_index_list('conv_events') UNION ALL SELECT 'devices', * FROM pragma_index_list('devices') UNION ALL SELECT 'seq_high_water_marks', * FROM pragma_index_list('seq_high_water_marks')) ORDER BY table_name, name;")" || \
  fail 'cannot inspect storage index constraints'
[[ "$actual_index_shapes" == "$expected_index_shapes" ]] || fail 'storage index constraints are not the exact Relay v1 schema'

credential_index_column="$(sqlite_read \
  "SELECT name FROM pragma_index_info('sqlite_autoindex_devices_2') ORDER BY seqno;")" || \
  fail 'cannot inspect credential hash uniqueness'
[[ "$credential_index_column" == 'credential_hash' ]] || fail 'storage credential_hash uniqueness is not Relay v1'

device_foreign_key="$(sqlite_read \
  "SELECT \"table\" || '|' || \"from\" || '|' || \"to\" || '|' || on_update || '|' || on_delete || '|' || match FROM pragma_foreign_key_list('devices') ORDER BY id, seq;")" || \
  fail 'cannot inspect device foreign key'
[[ "$device_foreign_key" == 'accounts|account_id|account_id|NO ACTION|NO ACTION|NONE' ]] || \
  fail 'storage device foreign key is not Relay v1'

jq -e '
  type == "object" and
  keys == ["account_id", "credential", "device_id", "relay_url", "role"] and
  all(.[]; type == "string") and
  (.relay_url | length > 0) and
  (.account_id | length > 0) and
  (.device_id | length > 0) and
  (.credential | length > 0) and
  (.role == "machine" or .role == "device")
' "$credentials" >/dev/null || fail 'credentials JSON is not the exact Relay v1 bearer shape'

account_id="$(jq -er '.account_id' "$credentials")" || fail 'cannot read credentials account_id'
device_id="$(jq -er '.device_id' "$credentials")" || fail 'cannot read credentials device_id'
role="$(jq -er '.role' "$credentials")" || fail 'cannot read credentials role'
credential="$(jq -er '.credential' "$credentials")" || fail 'cannot read bearer credential'
decoded_credential_length="$(
  printf '%s' "$credential" | openssl base64 -d -A | LC_ALL=C wc -c | awk '{print $1}'
)" || fail 'bearer credential is not valid Base64'
[[ "$decoded_credential_length" == '32' ]] || fail 'bearer credential must decode to exactly 32 bytes'
canonical_credential="$(
  printf '%s' "$credential" | openssl base64 -d -A | openssl base64 -A
)" || fail 'cannot canonicalize bearer credential Base64'
[[ "$canonical_credential" == "$credential" ]] || fail 'bearer credential Base64 is not canonical'
hash="$(printf '%s' "$credential" | openssl dgst -sha256 -binary | openssl base64 -A)" || \
  fail 'cannot hash bearer credential'

device_rows="$(sqlite3 -batch -json "$storage_uri" \
  'SELECT device_id, account_id, role, credential_hash FROM devices;')" || \
  fail 'cannot read Relay v1 device rows'
jq -e \
  --arg account_id "$account_id" \
  --arg device_id "$device_id" \
  --arg role "$role" \
  --arg credential_hash "$hash" \
  '[.[] | select(
    .account_id == $account_id and
    .device_id == $device_id and
    .role == $role and
    .credential_hash == $credential_hash
  )] | length == 1' <<<"$device_rows" >/dev/null || \
  fail 'credentials do not match exactly one Relay v1 device row'

# Schema、credential 和全部四个 path 已验证完成；删除前再检查一次文件身份，
# 以便 Relay 未停止或本地并发写入时 fail closed，而不是部分清理。
validate_required_file storage "$storage"
validate_required_file credentials "$credentials"
validate_optional_sidecar storage-wal "$wal"
validate_optional_sidecar storage-shm "$shm"
[[ "$(stat_fingerprint "$storage")" == "$storage_before" ]] || fail 'storage changed during validation; stop Relay and retry'
[[ "$(stat_fingerprint "$wal")" == "$wal_before" ]] || fail 'storage-wal changed during validation; stop Relay and retry'
[[ "$(stat_fingerprint "$shm")" == "$shm_before" ]] || fail 'storage-shm changed during validation; stop Relay and retry'
[[ "$(stat_fingerprint "$credentials")" == "$credentials_before" ]] || fail 'credentials changed during validation; stop Relay and retry'

delete_paths=("$wal" "$shm" "$storage" "$credentials")
unlink_failed=0
for path in "${delete_paths[@]}"; do
  if ! rm -f -- "$path"; then
    unlink_failed=1
  fi
done

remaining_paths=()
for path in "${delete_paths[@]}"; do
  if [[ -e "$path" || -L "$path" ]]; then
    remaining_paths+=("$path")
  fi
done

if ((unlink_failed != 0 || ${#remaining_paths[@]} != 0)); then
  printf 'reset-relay-v1-dev-state: unlink stage failed; no rollback is guaranteed\n' >&2
  for path in "${remaining_paths[@]}"; do
    printf 'reset-relay-v1-dev-state: remaining exact path: %s\n' "$path" >&2
  done
  printf '%s\n' \
    'reset-relay-v1-dev-state: manually remove the remaining exact paths, then pair again before reuse' >&2
  exit 1
fi

printf 'reset-relay-v1-dev-state: deleted exact Relay v1 DB, -wal, -shm, and credentials paths\n'
printf 'reset-relay-v1-dev-state: no development recovery is available; pair again before reuse\n'

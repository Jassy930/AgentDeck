#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd -P)"
runner="$repo_root/scripts/run-relay-web-companion-e2e.sh"
pairing_runner="$repo_root/scripts/run-relay-web-companion-pairing-e2e.sh"
business_runner="$repo_root/scripts/run-relay-web-companion-business-e2e.sh"
durable_runner="$repo_root/scripts/run-relay-web-companion-durable-e2e.sh"

bash -n "$runner"
bash -n "$pairing_runner"
bash -n "$business_runner"
bash -n "$durable_runner"

all_case="$(sed -n '/^[[:space:]]*--all)/,/^[[:space:]]*;;/p' "$runner")"
printf '%s\n' "$all_case" | grep -Fq 'run_contract' \
  || { printf 'runner --all omitted contract gate\n' >&2; exit 1; }
printf '%s\n' "$all_case" | grep -Fq 'run_transport' \
  || { printf 'runner --all omitted transport gate\n' >&2; exit 1; }
printf '%s\n' "$all_case" | grep -Fq 'run_pairing' \
  || { printf 'runner --all omitted pairing gate\n' >&2; exit 1; }
printf '%s\n' "$all_case" | grep -Fq 'run_business' \
  || { printf 'runner --all omitted business gate\n' >&2; exit 1; }
printf '%s\n' "$all_case" | grep -Fq 'run_durable' \
  || { printf 'runner --all omitted durable gate\n' >&2; exit 1; }
printf '%s\n' "$all_case" | grep -Fq 'run_negative' \
  || { printf 'runner --all omitted negative gate\n' >&2; exit 1; }

durable_case="$(sed -n '/^[[:space:]]*--durable)/,/^[[:space:]]*;;/p' "$runner")"
printf '%s\n' "$durable_case" | grep -Fq 'run_durable' \
  || { printf 'runner --durable omitted durable gate\n' >&2; exit 1; }

negative_case="$(sed -n '/^[[:space:]]*--negative)/,/^[[:space:]]*;;/p' "$runner")"
printf '%s\n' "$negative_case" | grep -Fq 'run_negative' \
  || { printf 'runner --negative omitted negative gate\n' >&2; exit 1; }

if "$runner" --unknown >/dev/null 2>&1; then
  printf 'runner accepted an unknown mode\n' >&2
  exit 1
fi

if "$runner" >/dev/null 2>&1; then
  printf 'runner accepted a missing mode\n' >&2
  exit 1
fi

printf 'run-relay-web-companion-e2e contract: PASS\n'

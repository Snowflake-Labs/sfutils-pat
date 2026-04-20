#!/usr/bin/env bash
# Minimal integration smoke: Snowflake CLI JSON + PAT create dry-runs (no DDL) +
# keyring store/load/delete of a dummy secret (same service-string layout as real PATs).
# Requires: snow CLI, uv, repo synced. See docs/it/README.md.
# May prompt for OS keychain access once; uses isolated identity SF_UTILS_PAT_IT_SMOKE only.
#
# Loads .env from repo root when present (same idea as Taskfile dotenv).
# Dry-run user/role/db resolution (first match wins): SF_UTILS_PAT_* → SA_USER/SA_ROLE/SF_UTILS_DB
# (legacy SNOW_UTILS_DB / IT_SNOW_UTILS_DB) → IT_* → slug from snow connection test User. Slug fallback is dry-run-only.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

CONN_JSON="$(snow connection test --format json)"

echo "== snow connection test --format json (first 800 chars) =="
printf '%s' "$CONN_JSON" | head -c 800
echo
echo

# Slug from connection User (e.g. JDOE -> JDOE_IT) for default object names; not from Account (often long).
_IT_SLUG="$(
  printf '%s' "$CONN_JSON" | uv run python -c "
import json, re, sys

d = json.load(sys.stdin)
user = d.get('User') or d.get('user') or 'UNKNOWN'
slug = re.sub(r'[^A-Za-z0-9]+', '_', str(user)).upper().strip('_') or 'IT_SMOKE'
base = (slug + '_IT')[:60]
print(base)
"
)"

_DRY_SA_USER="${SF_UTILS_PAT_SA_USER:-${SA_USER:-${IT_SA_USER:-${_IT_SLUG}_RUNNER}}}"
_DRY_SA_ROLE="${SF_UTILS_PAT_SA_ROLE:-${SA_ROLE:-${IT_SA_ROLE:-${_IT_SLUG}_ACCESS}}}"
_DRY_SF_UTILS_DB="${SF_UTILS_PAT_SF_UTILS_DB:-${SF_UTILS_DB:-${SNOW_UTILS_DB:-${IT_SF_UTILS_DB:-${IT_SNOW_UTILS_DB:-${_IT_SLUG}_UTILS}}}}}"

echo "== Effective dry-run identifiers (SF_UTILS_PAT_* > SA_* / SF_UTILS_DB > legacy SNOW_UTILS_DB > IT_* > slug) =="
echo "  SA_USER (dry-run)=$_DRY_SA_USER"
echo "  SA_ROLE (dry-run)=$_DRY_SA_ROLE"
echo "  SF_UTILS_DB (dry-run)=$_DRY_SF_UTILS_DB"
echo

echo "== sfutils-pat create --dry-run --skip-network =="
uv run sfutils-pat create \
  --user "$_DRY_SA_USER" \
  --role "$_DRY_SA_ROLE" \
  --db "$_DRY_SF_UTILS_DB" \
  --dry-run \
  --skip-network

echo
echo "== sfutils-pat create --dry-run --no-local --allow-gh (hybrid policy SQL; no DDL, no IP discovery) =="
uv run sfutils-pat create \
  --user "$_DRY_SA_USER" \
  --role "$_DRY_SA_ROLE" \
  --db "$_DRY_SF_UTILS_DB" \
  --dry-run \
  --no-local \
  --allow-gh

echo
echo "== keyring roundtrip (dummy password; same APIs as PAT storage) =="
printf '%s' "$CONN_JSON" | uv run python -c "
import json
import sys

from sfutils_pat._keyring_store import delete_pat, load_pat, store_pat

d = json.load(sys.stdin)
account = d.get('Account') or d.get('account')
if not account:
    sys.exit('connection JSON missing Account')
host = (
    d.get('Host')
    or d.get('host')
    or d.get('SnowflakeHost')
    or d.get('snowflake_host')
)
sa_user = 'SF_UTILS_PAT_IT_SMOKE'
pat_name = 'SF_UTILS_PAT_IT_SMOKE'
secret = 'sfutils-pat-it-smoke-dummy-not-a-real-pat'
try:
    store_pat(host, account, sa_user, pat_name, secret)
    got = load_pat(host, account, sa_user, pat_name)
    assert got == secret, (got, secret)
finally:
    delete_pat(host, account, sa_user, pat_name)
if load_pat(host, account, sa_user, pat_name) is not None:
    sys.exit('keyring entry still present after delete')
print('keyring store/load/delete OK')
"

echo
echo "== smoke OK =="

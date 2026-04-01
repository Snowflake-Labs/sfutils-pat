# Integration tests (snow-utils-pat)

These checks exercise the **Snowflake CLI** (`snow`), and optionally the **real OS keychain** via Python `keyring`. They are **opt-in** and should use a **non-production** Snowflake account.

## Enable

| Mechanism | How |
|-----------|-----|
| Task pipeline (ordered) | `task it` — runs `it-unit` → `it-smoke` |
| Unit tests only | `task it-unit` — `uv run pytest -q` (offline; no `snow`) |
| Automated IT (scenarios 1–2 + keyring) | `task it-smoke` or `bash scripts/it/smoke.sh` — **single** scripted check; there is no separate pytest IT suite duplicating this. |

## Prerequisites

- [Snowflake CLI](https://docs.snowflake.com/developer-guide/snowflake-cli/index) installed; default connection configured (`SNOWFLAKE_DEFAULT_CONNECTION_NAME` or your usual `snow` profile).
- Admin-capable role for full lifecycle (often `ACCOUNTADMIN` or equivalent) to create users, roles, network rules/policies, authentication policies, and PATs.
- A dedicated database for policy objects (e.g. `MY_SNOW_UTILS`) already created in the account.
- **Network policy:** the runner’s egress IP must be allowed. For local runs, `--allow-local` (default on `create`) includes your detected public CIDR; add `--extra-cidrs` as needed. `--allow-gh` adds Snowflake’s managed GitHub Actions rule to the policy (hybrid with your custom rule); requires [Snowflake-managed network rules](https://docs.snowflake.com/en/user-guide/network-rules.html#snowflake-managed-network-rules) in the account (not gov regions).
- **Keychain:** first access may prompt for OS keychain permission; unattended runners need a non-interactive keyring backend or prior approval.
- **PAT limit:** Snowflake allows up to **15 active PATs per user**. Rotate/remove test users so you do not hit the limit during repeated IT runs.

## Maintainer TODO

- **Government / restricted regions:** Automated smoke and documented manual flows are validated in commercial-style accounts only. When a disposable Snowflake account in a gov or otherwise restricted region is available, run `SHOW NETWORK RULES IN SNOWFLAKE.NETWORK_SECURITY` and exercise `create` (or `--dry-run`) with `--allow-gh`; capture whether managed GitHub rules exist, how hybrid policy SQL fails or succeeds, and update [docs/SECURITY.md](../SECURITY.md) residual risk #5 if needed.

## Manual IT: use the same `.env` as the CLI

The `snow-utils-pat` commands read **`SA_USER`**, **`SA_ROLE`**, and **`SNOW_UTILS_DB`** from the process environment (same as `--user` / `--role` / `--db`). For manual scenarios **3–6**, **prefer the project `.env`** (or a dedicated file such as `.env.it`) so you do not maintain a second variable family.

**Safety:** Point `SA_USER` / `SA_ROLE` / `SNOW_UTILS_DB` at **disposable** resources in a **non-production** account—not production service users.

Example workflow:

```bash
cd /path/to/snow-utils-pat
uv sync

# Load vars (matches Taskfile dotenv behavior when you use task create, etc.)
set -a && source .env && set +a
# Or: set -a && source .env.it && set +a

uv run snow-utils-pat create --yes
uv run snow-utils-pat verify
uv run snow-utils-pat rotate
uv run snow-utils-pat verify
# uv run snow-utils-pat show-pat   # optional; confirms with warning, then prints secret (or --yes)

uv run snow-utils-pat remove --drop-user --yes
```

Pass `--user` / `--role` / `--db` only when you need to override what is in the environment for a single invocation.

Optional: `SA_ADMIN_ROLE`, `PAT_NAME`, and `SNOWFLAKE_DEFAULT_CONNECTION_NAME` as documented in the [main README](../../README.md).

### Optional overrides (smoke / CI / one-off shells)

If you do **not** want to load `.env`, or need to override only for a script:

| Variable | Purpose |
|----------|---------|
| `SNOW_UTILS_PAT_SA_USER` | Overrides `SA_USER` for [`scripts/it/smoke.sh`](../../scripts/it/smoke.sh) dry-run identifiers only |
| `SNOW_UTILS_PAT_SA_ROLE` | Overrides `SA_ROLE` (same) |
| `SNOW_UTILS_PAT_SNOW_UTILS_DB` | Overrides `SNOW_UTILS_DB` (same) |

**Legacy:** `IT_SA_USER`, `IT_SA_ROLE`, `IT_SNOW_UTILS_DB` are still honored in `smoke.sh` after the above.

These `SNOW_UTILS_PAT_*` names avoid colliding with **`SNOWFLAKE_*`** vars used by the Snowflake CLI; they are **not** required for normal manual IT when using `.env`.

### What `snow connection test --format json` provides

The JSON includes your **current session** fields (e.g. `User`, `Account`, `Host` depending on CLI version). It does **not** define the PAT service user, role, or utils database—those come from **`.env` / env** (or smoke’s slug fallback when nothing is set).

[`scripts/it/smoke.sh`](../../scripts/it/smoke.sh) loads `.env` from the repo root when present (`set -a` / `source` / `set +a`, same idea as Task’s `dotenv`). It resolves dry-run **user / role / db** in this order: **`SNOW_UTILS_PAT_*` → `SA_USER` / `SA_ROLE` / `SNOW_UTILS_DB` → `IT_*` → slug from connection `User`**. The slug fallback is only suitable for **dry-run**; for a real `create`, **`SNOW_UTILS_DB` in `.env` must name an existing database**.

## Naming (avoid collisions)

Use a unique prefix per engineer or CI run for `SA_USER` / related objects in the account.

## Recommended scenarios

| # | Scenario | Command / action | Risk |
|---|----------|------------------|------|
| 1 | `create` dry-run (no Snowflake DDL) | With env loaded: `snow-utils-pat create --dry-run --skip-network` (or explicit `--user` / `--role` / `--db`) | None for `--skip-network` path |
| 2 | Connection metadata (read-only) | `snow connection test --format json` | Read-only |
| 3 | Full `create` → `verify` | Env from `.env`: `create --yes` then `verify` | Creates objects + PAT; **OS keyring** |
| 4 | `rotate` → `verify` | `rotate` then `verify` | New PAT secret |
| 5 | `show-pat` (optional) | `show-pat` (interactive confirm; `--yes` to skip) | Prints secret to stdout—avoid in shared logs |
| 6 | `remove` (cleanup) | `remove --drop-user --yes` | Drops PAT, policies, user; `--yes` skips per-step prompts (required when stdin is not a TTY); clears obsolete lines on default `.env` path |

For scenario 1 with **full** network CIDR resolution (no `--skip-network`), run from a network that allows the tool’s IP discovery (same as production `create`).

If `remove` fails partway, clean up objects in Snowflake and delete the keyring entry for the service string pattern documented in the [main README](../../README.md#keyring-layout).

## Unit tests (pytest)

Offline tests live under `tests/` (e.g. keyring helpers with an in-memory backend). They do **not** replace `it-smoke`.

```bash
uv sync --extra dev
uv run pytest -q
```

## CI guidance

Do **not** run integration tests in default PR workflows unless you provide Snowflake auth, a disposable account, and teardown. Prefer **manual** or **scheduled** jobs with secrets and strict resource naming.

## Shell smoke script

See [scripts/it/smoke.sh](../../scripts/it/smoke.sh) and `task it-smoke` in the Taskfile. It:

1. Optionally sources **`.env`** in the repo root when the file exists.
2. Runs `snow connection test --format json`.
3. Runs `snow-utils-pat create --dry-run --skip-network` using resolved user/role/db (precedence above).
4. Runs `snow-utils-pat create --dry-run --no-local --allow-gh` to print **hybrid** network policy SQL (Snowflake-managed GitHub rule only in the allow list; still no DDL).
5. **Keyring roundtrip:** stores a **dummy** secret via `store_pat` / `load_pat` / `delete_pat` using the same service-string layout as real PATs, with fixed identity `SNOW_UTILS_PAT_IT_SMOKE` (does not overlap normal SA user names). Your OS may prompt for keychain access.

Step 5 validates the local keyring backend without creating Snowflake objects or real PATs.

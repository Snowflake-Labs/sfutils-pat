# Snowflake PAT (Programmatic Access Token) Manager

Create and manage Snowflake [Programmatic Access Tokens (PATs)](https://docs.snowflake.com/en/user-guide/programmatic-access-tokens) for service users. Handles the full lifecycle: service user creation, authentication policies, network policies, PAT generation, rotation, and local configuration.

**PAT secrets are stored only in the OS keychain** (via Python [`keyring`](https://pypi.org/project/keyring/)), using a service string aligned with `snowflake-connector-python` conventions. The tool **does not write PAT material to `.env` or other files**. It may update `.env` with **`SA_USER`** and **`SA_ROLE`** only.

**8+ manual steps → single command.**

## Prerequisites

- [Snowflake CLI](https://docs.snowflake.com/developer-guide/snowflake-cli/index) (`snow`) installed and configured
- Python 3.12+
- [Task](https://taskfile.dev) (optional, for task-based workflow)

## Install

```bash
uv sync          # or: pip install .
```

For running tests: `uv sync --extra dev`

## Quick Start

```bash
# Create PAT with local IP network policy (most secure)
sfutils-pat create --user my_sa --role demo_role --db my_db

# Allow GitHub Actions (hybrid policy: custom CIDRs + Snowflake-managed rule; see Network Policy)
sfutils-pat create --user ci_sa --role ci_role --db my_db --allow-gh

# Skip network setup (if managed separately by sfutils-networks)
sfutils-pat create --user my_sa --role demo_role --db my_db --skip-network

# Preview all SQL without executing
sfutils-pat create --user my_sa --role demo_role --db my_db --dry-run

# Rotate an existing PAT (keeps all policies)
sfutils-pat rotate --user my_sa --role demo_role

# Verify PAT works (loads token from keyring only)
sfutils-pat verify --user my_sa --role demo_role

# Print PAT to stdout once (insecure; appears in logs) — optional
sfutils-pat create --user my_sa --role demo_role --db my_db --print

# Remove PAT and all associated objects (per-step prompts; use --yes to skip)
sfutils-pat remove --user my_sa --db my_db
sfutils-pat remove --user my_sa --db my_db --yes
```

## Keyring layout

The PAT is stored with:

- **`keyring` service (first argument):**  
  `{HOST}:{ACCOUNT}:{SA_USER}:SFUTILS-PAT:{PAT_NAME}`  
  All segments are uppercased. `HOST` comes from `snow connection test --format json` when present; otherwise the first segment is `NA`. `ACCOUNT` is the connection account identifier from the same JSON. **Legacy installs** may still have secrets under `SNOW-UTILS-PAT`; the CLI reads that label as a fallback and deletes both on `remove`.
- **`keyring` username (second argument):** `SA_USER` uppercased (same pattern as the Snowflake Python connector for cached tokens).

The same tuple is used for `create`, `rotate`, `verify`, `show-pat`, and keyring cleanup on `remove`.

## What `create` Does

1. Creates a service user (if not exists)
2. Creates a network rule and policy with your allowed CIDRs (unless `--skip-network`). With `--allow-gh`, the policy also references Snowflake’s managed GitHub Actions rule ([Snowflake-managed network rules](https://docs.snowflake.com/en/user-guide/network-rules.html#snowflake-managed-network-rules)); GitHub IPs are no longer copied from the GitHub meta API into your rule.
3. Assigns the network policy to the user
4. Creates an authentication policy (PAT-only, with network policy enforcement). **Default expiry profile is 7 days default / 30 days max** (hardened baseline). For Snowflake’s platform-style limits, pass `--default-expiry-days 15 --max-expiry-days 365`.
5. Generates or rotates the PAT in Snowflake
6. **Stores the PAT in the OS keyring** (not on disk)
7. Updates `.env` with **`SA_USER`** and **`SA_ROLE`** only (strips obsolete raw-PAT lines from older layouts)
8. Verifies the connection by **loading the PAT from the keyring** and running a test query (unless `--skip-verify`)

JSON output (`-o json`) never includes the raw token; it includes redaction and keyring metadata (e.g. `keyring_service`, `account`, `host`).

`--print` may print the PAT to stdout after storage (default: off). It **cannot** be combined with `-o json`.

## `verify` and `show-pat`

- **`verify`** reads the PAT **only from the keyring**. It does not accept `--password`, PAT-in-env, or `.env` secrets for the token.
- **`show-pat`** asks for confirmation (with a warning) before printing the PAT to stdout; use `--yes` only when you must script it and accept log exposure.

## Task Workflow

```bash
task create SA_USER=my_sa SA_ROLE=demo_role SF_UTILS_DB=my_db
task create SA_USER=ci_sa SA_ROLE=ci_role SF_UTILS_DB=my_db -- --allow-gh
task no-rotate SA_USER=my_sa SA_ROLE=demo_role SF_UTILS_DB=my_db
task remove SA_USER=my_sa SF_UTILS_DB=my_db
```

## Integration testing

Opt-in checks against a real Snowflake account and the OS keychain are documented in [docs/it/README.md](docs/it/README.md). `task it` runs unit tests (`pytest`) then shell smoke (`scripts/it/smoke.sh`). For **manual** full lifecycle IT, use the same **`.env`** keys as daily CLI use (`SA_USER`, `SA_ROLE`, `SF_UTILS_DB`; legacy `SNOW_UTILS_DB` is still accepted); see the runbook.

## CLI Commands

| Command | Description |
|---------|-------------|
| `create` | Create/rotate PAT for a service user (full setup) |
| `rotate` | Rotate an existing PAT (keeps policies intact) |
| `verify` | Test PAT connection; PAT loaded from keyring only |
| `show-pat` | Print PAT from keyring to stdout after confirm (or `--yes`; insecure) |
| `remove` | Remove PAT and associated objects (your account network policy and `{db}.NETWORKS.{user}` rule; auth policy); does **not** drop `SNOWFLAKE.NETWORK_SECURITY` managed rules; per-step confirmation unless `--yes`; non-interactive runs require `--yes`; clears keyring entry when connection metadata is available |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SA_USER` | Service account username |
| `SA_ROLE` | Role restriction for the PAT |
| `SA_ADMIN_ROLE` | Admin role for creating policies (default: `ACCOUNTADMIN`) |
| `SF_UTILS_DB` | Database for PAT objects (network rules, auth policies); legacy `SNOW_UTILS_DB` still read by CLI and `check-setup` |
| `PAT_NAME` | Snowflake PAT object name (default: `{USER}_PAT`) |
| `DOT_ENV_FILE` | Used by Taskfile examples; CLI uses `--env-path` / `--dot-env-file` |

The PAT is **not** supplied through any environment variable; only the keychain entry is used for auth in this tool.

## Migration from older versions

Older releases may have stored the raw PAT in `.env`. After upgrading:

1. Run `create` or `rotate` again so the PAT is stored in the keychain.
2. When this tool updates `.env`, it removes obsolete file-stored PAT lines automatically; delete any leftover secret manually if you still see one.
3. Use `verify` (keyring) or export secrets for other tools **outside** this CLI, at your own risk.

## Network Policy

PATs require a network policy for security (Snowflake best practice). By default, `create` sets up:

- A network rule `{USER}_NETWORK_RULE` in your utils database’s `NETWORKS` schema with CIDRs from `--allow-local` (default), `--allow-google`, and `--extra-cidrs` (no GitHub IPs in this rule).
- A network policy `{USER}_NETWORK_POLICY`. With `--allow-gh`, this is a **hybrid** policy: it lists your custom rule **and** `SNOWFLAKE.NETWORK_SECURITY.GITHUB_ACTIONS` so GitHub egress is maintained by Snowflake (not available in government regions; confirm names with `SHOW NETWORK RULES IN SNOWFLAKE.NETWORK_SECURITY`).
- With `--allow-gh` and no custom CIDRs (e.g. `--no-local --allow-gh` only), the policy may reference **only** the managed GitHub rule—no custom network rule is created.
- Assigns the policy to the service user.

Use `--skip-network` if you manage network rules separately with `sfutils-networks` (or the **sf-utils-networks** Cortex skill).

## Security

For security principles, residual risks, and an informal compliance-oriented review, see [docs/SECURITY.md](docs/SECURITY.md).

## Related

- [sf-utils-skills](https://github.com/Snowflake-Labs/sf-utils-skills) (Cortex Code skills; use path `sf-utils-pat` after repo rename from `snow-utils-skills`)

## License

Apache 2.0

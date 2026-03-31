# snow-utils-pat

Create and manage Snowflake Programmatic Access Tokens (PATs) for service users. Handles the full lifecycle: service user creation, authentication policies, network policies, PAT generation, rotation, and .env file management.

**8+ manual steps → single command.**

## Prerequisites

- [Snowflake CLI](https://docs.snowflake.com/developer-guide/snowflake-cli/index) (`snow`) installed and configured
- Python 3.12+
- [Task](https://taskfile.dev) (optional, for task-based workflow)

## Install

```bash
uv sync          # or: pip install .
```

## Quick Start

```bash
# Create PAT with local IP network policy (most secure)
snow-utils-pat create --user my_sa --role demo_role --db my_db

# Include GitHub Actions IPs for CI/CD pipelines
snow-utils-pat create --user ci_sa --role ci_role --db my_db --allow-gh

# Skip network setup (if managed separately by snow-utils-networks)
snow-utils-pat create --user my_sa --role demo_role --db my_db --skip-network

# Preview all SQL without executing
snow-utils-pat create --user my_sa --role demo_role --db my_db --dry-run

# Rotate an existing PAT (keeps all policies)
snow-utils-pat rotate --user my_sa --role demo_role

# Verify PAT works
snow-utils-pat verify --user my_sa --role demo_role

# Remove PAT and all associated objects
snow-utils-pat remove --user my_sa --db my_db
```

## What `create` Does

1. Creates a service user (if not exists)
2. Creates a network rule and policy with your allowed CIDRs (unless `--skip-network`)
3. Assigns the network policy to the user
4. Creates an authentication policy (PAT-only, with network policy enforcement)
5. Generates or rotates the PAT
6. Writes `SA_PAT`, `SA_USER`, `SA_ROLE` to your `.env` file
7. Verifies the connection works

## Task Workflow

```bash
task create SA_USER=my_sa SA_ROLE=demo_role SNOW_UTILS_DB=my_db
task create SA_USER=ci_sa SA_ROLE=ci_role SNOW_UTILS_DB=my_db -- --allow-gh
task no-rotate SA_USER=my_sa SA_ROLE=demo_role SNOW_UTILS_DB=my_db
task remove SA_USER=my_sa SNOW_UTILS_DB=my_db
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `create` | Create/rotate PAT for a service user (full setup) |
| `rotate` | Rotate an existing PAT (keeps policies intact) |
| `verify` | Test PAT connection with a simple query |
| `remove` | Remove PAT and associated objects (network policy, auth policy) |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SA_USER` | Service account username |
| `SA_ROLE` | Role restriction for the PAT |
| `SA_ADMIN_ROLE` | Admin role for creating policies (default: `ACCOUNTADMIN`) |
| `SNOW_UTILS_DB` | Database for PAT objects (network rules, auth policies) |
| `DOT_ENV_FILE` | Path to .env file to update (default: `.env` in cwd) |
| `SA_PAT` | The PAT token (written by `create`, read by `verify`) |

## Network Policy

PATs require a network policy for security (Snowflake best practice). By default, `create` sets up:

- A network rule `{USER}_NETWORK_RULE` with your allowed CIDRs
- A network policy `{USER}_NETWORK_POLICY` referencing that rule
- Assigns the policy to the service user

Use `--skip-network` if you manage network rules separately with `snow-utils-networks`.

## License

Apache 2.0

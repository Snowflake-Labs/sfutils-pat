#!/usr/bin/env python3
# Copyright 2026 Snowflake Inc.
# Generated with Cortex Code
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Snowflake PAT (Programmatic Access Token) Manager

Sets up a service user with authentication policies and creates/rotates PATs.
Network setup is handled separately via network.py.
"""

import datetime
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import click
from dotenv import dotenv_values

from sfutils_pat._keyring_store import (
    build_pat_credential_service,
    delete_pat,
    load_pat,
    store_pat,
)
from sfutils_pat._network_helpers import (
    assign_network_policy_to_user,
    cleanup_network_for_user,
    get_setup_network_for_user_sql,
    setup_network_for_user,
)
from sfutils_pat._presets import (
    SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN,
    collect_ipv4_cidrs,
)
from sfutils_pat._snow import (
    get_snow_cli_options,
    run_snow_sql,
    run_snow_sql_stdin,
    set_connection,
    set_masking,
    set_snow_cli_options,
)
from sfutils_pat._toml_manifest import (
    ensure_manifest_defaults,
    get_pat_entry,
    load_manifest,
    resolve_pat_connection,
    save_manifest,
    update_pat_status,
    upsert_pat,
    validate_manifest,
)
from sfutils_pat._verify_pat_connector import verify_pat_with_connector

# Older layouts stored the raw PAT in .env; strip when rewriting .env (not used for auth).
_LEGACY_DOTENV_RAW_PAT_KEY = "SA_PAT"


def _sql_str(value: str) -> str:
    """Escape a value for safe use inside a SQL single-quoted literal."""
    return value.replace("'", "''")


_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


def _assert_safe_identifier(value: str, label: str = "identifier") -> None:
    """Raise ClickException if value is not a safe unquoted SQL identifier."""
    if not _IDENT_RE.match(value):
        raise click.ClickException(
            f"Invalid {label} '{value}': must match ^[A-Za-z_][A-Za-z0-9_$]*$"
        )


def _confirm_remove_step(*, skip_all_prompts: bool, message: str) -> bool:
    """If skip_all_prompts, return True. Else prompt; return False if user declines."""
    if skip_all_prompts:
        return True
    if not click.confirm(message, default=False):
        click.echo("Aborted.")
        return False
    return True


def _strip_obsolete_dotenv_pat_lines(content: str) -> str:
    """Remove obsolete .env lines that stored a raw PAT (pre-keyring releases)."""
    return re.sub(
        rf"^{_LEGACY_DOTENV_RAW_PAT_KEY}=.*\n?",
        "",
        content,
        flags=re.MULTILINE,
    )


def get_snowflake_account() -> str:
    """Get the current Snowflake account from connection test."""
    result = subprocess.run(
        ["snow", "connection", "test", "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise click.ClickException(f"Failed to test connection: {result.stderr}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise click.ClickException(
            f"Invalid JSON from connection test: {e}"
        ) from e

    account = data.get("Account") or data.get("account")
    if not account:
        raise click.ClickException(
            f"Could not find 'Account' in connection test output: {list(data.keys())}"
        )
    return account


def get_snowflake_connection_metadata() -> tuple[str, str | None]:
    """Return (account, host) from `snow connection test --format json`. Host may be absent."""
    result = subprocess.run(
        ["snow", "connection", "test", "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise click.ClickException(f"Failed to test connection: {result.stderr}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise click.ClickException(
            f"Invalid JSON from connection test: {e}"
        ) from e

    account = data.get("Account") or data.get("account")
    if not account:
        raise click.ClickException(
            f"Could not find 'Account' in connection test output: {list(data.keys())}"
        )

    host = (
        data.get("Host")
        or data.get("host")
        or data.get("SnowflakeHost")
        or data.get("snowflake_host")
    )
    if host is not None:
        host = str(host).strip() or None
    return str(account).strip(), host


def normalize_identifier(name: str, style: str = "snowflake") -> str:
    """Normalize name for SQL or DNS compliance.

    Args:
        name: Raw input (e.g., "My Cool Project!")
        style: "snowflake" (UPPER_SNAKE) or "aws" (lower-kebab)

    Returns:
        Normalized identifier safe for SQL or AWS DNS
    """
    clean = re.sub(r"[^a-zA-Z0-9\s\-_]", "", name)
    clean = re.sub(r"\s+", "_" if style == "snowflake" else "-", clean)
    clean = re.sub(r"[-_]+", "_" if style == "snowflake" else "-", clean)
    clean = clean.strip("-_")

    if style == "snowflake":
        return clean.upper()
    else:
        return clean.lower()


def infer_comment_prefix(user: str) -> str:
    """Infer comment prefix from user name by stripping common suffixes."""
    upper_user = normalize_identifier(user, "snowflake")
    for suffix in ("_RUNNER", "_SA", "_SERVICE", "_USER"):
        if upper_user.endswith(suffix):
            return upper_user[: -len(suffix)]
    return upper_user


def format_comment(comment_prefix: str, suffix: str = "") -> str:
    """Format comment as 'Used by USER - PROJECT app - managed by sfutils-pat'.

    Parses comment_prefix (e.g., KAMESHS_PAT_DEMO) into user + project parts.
    If no underscore found, uses the whole prefix as project name.
    Avoids possessives ('s) to prevent SQL quoting issues.
    """
    normalized = normalize_identifier(comment_prefix, "snowflake")
    parts = normalized.split("_", 1)
    if len(parts) == 2:
        user_part, project_part = parts
        return f"Used by {user_part} - {project_part} app{suffix} - managed by sfutils-pat"
    return f"Used by {normalized} app{suffix} - managed by sfutils-pat"


def get_service_user_and_role_sql(
    user: str, pat_role: str, comment_prefix: str, admin_role: str = "accountadmin"
) -> str:
    """Generate SQL for creating service user and role (idempotent)."""
    _assert_safe_identifier(user, "user")
    _assert_safe_identifier(pat_role, "pat_role")
    _assert_safe_identifier(admin_role, "admin_role")
    comment = format_comment(comment_prefix)
    return f"""USE ROLE {admin_role};
-- Create PAT role if not exists
CREATE ROLE IF NOT EXISTS {pat_role}
    COMMENT = '{_sql_str(comment)}';
-- Create service user
CREATE USER IF NOT EXISTS {user}
    TYPE = SERVICE
    COMMENT = '{_sql_str(comment)}';
GRANT ROLE {pat_role} TO USER {user};"""


def setup_service_user(
    user: str, pat_role: str, comment_prefix: str, admin_role: str = "accountadmin"
) -> None:
    """Create PAT role (if needed) and service user, then grant role (idempotent)."""
    click.echo(f"Setting up PAT role {pat_role} and service user {user}")
    sql = get_service_user_and_role_sql(user, pat_role, comment_prefix, admin_role)
    run_snow_sql_stdin(sql)
    click.echo(f"✓ Role {pat_role} and service user {user} configured")


def get_auth_policy_sql(
    user: str,
    db: str,
    default_expiry_days: int,
    max_expiry_days: int,
    comment_prefix: str,
    admin_role: str = "accountadmin",
) -> str:
    """Generate SQL for creating authentication policy (idempotent)."""
    _assert_safe_identifier(user, "user")
    _assert_safe_identifier(db, "db")
    _assert_safe_identifier(admin_role, "admin_role")
    auth_policy_name = f"{user}_auth_policy".upper()
    comment = format_comment(comment_prefix)

    return f"""USE ROLE {admin_role};
CREATE SCHEMA IF NOT EXISTS {db}.POLICIES;
CREATE OR ALTER AUTHENTICATION POLICY {db}.POLICIES.{auth_policy_name}
    AUTHENTICATION_METHODS = ('PROGRAMMATIC_ACCESS_TOKEN')
    PAT_POLICY = (
        DEFAULT_EXPIRY_IN_DAYS = {default_expiry_days}
        MAX_EXPIRY_IN_DAYS = {max_expiry_days}
        NETWORK_POLICY_EVALUATION = ENFORCED_REQUIRED
    )
    COMMENT = '{_sql_str(comment)}';

ALTER USER {user} SET AUTHENTICATION POLICY {db}.POLICIES.{auth_policy_name};"""


def setup_auth_policy(
    user: str,
    db: str,
    default_expiry_days: int,
    max_expiry_days: int,
    comment_prefix: str,
    admin_role: str = "accountadmin",
) -> None:
    """Create authentication policy for PAT access (idempotent)."""
    click.echo("Setting up authentication policy...")
    sql = get_auth_policy_sql(
        user, db, default_expiry_days, max_expiry_days, comment_prefix, admin_role
    )
    run_snow_sql_stdin(sql)
    click.echo("✓ Authentication policy configured")


def remove_auth_policy(user: str, db: str, admin_role: str = "accountadmin") -> None:
    """Remove authentication policy for a user (idempotent)."""
    _assert_safe_identifier(user, "user")
    _assert_safe_identifier(db, "db")
    _assert_safe_identifier(admin_role, "admin_role")
    auth_policy_name = f"{user}_auth_policy".upper()

    click.echo(f"Removing authentication policy: {db}.POLICIES.{auth_policy_name}")

    sql = f"""
        USE ROLE {admin_role};
        ALTER USER IF EXISTS {user} UNSET AUTHENTICATION POLICY;
        DROP AUTHENTICATION POLICY IF EXISTS {db}.POLICIES.{auth_policy_name};
    """
    run_snow_sql_stdin(sql, check=False)
    click.echo("✓ Authentication policy removed")


def get_existing_pat(user: str, pat_name: str, admin_role: str = "accountadmin") -> str | None:
    """Check if a PAT with the given name exists for the user."""
    _assert_safe_identifier(user, "user")
    result = run_snow_sql(f"SHOW USER PATS FOR USER {user}", role=admin_role)

    if not result:
        return None

    for pat in result:
        if pat.get("name", "").lower() == pat_name.lower():
            return pat.get("name")

    return None


def get_pat_sql(user: str, pat_role: str, pat_name: str) -> str:
    """Generate SQL for creating PAT."""
    _assert_safe_identifier(user, "user")
    _assert_safe_identifier(pat_role, "pat_role")
    _assert_safe_identifier(pat_name, "pat_name")
    return f"ALTER USER IF EXISTS {user} ADD PAT {pat_name} ROLE_RESTRICTION = {pat_role};"


def create_or_rotate_pat(
    user: str, pat_role: str, pat_name: str, rotate: bool = False, admin_role: str = "accountadmin"
) -> str:
    """Create a new PAT or rotate an existing one (idempotent for rotate=True)."""
    _assert_safe_identifier(user, "user")
    _assert_safe_identifier(pat_role, "pat_role")
    _assert_safe_identifier(pat_name, "pat_name")
    existing = get_existing_pat(user, pat_name, admin_role=admin_role)

    if existing and not rotate:
        click.echo(f"PAT '{pat_name}' exists. Removing and recreating (--no-rotate)...")
        run_snow_sql(f"ALTER USER IF EXISTS {user} REMOVE PAT {pat_name}", role=admin_role)
        click.echo(f"✓ Removed existing PAT '{pat_name}'")
        existing = None

    if existing:
        click.echo(f"Rotating PAT for service user {user}...")
        query = f"ALTER USER IF EXISTS {user} ROTATE PAT {pat_name}"
    else:
        click.echo(f"Creating new PAT for service user {user} with role restriction {pat_role}...")
        query = f"ALTER USER IF EXISTS {user} ADD PAT {pat_name} ROLE_RESTRICTION = {pat_role}"

    result = run_snow_sql(query, role=admin_role)

    if not result or not result[0].get("token_secret"):
        raise click.ClickException("Failed to get PAT token from response")

    token = result[0]["token_secret"]
    click.echo("✓ PAT created/rotated successfully")
    return token


def remove_pat(user: str, pat_name: str, admin_role: str = "accountadmin") -> None:
    """Remove a PAT from a user (idempotent)."""
    _assert_safe_identifier(user, "user")
    _assert_safe_identifier(pat_name, "pat_name")
    click.echo(f"Removing PAT '{pat_name}' from user {user}...")

    existing = get_existing_pat(user, pat_name, admin_role=admin_role)
    if not existing:
        click.echo(f"⚠ PAT '{pat_name}' not found for user {user}")
        return

    run_snow_sql(f"ALTER USER IF EXISTS {user} REMOVE PAT {pat_name}", role=admin_role)
    click.echo(f"✓ Removed PAT '{pat_name}'")


def remove_service_user(user: str, admin_role: str = "accountadmin") -> None:
    """Drop the service user (idempotent)."""
    _assert_safe_identifier(user, "user")
    _assert_safe_identifier(admin_role, "admin_role")
    click.echo(f"Dropping service user: {user}")

    sql = f"""
        USE ROLE {admin_role};
        DROP USER IF EXISTS {user};
    """
    run_snow_sql_stdin(sql)
    click.echo(f"✓ Service user {user} dropped")


def _escape_env_value(value: str) -> str:
    """Escape a value for safe storage in .env file."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def update_env_non_secrets(env_path: Path, user: str, pat_role: str) -> None:
    """Update .env with SA_USER and SA_ROLE; strip obsolete raw-PAT lines (PAT is keyring-only)."""
    if not env_path.exists():
        click.echo(f"⚠ {env_path} not found, skipping update")
        return

    content = env_path.read_text()
    backup_path = env_path.with_suffix(".env.bak")
    shutil.copy(env_path, backup_path)

    new_content = _strip_obsolete_dotenv_pat_lines(content)

    user_pattern = r"^SA_USER=.*$"
    user_replacement = f"SA_USER={_escape_env_value(user)}"
    if re.search(user_pattern, new_content, re.MULTILINE):
        new_content = re.sub(user_pattern, user_replacement, new_content, flags=re.MULTILINE)
    else:
        new_content = new_content.rstrip() + f"\n{user_replacement}\n"

    role_pattern = r"^SA_ROLE=.*$"
    role_replacement = f"SA_ROLE={_escape_env_value(pat_role)}"
    if re.search(role_pattern, new_content, re.MULTILINE):
        new_content = re.sub(role_pattern, role_replacement, new_content, flags=re.MULTILINE)
    else:
        new_content = new_content.rstrip() + f"\n{role_replacement}\n"

    env_path.write_text(new_content)
    click.echo(f"✓ Updated {env_path} with SA_USER and SA_ROLE (PAT stored in keyring only)")


def clear_env(env_path: Path) -> None:
    """Remove obsolete raw-PAT lines from .env if present (same cleanup as non-secret updates)."""
    if not env_path.exists():
        click.echo(f"⚠ {env_path} not found, skipping")
        return

    content = env_path.read_text()

    backup_path = env_path.with_suffix(".env.bak")
    shutil.copy(env_path, backup_path)
    click.echo(f"✓ Created backup: {backup_path}")

    new_content = _strip_obsolete_dotenv_pat_lines(content)

    env_path.write_text(new_content)
    click.echo(f"✓ Removed obsolete file-stored PAT lines from {env_path}")


def verify_connection(
    user: str,
    pat_token: str,
    pat_role: str,
    account: str | None = None,
    host: str | None = None,
) -> None:
    """Verify the PAT using the Python connector (PROGRAMMATIC_ACCESS_TOKEN).

    Avoids ``snow sql`` with ``SNOWFLAKE_PASSWORD`` (see sf-utils-pat skill Step 6).
    """
    click.echo("Verifying connection with PAT...")

    acct = account if account is not None else get_snowflake_account()

    if get_snow_cli_options().debug:
        click.echo(
            f"[DEBUG] verify_pat_with_connector account={acct!r} user={user!r} "
            f"role={pat_role!r} host={host!r}"
        )

    verify_pat_with_connector(
        account=acct,
        user=user,
        role=pat_role,
        pat_token=pat_token,
        host=host,
    )

    click.echo("✓ Connection verified successfully")


def _persist_pat_state(
    manifest_path: Path,
    env_path: Path,
    user: str,
    role: str,
    label: str,
    pat_config: dict,
) -> None:
    """Write PAT entry to manifest.toml and update .env for backward compat.

    The manifest.toml upsert is the primary state store for multi-PAT projects.
    The .env update is kept so single-PAT / legacy consumers are not broken.
    """
    data = load_manifest(manifest_path)
    ensure_manifest_defaults(data, manifest_path)
    upsert_pat(data, label, pat_config)
    save_manifest(manifest_path, data)
    click.echo(f"✓ Updated {manifest_path} with PAT entry '{label}' for {user}")
    # Backward compat: still write SA_USER / SA_ROLE to .env if the file exists.
    update_env_non_secrets(env_path, user, role)


def _resolve_user_role_from_profile(
    profile: str | None,
    user: str | None,
    role: str | None,
    manifest_path: Path,
) -> tuple[str | None, str | None]:
    """If --profile is given, fill in any missing --user / --role from manifest.toml.

    Also switches the active Snowflake connection to the PAT entry's connection
    override (if set), so rotate/verify/remove all use the right account.
    """
    if not profile:
        return user, role
    data = load_manifest(manifest_path)
    entry = get_pat_entry(data, label=profile)
    if entry is None:
        raise click.ClickException(
            f"Profile '{profile}' not found in manifest.toml. "
            "Run 'sfutils-pat list' to see available profiles."
        )
    # Switch connection if the PAT entry has a per-PAT override.
    pat_conn = entry.get("connection")
    if pat_conn:
        set_connection(pat_conn)
    return user or entry.get("sa_user"), role or entry.get("sa_role")


# Auto-load connection from manifest when available.
# load_dotenv() is intentionally NOT called — manifest.toml is the canonical
# config source.  SNOWFLAKE_DEFAULT_CONNECTION_NAME in the shell environment
# still works as a fallback via resolve_pat_connection().


@click.group(invoke_without_command=True)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--debug", "-d", is_flag=True, help="Enable debug output")
@click.option(
    "--comment",
    "-c",
    envvar=["SF_UTILS_COMMENT", "SNOW_UTILS_COMMENT"],
    default=None,
    help="Comment prefix for SQL resources (inferred from SA_USER if not provided)",
)
@click.option(
    "--manifest-path",
    "-m",
    type=click.Path(path_type=Path),
    default=Path(".sfutils/manifest.toml"),
    show_default=True,
    help="Path to TOML manifest (default: .sfutils/manifest.toml)",
)
@click.pass_context
def cli(
    ctx: click.Context,
    verbose: bool,
    debug: bool,
    comment: str | None,
    manifest_path: Path,
) -> None:
    """
    Snowflake PAT Manager - Manage service users with programmatic access tokens.

    \b
    Commands:
        create             - Create/rotate PAT for service user
        rotate             - Rotate existing PAT (keep policies)
        verify             - Test PAT connection (PAT from keyring only)
        show-pat           - Print PAT from keyring to stdout (insecure)
        remove             - Remove PAT and associated objects
        list               - List all PATs from manifest.toml
        setup-connection   - Set project Snowflake connection in manifest.toml
        validate-manifest  - Validate (and optionally repair) manifest.toml
        migrate            - Migrate .env + sfutils-manifest.md to manifest.toml
    """
    set_snow_cli_options(verbose=verbose, debug=debug)
    ctx.ensure_object(dict)
    ctx.obj["comment"] = comment
    ctx.obj["manifest_path"] = manifest_path

    # Set connection from manifest so all snow SQL calls use -c <connection>.
    _manifest = load_manifest(manifest_path)
    _conn = resolve_pat_connection({}, _manifest)
    if _conn:
        set_connection(_conn)

    # ── Manifest auto-gate ────────────────────────────────────────────────────
    # Runs before EVERY subcommand. If manifest exists and is broken:
    #   1. Auto-repair structural gaps (missing schema_version, [snowflake],
    #      [prereqs] sections) via ensure_manifest_defaults — silent success.
    #   2. Warn loudly about non-structural issues that need manual action
    #      (empty connection, missing sa_user/sa_role in a PAT entry, etc.).
    # New projects with no manifest yet are skipped — setup-connection / create
    # will initialise it correctly.
    if manifest_path.exists() and ctx.invoked_subcommand not in (
        "validate-manifest",
        "setup-connection",
    ):
        _gdata = load_manifest(manifest_path)
        _issues_before = validate_manifest(_gdata)
        if _issues_before:
            ensure_manifest_defaults(_gdata, manifest_path)
            save_manifest(manifest_path, _gdata)
            _issues_after = validate_manifest(_gdata)
            if _issues_after:
                # Non-structural issues remain — warn but don't block.
                # Commands that use --profile or remove will fail naturally
                # if the field they need is missing.
                click.echo(
                    f"\n⚠️  manifest.toml has {len(_issues_after)} issue(s) "
                    "that need attention before this operation:",
                    err=True,
                )
                for _issue in _issues_after:
                    click.echo(f"   ✗ {_issue}", err=True)
                click.echo(
                    "   Run 'sfutils-pat validate-manifest' for details "
                    "or 'sfutils-pat setup-connection' to fix an empty connection.\n",
                    err=True,
                )
            else:
                click.echo(
                    f"[manifest] auto-repaired "
                    f"{len(_issues_before)} structural gap(s)",
                    err=True,
                )

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command(name="create")
@click.option("--user", "-u", envvar="SA_USER", default=None, help="Service account user name")
@click.option("--role", "-r", envvar="SA_ROLE", default=None, help="Role restriction for the PAT")
@click.option(
    "--profile", "-p",
    default=None,
    help="PAT label in manifest.toml — resolves --user/--role when not explicitly provided",
)
@click.option(
    "--db",
    "-d",
    envvar=["SF_UTILS_DB", "SNOW_UTILS_DB"],
    required=True,
    help="Database for PAT objects",
)
@click.option("--pat-name", default=None, envvar="PAT_NAME", help="Name for the PAT token")
@click.option("--rotate/--no-rotate", default=True, help="Rotate existing PAT (default: True)")
@click.option(
    "--env-path",
    type=click.Path(path_type=Path),
    default=Path(".env"),
    help=".env file path",
)
@click.option("--skip-verify", is_flag=True, help="Skip connection verification")
@click.option(
    "--allow-local/--no-local",
    "allow_local",
    default=True,
    help="Include local IP (default: True)",
)
@click.option(
    "--allow-gh",
    is_flag=True,
    default=False,
    help=(
        "Allow GitHub Actions via Snowflake-managed rule "
        f"{SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN} (hybrid policy; not gov regions)"
    ),
)
@click.option("--allow-google", is_flag=True, default=False, help="Include Google IPs")
@click.option("--extra-cidrs", multiple=True, help="Additional CIDRs (can be repeated)")
@click.option(
    "--default-expiry-days",
    default=7,
    type=int,
    help="Default PAT expiry days (secure default: 7; use 15 to match Snowflake platform default)",
)
@click.option(
    "--max-expiry-days",
    default=30,
    type=int,
    help=(
        "Maximum PAT expiry days (secure default: 30; use 365 to match Snowflake platform default)"
    ),
)
@click.option("--dry-run", is_flag=True, help="Preview without making changes")
@click.option(
    "--connection",
    default=None,
    help=(
        "Snowflake connection name for this PAT (overrides manifest [snowflake].connection). "
        "account/user/account_url are resolved from this connection and stored in the PAT entry."
    ),
)
@click.option(
    "--admin-role",
    "-a",
    default="accountadmin",
    help="Admin role for creating resources (default: ACCOUNTADMIN)",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Overwrite existing network rule/policy (CREATE OR REPLACE)",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.option(
    "--skip-network",
    is_flag=True,
    help="Skip network rule/policy creation (use when delegating to sf-utils-networks skill)",
)
@click.option(
    "--dot-env-file",
    type=click.Path(path_type=Path),
    default=None,
    help="Also update this .env with SA_USER and SA_ROLE only (PAT is never written to disk)",
)
@click.option(
    "--print",
    "print_token",
    is_flag=True,
    default=False,
    help="Print PAT to stdout after storing in keyring (insecure; cannot use with -o json)",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    default=False,
    help="Skip interactive confirmation (use after reviewing dry-run output)",
)
@click.pass_context
def create_command(
    ctx: click.Context,
    user: str | None,
    role: str | None,
    profile: str | None,
    db: str,
    pat_name: str | None,
    rotate: bool,
    env_path: Path,
    skip_verify: bool,
    allow_local: bool,
    allow_gh: bool,
    allow_google: bool,
    extra_cidrs: tuple[str, ...],
    default_expiry_days: int,
    max_expiry_days: int,
    dry_run: bool,
    connection: str | None,
    admin_role: str,
    force: bool,
    output: str,
    skip_network: bool,
    dot_env_file: Path | None,
    print_token: bool,
    yes: bool,
) -> None:
    """
    Create or rotate a PAT for a service user.

    Network policy is REQUIRED for PAT security (Snowflake best practice).
    Use --skip-network if network resources were created by sf-utils-networks skill.

    \b
    Steps:
    1. Create service user (if not exists)
    2. Create network rule and policy (unless --skip-network)
    3. Create authentication policy
    4. Create or rotate PAT
    5. Store PAT in OS keyring; update manifest.toml and .env
    6. Verify connection using PAT loaded from keyring

    \b
    Examples:
        # Basic usage - local IP only (most secure)
        pat.py create --user my_sa --role demo_role --db my_db

        # Use a saved profile from manifest.toml
        pat.py create --profile app-runner --db my_db

        # Skip network (created by sf-utils-networks skill)
        pat.py create --user my_sa --role demo_role --db my_db --skip-network

        # Allow GitHub Actions (Snowflake-managed network rule on the policy)
        pat.py create --user ci_sa --role ci_role --db my_db --allow-gh
    """
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))
    user, role = _resolve_user_role_from_profile(profile, user, role, manifest_path)
    if not user:
        raise click.UsageError(
            "--user / SA_USER is required (or use --profile to resolve from manifest.toml)"
        )
    if not role:
        raise click.UsageError(
            "--role / SA_ROLE is required (or use --profile to resolve from manifest.toml)"
        )

    # If a connection override is provided, switch the active connection so all
    # subsequent snow SQL calls use it, and fetch its metadata for the PAT entry.
    if connection:
        set_connection(connection)
    if not pat_name:
        pat_name = f"{user}_pat".upper()

    if print_token and output == "json":
        raise click.UsageError("--print cannot be used with -o json")

    cidrs: list[str] = []
    if not skip_network:
        cidrs = collect_ipv4_cidrs(
            with_local=allow_local,
            with_google=allow_google,
            extra_cidrs=list(extra_cidrs) if extra_cidrs else None,
        )
        if not cidrs and not allow_gh:
            raise click.ClickException(
                "Network policy required for PAT security. "
                "Use --allow-local (default), --allow-gh, --allow-google, or --extra-cidrs"
            )

    comment_prefix = ctx.obj.get("comment") or infer_comment_prefix(user)

    def build_result(status: str) -> dict:
        result = {
            "status": status,
            "user": user,
            "pat_name": pat_name,
            "pat_role": role,
            "database": db,
            "comment_prefix": comment_prefix,
            "resources": {
                "auth_policy": f"{db}.POLICIES.{user}_AUTH_POLICY".upper(),
            },
            "skip_network": skip_network,
        }
        if not skip_network:
            result["resources"]["network_rule"] = f"{db}.NETWORKS.{user}_NETWORK_RULE".upper()
            result["resources"]["network_policy"] = f"{user}_NETWORK_POLICY".upper()
            result["cidrs_count"] = len(cidrs)
            if allow_gh:
                result["resources"]["snowflake_managed_github_rule"] = (
                    SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN
                )
        return result

    if output == "json" and dry_run:
        result = build_result("dry_run")
        result["cidrs"] = cidrs
        click.echo(json.dumps(result, indent=2))
        return

    if output == "text":
        click.echo("=" * 50)
        click.echo("Snowflake PAT Manager")
        if dry_run:
            click.echo("  [DRY RUN]")
        click.echo("=" * 50)
        click.echo(f"User:     {user}")
        click.echo(f"Role:     {role}")
        click.echo(f"Database: {db}")
        click.echo(f"PAT Name: {pat_name}")
        if not skip_network:
            suffix = "y" if len(cidrs) == 1 else "ies"
            click.echo(f"CIDRs:    {len(cidrs)} custom rule entr{suffix}")
            if allow_gh:
                click.echo(f"GitHub:   {SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN} (hybrid policy)")
        else:
            click.echo("Network:  (skipped - delegated to sf-utils-networks)")
        click.echo()

    if dry_run:
        set_masking(False)
        click.echo("SQL that would be executed:")
        click.echo("─" * 60)
        click.echo("-- Step 1: Create service user")
        click.echo(get_service_user_and_role_sql(user, role, comment_prefix, admin_role))
        click.echo()
        if not skip_network:
            click.echo("-- Step 2: Create network rule and policy")
            click.echo(
                get_setup_network_for_user_sql(
                    user=user,
                    db=db,
                    cidrs=cidrs,
                    force=force,
                    comment_prefix=comment_prefix,
                    admin_role=admin_role,
                    allow_managed_github=allow_gh,
                )
            )
            click.echo()
            click.echo("-- Step 3: Create authentication policy")
        else:
            click.echo("-- Step 2: (Network skipped - use sf-utils-networks skill)")
            click.echo()
            click.echo("-- Step 3: Create authentication policy")
        click.echo(
            get_auth_policy_sql(
                user, db, default_expiry_days, max_expiry_days, comment_prefix, admin_role
            )
        )
        click.echo()
        click.echo("-- Step 4: Create PAT")
        click.echo(get_pat_sql(user, role, pat_name))
        click.echo("─" * 60)
        return

    if (
        output == "text"
        and not yes
        and not click.confirm("\nProceed with resource creation?", default=True)
    ):
        click.echo("Aborted.")
        return

    setup_service_user(
        user=user, pat_role=role, comment_prefix=comment_prefix, admin_role=admin_role
    )

    if not skip_network:
        gh_note = f", hybrid with {SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN}" if allow_gh else ""
        click.echo(f"Setting up network rule and policy ({len(cidrs)} custom CIDRs{gh_note})...")
        rule_fqn, policy_name = setup_network_for_user(
            user=user,
            db=db,
            cidrs=cidrs,
            force=force,
            comment_prefix=comment_prefix,
            admin_role=admin_role,
            allow_managed_github=allow_gh,
        )
        if rule_fqn:
            click.echo(f"✓ Network rule: {rule_fqn}")
        else:
            click.echo(
                "✓ Network rule: (skipped; policy allows Snowflake-managed GitHub Actions only)"
            )
        click.echo(f"✓ Network policy: {policy_name}")
        assign_network_policy_to_user(user, policy_name, admin_role=admin_role)
        click.echo(f"✓ Assigned network policy to user {user}")
    else:
        click.echo("Network setup skipped (delegated to sf-utils-networks skill)")

    setup_auth_policy(
        user=user,
        db=db,
        default_expiry_days=default_expiry_days,
        max_expiry_days=max_expiry_days,
        comment_prefix=comment_prefix,
        admin_role=admin_role,
    )

    password = create_or_rotate_pat(
        user=user, pat_role=role, pat_name=pat_name, rotate=rotate, admin_role=admin_role
    )

    account, host = get_snowflake_connection_metadata()
    try:
        store_pat(host, account, user, pat_name, password)
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e

    if print_token:
        click.echo(
            "WARNING: PAT printed to stdout; may appear in shell history and CI logs.",
            err=True,
        )
        click.echo(password)

    _now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    _label = user.lower().replace("_", "-")
    _pat_config: dict = {
        "status": "COMPLETE",
        "created_at": _now,
        "rotated_at": _now,
        "sa_user": user.upper(),
        "sa_role": role.upper(),
        "pat_name": pat_name.upper(),
        "comment_prefix": comment_prefix,
        "sf_utils_db": db.upper(),
        "admin_role": admin_role.upper(),
        "default_expiry_days": default_expiry_days,
        "max_expiry_days": max_expiry_days,
        "local_ip": cidrs[0] if cidrs else "",
        "allow_github": allow_gh,
        "allow_google": allow_google,
        "extra_cidrs": list(extra_cidrs),
        "resources": {
            "network_rule": (
                f"{db.upper()}.NETWORKS.{user.upper()}_NETWORK_RULE"
                if not skip_network else ""
            ),
            "network_policy": f"{user.upper()}_NETWORK_POLICY" if not skip_network else "",
            "auth_policy": f"{db.upper()}.POLICIES.{user.upper()}_AUTH_POLICY",
            "service_user": user.upper(),
            "service_role": role.upper(),
            "pat": pat_name.upper(),
        },
        "cleanup": {
            "user": user.upper(),
            "db": db.upper(),
            "drop_user": True,
        },
    }
    # Store connection metadata only when an explicit override is provided.
    # The root [snowflake] block already holds metadata for the default connection.
    if connection:
        _pat_config["connection"] = connection
        _pat_config["account"] = account
        _pat_config["user"] = user  # Snowflake login user (from connection test)
        _pat_config["account_url"] = f"https://{host}" if host else ""
    _persist_pat_state(manifest_path, env_path, user, role, _label, _pat_config)
    if dot_env_file:
        update_env_non_secrets(dot_env_file, user, role)

    if not skip_verify:
        loaded = load_pat(host, account, user, pat_name)
        if not loaded:
            raise click.ClickException(
                "PAT not found in keyring immediately after store; cannot verify."
            )
        verify_connection(user=user, pat_token=loaded, pat_role=role, account=account, host=host)

    if output == "json":
        result = build_result("success")
        result["cidrs"] = cidrs
        result["account"] = account
        result["host"] = host if host else "NA"
        result["keyring_service"] = build_pat_credential_service(host, account, user, pat_name)
        result["pat"] = "***REDACTED***"
        result["env_files_updated"] = [str(env_path)] + (
            [str(dot_env_file)] if dot_env_file else []
        )
        click.echo(json.dumps(result, indent=2))
        return

    click.echo()
    click.echo("=" * 50)
    click.echo("✓ PAT setup completed successfully!")
    click.echo("  PAT stored in OS keyring (not written to .env or manifest token fields)")
    click.echo("=" * 50)


@cli.command(name="remove")
@click.option("--user", "-u", envvar="SA_USER", default=None, help="Service account user name")
@click.option(
    "--profile", "-p",
    default=None,
    help="PAT label in manifest.toml — resolves --user when not explicitly provided",
)
@click.option(
    "--db",
    "-d",
    envvar=["SF_UTILS_DB", "SNOW_UTILS_DB"],
    required=True,
    help="Database for PAT objects",
)
@click.option("--pat-name", default=None, envvar="PAT_NAME", help="Name of the PAT to remove")
@click.option("--drop-user", is_flag=True, help="Also drop the service user")
@click.option("--pat-only", is_flag=True, help="Only remove PAT, keep policies")
@click.option(
    "--admin-role",
    "-a",
    default="accountadmin",
    help="Admin role for removing resources (default: ACCOUNTADMIN)",
)
@click.option(
    "--env-path",
    type=click.Path(path_type=Path),
    default=Path(".env"),
    help=".env file path",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    default=False,
    help="Skip per-step confirmation prompts (required in non-interactive terminals)",
)
@click.pass_context
def remove_command(
    ctx: click.Context,
    user: str | None,
    profile: str | None,
    db: str,
    pat_name: str | None,
    drop_user: bool,
    pat_only: bool,
    admin_role: str,
    env_path: Path,
    yes: bool,
) -> None:
    """
    Remove PAT and associated objects for a service user.

    Each destructive step asks for confirmation unless --yes. Step 5 only strips
    legacy raw-PAT lines from .env and updates manifest.toml status (no confirmation).

    \b
    Steps:
    1. Remove PAT
    2. Remove network policy and rule (unless --pat-only)
    3. Remove authentication policy (unless --pat-only)
    4. Drop service user (if --drop-user)
    5. Strip legacy PAT lines from .env; mark REMOVED in manifest.toml
    """
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))
    user, _ = _resolve_user_role_from_profile(profile, user, None, manifest_path)
    if not user:
        raise click.UsageError(
            "--user / SA_USER is required (or use --profile to resolve from manifest.toml)"
        )
    click.echo("=" * 50)
    click.echo("Snowflake PAT Manager - Remove")
    click.echo("=" * 50)
    click.echo()

    if not pat_name:
        pat_name = f"{user}_pat".upper()

    click.echo(f"User:     {user}")
    click.echo(f"Database: {db}")
    click.echo(f"PAT Name: {pat_name}")
    click.echo()

    if not yes and not sys.stdin.isatty():
        raise click.ClickException(
            "Non-interactive terminal: pass --yes to confirm all remove steps."
        )

    click.echo("─" * 40)
    click.echo("Step 1: Remove PAT")
    click.echo("─" * 40)
    if not _confirm_remove_step(
        skip_all_prompts=yes,
        message=(
            f"Remove PAT '{pat_name}' from Snowflake user {user} and delete the "
            "matching OS keyring entry (if present)?"
        ),
    ):
        return

    try:
        acc, h = get_snowflake_connection_metadata()
        delete_pat(h, acc, user, pat_name)
        click.echo("✓ Removed PAT from OS keyring (if present)")
    except click.ClickException as e:
        click.echo(f"⚠ Keyring cleanup skipped: {e}", err=True)

    remove_pat(user=user, pat_name=pat_name, admin_role=admin_role)
    click.echo()

    if not pat_only:
        net_rule = f"{user}_NETWORK_RULE".upper()
        net_policy = f"{user}_NETWORK_POLICY".upper()
        rule_fqn = f"{db.upper()}.NETWORKS.{net_rule}"
        click.echo("─" * 40)
        click.echo("Step 2: Remove network policy and rule")
        click.echo("─" * 40)
        click.echo(f"  Unset NETWORK_POLICY on user {user}")
        click.echo(f"  Drop network policy: {net_policy}")
        click.echo(f"  Drop network rule:   {rule_fqn}")
        click.echo()
        if not _confirm_remove_step(
            skip_all_prompts=yes,
            message="Proceed with Step 2 (network policy and rule removal)?",
        ):
            return
        cleanup_network_for_user(user=user, db=db, admin_role=admin_role)
        click.echo("✓ Network policy and rule removed")
        click.echo()

        auth_policy_name = f"{user}_auth_policy".upper()
        auth_fqn = f"{db}.POLICIES.{auth_policy_name}"
        click.echo("─" * 40)
        click.echo("Step 3: Remove authentication policy")
        click.echo("─" * 40)
        click.echo(f"  Drop authentication policy: {auth_fqn}")
        click.echo()
        if not _confirm_remove_step(
            skip_all_prompts=yes,
            message=f"Proceed with Step 3 (remove {auth_fqn})?",
        ):
            return
        remove_auth_policy(user=user, db=db, admin_role=admin_role)
        click.echo()

    if drop_user:
        click.echo("─" * 40)
        click.echo("Step 4: Drop service user")
        click.echo("─" * 40)
        click.echo(f"  DROP USER {user}")
        click.echo()
        if not _confirm_remove_step(
            skip_all_prompts=yes,
            message=f"Proceed with Step 4 (drop service user {user})?",
        ):
            return
        remove_service_user(user=user, admin_role=admin_role)
        click.echo()

    # Step 5: non-secret cleanup — no confirmation (legacy raw-PAT lines in .env + TOML status).
    click.echo("─" * 40)
    click.echo("Step 5: Strip legacy PAT lines from .env; update manifest.toml")
    click.echo("─" * 40)
    click.echo(f"  File: {env_path} (SA_USER / SA_ROLE are not removed)")
    clear_env(env_path=env_path)
    _manifest_data = load_manifest(manifest_path)
    update_pat_status(_manifest_data, user, "REMOVED")
    save_manifest(manifest_path, _manifest_data)
    click.echo(f"  manifest.toml: marked {user} as REMOVED")
    click.echo()

    click.echo("=" * 50)
    click.echo("✓ PAT removal completed!")
    click.echo("=" * 50)


@cli.command(name="rotate")
@click.option("--user", "-u", required=True, envvar="SA_USER", help="Service account user name")
@click.option("--role", "-r", required=True, envvar="SA_ROLE", help="Role restriction for the PAT")
@click.option(
    "--pat-name", envvar="PAT_NAME", help="Name for the PAT token (defaults to {USER}_PAT)"
)
@click.option(
    "--admin-role",
    "-a",
    default="accountadmin",
    help="Admin role for rotating PAT (default: ACCOUNTADMIN)",
)
@click.option(
    "--env-path", type=click.Path(path_type=Path), default=Path(".env"), help=".env file path"
)
@click.option("--skip-verify", is_flag=True, help="Skip connection verification")
@click.option(
    "-o", "--output", type=click.Choice(["text", "json"]), default="text", help="Output format"
)
@click.option(
    "--print",
    "print_token",
    is_flag=True,
    default=False,
    help="Print PAT to stdout after storing in keyring (insecure; cannot use with -o json)",
)
@click.pass_context
def rotate_command(
    ctx: click.Context,
    user: str,
    role: str,
    pat_name: str | None,
    admin_role: str,
    env_path: Path,
    skip_verify: bool,
    output: str,
    print_token: bool,
) -> None:
    """
    Rotate an existing PAT for a service user.

    This regenerates the PAT token while keeping all policies intact.
    The new token is stored in the OS keyring; .env is updated with SA_USER and SA_ROLE only.

    \b
    Examples:
        # Rotate PAT with defaults
        pat.py rotate --user my_sa --role demo_role

        # Rotate and skip verification
        pat.py rotate --user my_sa --role demo_role --skip-verify
    """
    if not pat_name:
        pat_name = f"{user}_pat".upper()

    if print_token and output == "json":
        raise click.UsageError("--print cannot be used with -o json")

    click.echo("=" * 50)
    click.echo("Snowflake PAT Manager - Rotate")
    click.echo("=" * 50)
    click.echo(f"User:     {user}")
    click.echo(f"Role:     {role}")
    click.echo(f"PAT Name: {pat_name}")
    click.echo()

    existing = get_existing_pat(user, pat_name, admin_role=admin_role)
    if not existing:
        raise click.ClickException(
            f"PAT '{pat_name}' not found for user {user}. Use 'create' command first."
        )

    password = create_or_rotate_pat(
        user=user, pat_role=role, pat_name=pat_name, rotate=True, admin_role=admin_role
    )

    account, host = get_snowflake_connection_metadata()
    try:
        store_pat(host, account, user, pat_name, password)
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e

    if print_token:
        click.echo(
            "WARNING: PAT printed to stdout; may appear in shell history and CI logs.",
            err=True,
        )
        click.echo(password)

    update_env_non_secrets(env_path, user, role)

    # Update rotated_at in manifest so the rotation timestamp is always current.
    _mpath: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))
    if _mpath.exists():
        _mdata = load_manifest(_mpath)
        _rot_now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        for _entry in _mdata.get("pat", {}).values():
            if _entry.get("sa_user", "").upper() == user.upper():
                _entry["rotated_at"] = _rot_now
                break
        save_manifest(_mpath, _mdata)

    if not skip_verify:
        loaded = load_pat(host, account, user, pat_name)
        if not loaded:
            raise click.ClickException(
                "PAT not found in keyring immediately after store; cannot verify."
            )
        verify_connection(user=user, pat_token=loaded, pat_role=role, account=account, host=host)

    if output == "json":
        result = {
            "status": "rotated",
            "user": user,
            "pat_name": pat_name,
            "pat_role": role,
            "account": account,
            "host": host if host else "NA",
            "keyring_service": build_pat_credential_service(host, account, user, pat_name),
            "pat": "***REDACTED***",
        }
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo()
        click.echo("=" * 50)
        click.echo("✓ PAT rotated successfully!")
        click.echo("  PAT stored in OS keyring (not written to .env)")
        click.echo("=" * 50)


@cli.command(name="verify")
@click.option("--user", "-u", required=True, envvar="SA_USER", help="Service account user name")
@click.option("--role", "-r", required=True, envvar="SA_ROLE", help="Role for the PAT")
@click.option(
    "--pat-name",
    default=None,
    envvar="PAT_NAME",
    help="PAT name in Snowflake (default: {USER}_PAT)",
)
def verify_command(
    user: str,
    role: str,
    pat_name: str | None,
) -> None:
    """
    Verify PAT connection works correctly.

    Loads the PAT from the OS keyring only (same entry as create/rotate). There is no
    password flag, env-based PAT, or .env secret fallback.

    \b
    Example:
        sfutils-pat verify --user my_sa --role demo_role
    """
    if not pat_name:
        pat_name = f"{user}_pat".upper()

    account, host = get_snowflake_connection_metadata()
    password = load_pat(host, account, user, pat_name)
    if not password:
        raise click.ClickException(
            "No PAT found in keyring for this Snowflake connection, user, and PAT name. "
            "Run `create` or `rotate` first."
        )

    click.echo("=" * 50)
    click.echo("Snowflake PAT Manager - Verify")
    click.echo("=" * 50)
    click.echo(f"User: {user}")
    click.echo(f"Role: {role}")
    click.echo()

    verify_connection(user=user, pat_token=password, pat_role=role, account=account, host=host)

    click.echo()
    click.echo("=" * 50)
    click.echo("✓ PAT verification successful!")
    click.echo("=" * 50)


@cli.command("show-pat")
@click.option("--user", "-u", required=True, envvar="SA_USER", help="Service account user name")
@click.option(
    "--pat-name",
    default=None,
    envvar="PAT_NAME",
    help="PAT name in Snowflake (default: {USER}_PAT)",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    default=False,
    help="Skip confirmation before printing (unsafe in logged or shared terminals)",
)
def show_pat_command(user: str, pat_name: str | None, yes: bool) -> None:
    """
    Print the PAT from the OS keyring to stdout (insecure).

    Prompts for confirmation unless --yes. The secret may appear in shell history,
    terminal scrollback, CI logs, observability tools, and screen sharing.
    """
    if not pat_name:
        pat_name = f"{user}_pat".upper()

    account, host = get_snowflake_connection_metadata()
    secret = load_pat(host, account, user, pat_name)
    if not secret:
        raise click.ClickException(
            "No PAT found in keyring for this Snowflake connection, user, and PAT name."
        )

    if not yes and not click.confirm(
        "WARNING: The raw PAT will be printed to stdout.\n"
        "It may be captured in shell history, terminal scrollback, CI logs, "
        "observability pipelines, and screen sharing.\n\n"
        "Do you want to continue?",
        default=False,
    ):
        click.echo("Aborted.")
        return

    click.echo(
        "WARNING: PAT is printed to stdout; may be captured in shell history or logs.",
        err=True,
    )
    click.echo(secret)


@cli.command(name="list")
@click.pass_context
def list_command(ctx: click.Context) -> None:
    """List all PATs recorded in manifest.toml."""
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))
    data = load_manifest(manifest_path)
    pats = data.get("pat", {})

    if not pats:
        if not manifest_path.exists():
            click.echo(f"No manifest found at {manifest_path}. Run 'sfutils-pat create' first.")
        else:
            click.echo("No PAT entries found in manifest.toml.")
        return

    # Header
    click.echo(f"\n{'LABEL':<20} {'SA_USER':<35} {'STATUS':<12} {'EXPIRY (def/max)'}")
    click.echo("─" * 85)
    for label, pat in pats.items():
        sa_user = pat.get("sa_user", "—")
        status = pat.get("status", "—")
        default_exp = pat.get("default_expiry_days", "?")
        max_exp = pat.get("max_expiry_days", "?")
        expiry = f"{default_exp}d / {max_exp}d"
        # Colour-code status
        status_display = (
            click.style(status, fg="green") if status == "COMPLETE"
            else click.style(status, fg="yellow") if status == "IN_PROGRESS"
            else click.style(status, fg="red") if status == "REMOVED"
            else status
        )
        click.echo(f"{label:<20} {sa_user:<35} {status_display:<12} {expiry}")
    click.echo()


def _parse_legacy_manifest(path: Path) -> dict:
    """Extract structured data from a legacy sfutils-manifest.md file.

    sfutils-manifest.md is the authoritative record of what was created.
    Returns a dict with whatever fields could be parsed; missing fields are
    absent from the dict (not None/empty) so callers can chain fallbacks cleanly.

    Parsed fields: project_name, tools_verified, admin_role, sa_user, sa_role,
    sf_utils_db, status, created_at, comment_prefix, default_expiry_days,
    max_expiry_days, resources (dict of FQN strings).
    """
    if not path.exists():
        return {}
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return {}

    result: dict = {}

    def _s(m_: re.Match | None) -> str | None:
        return m_.group(1).strip() if m_ else None

    # ── Global sections ───────────────────────────────────────────────────────
    if v := _s(re.search(r"^project_name:\s*(.+?)$", content, re.MULTILINE)):
        result["project_name"] = v
    if v := _s(re.search(r"^tools_verified:\s*(.+?)$", content, re.MULTILINE)):
        result["tools_verified"] = v
    # admin_role stored as "programmatic-access-token: ROLE"
    if v := _s(re.search(r"^programmatic-access-token:\s*(.+?)$", content, re.MULTILINE)):
        result["admin_role"] = v

    # ── PAT skill section ─────────────────────────────────────────────────────
    start = content.find("<!-- START -- programmatic-access-token -->")
    end = content.find("<!-- END -- programmatic-access-token -->")
    pat_section = content[start: end if end != -1 else len(content)] if start != -1 else ""

    if pat_section:
        # Scalar key-value pairs (bold markdown format)
        _kv = [
            ("sa_user",        r"\*\*User:\*\*\s*(\S+)"),
            ("sa_role",        r"\*\*Role:\*\*\s*(\S+)"),
            ("sf_utils_db",    r"\*\*Database:\*\*\s*(\S+)"),
            ("status",         r"\*\*Status:\*\*\s*(\S+)"),
            ("comment_prefix", r"\*\*Comment:\*\*\s*(\S+)"),
            ("created_at",     r"\*\*Created:\*\*\s*(.+?)$"),
        ]
        for field, pat in _kv:
            if v := _s(re.search(pat, pat_section, re.MULTILINE)):
                result[field] = v

        for field, pat in [
            ("default_expiry_days", r"\*\*Default Expiry \(days\):\*\*\s*(\d+)"),
            ("max_expiry_days",     r"\*\*Max Expiry \(days\):\*\*\s*(\d+)"),
        ]:
            m = re.search(pat, pat_section)
            if m:
                result[field] = int(m.group(1))

        # Resource FQNs from the resources table
        # Row: | N | Type | Name | Location | Status |
        resources: dict = {}
        for row in re.finditer(
            r"\|\s*\d+\s*\|\s*(.+?)\s*\|\s*(\S+)\s*\|\s*(.+?)\s*\|\s*\w+\s*\|",
            pat_section,
        ):
            rtype = row.group(1).strip().lower()
            rname = row.group(2).strip()
            rloc  = row.group(3).strip()

            if "network rule" in rtype:
                # Extract sf_utils_db from Location = "SFUTILS_DB.NETWORKS"
                if "." in rloc:
                    result.setdefault("sf_utils_db", rloc.split(".")[0])
                resources["network_rule"] = (
                    f"{rloc}.{rname}" if rloc not in ("Account", "—") else rname
                )
            elif "network policy" in rtype:
                resources["network_policy"] = rname
            elif "auth" in rtype and "policy" in rtype:
                resources["auth_policy"] = (
                    f"{rloc}.{rname}" if "." in rloc else rname
                )
            elif "service role" in rtype:
                resources["service_role"] = rname
            elif "service user" in rtype:
                resources["service_user"] = rname
            elif rtype.strip() == "pat":
                resources["pat"] = rname

        if resources:
            result["resources"] = resources

    return result


@cli.command(name="migrate")
@click.option(
    "--env-path",
    type=click.Path(path_type=Path),
    default=Path(".env"),
    help=".env file to read from (default: .env)",
)
@click.option(
    "--manifest-md",
    type=click.Path(path_type=Path),
    default=Path(".sfutils/sfutils-manifest.md"),
    help="Existing markdown manifest to read resources from "
         "(default: .sfutils/sfutils-manifest.md)",
)
@click.option("--dry-run", is_flag=True, help="Print what would be written without writing")
@click.pass_context
def migrate_command(
    ctx: click.Context,
    env_path: Path,
    manifest_md: Path,
    dry_run: bool,
) -> None:
    """Migrate .env + sfutils-manifest.md to manifest.toml.

    sfutils-manifest.md is the PRIMARY source — it contains SA_USER, SA_ROLE,
    SFUTILS_DB, admin_role, project_name, prereqs, resource FQNs, and status.
    .env is SUPPLEMENTARY — it adds the Snowflake connection name and account
    details that were never stored in the old markdown manifest.

    Works correctly even when .env is absent or empty.
    Does NOT delete the old files.

    \b
    Example:
        sfutils-pat migrate --dry-run
        sfutils-pat migrate
    """
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))

    # ── Step 1: Read both legacy sources ──────────────────────────────────────
    env_vals = dotenv_values(env_path) if env_path.exists() else {}
    md = _parse_legacy_manifest(manifest_md)

    sources: list[str] = []
    if env_path.exists():
        sources.append(str(env_path))
    if manifest_md.exists():
        sources.append(str(manifest_md))

    # ── Step 2: Resolve each field (manifest.md wins, .env supplements) ───────
    # Connection info lives ONLY in .env (never in the old markdown manifest).
    connection  = env_vals.get("SNOWFLAKE_DEFAULT_CONNECTION_NAME", "")
    account     = env_vals.get("SNOWFLAKE_ACCOUNT", "")
    sf_user_env = env_vals.get("SNOWFLAKE_USER", "")
    account_url = env_vals.get("SNOWFLAKE_ACCOUNT_URL", "")

    # PAT / infra: markdown manifest → .env → default
    sa_user = md.get("sa_user") or env_vals.get("SA_USER", "")
    sa_role = md.get("sa_role") or env_vals.get("SA_ROLE", "")
    sf_utils_db = (
        md.get("sf_utils_db")
        or env_vals.get("SF_UTILS_DB")
        or env_vals.get("SFUTILS_DB")
        or env_vals.get("SNOW_UTILS_DB")
        or ""
    )
    admin_role      = md.get("admin_role", "ACCOUNTADMIN")
    project_name    = md.get("project_name") or Path.cwd().name
    tools_verified  = md.get("tools_verified") or datetime.date.today().isoformat()
    pat_status      = (md.get("status") or "COMPLETE").upper()
    default_expiry  = md.get("default_expiry_days", 7)
    max_expiry      = md.get("max_expiry_days", 30)
    created_at      = (
        md.get("created_at")
        or datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    comment_prefix  = md.get("comment_prefix") or infer_comment_prefix(sa_user) if sa_user else ""

    # ── Step 3: Build manifest data structure ─────────────────────────────────
    data = load_manifest(manifest_path)
    if not data:
        data = {
            "schema_version": "1",
            "project_name": project_name,
            "created_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    else:
        data.setdefault("project_name", project_name)

    if "snowflake" not in data:
        data["snowflake"] = {}
    sf = data["snowflake"]
    if connection:
        sf["connection"] = connection
    if account:
        sf["account"] = account
    if sf_user_env:
        sf["user"] = sf_user_env
    if account_url:
        sf["account_url"] = account_url
    if sf_utils_db:
        sf["sf_utils_db"] = sf_utils_db
    sf.setdefault("admin_role", admin_role)

    data["prereqs"] = {
        "tools_verified": tools_verified,
        "infra_ready": bool(sf_utils_db),  # only true when sf_utils_db was resolved
    }

    # ── Step 4: Build PAT entry ────────────────────────────────────────────────
    if sa_user:
        _label = sa_user.lower().replace("_", "-")
        _now   = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        parsed_res = md.get("resources", {})

        # Resource FQNs: prefer parsed values; fall back to naming convention
        resources = {
            "network_rule": (
                parsed_res.get("network_rule")
                or f"{sf_utils_db.upper()}.NETWORKS.{sa_user.upper()}_NETWORK_RULE"
            ),
            "network_policy": (
                parsed_res.get("network_policy")
                or f"{sa_user.upper()}_NETWORK_POLICY"
            ),
            "auth_policy": (
                parsed_res.get("auth_policy")
                or f"{sf_utils_db.upper()}.POLICIES.{sa_user.upper()}_AUTH_POLICY"
            ),
            "service_user": parsed_res.get("service_user", sa_user.upper()),
            "service_role": parsed_res.get("service_role", sa_role.upper()),
            "pat":          parsed_res.get("pat", f"{sa_user.upper()}_PAT"),
        }
        upsert_pat(data, _label, {
            "status":             pat_status,
            "created_at":         created_at,
            "rotated_at":         _now,
            "sa_user":            sa_user.upper(),
            "sa_role":            sa_role.upper(),
            "pat_name":           f"{sa_user.upper()}_PAT",
            "comment_prefix":     comment_prefix,
            "sf_utils_db":        sf_utils_db.upper(),
            "admin_role":         admin_role,
            "default_expiry_days": default_expiry,
            "max_expiry_days":    max_expiry,
            "local_ip":           "",
            "allow_github":       False,
            "allow_google":       False,
            "extra_cidrs":        [],
            "resources":          resources,
            "cleanup": {
                "user":      sa_user.upper(),
                "db":        sf_utils_db.upper(),
                "drop_user": True,
            },
        })

    # ── Step 5: Dry-run summary ────────────────────────────────────────────────
    if dry_run:
        click.echo(f"[dry-run] Would write to: {manifest_path}")
        click.echo(f"[dry-run] Sources:       {', '.join(sources) or '(none found)'}")
        click.echo(f"[dry-run] project_name:  {data.get('project_name', '?')}")
        conn_prompt = connection or "(not set — will prompt after write)"
        click.echo(f"[dry-run] connection:    {conn_prompt}")
        click.echo(f"[dry-run] sf_utils_db:   {sf_utils_db or '(not found)'}")
        click.echo(f"[dry-run] admin_role:    {admin_role}")
        click.echo(f"[dry-run] PAT entries:   {len(data.get('pat', {}))}")
        for lbl, _pat in data.get("pat", {}).items():
            click.echo(f"  [{lbl}] {_pat.get('sa_user', '?')} ({_pat.get('status', '?')})")
        return

    # ── Step 6: Write manifest ─────────────────────────────────────────────────
    save_manifest(manifest_path, data)
    click.echo(f"✓ Written to {manifest_path}")
    click.echo(f"  Sources:    {', '.join(sources) or '(none — skeleton only)'}")
    click.echo(f"  PAT entries: {len(data.get('pat', {}))}")
    click.echo("  Old files were NOT modified.")

    # ── Step 7: Test connection (or pick a new one) ────────────────────────────
    _active_conn = data["snowflake"].get("connection", "")

    def _test_and_cache(conn_name: str) -> bool:
        """Test conn_name; cache metadata into manifest on success. Returns True on pass."""
        _r = subprocess.run(
            ["snow", "connection", "test", "-c", conn_name, "--format", "json"],
            capture_output=True, text=True, check=False, timeout=30,
        )
        if _r.returncode != 0:
            return False
        # Cache account metadata
        try:
            _meta = json.loads(_r.stdout)
            _d = load_manifest(manifest_path)
            if v := (_meta.get("Account") or _meta.get("account") or ""):
                _d["snowflake"]["account"] = str(v).strip()
            if v := (_meta.get("User") or _meta.get("user") or ""):
                _d["snowflake"]["user"] = str(v).strip()
            if v := (_meta.get("Host") or _meta.get("host") or ""):
                _d["snowflake"]["account_url"] = f"https://{v}".strip()
            _d["snowflake"]["connection"] = conn_name
            save_manifest(manifest_path, _d)
            set_connection(conn_name)
        except Exception:
            pass
        return True

    if _active_conn:
        click.echo(f"\nTesting connection '{_active_conn}'...")
        if _test_and_cache(_active_conn):
            click.echo(f"✓ Connection '{_active_conn}' verified and cached in manifest.toml")
            return
        click.echo(f"⚠️  Connection '{_active_conn}' test failed — picking a new one.")
    else:
        click.echo("\n⚠️  No connection found in .env or manifest — pick one from the list below.")

    # ── Step 8: Interactive connection picker ─────────────────────────────────
    click.echo("Listing available connections...")
    _list_r = subprocess.run(
        ["snow", "connection", "list", "--format", "json"],
        capture_output=True, text=True, check=False,
    )
    if _list_r.returncode != 0 or not _list_r.stdout.strip():
        click.echo(
            "Could not list connections. "
            "Run 'sfutils-pat setup-connection -c <name>' to set the connection manually."
        )
        return
    try:
        _conns = json.loads(_list_r.stdout)
    except json.JSONDecodeError:
        click.echo("Failed to parse connection list. Run 'sfutils-pat setup-connection -c <name>'.")
        return
    if not _conns:
        click.echo("No connections configured. Run 'snow connection add' first.")
        return

    click.echo()
    for _i, _c in enumerate(_conns, 1):
        _cname = _c.get("connection_name") or _c.get("name") or f"connection-{_i}"
        _def   = " (default)" if _c.get("is_default") else ""
        click.echo(f"  {_i}. {_cname}{_def}")
    click.echo()

    if sys.stdin.isatty():
        _raw = click.prompt("Enter connection number", default="1")
        try:
            _chosen_name = (
                _conns[int(_raw) - 1].get("connection_name")
                or _conns[int(_raw) - 1].get("name")
            )
        except (ValueError, IndexError):
            click.echo("Invalid choice. Run 'sfutils-pat setup-connection -c <name>'.")
            return
    else:
        _dflt = next((_c for _c in _conns if _c.get("is_default")), _conns[0])
        _chosen_name = _dflt.get("connection_name") or _dflt.get("name")
        click.echo(f"Non-interactive: auto-selecting '{_chosen_name}'")

    click.echo(f"\nTesting '{_chosen_name}'...")
    if _test_and_cache(_chosen_name):
        click.echo(f"✓ Connection '{_chosen_name}' verified and saved to {manifest_path}")
    else:
        click.echo(
            f"⚠️  '{_chosen_name}' also failed. "
            "Run 'sfutils-pat setup-connection -c <name>' to set the connection manually."
        )


@cli.command(name="validate-manifest")
@click.option(
    "--fix",
    is_flag=True,
    default=False,
    help=(
        "Fill in any missing sections with sensible defaults before validating. "
        "Useful for repairing manifests from older projects."
    ),
)
@click.pass_context
def validate_manifest_command(ctx: click.Context, fix: bool) -> None:
    """Validate manifest.toml structure and report issues.

    Checks that all required sections and fields are present and well-formed.
    Exits with code 1 if validation fails so it can gate CI/CD workflows.

    Use --fix to automatically fill in any missing sections with defaults
    (equivalent to running 'sfutils-pat setup-connection' for structural gaps,
    without touching connection credentials).

    \b
    Example:
        sfutils-pat validate-manifest
        sfutils-pat validate-manifest --fix   # repair then validate
    """
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))

    if not manifest_path.exists():
        if fix:
            # Create a fresh manifest skeleton from scratch.
            data: dict = {}
            ensure_manifest_defaults(data, manifest_path)
            save_manifest(manifest_path, data)
            click.echo(f"✓ Created {manifest_path} with default structure")
        else:
            raise click.ClickException(
                f"manifest.toml not found at {manifest_path}. "
                "Run 'sfutils-pat setup-connection' to initialise, "
                "or use --fix to create a skeleton."
            )
    else:
        data = load_manifest(manifest_path)

    if fix:
        before = validate_manifest(data)
        ensure_manifest_defaults(data, manifest_path)
        save_manifest(manifest_path, data)
        after = validate_manifest(data)
        fixed_count = len(before) - len(after)
        if fixed_count > 0:
            click.echo(f"✓ Repaired {fixed_count} issue(s) in {manifest_path}")
        # Re-read the saved file to validate final state.
        data = load_manifest(manifest_path)

    issues = validate_manifest(data)

    if issues:
        click.echo(f"✗ manifest.toml validation failed ({len(issues)} issue(s)):", err=True)
        for issue in issues:
            click.echo(f"  ✗ {issue}", err=True)
        if not fix:
            click.echo(
                "  Tip: run 'sfutils-pat validate-manifest --fix' to repair structural gaps",
                err=True,
            )
        raise click.ClickException("Fix the issues above and re-run.")

    pat_count = len(data.get("pat", {}))
    click.echo(
        f"✓ manifest.toml is valid  "
        f"(connection: {data.get('snowflake', {}).get('connection', '(not set)')}, "
        f"PATs: {pat_count})"
    )


@cli.command(name="setup-connection")
@click.option(
    "--connection",
    "-c",
    required=True,
    help="Snowflake connection name to use for this project (from snow connection list)",
)
@click.option(
    "--admin-role",
    default=None,
    help="Admin role to cache in manifest.toml (default: ACCOUNTADMIN)",
)
@click.pass_context
def setup_connection_command(
    ctx: click.Context,
    connection: str,
    admin_role: str | None,
) -> None:
    """Persist a Snowflake connection to manifest.toml and cache its metadata.

    Run this once per project after picking a connection from 'snow connection list'.
    Writes [snowflake].connection + account/user/account_url to manifest.toml so
    manifest.toml becomes the source of truth for this project.

    \b
    Example:
        snow connection list              # see available connections
        sfutils-pat setup-connection -c local-oauth
    """
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))

    # Switch the active connection for this invocation.
    set_connection(connection)

    # Fetch connection metadata.
    click.echo(f"Testing connection '{connection}'...")
    account, host = get_snowflake_connection_metadata()

    # Load + ensure defaults + write connection block.
    data = load_manifest(manifest_path)
    ensure_manifest_defaults(data, manifest_path)

    sf = data["snowflake"]
    sf["connection"] = connection
    sf["account"] = account
    sf["account_url"] = f"https://{host}" if host else ""
    if admin_role:
        sf["admin_role"] = admin_role

    # Derive the Snowflake login user from the connection test output.
    # get_snowflake_connection_metadata returns (account, host); get full
    # output for user via the same snow connection test call.
    try:
        _res = subprocess.run(
            ["snow", "connection", "test", "-c", connection, "--format", "json"],
            capture_output=True, text=True, check=False,
        )
        if _res.returncode == 0 and _res.stdout.strip():
            _data = json.loads(_res.stdout)
            _user = _data.get("User") or _data.get("user") or ""
            if _user:
                sf["user"] = str(_user).strip()
    except Exception:
        pass  # non-fatal — user field just stays empty

    save_manifest(manifest_path, data)

    click.echo(f"✓ Connection '{connection}' saved to {manifest_path}")
    click.echo(f"  account:     {account}")
    click.echo(f"  account_url: {sf.get('account_url', '')}")
    if sf.get("user"):
        click.echo(f"  user:        {sf['user']}")


if __name__ == "__main__":
    cli()

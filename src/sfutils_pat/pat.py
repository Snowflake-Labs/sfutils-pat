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

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import click
from dotenv import load_dotenv

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
    set_masking,
    set_snow_cli_options,
)
from sfutils_pat._verify_pat_connector import verify_pat_with_connector

# Older layouts stored the raw PAT in .env; strip when rewriting .env (not used for auth).
_LEGACY_DOTENV_RAW_PAT_KEY = "SA_PAT"


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
    )
    if result.returncode != 0:
        raise click.ClickException(f"Failed to test connection: {result.stderr}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise click.ClickException(
            f"Invalid JSON from connection test: {e}\nOutput: {result.stdout[:500]}"
        )

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
    )
    if result.returncode != 0:
        raise click.ClickException(f"Failed to test connection: {result.stderr}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise click.ClickException(
            f"Invalid JSON from connection test: {e}\nOutput: {result.stdout[:500]}"
        )

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
    comment = format_comment(comment_prefix)
    return f"""USE ROLE {admin_role};
-- Create PAT role if not exists
CREATE ROLE IF NOT EXISTS {pat_role}
    COMMENT = '{comment}';
-- Create service user
CREATE USER IF NOT EXISTS {user}
    TYPE = SERVICE
    COMMENT = '{comment}';
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
    COMMENT = '{comment}';

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
    result = run_snow_sql(f"SHOW USER PATS FOR USER {user}", role=admin_role)

    if not result:
        return None

    for pat in result:
        if pat.get("name", "").lower() == pat_name.lower():
            return pat.get("name")

    return None


def get_pat_sql(user: str, pat_role: str, pat_name: str) -> str:
    """Generate SQL for creating PAT."""
    return f"ALTER USER IF EXISTS {user} ADD PAT {pat_name} ROLE_RESTRICTION = {pat_role};"


def create_or_rotate_pat(
    user: str, pat_role: str, pat_name: str, rotate: bool = False, admin_role: str = "accountadmin"
) -> str:
    """Create a new PAT or rotate an existing one (idempotent for rotate=True)."""
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
    click.echo(f"Removing PAT '{pat_name}' from user {user}...")

    existing = get_existing_pat(user, pat_name, admin_role=admin_role)
    if not existing:
        click.echo(f"⚠ PAT '{pat_name}' not found for user {user}")
        return

    run_snow_sql(f"ALTER USER IF EXISTS {user} REMOVE PAT {pat_name}", role=admin_role)
    click.echo(f"✓ Removed PAT '{pat_name}'")


def remove_service_user(user: str, admin_role: str = "accountadmin") -> None:
    """Drop the service user (idempotent)."""
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


# Auto-load .env from current working directory so callers
# don't need ``set -a && source .env && set +a`` before invoking.
load_dotenv()


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
@click.pass_context
def cli(ctx: click.Context, verbose: bool, debug: bool, comment: str | None) -> None:
    """
    Snowflake PAT Manager - Manage service users with programmatic access tokens.

    \b
    Commands:
        create   - Create/rotate PAT for service user
        rotate   - Rotate existing PAT (keep policies)
        verify   - Test PAT connection (PAT from keyring only)
        show-pat - Print PAT from keyring to stdout (insecure)
        remove   - Remove PAT and associated objects
    """
    set_snow_cli_options(verbose=verbose, debug=debug)
    ctx.ensure_object(dict)
    ctx.obj["comment"] = comment

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command(name="create")
@click.option("--user", "-u", envvar="SA_USER", required=True, help="Service account user name")
@click.option("--role", "-r", envvar="SA_ROLE", required=True, help="Role restriction for the PAT")
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
    user: str,
    role: str,
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
    5. Store PAT in OS keyring; update .env with SA_USER and SA_ROLE only
    6. Verify connection using PAT loaded from keyring

    \b
    Examples:
        # Basic usage - local IP only (most secure)
        pat.py create --user my_sa --role demo_role --db my_db

        # Skip network (created by sf-utils-networks skill)
        pat.py create --user my_sa --role demo_role --db my_db --skip-network

        # Allow GitHub Actions (Snowflake-managed network rule on the policy)
        pat.py create --user ci_sa --role ci_role --db my_db --allow-gh
    """
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
            click.echo(f"CIDRs:    {len(cidrs)} custom rule entr{'y' if len(cidrs) == 1 else 'ies'}")
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

    if output == "text" and not yes:
        if not click.confirm("\nProceed with resource creation?", default=True):
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

    update_env_non_secrets(env_path, user, role)
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
    click.echo("  PAT stored in OS keyring (not written to .env)")
    click.echo("=" * 50)


@cli.command(name="remove")
@click.option("--user", "-u", envvar="SA_USER", required=True, help="Service account user name")
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
def remove_command(
    user: str,
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
    legacy raw-PAT lines from .env (no confirmation).

    \b
    Steps:
    1. Remove PAT
    2. Remove network policy and rule (unless --pat-only)
    3. Remove authentication policy (unless --pat-only)
    4. Drop service user (if --drop-user)
    5. Strip legacy PAT lines from .env (SA_USER / SA_ROLE unchanged)
    """
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

    # Step 5: non-secret cleanup only — no confirmation (legacy raw-PAT lines in .env).
    click.echo("─" * 40)
    click.echo("Step 5: Strip legacy PAT lines from .env")
    click.echo("─" * 40)
    click.echo(f"  File: {env_path} (SA_USER / SA_ROLE are not removed)")
    clear_env(env_path=env_path)
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
def rotate_command(
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

    if not yes:
        if not click.confirm(
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


if __name__ == "__main__":
    cli()

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
from pathlib import Path

import click
from dotenv import load_dotenv
from snow_utils_pat._network_helpers import (
    assign_network_policy_to_user,
    cleanup_network_for_user,
    get_setup_network_for_user_sql,
    setup_network_for_user,
)
from snow_utils_pat._presets import collect_ipv4_cidrs
from snow_utils_pat._snow import (
    get_snow_cli_options,
    run_snow_sql,
    run_snow_sql_stdin,
    set_masking,
    set_snow_cli_options,
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


def normalize_identifier(name: str, style: str = "snowflake") -> str:
    """Normalize name for SQL or DNS compliance.

    Args:
        name: Raw input (e.g., "My Cool Project!")
        style: "snowflake" (UPPER_SNAKE) or "aws" (lower-kebab)

    Returns:
        Normalized identifier safe for SQL or AWS DNS
    """
    clean = re.sub(r"[^a-zA-Z0-9\\s\\-_]", "", name)
    clean = re.sub(r"\\s+", "_" if style == "snowflake" else "-", clean)
    clean = re.sub(r"[-_]+", "_" if style == "snowflake" else "-", clean)
    clean = clean.strip("-_")

    if style == "snowflake":
        return clean.upper()
    else:
        return clean.lower()

    account = data.get("Account")
    if not account:
        raise click.ClickException(
            f"Account not found in connection test response: {list(data.keys())}"
        )
    return account


def infer_comment_prefix(user: str) -> str:
    """Infer comment prefix from user name by stripping common suffixes."""
    upper_user = normalize_identifier(user, "snowflake")
    for suffix in ("_RUNNER", "_SA", "_SERVICE", "_USER"):
        if upper_user.endswith(suffix):
            return upper_user[: -len(suffix)]
    return upper_user


def format_comment(comment_prefix: str, suffix: str = "") -> str:
    """Format comment as 'Used by USER - PROJECT app - managed by snow-utils-pat'.

    Parses comment_prefix (e.g., KAMESHS_PAT_DEMO) into user + project parts.
    If no underscore found, uses the whole prefix as project name.
    Avoids possessives ('s) to prevent SQL quoting issues.
    """
    normalized = normalize_identifier(comment_prefix, "snowflake")
    parts = normalized.split("_", 1)
    if len(parts) == 2:
        user_part, project_part = parts
        return f"Used by {user_part} - {project_part} app{suffix} - managed by snow-utils-pat"
    return f"Used by {normalized} app{suffix} - managed by snow-utils-pat"


def get_service_user_sql(
    user: str, pat_role: str, comment_prefix: str, admin_role: str = "accountadmin"
) -> str:
    """Generate SQL for creating service user and role (idempotent)."""
    comment = format_comment(comment_prefix)
    return f"""USE ROLE {admin_role};
-- Create PAT role if not exists
CREATE ROLE IF NOT EXISTS {pat_role}
    COMMENT = '{comment}';
GRANT ROLE {pat_role} TO ROLE SYSADMIN;
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
    sql = get_service_user_sql(user, pat_role, comment_prefix, admin_role)
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


def update_env(env_path: Path, user: str, password: str, pat_role: str) -> None:
    """Update .env file with the new SA_PAT, SA_USER, and SA_ROLE."""
    if not env_path.exists():
        click.echo(f"⚠ {env_path} not found, skipping update")
        return

    content = env_path.read_text()

    backup_path = env_path.with_suffix(".env.bak")
    shutil.copy(env_path, backup_path)

    pat_pattern = r"^SA_PAT=.*$"
    pat_replacement = f"SA_PAT={_escape_env_value(password)}"

    if re.search(pat_pattern, content, re.MULTILINE):
        new_content = re.sub(pat_pattern, pat_replacement, content, flags=re.MULTILINE)
    else:
        new_content = content.rstrip() + f"\n{pat_replacement}\n"

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
    click.echo(f"✓ Updated {env_path} with new SA_PAT, SA_USER, and SA_ROLE")


def clear_env(env_path: Path) -> None:
    """Clear PAT credentials from .env file."""
    if not env_path.exists():
        click.echo(f"⚠ {env_path} not found, skipping")
        return

    content = env_path.read_text()

    backup_path = env_path.with_suffix(".env.bak")
    shutil.copy(env_path, backup_path)
    click.echo(f"✓ Created backup: {backup_path}")

    pat_pattern = r"^SA_PAT=.*$"
    new_content = re.sub(pat_pattern, 'SA_PAT=""', content, flags=re.MULTILINE)

    env_path.write_text(new_content)
    click.echo(f"✓ Cleared SA_PAT in {env_path}")


def verify_connection(user: str, password: str, pat_role: str) -> None:
    """Verify the PAT connection works."""
    click.echo("Verifying connection with PAT...")

    account = get_snowflake_account()

    cmd = [
        "snow",
        "sql",
        *get_snow_cli_options().get_flags(),
        "-x",
        "--user",
        user,
        "--account",
        account,
        "--role",
        pat_role,
        "-q",
        "SELECT current_timestamp()",
    ]

    if get_snow_cli_options().debug:
        click.echo(f"[DEBUG] Running: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        env={**os.environ, "SNOWFLAKE_PASSWORD": password},
        capture_output=True,
        text=True,
    )

    if get_snow_cli_options().debug and result.stderr:
        click.echo(f"[DEBUG] stderr: {result.stderr}")

    if result.returncode != 0:
        raise click.ClickException(f"Connection verification failed: {result.stderr}")

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
    envvar="SNOW_UTILS_COMMENT",
    default=None,
    help="Comment prefix for SQL resources (inferred from SA_USER if not provided)",
)
@click.pass_context
def cli(ctx: click.Context, verbose: bool, debug: bool, comment: str | None) -> None:
    """
    Snowflake PAT Manager - Manage service users with programmatic access tokens.

    \b
    Commands:
        create  - Create/rotate PAT for service user
        rotate  - Rotate existing PAT (keep policies)
        verify  - Test PAT connection
        remove  - Remove PAT and associated objects
    """
    set_snow_cli_options(verbose=verbose, debug=debug)
    ctx.ensure_object(dict)
    ctx.obj["comment"] = comment

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command(name="create")
@click.option("--user", "-u", envvar="SA_USER", required=True, help="Service account user name")
@click.option("--role", "-r", envvar="SA_ROLE", required=True, help="Role restriction for the PAT")
@click.option("--db", "-d", envvar="SNOW_UTILS_DB", required=True, help="Database for PAT objects")
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
@click.option("--allow-gh", is_flag=True, default=False, help="Include GitHub Actions IPs")
@click.option("--allow-google", is_flag=True, default=False, help="Include Google IPs")
@click.option("--extra-cidrs", multiple=True, help="Additional CIDRs (can be repeated)")
@click.option(
    "--default-expiry-days",
    default=15,
    type=int,
    help="Default PAT expiry days (Snowflake default: 15)",
)
@click.option(
    "--max-expiry-days",
    default=365,
    type=int,
    help="Maximum PAT expiry days (Snowflake default: 365)",
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
    help="Skip network rule/policy creation (use when delegating to snow-utils-networks skill)",
)
@click.option(
    "--dot-env-file",
    type=click.Path(path_type=Path),
    default=None,
    help="Write SA_PAT directly to this .env file (avoids token leaking in shell history)",
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
    yes: bool,
) -> None:
    """
    Create or rotate a PAT for a service user.

    Network policy is REQUIRED for PAT security (Snowflake best practice).
    Use --skip-network if network resources were created by snow-utils-networks skill.

    \b
    Steps:
    1. Create service user (if not exists)
    2. Create network rule and policy (unless --skip-network)
    3. Create authentication policy
    4. Create or rotate PAT
    5. Update .env file
    6. Verify connection

    \b
    Examples:
        # Basic usage - local IP only (most secure)
        pat.py create --user my_sa --role demo_role --db my_db

        # Skip network (created by snow-utils-networks skill)
        pat.py create --user my_sa --role demo_role --db my_db --skip-network

        # Include GitHub Actions IPs for CI/CD
        pat.py create --user ci_sa --role ci_role --db my_db --allow-gh
    """
    if not pat_name:
        pat_name = f"{user}_pat".upper()

    cidrs: list[str] = []
    if not skip_network:
        cidrs = collect_ipv4_cidrs(
            with_local=allow_local,
            with_gh=allow_gh,
            with_google=allow_google,
            extra_cidrs=list(extra_cidrs) if extra_cidrs else None,
        )
        if not cidrs:
            raise click.ClickException(
                "Network policy required for PAT security. "
                "Use --allow-local (default), --allow-gh, --allow-google, or --extra-cidrs"
            )

    comment_prefix = ctx.obj.get("comment") or infer_comment_prefix(user)

    def build_result(status: str, token: str | None = None) -> dict:
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
        if token:
            result["token"] = token
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
            click.echo(f"CIDRs:    {len(cidrs)} entries")
        else:
            click.echo("Network:  (skipped - delegated to snow-utils-networks)")
        click.echo()

    if dry_run:
        set_masking(False)
        click.echo("SQL that would be executed:")
        click.echo("─" * 60)
        click.echo("-- Step 1: Create service user")
        click.echo(get_service_user_sql(user, role, comment_prefix, admin_role))
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
                )
            )
            click.echo()
            click.echo("-- Step 3: Create authentication policy")
        else:
            click.echo("-- Step 2: (Network skipped - use snow-utils-networks skill)")
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
        click.echo(f"Setting up network rule and policy ({len(cidrs)} CIDRs)...")
        rule_fqn, policy_name = setup_network_for_user(
            user=user,
            db=db,
            cidrs=cidrs,
            force=force,
            comment_prefix=comment_prefix,
            admin_role=admin_role,
        )
        click.echo(f"✓ Network rule: {rule_fqn}")
        click.echo(f"✓ Network policy: {policy_name}")
        assign_network_policy_to_user(user, policy_name, admin_role=admin_role)
        click.echo(f"✓ Assigned network policy to user {user}")
    else:
        click.echo("Network setup skipped (delegated to snow-utils-networks skill)")

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

    # When --dot-env-file is provided, write SA_PAT directly to that file
    # so the raw token never appears in shell command text (security).
    target_env = dot_env_file if dot_env_file else env_path

    if output == "text":
        update_env(env_path=target_env, user=user, password=password, pat_role=role)

    if not skip_verify and output == "text":
        verify_connection(user=user, password=password, pat_role=role)

    if output == "json":
        result = build_result("success", password)
        result["cidrs"] = cidrs
        result["env_file"] = str(target_env)
        # When --dot-env-file is used, redact the token from JSON output
        if dot_env_file:
            update_env(env_path=dot_env_file, user=user, password=password, pat_role=role)
            result["pat"] = "***REDACTED***"
            result["pat_written_to"] = str(dot_env_file)
        click.echo(json.dumps(result, indent=2))
        return

    click.echo()
    click.echo("=" * 50)
    click.echo("✓ PAT setup completed successfully!")
    if dot_env_file:
        click.echo(f"  SA_PAT written to {dot_env_file} (token NOT shown in output)")
    click.echo("=" * 50)


@cli.command(name="remove")
@click.option("--user", "-u", envvar="SA_USER", required=True, help="Service account user name")
@click.option("--db", "-d", envvar="SNOW_UTILS_DB", required=True, help="Database for PAT objects")
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
@click.confirmation_option(prompt="Remove PAT and associated objects?")
def remove_command(
    user: str,
    db: str,
    pat_name: str | None,
    drop_user: bool,
    pat_only: bool,
    admin_role: str,
    env_path: Path,
) -> None:
    """
    Remove PAT and associated objects for a service user.

    \b
    Steps:
    1. Remove PAT
    2. Remove network policy and rule (unless --pat-only)
    3. Remove authentication policy (unless --pat-only)
    4. Drop service user (if --drop-user)
    5. Clear .env credentials
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

    click.echo("─" * 40)
    click.echo("Step 1: Remove PAT")
    click.echo("─" * 40)
    remove_pat(user=user, pat_name=pat_name, admin_role=admin_role)
    click.echo()

    if not pat_only:
        click.echo("─" * 40)
        click.echo("Step 2: Remove Network Policy")
        click.echo("─" * 40)
        cleanup_network_for_user(user=user, db=db, admin_role=admin_role)
        click.echo("✓ Network policy and rule removed")
        click.echo()

        click.echo("─" * 40)
        click.echo("Step 3: Remove Authentication Policy")
        click.echo("─" * 40)
        remove_auth_policy(user=user, db=db, admin_role=admin_role)
        click.echo()

    if drop_user:
        click.echo("─" * 40)
        click.echo("Step 4: Drop Service User")
        click.echo("─" * 40)
        remove_service_user(user=user, admin_role=admin_role)
        click.echo()

    click.echo("─" * 40)
    click.echo("Step 5: Clear .env Credentials")
    click.echo("─" * 40)
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
def rotate_command(
    user: str,
    role: str,
    pat_name: str | None,
    admin_role: str,
    env_path: Path,
    skip_verify: bool,
    output: str,
) -> None:
    """
    Rotate an existing PAT for a service user.

    This regenerates the PAT token while keeping all policies intact.
    The new token will be saved to the .env file.

    \b
    Examples:
        # Rotate PAT with defaults
        pat.py rotate --user my_sa --role demo_role

        # Rotate and skip verification
        pat.py rotate --user my_sa --role demo_role --skip-verify
    """
    if not pat_name:
        pat_name = f"{user}_pat".upper()

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

    if output == "text":
        update_env(env_path=env_path, user=user, password=password, pat_role=role)

    if not skip_verify:
        verify_connection(user=user, password=password, pat_role=role)

    if output == "json":
        result = {
            "status": "rotated",
            "user": user,
            "pat_name": pat_name,
            "pat_role": role,
            "token": password,
        }
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo()
        click.echo("=" * 50)
        click.echo("✓ PAT rotated successfully!")
        click.echo("=" * 50)


@cli.command(name="verify")
@click.option("--user", "-u", required=True, envvar="SA_USER", help="Service account user name")
@click.option("--role", "-r", required=True, envvar="SA_ROLE", help="Role for the PAT")
@click.option("--password", "-p", envvar="SA_PAT", help="PAT token (or use SA_PAT env var)")
@click.option(
    "--env-path",
    type=click.Path(path_type=Path),
    default=Path(".env"),
    help=".env file to read token from",
)
def verify_command(
    user: str,
    role: str,
    password: str | None,
    env_path: Path,
) -> None:
    """
    Verify PAT connection works correctly.

    Tests the PAT by connecting to Snowflake and running a simple query.
    The token can be provided via --password, SA_PAT env var, or read from .env file.

    \b
    Examples:
        # Verify using SA_PAT env var
        pat.py verify --user my_sa --role demo_role

        # Verify with explicit token
        pat.py verify --user my_sa --role demo_role --password "token..."

        # Verify reading from .env
        pat.py verify --user my_sa --role demo_role --env-path .env
    """
    if not password:
        if env_path.exists():
            content = env_path.read_text()
            import re

            match = re.search(
                r'^SA_PAT\s*=\s*["\']?([^"\'#\n]+)["\']?', content, re.MULTILINE
            )
            if match:
                password = match.group(1).strip()
                click.echo(f"Using token from {env_path}")

    if not password:
        raise click.ClickException(
            "No PAT token provided. Use --password, SA_PAT env var, or ensure .env contains SA_PAT"
        )

    click.echo("=" * 50)
    click.echo("Snowflake PAT Manager - Verify")
    click.echo("=" * 50)
    click.echo(f"User: {user}")
    click.echo(f"Role: {role}")
    click.echo()

    verify_connection(user=user, password=password, pat_role=role)

    click.echo()
    click.echo("=" * 50)
    click.echo("✓ PAT verification successful!")
    click.echo("=" * 50)


if __name__ == "__main__":
    cli()

#!/usr/bin/env python3
# Copyright 2026 Snowflake Inc.
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
"""Pre-flight check for sfutils shared infrastructure (database + schemas).

Checks whether the SF_UTILS_DB database exists (via Snowflake CLI). Does not
validate SA_ROLE or other skill-specific objects.
"""

import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import click
from sfutils_pat._toml_manifest import load_manifest, save_manifest

DEFAULT_DB = "SF_UTILS"


def resolved_sf_utils_db(*, database: str | None, default_db: str) -> str:
    """Resolve database name: CLI arg, then manifest, then env vars, then default."""
    return (
        database
        or _manifest_sf_utils_db()          # TOML-first (written by _update_manifest_prereqs)
        or os.environ.get("SF_UTILS_DB")    # legacy env fallback
        or os.environ.get("SNOW_UTILS_DB")  # legacy env fallback
        or default_db
    )


def resolved_sa_admin_role(*, admin_role: str | None) -> str:
    """Resolve admin role: --admin-role / SA_ADMIN_ROLE, then ACCOUNTADMIN."""
    for candidate in (admin_role, os.environ.get("SA_ADMIN_ROLE")):
        if candidate and str(candidate).strip():
            return str(candidate).strip()
    return "ACCOUNTADMIN"


def require_snow_cli() -> None:
    """Exit 2 if `snow` is not on PATH."""
    if not shutil.which("snow"):
        click.echo(
            click.style(
                "snow CLI not found on PATH. Install snowflake-cli (e.g. "
                "pip install 'snowflake-cli>=3.16.0') or run from a project venv: "
                "uv run check-setup",
                fg="red",
            )
        )
        sys.exit(2)


def _manifest_connection(manifest_path: str = ".sfutils/manifest.toml") -> str | None:
    """Read [snowflake].connection from manifest.toml.  Returns None if not set."""
    p = Path(manifest_path)
    if not p.exists():
        return None
    try:
        with p.open("rb") as fh:
            data = tomllib.load(fh)
        return data.get("snowflake", {}).get("connection") or None
    except Exception:
        return None


def _manifest_user(manifest_path: str = ".sfutils/manifest.toml") -> str | None:
    """Read [snowflake].user from manifest.toml.  Returns None if not set."""
    p = Path(manifest_path)
    if not p.exists():
        return None
    try:
        with p.open("rb") as fh:
            data = tomllib.load(fh)
        return data.get("snowflake", {}).get("user") or None
    except Exception:
        return None


def _manifest_sf_utils_db(manifest_path: str = ".sfutils/manifest.toml") -> str | None:
    """Read [snowflake].sf_utils_db from manifest.toml.  Returns None if not set."""
    p = Path(manifest_path)
    if not p.exists():
        return None
    try:
        with p.open("rb") as fh:
            data = tomllib.load(fh)
        return data.get("snowflake", {}).get("sf_utils_db") or None
    except Exception:
        return None


def run_sql(query: str, connection: str | None = None) -> list | None:
    """Execute SQL and return parsed JSON result.

    Uses *connection* if provided, otherwise falls back to the manifest
    connection, then the SNOWFLAKE_DEFAULT_CONNECTION_NAME env var (snow CLI
    default), keeping behaviour consistent with the rest of sfutils-pat.
    """
    conn = connection or _manifest_connection() or os.environ.get(
        "SNOWFLAKE_DEFAULT_CONNECTION_NAME"
    )
    cmd = ["snow", "sql", "--query", query, "--format", "json"]
    if conn:
        cmd.extend(["-c", conn])

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None

    if result.stdout.strip():
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
    return None


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


def check_database_exists(db_name: str) -> bool:
    """Check if a database exists."""
    _assert_safe_identifier(db_name, "db_name")
    try:
        result = run_sql(f"SHOW DATABASES LIKE '{_sql_str(db_name)}'")
        return result is not None and len(result) > 0
    except Exception:
        return False


def do_run_setup(db_name: str, script_dir: Path, admin_role: str) -> bool:
    """Run the setup script using admin_role for snow CLI and templating env."""
    setup_sql = script_dir / "sfutils-setup.sql"
    if not setup_sql.exists():
        click.echo(click.style(f"Setup script not found: {setup_sql}", fg="red"))
        return False

    click.echo(f"\nRunning setup with role {admin_role}...")
    click.echo(f"  SF_UTILS_DB: {db_name}")
    click.echo()

    env = os.environ.copy()
    env["SF_UTILS_DB"] = db_name
    env["SA_ADMIN_ROLE"] = admin_role

    cmd = [
        "snow",
        "sql",
        "-f",
        str(setup_sql),
        "--enable-templating",
        "ALL",
        "--role",
        admin_role,
    ]

    result = subprocess.run(cmd, env=env, capture_output=False, check=False)

    if result.returncode == 0:
        click.echo(click.style("\n✓ Setup complete!", fg="green"))
        return True
    else:
        click.echo(click.style("\n✗ Setup failed", fg="red"))
        return False


def _fetch_connection_metadata(connection: str | None) -> dict:
    """Run snow connection test and return account/user/account_url as a dict.

    Returns an empty dict if the test fails or snow CLI is unavailable.
    Best-effort — callers should not crash on failure.
    """
    cmd = ["snow", "connection", "test", "--format", "json"]
    if connection:
        cmd.extend(["-c", connection])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        data = json.loads(result.stdout)
        account = data.get("Account") or data.get("account") or ""
        host = (
            data.get("Host") or data.get("host")
            or data.get("SnowflakeHost") or data.get("snowflake_host")
            or ""
        )
        user = data.get("User") or data.get("user") or ""
        return {
            "account": str(account).strip(),
            "user": str(user).strip(),
            "account_url": f"https://{host}".strip() if host else "",
        }
    except Exception:
        return {}


def _update_manifest_prereqs(
    sf_utils_db: str,
    manifest_path: Path = Path(".sfutils/manifest.toml"),
    connection: str | None = None,
    admin_role: str | None = None,
) -> None:
    """Write sf_utils_db, connection metadata and tools_verified into manifest.toml.

    Best-effort — does not raise if manifest cannot be written (e.g. read-only fs).
    """
    try:
        data = load_manifest(manifest_path)
        if "snowflake" not in data:
            data["snowflake"] = {}
        data["snowflake"]["sf_utils_db"] = sf_utils_db
        if connection:
            data["snowflake"]["connection"] = connection
        if admin_role:
            data["snowflake"]["admin_role"] = admin_role

        # Cache account/user/account_url from the active connection.
        meta = _fetch_connection_metadata(connection)
        if meta.get("account"):
            data["snowflake"]["account"] = meta["account"]
        if meta.get("user"):
            data["snowflake"]["user"] = meta["user"]
        if meta.get("account_url"):
            data["snowflake"]["account_url"] = meta["account_url"]

        data["prereqs"] = {
            "tools_verified": datetime.date.today().isoformat(),
            "infra_ready": True,
        }
        save_manifest(manifest_path, data)
    except Exception:
        pass  # non-fatal: manifest is supplementary, not required for infra check


@click.command()
@click.option(
    "--database",
    "-d",
    help="Database name (or set SF_UTILS_DB env var; legacy SNOW_UTILS_DB accepted)",
)
@click.option("--run-setup", is_flag=True, help="Run setup if infrastructure missing")
@click.option("--suggest", is_flag=True, help="Output suggested defaults as JSON")
@click.option(
    "--admin-role",
    envvar="SA_ADMIN_ROLE",
    default=None,
    help="Admin role for setup (or set SA_ADMIN_ROLE env var; default ACCOUNTADMIN)",
)
def check(database: str | None, run_setup: bool, suggest: bool, admin_role: str | None):
    """Check if sfutils infrastructure is set up.

    Non-interactive - all values via CLI args or env vars.
    Designed to be called by Cortex Code skills.

    Exit codes:
      0 - Infrastructure ready
      1 - Infrastructure missing (setup not requested or failed)
      2 - Error during check (e.g. snow CLI missing)
    """
    script_dir = Path(__file__).resolve().parent

    require_snow_cli()

    user = (_manifest_user() or os.environ.get("SNOWFLAKE_USER", "")).upper()
    default_db = f"{user}_SF_UTILS" if user else DEFAULT_DB

    if suggest:
        db_to_check = resolved_sf_utils_db(database=database, default_db=default_db)
        db_exists = check_database_exists(db_to_check)
        click.echo(
            json.dumps(
                {
                    "user": user or None,
                    "suggested_database": default_db,
                    "database_exists": db_exists,
                    "ready": db_exists,
                }
            )
        )
        sys.exit(0)

    db_name = resolved_sf_utils_db(database=database, default_db=default_db)

    ver_result = subprocess.run(["snow", "--version"], capture_output=True, text=True, check=False)
    snow_version = ver_result.stdout.strip() if ver_result.returncode == 0 else "unknown"
    click.echo(f"Using {snow_version}")

    click.echo("sfutils infrastructure check\n")
    if user:
        click.echo(f"Detected user: {user}")
    click.echo(f"  SF_UTILS_DB: {db_name}\n")

    db_exists = check_database_exists(db_name)

    if db_exists:
        click.echo(click.style("✓ Infrastructure ready", fg="green"))
        click.echo(f"  Database: {db_name}")
        click.echo(f"  Schemas: {db_name}.NETWORKS, {db_name}.POLICIES")
        _update_manifest_prereqs(
            sf_utils_db=db_name,
            connection=os.environ.get("SNOWFLAKE_DEFAULT_CONNECTION_NAME"),
            admin_role=resolved_sa_admin_role(admin_role=admin_role),
        )
        sys.exit(0)

    click.echo(click.style("⚠ Infrastructure not ready", fg="yellow"))
    click.echo(f"  ✗ Database {db_name} does not exist")

    if not run_setup:
        click.echo("\nTo create infrastructure, re-run with --run-setup")
        sys.exit(1)

    click.echo("\nRunning setup...")
    click.echo(f"  - Database: {db_name}")
    click.echo(f"  - Schemas: {db_name}.NETWORKS, {db_name}.POLICIES")

    resolved_role = resolved_sa_admin_role(admin_role=admin_role)
    success = do_run_setup(db_name, script_dir, resolved_role)
    if success:
        _update_manifest_prereqs(
            sf_utils_db=db_name,
            connection=os.environ.get("SNOWFLAKE_DEFAULT_CONNECTION_NAME"),
            admin_role=resolved_role,
        )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    check()

"""
Network rule and policy helpers for PAT user setup.

Inlined from sfutils-networks so sfutils-pat is fully self-contained.
These functions handle creating, assigning, and cleaning up network rules
and policies that are scoped to individual service users.
"""

import re

import click

from sfutils_pat._presets import (
    SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN,
    NetworkRuleMode,
    NetworkRuleType,
    get_valid_types_for_mode,
    validate_mode_type,
)
from sfutils_pat._snow import run_snow_sql, run_snow_sql_stdin


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


def normalize_identifier(name: str, style: str = "snowflake") -> str:
    """Normalize name for SQL or DNS compliance."""
    clean = re.sub(r"[^a-zA-Z0-9\s\-_]", "", name)
    clean = re.sub(r"\s+", "_" if style == "snowflake" else "-", clean)
    clean = re.sub(r"[-_]+", "_" if style == "snowflake" else "-", clean)
    clean = clean.strip("-_")

    if style == "snowflake":
        return clean.upper()
    else:
        return clean.lower()


def get_network_rule_sql(
    name: str,
    db: str,
    schema: str,
    values: list[str],
    mode: NetworkRuleMode = NetworkRuleMode.INGRESS,
    rule_type: NetworkRuleType = NetworkRuleType.IPV4,
    comment: str = "",
    force: bool = False,
) -> str:
    """Generate SQL for creating a network rule."""
    _assert_safe_identifier(name, "name")
    _assert_safe_identifier(db, "db")
    _assert_safe_identifier(schema, "schema")
    value_list = ", ".join(f"'{_sql_str(v)}'" for v in values)
    comment_text = comment or "Created by sfutils"
    return f"""CREATE OR REPLACE NETWORK RULE {db}.{schema}.{name}
    MODE = {mode.value}
    TYPE = {rule_type.value}
    VALUE_LIST = ({value_list})
    COMMENT = '{_sql_str(comment_text)}';"""


def get_network_policy_sql(
    policy_name: str,
    rule_refs: list[str],
    comment: str = "",
    force: bool = False,
) -> str:
    """Generate SQL for creating a network policy."""
    _assert_safe_identifier(policy_name, "policy_name")
    rule_list = ", ".join(rule_refs)
    comment_text = comment or "Created by sfutils"
    return f"""CREATE NETWORK POLICY IF NOT EXISTS {policy_name}
    ALLOWED_NETWORK_RULE_LIST = ({rule_list})
    COMMENT = '{_sql_str(comment_text)}';"""


def get_policies_for_rule(
    rule_fqn: str, expected_policy_name: str, admin_role: str = "accountadmin"
) -> list[str]:
    """Check if the expected policy contains this network rule."""
    _assert_safe_identifier(expected_policy_name, "expected_policy_name")
    result = []
    try:
        desc = run_snow_sql(f"DESC NETWORK POLICY {expected_policy_name}", role=admin_role) or []
        for row in desc:
            if row.get("name") == "ALLOWED_NETWORK_RULE_LIST":
                rules_str = row.get("value", "")
                if rule_fqn.upper() in rules_str.upper():
                    result.append(expected_policy_name)
                    break
    except Exception:
        pass
    return result


def detach_rule_from_policy(policy_name: str, admin_role: str = "accountadmin") -> None:
    """Temporarily detach all rules from a policy."""
    _assert_safe_identifier(policy_name, "policy_name")
    _assert_safe_identifier(admin_role, "admin_role")
    sql = (
        f"USE ROLE {admin_role};\n"
        f"ALTER NETWORK POLICY IF EXISTS {policy_name} SET ALLOWED_NETWORK_RULE_LIST = ();"
    )
    run_snow_sql_stdin(sql)


def set_policy_allowed_rule_list(
    policy_name: str, rule_refs: list[str], admin_role: str = "accountadmin"
) -> None:
    """Set a network policy's ALLOWED_NETWORK_RULE_LIST (replaces previous list)."""
    _assert_safe_identifier(policy_name, "policy_name")
    _assert_safe_identifier(admin_role, "admin_role")
    if not rule_refs:
        detach_rule_from_policy(policy_name, admin_role=admin_role)
        return
    rule_list = ", ".join(f"'{_sql_str(r)}'" for r in rule_refs)
    sql = (
        f"USE ROLE {admin_role};\n"
        f"ALTER NETWORK POLICY IF EXISTS {policy_name}"
        f" SET ALLOWED_NETWORK_RULE_LIST = ({rule_list});"
    )
    run_snow_sql_stdin(sql)


def build_hybrid_policy_rule_refs(
    custom_rule_fqn: str | None,
    include_managed_github: bool,
) -> list[str]:
    """Build ALLOWED_NETWORK_RULE_LIST entries: optional custom rule + optional SaaS GitHub rule."""
    refs: list[str] = []
    if custom_rule_fqn:
        refs.append(custom_rule_fqn)
    if include_managed_github:
        refs.append(SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN)
    return refs


def create_network_rule(
    name: str,
    db: str,
    schema: str,
    values: list[str],
    mode: NetworkRuleMode = NetworkRuleMode.INGRESS,
    rule_type: NetworkRuleType = NetworkRuleType.IPV4,
    comment: str = "",
    dry_run: bool = False,
    force: bool = False,
    admin_role: str = "accountadmin",
    policy_rule_refs: list[str] | None = None,
) -> str:
    """Create a network rule in Snowflake. Returns fully qualified name.

    If the rule is attached to the expected user policy, it is detached before
    CREATE OR REPLACE and re-attached with ``policy_rule_refs`` when provided
    (hybrid policies with Snowflake-managed rules); otherwise only this rule.
    """
    _assert_safe_identifier(admin_role, "admin_role")
    if not validate_mode_type(mode, rule_type):
        valid = get_valid_types_for_mode(mode)
        raise click.ClickException(
            f"Invalid type '{rule_type.value}' for mode '{mode.value}'. Valid types: {valid}"
        )
    if not values:
        raise click.ClickException("Network rule VALUE_LIST cannot be empty")

    rule_fqn = f"{db}.{schema}.{name}"
    sql = get_network_rule_sql(name, db, schema, values, mode, rule_type, comment, force)

    if dry_run:
        click.echo(sql)
    else:
        expected_policy = name.replace("_NETWORK_RULE", "_NETWORK_POLICY")
        attached_policies = get_policies_for_rule(rule_fqn, expected_policy, admin_role=admin_role)

        if attached_policies:
            click.echo(f"  Detaching rule from {len(attached_policies)} policy(ies)...")
            for policy in attached_policies:
                detach_rule_from_policy(policy, admin_role=admin_role)

        setup_sql = (
            f"USE ROLE {admin_role};\n"
            f"CREATE DATABASE IF NOT EXISTS {db};\n"
            f"CREATE SCHEMA IF NOT EXISTS {db}.{schema};\n"
        )
        run_snow_sql_stdin(setup_sql + sql)

        if attached_policies:
            click.echo(f"  Re-attaching rule to {len(attached_policies)} policy(ies)...")
            restore_refs = policy_rule_refs if policy_rule_refs is not None else [rule_fqn]
            for policy in attached_policies:
                set_policy_allowed_rule_list(policy, restore_refs, admin_role=admin_role)

    return rule_fqn


def create_network_policy(
    policy_name: str,
    rule_refs: list[str],
    comment: str = "",
    dry_run: bool = False,
    force: bool = False,
    admin_role: str = "accountadmin",
) -> None:
    """Create a network policy referencing given rules."""
    _assert_safe_identifier(admin_role, "admin_role")
    sql = get_network_policy_sql(policy_name, rule_refs, comment, force)

    if dry_run:
        click.echo(sql)
    else:
        run_snow_sql_stdin(f"USE ROLE {admin_role};\n{sql}")


def delete_network_rule(name: str, db: str, schema: str, admin_role: str = "accountadmin") -> None:
    """Delete a network rule (idempotent)."""
    _assert_safe_identifier(name, "name")
    _assert_safe_identifier(db, "db")
    _assert_safe_identifier(schema, "schema")
    _assert_safe_identifier(admin_role, "admin_role")
    run_snow_sql_stdin(f"USE ROLE {admin_role};\nDROP NETWORK RULE IF EXISTS {db}.{schema}.{name}")


def delete_network_policy(policy_name: str, admin_role: str = "accountadmin") -> None:
    """Delete a network policy (idempotent)."""
    _assert_safe_identifier(policy_name, "policy_name")
    _assert_safe_identifier(admin_role, "admin_role")
    run_snow_sql_stdin(f"USE ROLE {admin_role};\nDROP NETWORK POLICY IF EXISTS {policy_name}")


def get_setup_network_for_user_sql(
    user: str,
    db: str,
    cidrs: list[str],
    schema: str = "NETWORKS",
    force: bool = False,
    comment_prefix: str | None = None,
    admin_role: str = "accountadmin",
    allow_managed_github: bool = False,
) -> str:
    """Generate SQL for creating network rule and policy for a user."""
    _assert_safe_identifier(admin_role, "admin_role")
    rule_name = f"{user}_NETWORK_RULE".upper()
    policy_name = f"{user}_NETWORK_POLICY".upper()
    rule_fqn = f"{db.upper()}.{schema.upper()}.{rule_name}"
    user_part = normalize_identifier(comment_prefix or user, "snowflake")
    project_part = normalize_identifier(db, "snowflake")

    policy_refs = build_hybrid_policy_rule_refs(
        custom_rule_fqn=rule_fqn if cidrs else None,
        include_managed_github=allow_managed_github,
    )
    if not policy_refs:
        raise click.ClickException(
            "Network policy requires at least one allowed rule (custom CIDRs or --allow-gh)."
        )

    chunks: list[str] = [f"USE ROLE {admin_role};"]
    if cidrs:
        rule_sql = get_network_rule_sql(
            name=rule_name,
            db=db.upper(),
            schema=schema.upper(),
            values=cidrs,
            mode=NetworkRuleMode.INGRESS,
            rule_type=NetworkRuleType.IPV4,
            comment=f"Used by {user_part} - {project_part} app - managed by sf-utils-networks",
            force=force,
        )
        chunks.append(rule_sql)

    policy_sql = get_network_policy_sql(
        policy_name=policy_name,
        rule_refs=policy_refs,
        comment=f"Used by {user_part} - {project_part} app - managed by sf-utils-networks",
        force=force,
    )
    chunks.append(policy_sql)

    return "\n\n".join(chunks)


def setup_network_for_user(
    user: str,
    db: str,
    cidrs: list[str],
    schema: str = "NETWORKS",
    dry_run: bool = False,
    force: bool = False,
    comment_prefix: str | None = None,
    admin_role: str = "accountadmin",
    allow_managed_github: bool = False,
) -> tuple[str | None, str]:
    """Create network rule and policy for a user (idempotent).

    When ``allow_managed_github`` is True, the policy also references
    ``SNOWFLAKE.NETWORK_SECURITY.GITHUB_ACTIONS``. If ``cidrs`` is empty,
    only the managed GitHub rule is referenced (no custom network rule).
    """
    rule_name = f"{user}_NETWORK_RULE".upper()
    policy_name = f"{user}_NETWORK_POLICY".upper()
    ctx = comment_prefix or user.upper()

    custom_fqn = f"{db.upper()}.{schema.upper()}.{rule_name}"
    policy_refs = build_hybrid_policy_rule_refs(
        custom_rule_fqn=custom_fqn if cidrs else None,
        include_managed_github=allow_managed_github,
    )
    if not policy_refs:
        raise click.ClickException(
            "Network policy requires at least one allowed rule "
            "(enable --allow-local, --allow-google, --extra-cidrs, and/or --allow-gh)."
        )

    rule_fqn: str | None = None
    if cidrs:
        rule_fqn = create_network_rule(
            name=rule_name,
            db=db,
            schema=schema,
            values=cidrs,
            mode=NetworkRuleMode.INGRESS,
            rule_type=NetworkRuleType.IPV4,
            comment=f"{ctx} network rule - managed by sfutils-pat",
            dry_run=dry_run,
            force=force,
            admin_role=admin_role,
            policy_rule_refs=policy_refs,
        )
        policy_refs = build_hybrid_policy_rule_refs(
            custom_rule_fqn=rule_fqn,
            include_managed_github=allow_managed_github,
        )

    create_network_policy(
        policy_name=policy_name,
        rule_refs=policy_refs,
        comment=f"{ctx} network policy - managed by sfutils-pat",
        dry_run=dry_run,
        force=force,
        admin_role=admin_role,
    )

    return rule_fqn, policy_name


def cleanup_network_for_user(
    user: str,
    db: str,
    schema: str = "NETWORKS",
    unset_from_user: bool = True,
    admin_role: str = "accountadmin",
) -> None:
    """Remove network rule and policy for a user (idempotent)."""
    _assert_safe_identifier(user, "user")
    _assert_safe_identifier(admin_role, "admin_role")
    rule_name = f"{user}_NETWORK_RULE".upper()
    policy_name = f"{user}_NETWORK_POLICY".upper()

    if unset_from_user:
        run_snow_sql_stdin(
            f"USE ROLE {admin_role};\nALTER USER IF EXISTS {user} UNSET NETWORK_POLICY;",
            check=False,
        )

    delete_network_policy(policy_name, admin_role=admin_role)
    delete_network_rule(rule_name, db.upper(), schema.upper(), admin_role=admin_role)


def assign_network_policy_to_user(
    user: str, policy_name: str, admin_role: str = "accountadmin"
) -> None:
    """Assign a network policy to a user."""
    _assert_safe_identifier(user, "user")
    _assert_safe_identifier(admin_role, "admin_role")
    run_snow_sql_stdin(
        f"USE ROLE {admin_role};\nALTER USER {user} SET NETWORK_POLICY = '{_sql_str(policy_name)}';"
    )

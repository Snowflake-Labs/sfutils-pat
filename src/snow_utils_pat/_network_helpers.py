"""
Network rule and policy helpers for PAT user setup.

Inlined from snow-utils-networks so snow-utils-pat is fully self-contained.
These functions handle creating, assigning, and cleaning up network rules
and policies that are scoped to individual service users.
"""

import re

import click

from snow_utils_pat._presets import (
    NetworkRuleMode,
    NetworkRuleType,
    validate_mode_type,
    get_valid_types_for_mode,
)
from snow_utils_pat._snow import run_snow_sql, run_snow_sql_stdin


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
    value_list = ", ".join(f"'{v}'" for v in values)
    comment_text = comment or "Created by snow-utils"
    return f"""CREATE OR REPLACE NETWORK RULE {db}.{schema}.{name}
    MODE = {mode.value}
    TYPE = {rule_type.value}
    VALUE_LIST = ({value_list})
    COMMENT = '{comment_text}';"""


def get_network_policy_sql(
    policy_name: str,
    rule_refs: list[str],
    comment: str = "",
    force: bool = False,
) -> str:
    """Generate SQL for creating a network policy."""
    rule_list = ", ".join(rule_refs)
    comment_text = comment or "Created by snow-utils"
    return f"""CREATE NETWORK POLICY IF NOT EXISTS {policy_name}
    ALLOWED_NETWORK_RULE_LIST = ({rule_list})
    COMMENT = '{comment_text}';"""


def get_policies_for_rule(
    rule_fqn: str, expected_policy_name: str, admin_role: str = "accountadmin"
) -> list[str]:
    """Check if the expected policy contains this network rule."""
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
    sql = f"USE ROLE {admin_role};\nALTER NETWORK POLICY IF EXISTS {policy_name} SET ALLOWED_NETWORK_RULE_LIST = ();"
    run_snow_sql_stdin(sql)


def reattach_rule_to_policy(
    policy_name: str, rule_fqn: str, admin_role: str = "accountadmin"
) -> None:
    """Re-attach a rule to a policy."""
    sql = f"USE ROLE {admin_role};\nALTER NETWORK POLICY IF EXISTS {policy_name} SET ALLOWED_NETWORK_RULE_LIST = ('{rule_fqn}');"
    run_snow_sql_stdin(sql)


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
) -> str:
    """Create a network rule in Snowflake. Returns fully qualified name."""
    if not validate_mode_type(mode, rule_type):
        valid = get_valid_types_for_mode(mode)
        raise click.ClickException(
            f"Invalid type '{rule_type.value}' for mode '{mode.value}'. Valid types: {valid}"
        )

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

        setup_sql = f"USE ROLE {admin_role};\nCREATE DATABASE IF NOT EXISTS {db};\nCREATE SCHEMA IF NOT EXISTS {db}.{schema};\n"
        run_snow_sql_stdin(setup_sql + sql)

        if attached_policies:
            click.echo(f"  Re-attaching rule to {len(attached_policies)} policy(ies)...")
            for policy in attached_policies:
                reattach_rule_to_policy(policy, rule_fqn, admin_role=admin_role)

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
    sql = get_network_policy_sql(policy_name, rule_refs, comment, force)

    if dry_run:
        click.echo(sql)
    else:
        run_snow_sql_stdin(f"USE ROLE {admin_role};\n{sql}")


def delete_network_rule(name: str, db: str, schema: str, admin_role: str = "accountadmin") -> None:
    """Delete a network rule (idempotent)."""
    run_snow_sql_stdin(f"USE ROLE {admin_role};\nDROP NETWORK RULE IF EXISTS {db}.{schema}.{name}")


def delete_network_policy(policy_name: str, admin_role: str = "accountadmin") -> None:
    """Delete a network policy (idempotent)."""
    run_snow_sql_stdin(f"USE ROLE {admin_role};\nDROP NETWORK POLICY IF EXISTS {policy_name}")


def get_setup_network_for_user_sql(
    user: str,
    db: str,
    cidrs: list[str],
    schema: str = "NETWORKS",
    force: bool = False,
    comment_prefix: str | None = None,
    admin_role: str = "accountadmin",
) -> str:
    """Generate SQL for creating network rule and policy for a user."""
    rule_name = f"{user}_NETWORK_RULE".upper()
    policy_name = f"{user}_NETWORK_POLICY".upper()
    rule_fqn = f"{db.upper()}.{schema.upper()}.{rule_name}"
    user_part = normalize_identifier(comment_prefix or user, "snowflake")
    project_part = normalize_identifier(db, "snowflake")

    rule_sql = get_network_rule_sql(
        name=rule_name,
        db=db.upper(),
        schema=schema.upper(),
        values=cidrs,
        mode=NetworkRuleMode.INGRESS,
        rule_type=NetworkRuleType.IPV4,
        comment=f"Used by {user_part} - {project_part} app - managed by snow-utils-networks",
        force=force,
    )

    policy_sql = get_network_policy_sql(
        policy_name=policy_name,
        rule_refs=[rule_fqn],
        comment=f"Used by {user_part} - {project_part} app - managed by snow-utils-networks",
        force=force,
    )

    return f"USE ROLE {admin_role};\n{rule_sql}\n\n{policy_sql}"


def setup_network_for_user(
    user: str,
    db: str,
    cidrs: list[str],
    schema: str = "NETWORKS",
    dry_run: bool = False,
    force: bool = False,
    comment_prefix: str | None = None,
    admin_role: str = "accountadmin",
) -> tuple[str, str]:
    """Create network rule and policy for a user (idempotent)."""
    rule_name = f"{user}_NETWORK_RULE".upper()
    policy_name = f"{user}_NETWORK_POLICY".upper()
    ctx = comment_prefix or user.upper()

    rule_fqn = create_network_rule(
        name=rule_name,
        db=db,
        schema=schema,
        values=cidrs,
        mode=NetworkRuleMode.INGRESS,
        rule_type=NetworkRuleType.IPV4,
        comment=f"{ctx} network rule - managed by snow-utils-pat",
        dry_run=dry_run,
        force=force,
        admin_role=admin_role,
    )

    create_network_policy(
        policy_name=policy_name,
        rule_refs=[rule_fqn],
        comment=f"{ctx} network policy - managed by snow-utils-pat",
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
    run_snow_sql_stdin(
        f"USE ROLE {admin_role};\nALTER USER {user} SET NETWORK_POLICY = '{policy_name}';"
    )

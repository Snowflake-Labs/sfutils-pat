# Copyright 2026 Snowflake Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import click
import pytest

from snow_utils_pat._network_helpers import (
    build_hybrid_policy_rule_refs,
    get_setup_network_for_user_sql,
)
from snow_utils_pat._presets import SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN


def test_build_hybrid_policy_rule_refs_github_only() -> None:
    assert build_hybrid_policy_rule_refs(None, True) == [SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN]


def test_build_hybrid_policy_rule_refs_custom_and_github() -> None:
    assert build_hybrid_policy_rule_refs("MY_DB.NETWORKS.MY_SA_NETWORK_RULE", True) == [
        "MY_DB.NETWORKS.MY_SA_NETWORK_RULE",
        SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN,
    ]


def test_get_setup_sql_allow_gh_hybrid_includes_managed_rule_not_empty_rule() -> None:
    sql = get_setup_network_for_user_sql(
        user="ci_sa",
        db="MY_DB",
        cidrs=["203.0.113.1/32"],
        allow_managed_github=True,
    )
    assert SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN in sql
    assert "203.0.113.1/32" in sql
    assert "MY_DB.NETWORKS.CI_SA_NETWORK_RULE" in sql.upper()
    assert "CI_SA_NETWORK_POLICY" in sql.upper()


def test_get_setup_sql_allow_gh_only_no_custom_network_rule() -> None:
    sql = get_setup_network_for_user_sql(
        user="ci_sa",
        db="MY_DB",
        cidrs=[],
        allow_managed_github=True,
    )
    assert SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN in sql
    assert "CREATE OR REPLACE NETWORK RULE" not in sql


def test_get_setup_sql_rejects_empty_policy() -> None:
    with pytest.raises(click.ClickException):
        get_setup_network_for_user_sql(
            user="u",
            db="d",
            cidrs=[],
            allow_managed_github=False,
        )

# Copyright 2026 Snowflake Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from snow_utils_pat.pat import cli


def test_remove_noninteractive_requires_yes() -> None:
    runner = CliRunner()
    stdin = MagicMock()
    stdin.isatty.return_value = False
    with patch("snow_utils_pat.pat.sys.stdin", stdin):
        result = runner.invoke(cli, ["remove", "-u", "MY_SA", "-d", "MY_DB"])
    assert result.exit_code == 1
    assert "pass --yes" in result.output


def test_remove_pat_only_yes_runs_without_prompts() -> None:
    runner = CliRunner()
    stdin = MagicMock()
    stdin.isatty.return_value = False
    with (
        patch("snow_utils_pat.pat.sys.stdin", stdin),
        patch(
            "snow_utils_pat.pat.get_snowflake_connection_metadata",
            return_value=("ACC", "host.example"),
        ),
        patch("snow_utils_pat.pat.delete_pat"),
        patch("snow_utils_pat.pat.remove_pat"),
        patch("snow_utils_pat.pat.clear_env"),
    ):
        result = runner.invoke(
            cli,
            ["remove", "-u", "my_sa", "-d", "MY_DB", "--pat-only", "--yes"],
        )
    assert result.exit_code == 0
    assert "Step 1: Remove PAT" in result.output
    assert "Step 2:" not in result.output


def test_remove_yes_lists_network_objects() -> None:
    runner = CliRunner()
    with (
        patch(
            "snow_utils_pat.pat.get_snowflake_connection_metadata",
            return_value=("ACC", "host.example"),
        ),
        patch("snow_utils_pat.pat.delete_pat"),
        patch("snow_utils_pat.pat.remove_pat"),
        patch("snow_utils_pat.pat.cleanup_network_for_user"),
        patch("snow_utils_pat.pat.remove_auth_policy"),
        patch("snow_utils_pat.pat.clear_env"),
    ):
        result = runner.invoke(
            cli,
            ["remove", "-u", "svc_user", "-d", "UTILS_DB", "--yes"],
        )
    assert result.exit_code == 0
    assert "Unset NETWORK_POLICY on user svc_user" in result.output
    assert "SVC_USER_NETWORK_POLICY" in result.output
    assert "UTILS_DB.NETWORKS.SVC_USER_NETWORK_RULE" in result.output

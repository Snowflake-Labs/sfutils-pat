# Copyright 2026 Snowflake Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from unittest.mock import MagicMock, patch

import click
import pytest

from sfutils_pat._verify_pat_connector import verify_pat_with_connector


@patch("snowflake.connector.connect")
def test_verify_pat_with_connector_uses_programmatic_token(mock_connect: MagicMock) -> None:
    mock_conn = MagicMock()
    mock_connect.return_value = mock_conn
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    verify_pat_with_connector(
        account="org-acct",
        user="u",
        role="r",
        pat_token="tok",
        host="h.example.com",
    )

    mock_connect.assert_called_once()
    kwargs = mock_connect.call_args.kwargs
    assert kwargs["authenticator"] == "PROGRAMMATIC_ACCESS_TOKEN"
    assert kwargs["token"] == "tok"
    assert kwargs["account"] == "org-acct"
    assert kwargs["user"] == "u"
    assert kwargs["role"] == "r"
    assert kwargs["host"] == "h.example.com"
    mock_cursor.execute.assert_called_once_with("SELECT CURRENT_TIMESTAMP()")
    mock_cursor.fetchone.assert_called_once()
    mock_cursor.close.assert_called_once()
    mock_conn.close.assert_called_once()


@patch("snowflake.connector.connect")
def test_verify_pat_with_connector_omits_empty_host(mock_connect: MagicMock) -> None:
    mock_connect.return_value = MagicMock()
    mock_connect.return_value.cursor.return_value = MagicMock()

    verify_pat_with_connector(
        account="a",
        user="u",
        role="r",
        pat_token="t",
        host=None,
    )
    assert "host" not in mock_connect.call_args.kwargs

    verify_pat_with_connector(
        account="a",
        user="u",
        role="r",
        pat_token="t",
        host="   ",
    )
    assert "host" not in mock_connect.call_args.kwargs


@patch("snowflake.connector.connect")
def test_verify_pat_with_connector_maps_connector_error(mock_connect: MagicMock) -> None:
    from snowflake.connector.errors import Error as SnowflakeConnectorError

    mock_connect.side_effect = SnowflakeConnectorError("nope", errno=1)

    with pytest.raises(click.ClickException, match="PAT connection verification failed"):
        verify_pat_with_connector(
            account="a",
            user="u",
            role="r",
            pat_token="t",
        )

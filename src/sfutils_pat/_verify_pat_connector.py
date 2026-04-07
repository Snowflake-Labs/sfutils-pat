# Copyright 2026 Snowflake Inc.
# SPDX-License-Identifier: Apache-2.0
"""Verify PAT auth using Snowflake Python connector (PROGRAMMATIC_ACCESS_TOKEN).

Avoids passing the PAT through ``SNOWFLAKE_PASSWORD`` to a ``snow`` subprocess.
See https://docs.snowflake.com/en/user-guide/programmatic-access-tokens.html
"""

from __future__ import annotations

import click

# Snowflake docs: PAT with Python connector uses authenticator + token parameter.
# https://docs.snowflake.com/en/developer-guide/python-connector/python-connector-connect


def verify_pat_with_connector(
    *,
    account: str,
    user: str,
    role: str,
    pat_token: str,
    host: str | None = None,
) -> None:
    """Open a short-lived connection with the PAT and run a trivial query."""
    import snowflake.connector
    from snowflake.connector.errors import Error as SnowflakeConnectorError

    connect_kwargs: dict[str, str] = {
        "account": account,
        "user": user,
        "role": role,
        "authenticator": "PROGRAMMATIC_ACCESS_TOKEN",
        "token": pat_token,
    }
    if host and str(host).strip():
        connect_kwargs["host"] = str(host).strip()

    try:
        conn = snowflake.connector.connect(**connect_kwargs)
    except SnowflakeConnectorError as e:
        msg = getattr(e, "msg", None) or str(e)
        raise click.ClickException(f"PAT connection verification failed: {msg}") from None
    except Exception as e:
        raise click.ClickException(f"PAT connection verification failed: {e}") from None

    try:
        cur = conn.cursor()
        try:
            cur.execute("SELECT CURRENT_TIMESTAMP()")
            cur.fetchone()
        finally:
            cur.close()
    finally:
        conn.close()

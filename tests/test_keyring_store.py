# Copyright 2026 Snowflake Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from unittest.mock import patch

import keyring
import pytest
from click.testing import CliRunner
from keyring.backend import KeyringBackend

from sfutils_pat._keyring_store import (
    LEGACY_DRIVER_LABEL,
    MISSING_HOST_SENTINEL,
    build_pat_credential_service,
    delete_pat,
    keyring_username,
    load_pat,
    store_pat,
)
from sfutils_pat.pat import cli


class DictKeyring(KeyringBackend):
    """Ephemeral backend for tests (no OS keychain)."""

    priority = 1

    def __init__(self) -> None:
        self._data: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self._data.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._data[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        try:
            del self._data[(service, username)]
        except KeyError as e:
            import keyring.errors

            raise keyring.errors.PasswordDeleteError("not found") from e


@pytest.fixture
def isolated_keyring():
    prev = keyring.get_keyring()
    backend = DictKeyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(prev)


def test_build_pat_credential_service_normal():
    s = build_pat_credential_service(
        "abc.snowflakecomputing.com", "myorg-myacct", "svc_user", "SVC_USER_PAT"
    )
    assert s == "ABC.SNOWFLAKECOMPUTING.COM:MYORG-MYACCT:SVC_USER:SFUTILS-PAT:SVC_USER_PAT"


def test_build_pat_credential_service_missing_host_uses_sentinel():
    s = build_pat_credential_service(None, "acct", "u", "P1")
    assert s.startswith(f"{MISSING_HOST_SENTINEL}:")
    assert ":ACCT:U:SFUTILS-PAT:P1" in s


def test_build_pat_different_accounts_differ():
    a = build_pat_credential_service("h.example.com", "acct-a", "u", "PAT1")
    b = build_pat_credential_service("h.example.com", "acct-b", "u", "PAT1")
    assert a != b


def test_roundtrip_store_load_delete(isolated_keyring):
    store_pat("host.example", "acct", "user1", "PAT_A", "secret-value")
    assert load_pat("host.example", "acct", "user1", "PAT_A") == "secret-value"
    delete_pat("host.example", "acct", "user1", "PAT_A")
    assert load_pat("host.example", "acct", "user1", "PAT_A") is None


def test_load_pat_falls_back_to_legacy_keyring_label(isolated_keyring):
    user = keyring_username("user1")
    legacy_svc = build_pat_credential_service(
        "host.example", "acct", "user1", "PAT_A", driver_label=LEGACY_DRIVER_LABEL
    )
    keyring.set_password(legacy_svc, user, "legacy-secret")
    assert load_pat("host.example", "acct", "user1", "PAT_A") == "legacy-secret"


def test_delete_pat_idempotent(isolated_keyring):
    store_pat("h", "a", "u", "P", "x")
    delete_pat("h", "a", "u", "P")
    delete_pat("h", "a", "u", "P")


def test_keyring_username_matches_connector_style(isolated_keyring):
    store_pat("h", "a", "Mixed_User", "P", "tok")
    assert load_pat("h", "a", "mixed_user", "P") == "tok"


def test_create_rejects_print_with_json():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "create",
            "--user",
            "u",
            "--role",
            "r",
            "--db",
            "d",
            "-o",
            "json",
            "--print",
            "--dry-run",
        ],
    )
    assert result.exit_code != 0
    assert "print" in result.output.lower() and "json" in result.output.lower()


@patch("sfutils_pat.pat.load_pat", return_value=None)
@patch(
    "sfutils_pat.pat.get_snowflake_connection_metadata",
    return_value=("myacct", "host.snowflakecomputing.com"),
)
def test_verify_fails_when_keyring_empty(_meta, _load):
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", "--user", "svc", "--role", "r1"])
    assert result.exit_code != 0
    assert "keyring" in result.output.lower()


@patch("sfutils_pat.pat.load_pat", return_value="PAT_SECRET_VALUE")
@patch(
    "sfutils_pat.pat.get_snowflake_connection_metadata",
    return_value=("myacct", "host.example.com"),
)
def test_show_pat_confirm_no_aborts(_meta, _load):
    runner = CliRunner()
    result = runner.invoke(cli, ["show-pat", "--user", "svc"], input="n\n")
    assert result.exit_code == 0
    assert "Aborted" in result.output
    assert "PAT_SECRET_VALUE" not in result.output


@patch("sfutils_pat.pat.load_pat", return_value="PAT_SECRET_VALUE")
@patch(
    "sfutils_pat.pat.get_snowflake_connection_metadata",
    return_value=("myacct", "host.example.com"),
)
def test_show_pat_confirm_yes_prints(_meta, _load):
    runner = CliRunner()
    result = runner.invoke(cli, ["show-pat", "--user", "svc"], input="y\n")
    assert result.exit_code == 0
    assert "PAT_SECRET_VALUE" in result.output
    assert "WARNING" in result.output


@patch("sfutils_pat.pat.load_pat", return_value="PAT_SECRET_VALUE")
@patch(
    "sfutils_pat.pat.get_snowflake_connection_metadata",
    return_value=("myacct", "host.example.com"),
)
def test_show_pat_yes_skips_confirm(_meta, _load):
    runner = CliRunner()
    result = runner.invoke(cli, ["show-pat", "--user", "svc", "--yes"])
    assert result.exit_code == 0
    assert "PAT_SECRET_VALUE" in result.output

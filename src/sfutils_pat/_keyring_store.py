# Copyright 2026 Snowflake Inc.
# SPDX-License-Identifier: Apache-2.0
"""Store PAT secrets in the OS keyring (connector-style service string)."""

from __future__ import annotations

import keyring
import keyring.errors

DRIVER_LABEL = "SFUTILS-PAT"
LEGACY_DRIVER_LABEL = "SNOW-UTILS-PAT"
MISSING_HOST_SENTINEL = "NA"


def build_pat_credential_service(
    host: str | None,
    account: str,
    sa_user: str,
    pat_name: str,
    *,
    driver_label: str | None = None,
) -> str:
    """Build keyring *service* string: HOST:ACCOUNT:USER:<DRIVER>:PAT_NAME (upper)."""
    label = driver_label or DRIVER_LABEL
    host_part = (host or "").strip().upper() or MISSING_HOST_SENTINEL
    return ":".join(
        [
            host_part,
            account.strip().upper(),
            sa_user.strip().upper(),
            label,
            pat_name.strip().upper(),
        ]
    )


def keyring_username(sa_user: str) -> str:
    """Second argument to keyring APIs (Snowflake login, uppercased)."""
    return sa_user.strip().upper()


def store_pat(
    host: str | None, account: str, sa_user: str, pat_name: str, secret: str
) -> None:
    service = build_pat_credential_service(host, account, sa_user, pat_name)
    user = keyring_username(sa_user)
    try:
        keyring.set_password(service, user, secret)
    except keyring.errors.KeyringError as e:
        raise RuntimeError(
            f"Could not store PAT in keyring (service={service!r}, user={user!r}): {e}"
        ) from e


def load_pat(host: str | None, account: str, sa_user: str, pat_name: str) -> str | None:
    user = keyring_username(sa_user)
    for drv in (DRIVER_LABEL, LEGACY_DRIVER_LABEL):
        service = build_pat_credential_service(
            host, account, sa_user, pat_name, driver_label=drv
        )
        try:
            pw = keyring.get_password(service, user)
        except keyring.errors.KeyringError:
            pw = None
        if pw:
            return pw
    return None


def delete_pat(host: str | None, account: str, sa_user: str, pat_name: str) -> None:
    user = keyring_username(sa_user)
    for drv in (DRIVER_LABEL, LEGACY_DRIVER_LABEL):
        service = build_pat_credential_service(
            host, account, sa_user, pat_name, driver_label=drv
        )
        try:
            keyring.delete_password(service, user)
        except keyring.errors.PasswordDeleteError:
            pass
        except keyring.errors.KeyringError:
            pass

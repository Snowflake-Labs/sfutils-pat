"""TOML manifest helpers for sfutils-pat multi-PAT support.

Reads .sfutils/manifest.toml using stdlib tomllib (Python 3.12, read-only).
Writes using a hand-rolled serializer scoped to the manifest schema — no
external dependencies required.

Schema:

    schema_version = "1"
    project_name   = "my-project"
    created_at     = "2026-05-02T10:00:00Z"

    [snowflake]
    connection   = "local-oauth"   # default connection for all PATs
    account      = "ABC12345"      # cached from snow connection test
    user         = "KAMESHS"
    account_url  = "https://abc12345.snowflakecomputing.com"
    sf_utils_db  = "KAMESHS_SF_UTILS"
    admin_role   = "ACCOUNTADMIN"

    [prereqs]
    tools_verified = "2026-05-02"
    infra_ready    = true

    [pat.app-runner]               # label is the TOML key, not a field
    status              = "COMPLETE"
    sa_user             = "KAMESHS_MYAPP_RUNNER"
    ...

    [pat.app-runner.resources]
    network_rule = "..."

    [pat.app-runner.cleanup]
    user = "KAMESHS_MYAPP_RUNNER"
"""

from __future__ import annotations

import contextlib
import datetime
import os
import tomllib
from pathlib import Path

MANIFEST_PATH = ".sfutils/manifest.toml"
SCHEMA_VERSION = "1"

# Ordered field lists drive the serializer — order is preserved in output.
# Note: no "label" — the label is the TOML key, not a field inside the table.
_PAT_SCALAR_KEYS = [
    "status",
    "created_at",
    "updated_at",
    "removed_at",
    "sa_user",
    "sa_role",
    "pat_name",
    "comment_prefix",
    "connection",
    "account",
    "user",
    "account_url",
    "sf_utils_db",
    "admin_role",
    "default_expiry_days",
    "max_expiry_days",
    "local_ip",
    "allow_github",
    "allow_google",
    "extra_cidrs",
]

_SNOWFLAKE_KEYS = [
    "connection",
    "account",
    "user",
    "account_url",
    "sf_utils_db",
    "admin_role",
]

_PREREQS_KEYS = [
    "tools_verified",
    "infra_ready",
]

_ROOT_KEYS = [
    "schema_version",
    "project_name",
    "created_at",
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today_iso() -> str:
    return datetime.date.today().isoformat()


def _escape_str(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _toml_value(v: object) -> str:
    """Serialize a Python value to a TOML literal string."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        items = ", ".join(f'"{_escape_str(str(i))}"' for i in v)
        return f"[{items}]"
    if isinstance(v, str):
        return f'"{_escape_str(v)}"'
    # Fallback — should not happen with our fixed schema
    return f'"{_escape_str(str(v))}"'


def _section_comment(title: str, width: int = 78) -> str:
    """Return a TOML comment line: '# ── {title} ──...──'."""
    fill = "─" * max(2, width - len(title) - 5)
    return f"# ── {title} {fill}"


def _write_table(section: dict, ordered_keys: list[str]) -> list[str]:
    """Serialize a flat dict in key-declaration order, then remaining keys."""
    lines: list[str] = []
    emitted: set[str] = set()
    for key in ordered_keys:
        if key in section:
            lines.append(f"{key:<20} = {_toml_value(section[key])}")
            emitted.add(key)
    for key, val in section.items():
        if key not in emitted:
            lines.append(f"{key:<20} = {_toml_value(val)}")
    return lines


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def ensure_manifest_defaults(data: dict, manifest_path: Path | str = MANIFEST_PATH) -> None:
    """Ensure *data* has all required top-level sections with sensible defaults.

    Called before writing a PAT entry so the manifest is always well-formed,
    even when the prereqs init block was skipped.  Mutates *data* in place.

    Connection is NOT auto-filled here — that is the skill's responsibility
    (interactive picker at Step 1).  If SNOWFLAKE_DEFAULT_CONNECTION_NAME is
    already set in the environment, it is used as a silent fallback so CI/CD
    environments that export it don't need interactive prompting.
    """
    if "schema_version" not in data:
        data["schema_version"] = SCHEMA_VERSION
    if "project_name" not in data:
        # Derive from the project directory (parent of the .sfutils/ dir).
        data["project_name"] = Path(manifest_path).resolve().parent.parent.name
    if "created_at" not in data:
        data["created_at"] = _now_iso()

    if "snowflake" not in data:
        data["snowflake"] = {}
    sf = data["snowflake"]
    if not sf.get("connection"):
        sf["connection"] = os.environ.get("SNOWFLAKE_DEFAULT_CONNECTION_NAME", "")
    if not sf.get("sf_utils_db"):
        sf["sf_utils_db"] = (
            os.environ.get("SF_UTILS_DB")
            or os.environ.get("SFUTILS_DB")
            or os.environ.get("SNOW_UTILS_DB")
            or ""
        )
    sf.setdefault("admin_role", "ACCOUNTADMIN")

    if "prereqs" not in data:
        data["prereqs"] = {"tools_verified": _today_iso(), "infra_ready": False}
    data.setdefault("pat", {})


def load_manifest(path: Path | str = MANIFEST_PATH) -> dict:
    """Read manifest.toml.  Returns empty dict if the file is missing or
    cannot be parsed (tolerant — caller should not crash on missing manifest).
    """
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with p.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError:
        return {}


def save_manifest(path: Path | str, data: dict) -> None:
    """Write *data* to *path* as TOML.

    Creates the parent directory with mode 700 if needed.
    Sets the file mode to 600 after writing.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(p.parent, 0o700)

    lines: list[str] = ["# Machine-managed by Cortex Code. Do not hand-edit."]

    # Root-level scalars
    for key in _ROOT_KEYS:
        if key in data:
            lines.append(f"{key:<14} = {_toml_value(data[key])}")
    # Any extra root scalars not in the ordered list
    for key, val in data.items():
        if key not in _ROOT_KEYS and not isinstance(val, (dict, list)):
            lines.append(f"{key:<14} = {_toml_value(val)}")

    # [snowflake]
    if "snowflake" in data:
        _sc = _section_comment("Shared Snowflake connection (captured once, reused by all PATs)")
        lines += ["", _sc, "[snowflake]"]
        lines += _write_table(data["snowflake"], _SNOWFLAKE_KEYS)

    # [prereqs]
    if "prereqs" in data:
        lines += ["", _section_comment("Tool / infra pre-flight cache")]
        lines += ["[prereqs]"]
        lines += _write_table(data["prereqs"], _PREREQS_KEYS)

    # [pat.<label>] named tables — label is the TOML key, not a field
    for label, pat in data.get("pat", {}).items():
        lines += ["", _section_comment(f"PAT: {label}")]
        lines += [f"[pat.{label}]"]
        # Scalar fields in declared order
        emitted: set[str] = set()
        for key in _PAT_SCALAR_KEYS:
            if key in pat:
                lines.append(f"{key:<20} = {_toml_value(pat[key])}")
                emitted.add(key)
        for key, val in pat.items():
            if key not in emitted and not isinstance(val, dict):
                lines.append(f"{key:<20} = {_toml_value(val)}")

        # [pat.<label>.resources] subtable
        if "resources" in pat:
            lines += ["", f"[pat.{label}.resources]"]
            for k, v in pat["resources"].items():
                lines.append(f"{k:<20} = {_toml_value(v)}")

        # [pat.<label>.cleanup] subtable
        if "cleanup" in pat:
            lines += ["", f"[pat.{label}.cleanup]"]
            for k, v in pat["cleanup"].items():
                lines.append(f"{k:<20} = {_toml_value(v)}")

    content = "\n".join(lines) + "\n"
    p.write_text(content, encoding="utf-8")
    with contextlib.suppress(OSError):
        os.chmod(p, 0o600)


def get_pat_entry(
    data: dict,
    *,
    sa_user: str | None = None,
    label: str | None = None,
) -> dict | None:
    """Return the PAT entry for *label* (O(1)) or the first entry matching
    *sa_user* (linear scan).  Returns None if not found.
    """
    pats = data.get("pat", {})
    if label:
        return pats.get(label)
    if sa_user:
        for entry in pats.values():
            if entry.get("sa_user", "").upper() == sa_user.upper():
                return entry
    return None


def upsert_pat(data: dict, label: str, pat_config: dict) -> None:
    """Add or replace the PAT entry for *label*.

    The label is the TOML key — it must not appear as a field inside
    *pat_config*.  Mutates *data* in place; caller must call save_manifest().
    """
    data.setdefault("pat", {})[label] = pat_config


def update_pat_status(data: dict, sa_user: str, status: str) -> None:
    """Set *status* on the PAT entry matching *sa_user* and update timestamps.

    Also sets *removed_at* when status is REMOVED.
    Mutates *data* in place — caller must call save_manifest() afterwards.
    """
    now = _now_iso()
    for entry in data.get("pat", {}).values():
        if entry.get("sa_user", "").upper() == sa_user.upper():
            entry["status"] = status
            entry["updated_at"] = now
            if status == "REMOVED":
                entry["removed_at"] = now
            return


def validate_manifest(data: dict) -> list[str]:
    """Validate *data* against the expected manifest schema.

    Returns a list of human-readable error/warning strings.
    An empty list means the manifest is valid.
    """
    issues: list[str] = []

    # Root-level required fields
    for field in ("schema_version", "project_name", "created_at"):
        if not data.get(field):
            issues.append(f"missing root field: {field}")

    # [snowflake] section
    if "snowflake" not in data:
        issues.append("missing section: [snowflake]")
    else:
        sf = data["snowflake"]
        if not sf.get("connection"):
            issues.append("[snowflake].connection is empty — run 'sfutils-pat setup-connection'")
        if not sf.get("sf_utils_db"):
            issues.append("[snowflake].sf_utils_db is empty — run 'sfutils-pat check-setup'")

    # [prereqs] section
    if "prereqs" not in data:
        issues.append("missing section: [prereqs]")
    else:
        prereqs = data["prereqs"]
        if not prereqs.get("tools_verified"):
            issues.append("[prereqs].tools_verified is empty")

    # [pat.*] entries
    for label, pat in data.get("pat", {}).items():
        prefix = f"[pat.{label}]"
        for field in ("status", "sa_user", "sa_role"):
            if not pat.get(field):
                issues.append(f"{prefix} missing required field: {field}")
        valid_statuses = {"IN_PROGRESS", "COMPLETE", "REMOVED"}
        if pat.get("status") and pat["status"] not in valid_statuses:
            issues.append(
                f"{prefix} invalid status '{pat['status']}' "
                f"(expected: {', '.join(sorted(valid_statuses))})"
            )
        cleanup = pat.get("cleanup", {})
        if not cleanup.get("user"):
            issues.append(f"{prefix} [cleanup].user is empty")
        if not cleanup.get("db"):
            issues.append(f"{prefix} [cleanup].db is empty")

    return issues


# ---------------------------------------------------------------------------
# Resolution helpers (3-level fallback: pat entry → root [snowflake] → env var)
# ---------------------------------------------------------------------------


def resolve_pat_connection(pat_entry: dict, manifest: dict) -> str | None:
    """Effective connection name: pat override → root snowflake → env var."""
    return (
        pat_entry.get("connection")
        or manifest.get("snowflake", {}).get("connection")
        or os.environ.get("SNOWFLAKE_DEFAULT_CONNECTION_NAME")
        or None
    )


def resolve_pat_sf_utils_db(pat_entry: dict, manifest: dict) -> str | None:
    """Effective sf_utils_db: pat override → root snowflake → env var."""
    return (
        pat_entry.get("sf_utils_db")
        or manifest.get("snowflake", {}).get("sf_utils_db")
        or os.environ.get("SF_UTILS_DB")
        or os.environ.get("SFUTILS_DB")
        or os.environ.get("SNOW_UTILS_DB")
        or None
    )


def resolve_pat_admin_role(pat_entry: dict, manifest: dict) -> str:
    """Effective admin role: pat override → root snowflake → env var → ACCOUNTADMIN."""
    return (
        pat_entry.get("admin_role")
        or manifest.get("snowflake", {}).get("admin_role")
        or os.environ.get("SA_ADMIN_ROLE")
        or "ACCOUNTADMIN"
    )

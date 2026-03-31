"""
IPv4 preset providers for snow-utils-pat.

Provides IPv4 CIDR collection from presets (GitHub Actions, Google, local IP)
for PAT network rule creation. Copied from snow-utils-common so this package
is fully self-contained.
"""

from enum import Enum
from functools import lru_cache

import requests


class NetworkRuleMode(str, Enum):
    """Snowflake network rule modes."""

    INGRESS = "INGRESS"
    INTERNAL_STAGE = "INTERNAL_STAGE"
    EGRESS = "EGRESS"
    POSTGRES_INGRESS = "POSTGRES_INGRESS"
    POSTGRES_EGRESS = "POSTGRES_EGRESS"


class NetworkRuleType(str, Enum):
    """Snowflake network rule value types."""

    IPV4 = "IPV4"
    HOST_PORT = "HOST_PORT"
    PRIVATE_HOST_PORT = "PRIVATE_HOST_PORT"
    AWSVPCEID = "AWSVPCEID"


VALID_MODE_TYPES: dict[NetworkRuleMode, list[NetworkRuleType]] = {
    NetworkRuleMode.INGRESS: [NetworkRuleType.IPV4, NetworkRuleType.AWSVPCEID],
    NetworkRuleMode.INTERNAL_STAGE: [NetworkRuleType.IPV4, NetworkRuleType.AWSVPCEID],
    NetworkRuleMode.EGRESS: [NetworkRuleType.IPV4, NetworkRuleType.HOST_PORT],
    NetworkRuleMode.POSTGRES_INGRESS: [NetworkRuleType.IPV4, NetworkRuleType.AWSVPCEID],
    NetworkRuleMode.POSTGRES_EGRESS: [NetworkRuleType.IPV4, NetworkRuleType.HOST_PORT],
}


def validate_mode_type(mode: NetworkRuleMode, rule_type: NetworkRuleType) -> bool:
    """Check if mode/type combination is valid per Snowflake docs."""
    return rule_type in VALID_MODE_TYPES.get(mode, [])


def get_valid_types_for_mode(mode: NetworkRuleMode) -> list[str]:
    """Get list of valid type names for a given mode."""
    return [t.value for t in VALID_MODE_TYPES.get(mode, [])]


def _is_ipv4_cidr(cidr: str) -> bool:
    """Check if a CIDR is IPv4 (not IPv6)."""
    return ":" not in cidr


@lru_cache(maxsize=1)
def get_github_actions_ips() -> tuple[str, ...]:
    """Fetch GitHub Actions runner IPv4 CIDRs from GitHub meta API."""
    response = requests.get("https://api.github.com/meta", timeout=30)
    response.raise_for_status()
    all_ips = response.json().get("actions", [])
    return tuple(ip for ip in all_ips if _is_ipv4_cidr(ip))


@lru_cache(maxsize=1)
def get_google_ips() -> tuple[str, ...]:
    """Fetch Google IPv4 ranges from gstatic.com."""
    response = requests.get("https://www.gstatic.com/ipranges/goog.json", timeout=30)
    response.raise_for_status()
    prefixes = response.json().get("prefixes", [])
    return tuple(p["ipv4Prefix"] for p in prefixes if "ipv4Prefix" in p)


def get_local_ip() -> str:
    """Get current public IP address with /32 CIDR suffix."""
    response = requests.get("https://api.ipify.org", timeout=10)
    response.raise_for_status()
    return f"{response.text.strip()}/32"


def collect_ipv4_cidrs(
    with_local: bool = True,
    with_gh: bool = False,
    with_google: bool = False,
    extra_cidrs: list[str] | None = None,
) -> list[str]:
    """Collect IPv4 CIDRs from enabled presets and extra values."""
    cidrs: list[str] = []

    if with_local:
        cidrs.append(get_local_ip())
    if with_gh:
        cidrs.extend(get_github_actions_ips())
    if with_google:
        cidrs.extend(get_google_ips())
    if extra_cidrs:
        cidrs.extend(extra_cidrs)

    return list(dict.fromkeys(cidrs))

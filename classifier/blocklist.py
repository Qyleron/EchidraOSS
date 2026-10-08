"""Which captured source IPs belong in an exported blocklist.

Shared by `echidra blocklist` and the dashboard's Analytics export so both
apply the same rules.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable


def is_blocklistable(
    peer_ip: str,
    excluded: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network] = (),
    *,
    include_private: bool = False,
) -> bool:
    """True if peer_ip is a valid address that should go in a blocklist.

    Private, loopback, link-local, unspecified, multicast and reserved
    addresses are left out unless include_private is set, so an internal
    decoy can't push the operator's own network into a firewall rule.
    """
    try:
        address = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False  # never hand a firewall something that isn't an address
    if not include_private and (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_unspecified or address.is_multicast or address.is_reserved
    ):
        return False
    return not any(address.version == network.version and address in network for network in excluded)


def blocklist_ips(rows: Iterable[dict], **kwargs) -> list[str]:
    """peer_ip values from list_attacker_ips() rows that pass is_blocklistable."""
    return [row["peer_ip"] for row in rows if is_blocklistable(row["peer_ip"], **kwargs)]

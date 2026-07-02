"""Offline IP-to-country resolution using geoip2fast's bundled dataset."""

from __future__ import annotations

_geoip = None


def resolve_country(peer_ip: str | None) -> str | None:
    """Return the country name for a peer IP, or None if unavailable/private."""
    if not peer_ip:
        return None
    global _geoip
    try:
        if _geoip is None:
            from geoip2fast import GeoIP2Fast
            _geoip = GeoIP2Fast()
        result = _geoip.lookup(peer_ip)
        name = getattr(result, "country_name", None)
        if not name or name in ("Private Network", "--"):
            return None
        return name
    except Exception:
        return None

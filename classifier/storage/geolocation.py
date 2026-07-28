"""Offline IP-to-country resolution using geoip2fast's bundled dataset.

geoip2fast's country-level dataset returns a country_code/country_name only --
no coordinates -- so the map's latitude/longitude come from a static
country-centroid table keyed by ISO 3166-1 alpha-2 code, not a precise
per-IP location.
"""

from __future__ import annotations

from classifier.storage.country_centroids import COUNTRY_CENTROIDS

_geoip = None


def resolve_geo(peer_ip: str | None) -> tuple[str | None, float | None, float | None]:
    """Return (country_name, latitude, longitude) for a peer IP.

    All three are None if the IP is missing, private, or unresolvable.
    """
    if not peer_ip:
        return None, None, None
    global _geoip
    try:
        if _geoip is None:
            from geoip2fast import GeoIP2Fast
            _geoip = GeoIP2Fast()
        result = _geoip.lookup(peer_ip)
        if getattr(result, "is_private", False):
            return None, None, None
        name = getattr(result, "country_name", None)
        if not name or name == "--" or name == "<not found in database>":
            return None, None, None
        code = getattr(result, "country_code", None)
        centroid = COUNTRY_CENTROIDS.get(code)
        if centroid is None:
            return name, None, None
        return name, centroid[0], centroid[1]
    except Exception:
        return None, None, None


def resolve_country(peer_ip: str | None) -> str | None:
    """Return the country name for a peer IP, or None if unavailable/private."""
    name, _lat, _lon = resolve_geo(peer_ip)
    return name

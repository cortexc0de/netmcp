"""GeoIP enrichment for IP addresses using MaxMind GeoLite2."""

import asyncio
import concurrent.futures
import functools

try:
    from geolite2 import geolite2

    _GEOLITE_AVAILABLE = True
except ImportError:
    _GEOLITE_AVAILABLE = False

import threading

# Module-level singleton to avoid reopening database
_reader: object | None = None
_reader_lock = threading.Lock()


def _get_reader():
    """Get or create the GeoIP reader singleton (thread-safe)."""
    global _reader
    if _reader is None and _GEOLITE_AVAILABLE:
        with _reader_lock:
            if _reader is None:
                _reader = geolite2.reader()
    return _reader


@functools.lru_cache(maxsize=1024)
def lookup_ip(ip: str) -> dict:
    """
    Look up GeoIP information for an IP address.

    Results are cached via LRU cache. Uses a singleton reader to avoid
    file handle leaks.

    Returns:
        Dict with country, city, latitude, longitude, timezone.
    """
    if not _GEOLITE_AVAILABLE:
        return {"ip": ip, "error": "GeoLite2 not available"}

    try:
        reader = _get_reader()
        if reader is None:
            return {"ip": ip, "error": "GeoLite2 reader unavailable"}

        result = reader.get(ip)

        if not result:
            return {"ip": ip, "country": "Unknown", "city": "Unknown"}

        country = result.get("country", {}).get("names", {}).get("en", "Unknown")
        city = result.get("city", {}).get("names", {}).get("en", "Unknown")
        location = result.get("location", {})
        lat = location.get("latitude", 0)
        lon = location.get("longitude", 0)
        tz = location.get("time_zone", "")

        return {
            "ip": ip,
            "country": country,
            "city": city,
            "latitude": lat,
            "longitude": lon,
            "timezone": tz,
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}


# Bounded thread pool for GeoIP lookups
_geoip_executor = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="geoip")


async def enrich_ips(ip_list: list[str]) -> list[dict]:
    """
    Enrich a list of IPs with GeoIP data concurrently.

    Uses a bounded thread pool to avoid spawning excessive threads.

    Args:
        ip_list: List of IP addresses

    Returns:
        List of GeoIP result dicts
    """
    loop = asyncio.get_running_loop()
    tasks = [loop.run_in_executor(_geoip_executor, lookup_ip, ip) for ip in ip_list]
    return await asyncio.gather(*tasks)

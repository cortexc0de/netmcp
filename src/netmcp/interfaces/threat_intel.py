"""Threat intelligence interface for URLhaus and AbuseIPDB."""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

# URLhaus configuration
URLHAUS_TEXT_URL = "https://urlhaus.abuse.ch/downloads/text/"
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv/"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/payload/"

# AbuseIPDB configuration
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

# Cache TTL (1 hour)
CACHE_TTL = 3600

# Threat score threshold (0-100)
THREAT_THRESHOLD = 50


@dataclass
class CacheEntry:
    """A single cache entry with timestamp."""
    data: Any
    timestamp: float


class ThreatIntelInterface:
    """Threat intelligence lookups for IP addresses and PCAP files.

    Supports URLhaus (no key required) and AbuseIPDB (API key required).
    Results are cached in-memory with configurable TTL.
    """

    def __init__(
        self,
        abuseipdb_key: Optional[str] = None,
        providers: Optional[list[str]] = None,
        cache_ttl: int = CACHE_TTL,
    ) -> None:
        self.abuseipdb_key = abuseipdb_key
        self.cache_ttl = cache_ttl

        # Determine active providers
        if providers:
            self.providers = providers
        else:
            self.providers = ["urlhaus"]
            if abuseipdb_key:
                self.providers.append("abuseipdb")

        # Simple in-memory cache
        self._cache: dict[str, CacheEntry] = {}

    def __repr__(self) -> str:
        return f"ThreatIntelInterface(providers={self.providers})"

    # ── Cache helpers ───────────────────────────────────────────────────

    def _get_cache(self, key: str) -> Optional[Any]:
        """Get cached result if not expired."""
        entry = self._cache.get(key)
        if entry and (time.monotonic() - entry.timestamp) < self.cache_ttl:
            return entry.data
        return None

    def _set_cache(self, key: str, data: Any) -> None:
        """Store result in cache."""
        self._cache[key] = CacheEntry(data=data, timestamp=time.monotonic())

    # ── URLhaus ─────────────────────────────────────────────────────────

    async def _fetch_urlhaus(self) -> set[str]:
        """Fetch the URLhaus text feed and extract IPs."""
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(URLHAUS_TEXT_URL)
            resp.raise_for_status()

        ips = set()
        for line in resp.text.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            # Extract IPv4 addresses
            parts = line.split()
            for part in parts:
                # Simple IPv4 check
                tokens = part.split(".")
                if len(tokens) == 4:
                    try:
                        if all(0 <= int(t) <= 255 for t in tokens):
                            ips.add(part)
                    except ValueError:
                        continue
        return ips

    async def _check_urlhaus(self, ip: str) -> dict:
        """Check if an IP is in the URLhaus feed."""
        cached = self._get_cache(f"urlhaus:{ip}")
        if cached is not None:
            return cached

        try:
            malicious_ips = await self._fetch_urlhaus()
            is_threat = ip in malicious_ips
            result = {
                "provider": "urlhaus",
                "threat": is_threat,
                "url": URLHAUS_TEXT_URL,
            }
            self._set_cache(f"urlhaus:{ip}", result)
            return result
        except Exception as e:
            return {
                "provider": "urlhaus",
                "error": True,
                "message": str(e),
                "threat": False,
            }

    # ── AbuseIPDB ───────────────────────────────────────────────────────

    async def _check_abuseipdb(self, ip: str) -> dict:
        """Check an IP against AbuseIPDB API."""
        if not self.abuseipdb_key:
            return {
                "provider": "abuseipdb",
                "error": True,
                "message": "No API key configured",
                "threat": False,
            }

        cached = self._get_cache(f"abuseipdb:{ip}")
        if cached is not None:
            return cached

        try:
            headers = {
                "Key": self.abuseipdb_key,
                "Accept": "application/json",
            }
            params = {"ipAddress": ip, "maxAgeInDays": 90}

            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(ABUSEIPDB_API_URL, headers=headers, params=params)
                resp.raise_for_status()
                data = resp.json()

            ip_data = data.get("data", {})
            score = ip_data.get("abuseConfidenceScore", 0)
            is_threat = score >= THREAT_THRESHOLD

            result = {
                "provider": "abuseipdb",
                "threat": is_threat,
                "score": score,
                "reports": ip_data.get("totalReports", 0),
                "country": ip_data.get("countryCode", "unknown"),
                "usage_type": ip_data.get("usageType", "unknown"),
                "last_reported": ip_data.get("lastReportedAt", ""),
                "whitelisted": ip_data.get("isWhitelisted", False),
                "url": f"https://www.abuseipdb.com/check/{ip}",
            }
            self._set_cache(f"abuseipdb:{ip}", result)
            return result
        except Exception as e:
            return {
                "provider": "abuseipdb",
                "error": True,
                "message": str(e),
                "threat": False,
            }

    # ── Main API ────────────────────────────────────────────────────────

    async def check_ip(
        self,
        ip: str,
        providers: Optional[list[str]] = None,
    ) -> dict:
        """Check an IP against configured threat intelligence providers.

        Args:
            ip: IP address to check
            providers: Override providers for this call (optional)

        Returns:
            Dict with per-provider results and overall threat status.
        """
        active_providers = providers or self.providers
        results = {"ip": ip, "providers": {}}

        # Run checks concurrently
        tasks = []
        provider_map = {}

        for provider in active_providers:
            if provider == "urlhaus":
                tasks.append(self._check_urlhaus(ip))
                provider_map["urlhaus"] = True
            elif provider == "abuseipdb":
                tasks.append(self._check_abuseipdb(ip))
                provider_map["abuseipdb"] = True

        if tasks:
            checked = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(checked):
                if isinstance(result, Exception):
                    results["providers"][active_providers[i]] = {
                        "error": True,
                        "message": str(result),
                        "threat": False,
                    }
                elif isinstance(result, dict):
                    provider_name = result.get("provider", active_providers[i])
                    results["providers"][provider_name] = result

        # Overall threat assessment
        any_threat = any(
            p.get("threat", False)
            for p in results["providers"].values()
            if isinstance(p, dict)
        )
        results["is_threat"] = any_threat
        results["threat_providers"] = [
            name for name, p in results["providers"].items()
            if isinstance(p, dict) and p.get("threat", False)
        ]

        return results

    # ── PCAP scanning ───────────────────────────────────────────────────

    async def scan_pcap(
        self,
        filepath: str,
        tshark: Any,
        providers: Optional[list[str]] = None,
    ) -> dict:
        """Extract all IPs from a PCAP file and check against threat feeds.

        Args:
            filepath: Path to PCAP file
            tshark: TsharkInterface instance
            providers: Override providers (optional)

        Returns:
            Dict with all IPs found, per-IP threat results, and summary.
        """
        # Extract IPs from PCAP using tshark
        export_result = await tshark.export_fields(
            filepath,
            fields=["ip.src", "ip.dst"],
        )

        # Collect unique IPs
        ips = set()
        for row in export_result:
            for val in row.values():
                val = val.strip()
                if val and val not in ("", "unknown"):
                    ips.add(val)

        # Check each IP against threat feeds (concurrently, in batches)
        ip_results = {}
        batch_size = 10

        for i in range(0, len(ips), batch_size):
            batch = list(ips)[i:i + batch_size]
            tasks = [self.check_ip(ip, providers) for ip in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for ip, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    ip_results[ip] = {"error": str(result)}
                else:
                    ip_results[ip] = result

        # Summary
        threats = {
            ip: r for ip, r in ip_results.items()
            if isinstance(r, dict) and r.get("is_threat", False)
        }

        return {
            "filepath": filepath,
            "total_ips": len(ips),
            "threats_found": len(threats),
            "threat_ips": list(threats.keys()),
            "ip_results": ip_results,
        }

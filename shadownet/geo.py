"""Asynchronous geo-IP OSINT lookup with local address fast-path.

Queries a free geo-IP API (ipinfo.io by default) and caches results
to avoid redundant requests.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Dict, Optional

import aiohttp

from .logger import get_logger


logger = get_logger()


def _is_internal(ip: str) -> bool:
    """Return True if *ip* is a loopback, private, link-local, or multicast address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )


async def geo_lookup(
    session: aiohttp.ClientSession,
    ip: str,
    api_url: str = "https://ipinfo.io/{ip}/json",
) -> str:
    """Resolve an IP address to a city / region / country / organisation string.

    Internal addresses skip the HTTP request and return immediately
    with an "Internal Threat" label.

    Parameters
    ----------
    session:
        Shared aiohttp client session.
    ip:
        The IP address to look up.
    api_url:
        URL template with an ``{ip}`` placeholder.

    Returns
    -------
    A human-readable location string.
    """
    if _is_internal(ip):
        return "Internal Threat (LAN/Loopback)"

    url = api_url.format(ip=ip)
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                logger.warning("Geo lookup for %s returned HTTP %d", ip, resp.status)
                return "Unknown (geo lookup failed)"
            data = await resp.json()
            parts = []
            for key in ("city", "region", "country"):
                val = data.get(key)
                if val and (not parts or val != parts[-1]):
                    parts.append(str(val))
            org = data.get("org")
            loc = ", ".join(parts) or "Unknown"
            if org:
                loc = f"{loc} | {org}"
            logger.info("Geo resolved %s -> %s", ip, loc)
            return loc
    except asyncio.TimeoutError:
        logger.warning("Geo lookup timed out for %s", ip)
        return "Unknown (geo timeout)"
    except aiohttp.ClientError as exc:
        logger.warning("Geo lookup HTTP error for %s: %s", ip, exc)
        return "Unknown (geo network error)"
    except Exception as exc:
        logger.error("Geo lookup unexpected error for %s: %s", ip, exc)
        return "Unknown (geo error)"


async def geo_fill_worker(
    geo_cache: Dict[str, str],
    geo_queue: "asyncio.Queue[str]",
    api_url: str = "https://ipinfo.io/{ip}/json",
) -> None:
    """Background worker that consumes IPs from *geo_queue* and fills *geo_cache*.

    Runs until cancelled.  Each IP is looked up exactly once; subsequent
    enqueues are silently skipped if the cache already holds a resolved
    (non-placeholder) value.
    """
    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=10),
    ) as session:
        while True:
            ip = await geo_queue.get()
            try:
                if ip in geo_cache and geo_cache[ip] not in ("Resolving...",):
                    continue
                loc = await geo_lookup(session, ip, api_url)
                geo_cache[ip] = loc
            except Exception as exc:
                logger.error("Geo worker exception for %s: %s", ip, exc)
                geo_cache[ip] = "Unknown (worker error)"
            finally:
                geo_queue.task_done()

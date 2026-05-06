import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Optional, Callable

import aiohttp

from .resolver import resolve_a, resolve_aaaa, build_resolver

_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,120})</title>", re.IGNORECASE)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

_TASK_BATCH = 1000


@dataclass
class ScanResult:
    subdomain: str
    ips: list[str]
    ipv6: list[str] = field(default_factory=list)
    cname: Optional[str] = None
    ttl: Optional[int] = None
    dns_ms: float = 0.0
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    title: Optional[str] = None
    http_ms: float = 0.0
    https_ms: float = 0.0
    http_size: int = 0
    https_size: int = 0
    wildcard: bool = False


@dataclass
class ScanStats:
    total: int = 0
    found: int = 0
    wildcard_filtered: int = 0
    elapsed: float = 0.0
    scanned: int = 0


async def _fetch(
    session: aiohttp.ClientSession,
    url: str,
    timeout: int,
    follow_redirects: bool,
) -> tuple[Optional[int], Optional[str], int, float]:
    t0 = time.perf_counter()
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=follow_redirects,
            ssl=False,
        ) as resp:
            elapsed = (time.perf_counter() - t0) * 1000
            status = resp.status
            body = await resp.read()
            size = len(body)
            title: Optional[str] = None
            try:
                text = body.decode(errors="ignore")
                m = _TITLE_RE.search(text)
                if m:
                    title = m.group(1).strip()
            except Exception:
                pass
            return status, title, size, elapsed
    except Exception:
        return None, None, 0, (time.perf_counter() - t0) * 1000


async def _scan_one(
    subdomain: str,
    resolver,
    semaphore: asyncio.Semaphore,
    wildcard_ips: Optional[set[str]],
    probe_http: bool,
    probe_aaaa: bool,
    http_session: Optional[aiohttp.ClientSession],
    http_timeout: int,
    follow_redirects: bool,
    filter_status: Optional[set[int]],
    match_status: Optional[set[int]],
    match_ip: Optional[str],
) -> Optional[ScanResult]:
    async with semaphore:
        ips, ttl, dns_ms, cname = await resolve_a(subdomain, resolver)
        if not ips:
            return None

        if wildcard_ips and set(ips) & wildcard_ips:
            return ScanResult(subdomain=subdomain, ips=ips, ttl=ttl, dns_ms=dns_ms, wildcard=True)

        if match_ip and match_ip not in ips:
            return None

        ipv6: list[str] = []
        if probe_aaaa:
            ipv6 = await resolve_aaaa(subdomain, resolver) or []

        result = ScanResult(
            subdomain=subdomain,
            ips=ips,
            ipv6=ipv6,
            cname=cname,
            ttl=ttl,
            dns_ms=dns_ms,
        )

        if probe_http and http_session:
            http_status, title, http_size, http_ms = await _fetch(
                http_session, f"http://{subdomain}", http_timeout, follow_redirects
            )
            https_status, https_title, https_size, https_ms = await _fetch(
                http_session, f"https://{subdomain}", http_timeout, follow_redirects
            )

            result.http_status  = http_status
            result.https_status = https_status
            result.title        = https_title or title
            result.http_ms      = http_ms
            result.https_ms     = https_ms
            result.http_size    = http_size
            result.https_size   = https_size

            effective_status = https_status or http_status
            if filter_status and effective_status in filter_status:
                return None
            if match_status and effective_status not in match_status:
                return None

        return result


async def run_scan(
    domain: str,
    wordlist: list[str],
    concurrency: int = 300,
    probe_http: bool = False,
    probe_aaaa: bool = False,
    nameservers: Optional[list[str]] = None,
    dns_timeout: float = 3.0,
    dns_retries: int = 1,
    http_timeout: int = 5,
    follow_redirects: bool = True,
    user_agent: str = DEFAULT_UA,
    wildcard_ips: Optional[set[str]] = None,
    filter_status: Optional[set[int]] = None,
    match_status: Optional[set[int]] = None,
    match_ip: Optional[str] = None,
    on_found: Optional[Callable[[ScanResult], None]] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> tuple[list[ScanResult], ScanStats]:
    resolver = build_resolver(nameservers, timeout=dns_timeout, retries=dns_retries)
    semaphore = asyncio.Semaphore(concurrency)
    stats = ScanStats(total=len(wordlist))
    results: list[ScanResult] = []
    start = time.perf_counter()

    headers = {"User-Agent": user_agent}
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    session: Optional[aiohttp.ClientSession] = (
        aiohttp.ClientSession(connector=connector, headers=headers)
        if probe_http else None
    )

    async def _worker(word: str) -> None:
        subdomain = f"{word}.{domain}"
        result = await _scan_one(
            subdomain, resolver, semaphore,
            wildcard_ips=wildcard_ips,
            probe_http=probe_http,
            probe_aaaa=probe_aaaa,
            http_session=session,
            http_timeout=http_timeout,
            follow_redirects=follow_redirects,
            filter_status=filter_status,
            match_status=match_status,
            match_ip=match_ip,
        )
        stats.scanned += 1
        if result:
            if result.wildcard:
                stats.wildcard_filtered += 1
            else:
                stats.found += 1
                results.append(result)
                if on_found:
                    on_found(result)
        if on_progress:
            on_progress(stats.scanned, stats.total)

    try:
        for i in range(0, len(wordlist), _TASK_BATCH):
            batch = wordlist[i : i + _TASK_BATCH]
            await asyncio.gather(*[asyncio.create_task(_worker(w)) for w in batch])
    finally:
        if session:
            await session.close()
        await asyncio.sleep(0.05)

    stats.elapsed = time.perf_counter() - start
    results.sort(key=lambda r: r.subdomain)
    return results, stats

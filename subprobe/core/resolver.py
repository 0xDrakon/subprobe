import asyncio
import random
import string
import time
from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver


def build_resolver(
    nameservers: Optional[list[str]] = None,
    timeout: float = 3.0,
    retries: int = 1,
) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * (retries + 1)
    resolver.retry_servfail = retries > 0
    if nameservers:
        resolver.nameservers = nameservers
    return resolver


async def resolve_a(
    hostname: str,
    resolver: dns.asyncresolver.Resolver,
) -> tuple[Optional[list[str]], Optional[int], float, Optional[str]]:

    t0 = time.perf_counter()
    try:
        ans = await resolver.resolve(hostname, "A")
        elapsed = (time.perf_counter() - t0) * 1000
        ips = [rdata.address for rdata in ans]
        ttl = ans.rrset.ttl if ans.rrset else None

        cname: Optional[str] = None
        for rrset in ans.response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                cname = str(rrset[0].target).rstrip(".")
                break

        return ips, ttl, elapsed, cname
    except Exception:
        return None, None, (time.perf_counter() - t0) * 1000, None


async def resolve_aaaa(
    hostname: str,
    resolver: dns.asyncresolver.Resolver,
) -> Optional[list[str]]:
    try:
        ans = await resolver.resolve(hostname, "AAAA")
        return [rdata.address for rdata in ans]
    except Exception:
        return None


async def detect_wildcard(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
) -> Optional[set[str]]:

    def _rand() -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=16))

    hits: list[set[str]] = []
    for _ in range(2):
        probe = f"{_rand()}.{domain}"
        ips, _, _, _ = await resolve_a(probe, resolver)
        if ips:
            hits.append(set(ips))
        await asyncio.sleep(0.05)

    if len(hits) == 2:
        common = hits[0] & hits[1]
        if common:
            return common
    return None

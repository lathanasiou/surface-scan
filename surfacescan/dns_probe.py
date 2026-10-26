"""DNS resolution via dnspython. Collects A/AAAA/CNAME/MX/TXT/NS/CAA, follows
the CNAME chain, and flags common hygiene issues (dangling CNAME, private IP in
public DNS). Pure Python; no external binary required.
"""
from __future__ import annotations

import ipaddress

import dns.resolver
import dns.exception
import dns.name

from .models import HostResult
from .doh import DohResolver

_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CAA"]


def _mk_resolver(nameservers: list[str] | None, timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    if nameservers:
        r.nameservers = nameservers
    r.timeout = timeout
    r.lifetime = timeout * 2
    return r


def _query(resolver, name: str, rtype: str):
    try:
        ans = resolver.resolve(name, rtype, raise_on_no_answer=False)
        if ans.rrset is None:
            return []
        return [r.to_text() for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except (dns.exception.Timeout, dns.exception.DNSException):
        return []


def _follow_cname(resolver, host: str, max_depth: int = 10) -> tuple[list[str], bool]:
    """Return (chain, dangling). chain excludes the original host."""
    chain: list[str] = []
    current = host
    for _ in range(max_depth):
        try:
            ans = resolver.resolve(current, "CNAME", raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN,):
            # the current label doesn't exist at all
            return chain, bool(chain)   # dangling only if we were chasing a CNAME target
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout, dns.exception.DNSException):
            return chain, False
        if ans.rrset is None:
            return chain, False
        target = ans[0].to_text().rstrip(".")
        chain.append(target)
        current = target
        # does the final target resolve to anything?
        a = _query(resolver, current, "A")
        aaaa = _query(resolver, current, "AAAA")
        has_more_cname = False
        try:
            more = resolver.resolve(current, "CNAME", raise_on_no_answer=False)
            has_more_cname = more.rrset is not None
        except dns.exception.DNSException:
            has_more_cname = False
        if not has_more_cname:
            dangling = not (a or aaaa)
            return chain, dangling
    return chain, False


def _doh_follow_cname(doh: DohResolver, host: str, max_depth: int = 10) -> tuple[list[str], bool]:
    chain: list[str] = []
    current = host
    for _ in range(max_depth):
        target = doh.has_cname(current)
        if not target:
            return chain, False
        chain.append(target)
        current = target
        if not doh.has_cname(current):
            return chain, (not doh.resolves(current))
    return chain, False


def resolve_host(host: HostResult, nameservers: list[str] | None = None,
                 timeout: float = 5.0, mode: str = "auto",
                 doh_provider: str = "cloudflare") -> HostResult:
    """mode: 'udp' (classic only), 'doh' (DoH only), 'auto' (UDP then DoH fallback)."""
    name = host.hostname

    if mode in ("udp", "auto"):
        resolver = _mk_resolver(nameservers, timeout)
        chain, dangling = _follow_cname(resolver, name)
        terminal = chain[-1] if chain else name
        a = _query(resolver, terminal, "A")
        aaaa = _query(resolver, terminal, "AAAA")
        mx = _query(resolver, name, "MX")
        txt = _query(resolver, name, "TXT")
        ns = _query(resolver, name, "NS")
        caa = _query(resolver, name, "CAA")

        if mode == "auto" and not (a or aaaa or chain or ns):
            # UDP returned nothing useful -> fall back to DoH
            return _resolve_doh(host, timeout, doh_provider)

        host.cname_chain = chain
        host.a_records, host.aaaa_records = a, aaaa
        host.mx, host.txt, host.ns, host.caa = mx, txt, ns, caa
        host.resolved_ips = list(dict.fromkeys(a + aaaa))
        _finish_dns(host, chain, dangling)
        return host

    return _resolve_doh(host, timeout, doh_provider)


def _resolve_doh(host: HostResult, timeout: float, provider: str) -> HostResult:
    doh = DohResolver(provider=provider, timeout=timeout)
    try:
        name = host.hostname
        chain, dangling = _doh_follow_cname(doh, name)
        terminal = chain[-1] if chain else name
        host.cname_chain = chain
        host.a_records = doh.query(terminal, "A")
        host.aaaa_records = doh.query(terminal, "AAAA")
        host.mx = doh.query(name, "MX")
        host.txt = doh.query(name, "TXT")
        host.ns = doh.query(name, "NS")
        host.caa = doh.query(name, "CAA")
        host.resolved_ips = list(dict.fromkeys(host.a_records + host.aaaa_records))
        host.dns_notes.append("resolved via DoH")
        _finish_dns(host, chain, dangling)
    finally:
        doh.close()
    return host


def _finish_dns(host: HostResult, chain: list[str], dangling: bool) -> None:

    if dangling:
        host.dns_notes.append("dangling CNAME: target does not resolve (subdomain-takeover risk)")
        host.liveness = "dangling"

    for ip in host.resolved_ips:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                host.dns_notes.append(f"private/non-routable IP in public DNS: {ip}")
            elif not addr.is_global:
                # e.g. 100.64.0.0/10 CGNAT/shared, reserved ranges
                host.dns_notes.append(f"non-globally-routable IP in public DNS: {ip}")
        except ValueError:
            continue

    if not host.resolved_ips and not chain:
        if host.liveness == "untested":
            host.liveness = "dns_fail"
            host.dns_notes.append("no A/AAAA/CNAME records found")

    return host

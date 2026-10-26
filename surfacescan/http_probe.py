"""Liveness + HTTP probing (pure Python).

- TCP connect checks on a configurable port set -> open_ports + liveness state.
- HTTPS-first HTTP probe (falls back to HTTP) capturing status, redirect chain,
  title, headers, cookies, timing.
- TLS certificate issuer + expiry.
- A small set of benign GETs on well-known *framework* paths to strengthen
  fingerprinting. These are normal, unauthenticated requests for public paths;
  no payloads, no exploitation.
"""
from __future__ import annotations

import re
import socket
import ssl
import time
from datetime import datetime, timezone

import httpx

from .models import HostResult

DEFAULT_WEB_PORTS = [443, 80, 8443, 8080, 8000, 3000, 5000, 9000]
# Extra ports only probed on direct (non-CDN) hosts, and only if enabled.
EXTRA_PORTS = [22, 3389, 3306, 5432, 6379, 27017, 9200, 5601, 8081, 7001]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Benign fingerprint paths (public, no payloads).
FINGERPRINT_PATHS = ["/", "/robots.txt", "/index.php", "/_next/static/", "/sockjs-node/"]


def tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def check_ports(ip_or_host: str, ports: list[int], timeout: float) -> list[int]:
    return [p for p in ports if tcp_open(ip_or_host, p, timeout)]


def _tls_info(host: str, port: int, timeout: float) -> tuple[str, str, list[str]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    notes: list[str] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # getpeercert returns {} when verify_mode is CERT_NONE on some builds
                if not cert:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        notes.append("certificate present (details unverified)")
                    return "", "", notes
                issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "")
                not_after = cert.get("notAfter", "")
                try:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days = (exp - datetime.now(timezone.utc)).days
                    iso = exp.date().isoformat()
                    if days < 0:
                        notes.append(f"certificate EXPIRED ({iso})")
                    elif days < 30:
                        notes.append(f"certificate expires in {days}d ({iso})")
                    return issuer, iso, notes
                except ValueError:
                    return issuer, not_after, notes
    except (OSError, ssl.SSLError, socket.timeout) as e:
        notes.append(f"TLS error: {type(e).__name__}")
    return "", "", notes


def probe_http(host: HostResult, timeout: float, user_agent: str,
               extra_ports: bool, fetch_paths: bool) -> HostResult:
    if host.liveness in {"dns_fail", "dangling"}:
        return host

    name = host.hostname
    # Port scan runs against resolved IP when available (more accurate), else name.
    target = host.resolved_ips[0] if host.resolved_ips else name
    ports = list(DEFAULT_WEB_PORTS)
    # Extra ports only if direct host and enabled
    if extra_ports and host.cdn_waf in {"none", "unknown"}:
        ports += EXTRA_PORTS
    host.open_ports = check_ports(target, ports, timeout)

    if not host.open_ports:
        # Nothing answered TCP. Distinguish filtered vs refused is best-effort.
        host.liveness = "filtered"
        return host

    # HTTP probe: prefer HTTPS if 443 open
    schemes = []
    if 443 in host.open_ports or 8443 in host.open_ports:
        schemes.append("https")
    if 80 in host.open_ports or any(p in host.open_ports for p in (8080, 8000, 3000, 5000, 9000)):
        schemes.append("http")
    if not schemes:
        schemes = ["https", "http"]

    headers = {"User-Agent": user_agent, "Accept": "*/*"}
    probe_pages: dict[str, str] = {}
    answered = False

    for scheme in schemes:
        url = f"{scheme}://{name}/"
        start = time.perf_counter()
        try:
            with httpx.Client(follow_redirects=True, timeout=timeout, verify=False,
                              headers=headers, http2=False) as client:
                resp = client.get(url)
            elapsed = int((time.perf_counter() - start) * 1000)
        except httpx.HTTPError:
            continue

        answered = True
        host.scheme = scheme
        host.status_code = resp.status_code
        host.final_url = str(resp.url)
        host.response_ms = elapsed
        host.server_header = resp.headers.get("server", "")

        # headers + cookies for fingerprint/CDN
        host._headers = dict(resp.headers)          # type: ignore[attr-defined]
        host._cookies = [f"{k}={v}" for k, v in resp.cookies.items()]  # type: ignore[attr-defined]
        set_cookie = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        host._set_cookie = set_cookie               # type: ignore[attr-defined]

        text = resp.text if resp.headers.get("content-type", "").startswith(("text", "application")) else ""
        probe_pages["/"] = text[:200_000]
        m = TITLE_RE.search(text)
        if m:
            host.title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]

        # liveness classification
        if _looks_like_waf_block(resp, text):
            host.liveness = "waf_blocked"
        elif 200 <= resp.status_code < 400:
            host.liveness = "live"
        else:
            host.liveness = "live_error"

        # TLS
        if scheme == "https":
            port = 443 if 443 in host.open_ports else (8443 if 8443 in host.open_ports else 443)
            host.tls_issuer, host.tls_not_after, tls_notes = _tls_info(name, port, timeout)
            host.tls_notes.extend(tls_notes)

        # optional extra fingerprint paths
        if fetch_paths:
            _fetch_fingerprint_paths(name, scheme, headers, timeout, probe_pages)

        break  # first answering scheme wins

    if not answered:
        host.liveness = "refused"

    host._pages = probe_pages   # type: ignore[attr-defined]
    return host


def _fetch_fingerprint_paths(name, scheme, headers, timeout, pages: dict[str, str]):
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, verify=False,
                          headers=headers) as client:
            for path in FINGERPRINT_PATHS[1:]:
                try:
                    r = client.get(f"{scheme}://{name}{path}")
                    ct = r.headers.get("content-type", "")
                    body = r.text if ct.startswith(("text", "application")) else ""
                    pages[path] = f"[{r.status_code}] " + body[:50_000]
                except httpx.HTTPError:
                    continue
    except Exception:
        pass


def _looks_like_waf_block(resp, text: str) -> bool:
    if resp.status_code in (403, 406, 429, 503):
        blob = (text[:4000] + " " + " ".join(resp.headers.keys())).lower()
        markers = ["cloudflare", "attention required", "access denied", "request blocked",
                   "incapsula", "akamai", "sucuri", "web application firewall", "cf-ray",
                   "ray id", "forbidden", "blocked by", "mod_security", "captcha"]
        if any(mk in blob for mk in markers):
            return True
    return False

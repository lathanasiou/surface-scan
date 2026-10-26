"""CDN / WAF detection from CNAME suffixes, response headers, and (optionally)
IP-range membership. Automatic — the caller never has to say whether a host is
fronted.

IP-range membership is best-effort: it uses small built-in prefix lists for the
big providers. For authoritative coverage, drop provider range files into
signatures/cdn_ranges.json (a map of provider -> list of CIDRs) and they are
merged in at load time.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

# CNAME suffixes -> provider. Extend freely: a new CDN/WAF is usually just a
# line here (match is on the CNAME chain, case-insensitive, suffix-based).
CNAME_SUFFIXES = {
    # Amazon / AWS
    "cloudfront.net": "Amazon CloudFront",
    "awsglobalaccelerator.com": "AWS Global Accelerator",
    "elb.amazonaws.com": "AWS Elastic Load Balancer",
    "awsdns": "AWS (Route 53)",
    # Akamai
    "akamaiedge.net": "Akamai",
    "akamai.net": "Akamai",
    "akamaihd.net": "Akamai",
    "edgekey.net": "Akamai",
    "edgesuite.net": "Akamai",
    "akamaized.net": "Akamai",
    "akadns.net": "Akamai",
    "akamaitechnologies.com": "Akamai",
    # Fastly
    "fastly.net": "Fastly",
    "fastlylb.net": "Fastly",
    "freetls.fastly.net": "Fastly",
    # Microsoft Azure
    "azurefd.net": "Azure Front Door",
    "azureedge.net": "Azure CDN",
    "azurefd.microsoft.com": "Azure Front Door",
    "trafficmanager.net": "Azure Traffic Manager",
    "azure-dns": "Azure DNS",
    "cloudapp.azure.com": "Azure",
    # Cloudflare
    "cloudflare.net": "Cloudflare",
    "cloudflare.com": "Cloudflare",
    "cdn.cloudflare.net": "Cloudflare",
    # Google
    "ghs.googlehosted.com": "Google Cloud",
    "googleusercontent.com": "Google Cloud",
    "googlehosted.com": "Google Cloud",
    "googledomains.com": "Google Cloud",
    # F5 Distributed Cloud (Volterra / XC) and classic
    "ves.io": "F5 Distributed Cloud",
    "vh.ves.io": "F5 Distributed Cloud",
    "volterra.io": "F5 Distributed Cloud",
    # WAF / security clouds
    "incapdns.net": "Imperva Incapsula",
    "incapdns.com": "Imperva Incapsula",
    "sucuri.net": "Sucuri",
    "ddos-guard.net": "DDoS-Guard",
    "qrator.net": "Qrator Labs",
    "wafv2": "AWS WAF",
    "reblaze.io": "Reblaze",
    "mlytics.net": "Mlytics",
    "zenedge.net": "Oracle Dyn / Zenedge",
    "radwarecloud.net": "Radware Cloud",
    "nsone.net": "NS1 (managed DNS)",
    # CDNs
    "stackpathdns.com": "StackPath",
    "stackpathcdn.com": "StackPath",
    "cdn77.org": "CDN77",
    "b-cdn.net": "BunnyCDN",
    "bunnyinfra.net": "BunnyCDN",
    "kxcdn.com": "KeyCDN",
    "gcdn.co": "Gcore",
    "gcorelabs.com": "Gcore",
    "cachefly.net": "CacheFly",
    "llnwd.net": "Edgio (Limelight)",
    "lldns.net": "Edgio (Limelight)",
    "edgecastcdn.net": "Edgio (EdgeCast)",
    "section.io": "Section",
    "turbobytes.net": "TurboBytes",
    "cdnetworks.net": "CDNetworks",
    "chinanetcenter.com": "Wangsu / CDNetworks",
    "lswcdn.net": "Leaseweb CDN",
    "cdngc.net": "CDNetworks",
    "alikunlun.com": "Alibaba Cloud CDN",
    "alicdn.com": "Alibaba Cloud CDN",
    "cdntip.com": "Tencent Cloud CDN",
    "dnsv1.com": "Tencent Cloud",
    "wscloudcdn.com": "Wangsu",
    # PaaS / hosting edges (serve + often front with a CDN)
    "herokudns.com": "Heroku",
    "herokuapp.com": "Heroku",
    "vercel-dns.com": "Vercel",
    "vercel.app": "Vercel",
    "netlify.app": "Netlify",
    "netlifyglobalcdn.com": "Netlify",
    "netlify.com": "Netlify",
    "pages.dev": "Cloudflare Pages",
    "workers.dev": "Cloudflare Workers",
    "render.com": "Render",
    "onrender.com": "Render",
    "fly.dev": "Fly.io",
    "github.io": "GitHub Pages",
    "gitlab.io": "GitLab Pages",
    "firebaseapp.com": "Firebase Hosting",
    "web.app": "Firebase Hosting",
    "appspot.com": "Google App Engine",
    "wpengine.com": "WP Engine",
    "gslb.net": "generic GSLB",
}

# Response-header / cookie signals -> provider. kind is "header", "cookie" or
# "server" (matched against the Server header). Add rows freely.
HEADER_SIGNALS = {
    "Cloudflare": [("header", "cf-ray"), ("header", "cf-cache-status"), ("cookie", "__cf_bm"),
                   ("cookie", "__cfduid"), ("cookie", "cf_clearance"), ("server", "cloudflare")],
    "Amazon CloudFront": [("header", "x-amz-cf-id"), ("header", "x-amz-cf-pop"), ("server", "cloudfront")],
    "AWS WAF / ALB": [("cookie", "awsalb"), ("cookie", "awsalbcors"), ("header", "x-amzn-requestid"),
                      ("header", "x-amzn-trace-id"), ("header", "x-amz-apigw-id")],
    "Akamai": [("header", "x-akamai-transformed"), ("header", "akamai-grn"),
               ("header", "x-akamai-request-id"), ("header", "akamai-origin-hop"),
               ("server", "akamaighost")],
    "Fastly": [("header", "x-served-by"), ("header", "x-fastly-request-id"),
               ("header", "fastly-debug-digest"), ("server", "fastly")],
    "Imperva Incapsula": [("header", "x-iinfo"), ("header", "x-cdn"), ("cookie", "incap_ses_"),
                          ("cookie", "visid_incap_"), ("cookie", "nlbi_")],
    "Sucuri": [("header", "x-sucuri-id"), ("header", "x-sucuri-cache"), ("server", "sucuri")],
    "Azure Front Door": [("header", "x-azure-ref"), ("header", "x-fd-int-roxy-purgeid"),
                         ("header", "x-cache"), ("server", "ecacc")],
    "F5 Distributed Cloud": [("header", "x-volterra-location"), ("server", "volt-adc")],
    "F5 BIG-IP": [("cookie", "bigipserver"), ("cookie", "ts01"), ("cookie", "f5_cspm"),
                  ("cookie", "lastserver"), ("server", "big-ip")],
    "Vercel": [("header", "x-vercel-id"), ("header", "x-vercel-cache"), ("server", "vercel")],
    "Netlify": [("header", "x-nf-request-id"), ("server", "netlify")],
    "Google Cloud": [("header", "x-goog-"), ("server", "gse"), ("server", "gfe")],
    "DDoS-Guard": [("server", "ddos-guard")],
    "Qrator Labs": [("header", "qrator"), ("server", "qrator")],
    "Sucuri CloudProxy": [("header", "x-sucuri-id")],
    "BunnyCDN": [("header", "cdn-requestid"), ("server", "bunnycdn")],
    "KeyCDN": [("header", "x-edge-location"), ("server", "keycdn")],
    "Gcore": [("server", "gcore")],
    "StackPath": [("server", "stackpath"), ("header", "x-sp-edge")],
    "Section": [("header", "section-io-id")],
    "Reblaze": [("cookie", "rbzid"), ("cookie", "rbzsessionid")],
    "Barracuda WAF": [("cookie", "barra_counter_session")],
    "Wallarm": [("header", "x-wallarm")],
    "Fortinet FortiWeb": [("cookie", "cookiesession1"), ("header", "fortiwafsid")],
    "Citrix NetScaler": [("cookie", "citrix_ns_id"), ("cookie", "ns_af")],
    "Varnish": [("header", "x-varnish"), ("server", "varnish")],
}

# Built-in IPv4/IPv6 prefix hints. Not exhaustive — override or extend via
# signatures/cdn_ranges.json ({provider: [cidr, ...]}). Keep to well-known,
# stable anycast ranges.
_BUILTIN_RANGES = {
    "Cloudflare": ["104.16.0.0/13", "172.64.0.0/13", "131.0.72.0/22", "108.162.192.0/18",
                   "141.101.64.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
                   "198.41.128.0/17", "162.158.0.0/15", "173.245.48.0/20", "103.21.244.0/22",
                   "103.22.200.0/22", "103.31.4.0/22", "2400:cb00::/32", "2606:4700::/32"],
    "Fastly": ["151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16", "2a04:4e40::/32"],
    "F5 Distributed Cloud": ["159.60.0.0/16", "5.182.212.0/22", "84.54.60.0/22", "193.16.236.0/22"],
    "Sucuri": ["192.88.134.0/23", "185.93.228.0/22", "66.248.200.0/22"],
    "Imperva Incapsula": ["45.223.0.0/16", "45.60.0.0/16", "45.64.64.0/22", "199.83.128.0/21",
                          "198.143.32.0/19", "149.126.72.0/21", "103.28.248.0/22"],
}


class CdnMatcher:
    def __init__(self, signatures_dir: Path | None = None):
        self._nets: list[tuple[ipaddress._BaseNetwork, str]] = []
        ranges = dict(_BUILTIN_RANGES)
        if signatures_dir:
            f = signatures_dir / "cdn_ranges.json"
            if f.exists():
                try:
                    extra = json.loads(f.read_text())
                    for prov, cidrs in extra.items():
                        ranges.setdefault(prov, [])
                        ranges[prov].extend(cidrs)
                except Exception:
                    pass
        for prov, cidrs in ranges.items():
            for c in cidrs:
                try:
                    self._nets.append((ipaddress.ip_network(c, strict=False), prov))
                except ValueError:
                    continue

    def by_ip(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, prov in self._nets:
            if addr.version == net.version and addr in net:
                return prov
        return None

    @staticmethod
    def by_cname(chain: list[str]) -> str | None:
        for name in chain:
            n = name.lower().rstrip(".")
            for suffix, prov in CNAME_SUFFIXES.items():
                if n.endswith("." + suffix) or n.endswith(suffix):
                    return prov
        return None

    @staticmethod
    def by_headers(headers: dict[str, str], cookies: list[str]) -> str | None:
        hl = {k.lower(): (v or "").lower() for k, v in headers.items()}
        cl = [c.lower() for c in cookies]
        server = hl.get("server", "")
        for prov, signals in HEADER_SIGNALS.items():
            for kind, needle in signals:
                if kind == "header" and needle in hl:
                    return prov
                if kind == "server" and needle in server:
                    return prov
                if kind == "cookie" and any(ck.startswith(needle) for ck in cl):
                    return prov
        return None

    def detect(self, chain, resolved_ips, headers, cookies):
        """Return (provider_or_'none'_or_'unknown', confidence, evidence[])."""
        evidence: list[str] = []
        votes: dict[str, int] = {}

        p = self.by_cname(chain or [])
        if p:
            votes[p] = votes.get(p, 0) + 2
            evidence.append(f"CNAME chain -> {p}")

        p = self.by_headers(headers or {}, cookies or [])
        if p:
            votes[p] = votes.get(p, 0) + 2
            evidence.append(f"response header/cookie -> {p}")

        for ip in resolved_ips or []:
            p = self.by_ip(ip)
            if p:
                votes[p] = votes.get(p, 0) + 1
                evidence.append(f"IP {ip} in {p} range")

        if not votes:
            # We saw headers but no CDN signal -> likely direct
            if headers:
                return "none", "medium", ["no CDN/WAF signals in DNS or headers"]
            return "unknown", "low", ["not enough signal"]

        best = max(votes, key=votes.get)
        score = votes[best]
        conf = "high" if score >= 3 else ("medium" if score == 2 else "low")
        return best, conf, evidence

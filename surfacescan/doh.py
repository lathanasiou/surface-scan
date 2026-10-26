"""DNS-over-HTTPS resolver (RFC 8484 JSON form).

Used as a fallback when classic UDP/53 is blocked (locked-down networks,
proxied egress) or on demand via --doh. Pure HTTPS, so it works anywhere the
tool can already reach the web.
"""
from __future__ import annotations

import httpx

PROVIDERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/resolve",
}

_TYPE_NUM = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "TXT": 16, "NS": 2, "CAA": 257}


class DohResolver:
    def __init__(self, provider: str = "cloudflare", timeout: float = 5.0):
        self.url = PROVIDERS.get(provider, PROVIDERS["cloudflare"])
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout, headers={"accept": "application/dns-json"})

    def query(self, name: str, rtype: str) -> list[str]:
        try:
            r = self._client.get(self.url, params={"name": name, "type": rtype})
            if r.status_code != 200:
                return []
            data = r.json()
        except (httpx.HTTPError, ValueError):
            return []
        want = _TYPE_NUM.get(rtype)
        out = []
        for ans in data.get("Answer", []) or []:
            if want is None or ans.get("type") == want:
                val = ans.get("data", "").strip()
                if rtype in ("CNAME", "NS") and val.endswith("."):
                    val = val[:-1]
                out.append(val)
        # For CNAME we also want to know if the name itself had only a CNAME answer
        return out

    def has_cname(self, name: str) -> str | None:
        ans = self.query(name, "CNAME")
        return ans[0] if ans else None

    def resolves(self, name: str) -> bool:
        return bool(self.query(name, "A") or self.query(name, "AAAA"))

    def close(self):
        self._client.close()

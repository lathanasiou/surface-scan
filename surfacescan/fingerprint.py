"""Signature-driven technology fingerprinting.

Signatures are data, not code — add a technology by editing YAML, no script
changes. Each signature can match on response headers, cookies, HTML/body
regexes, specific paths' status/body, and the Server header. Version is captured
only when a regex named group `version` is present and matches.

Rules are merged from:
  signatures/base.yaml     (ships with the tool)
  signatures/custom.yaml   (your own additions / overrides)

This gives presence-detection first (your primary need: "is Node.js in use?")
and version when visible (used by advisory matching).
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from .models import Detection, HostResult


class Signature:
    def __init__(self, name: str, spec: dict):
        self.name = name
        self.category = spec.get("category", "other")
        self.confidence = spec.get("confidence", "medium")
        self.headers = {k.lower(): re.compile(v, re.I) for k, v in (spec.get("headers") or {}).items()}
        self.cookies = [re.compile(c, re.I) for c in (spec.get("cookies") or [])]
        self.server = re.compile(spec["server"], re.I) if spec.get("server") else None
        self.html = [re.compile(h, re.I) for h in (spec.get("html") or [])]
        # path rules: list of {path, status?, body?}
        self.paths = spec.get("paths") or []
        self.version_re = re.compile(spec["version"], re.I) if spec.get("version") else None
        self.implies = spec.get("implies") or []

    def match(self, host: HostResult) -> Detection | None:
        headers = {k.lower(): v for k, v in getattr(host, "_headers", {}).items()}
        cookies = getattr(host, "_set_cookie", []) + getattr(host, "_cookies", [])
        pages = getattr(host, "_pages", {}) or {}
        root = pages.get("/", "")

        evidence: list[str] = []
        version: str | None = None

        # headers
        for hk, rx in self.headers.items():
            val = headers.get(hk, "")
            if val and rx.search(val):
                evidence.append(f"header {hk}: {val[:80]}")

        # server header
        if self.server:
            sv = headers.get("server", "")
            if sv and self.server.search(sv):
                evidence.append(f"server: {sv[:80]}")

        # cookies
        for rx in self.cookies:
            for c in cookies:
                if rx.search(c):
                    evidence.append(f"cookie: {c.split('=')[0][:60]}")
                    break

        # html / body on root
        for rx in self.html:
            m = rx.search(root)
            if m:
                evidence.append(f"body matched /{rx.pattern[:50]}/")

        # path rules
        for pr in self.paths:
            p = pr.get("path", "/")
            page = pages.get(p)
            if page is None:
                continue
            ok = True
            if "status" in pr:
                ok = page.startswith(f"[{pr['status']}]")
            if ok and "body" in pr:
                ok = re.search(pr["body"], page, re.I) is not None
            if ok:
                evidence.append(f"path {p} matched")

        if not evidence:
            return None

        # version extraction (search across header values + server + root)
        if self.version_re:
            haystacks = list(headers.values()) + [root[:5000]]
            for h in haystacks:
                m = self.version_re.search(h)
                if m:
                    try:
                        version = m.group("version")
                    except IndexError:
                        version = m.group(0)
                    break

        return Detection(
            name=self.name,
            category=self.category,
            version=version,
            confidence=self.confidence,
            evidence=evidence[:5],
        )


class Fingerprinter:
    def __init__(self, signatures_dir: Path):
        self.signatures: list[Signature] = []
        self._by_name: dict[str, Signature] = {}
        for fname in ("base.yaml", "custom.yaml"):
            f = signatures_dir / fname
            if not f.exists():
                continue
            data = yaml.safe_load(f.read_text()) or {}
            for name, spec in data.items():
                sig = Signature(name, spec or {})
                self.signatures.append(sig)
                self._by_name[name] = sig

    def run(self, host: HostResult) -> HostResult:
        if host.liveness not in {"live", "live_error", "waf_blocked"}:
            return host
        found: dict[str, Detection] = {}
        for sig in self.signatures:
            det = sig.match(host)
            if det:
                found[det.name] = det
        # apply "implies" (e.g. Laravel implies PHP) without overwriting direct hits
        for name, det in list(found.items()):
            sig = self._by_name.get(name)
            if not sig:
                continue
            for imp in sig.implies:
                if imp not in found and imp in self._by_name:
                    isig = self._by_name[imp]
                    found[imp] = Detection(
                        name=imp, category=isig.category, version=None,
                        confidence="low", evidence=[f"implied by {name}"],
                    )
        host.detections = sorted(found.values(), key=lambda d: (d.category, d.name))
        return host

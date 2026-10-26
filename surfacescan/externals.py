"""Optional integration with maintained external tools (ProjectDiscovery).

Auto-detected on PATH. When present and enabled, they add speed and breadth;
when absent, the pure-Python path is used and nothing breaks.

  dnsx   - bulk DNS resolution
  httpx  - liveness + tech-detect + CDN + TLS (Wappalyzer rules)
  nuclei - DETECTION templates only (tags restricted to tech/detect/version);
           never exploit/intrusive templates from this tool.

All are run with subprocess over a temp host-list file; we parse their JSONL.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .models import HostResult, Detection


def available() -> dict[str, str | None]:
    return {t: shutil.which(t) for t in ("dnsx", "httpx", "nuclei")}


def _write_list(hosts: list[str]) -> str:
    f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    f.write("\n".join(hosts))
    f.close()
    return f.name


def httpx_enrich(hosts: list[HostResult], timeout: int = 10, rate: int = 150) -> None:
    """Run ProjectDiscovery httpx and merge status/title/tech/cdn/webserver."""
    bin_ = shutil.which("httpx")
    if not bin_:
        return
    by_name = {h.hostname: h for h in hosts}
    listfile = _write_list(list(by_name))
    cmd = [
        bin_, "-l", listfile, "-json", "-silent", "-no-color",
        "-status-code", "-title", "-tech-detect", "-web-server",
        "-cdn", "-ip", "-cname", "-tls-grab",
        "-timeout", str(timeout), "-rate-limit", str(rate),
        "-follow-redirects",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except (subprocess.TimeoutExpired, OSError):
        Path(listfile).unlink(missing_ok=True)
        return
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = by_name.get(j.get("input", "")) or by_name.get(j.get("host", ""))
        if not host:
            # httpx may report the final host; match by url host
            continue
        sc = j.get("status_code")
        if sc:
            host.status_code = sc
            if host.liveness in {"untested", "filtered"}:
                host.liveness = "live" if 200 <= sc < 400 else "live_error"
        if j.get("title"):
            host.title = host.title or j["title"][:200]
        if j.get("url"):
            host.final_url = host.final_url or j["url"]
        if j.get("webserver"):
            host.server_header = host.server_header or j["webserver"]
        if j.get("cdn_name"):
            if host.cdn_waf in {"unknown", "none"}:
                host.cdn_waf = j["cdn_name"]
                host.cdn_waf_confidence = "high"
                host.cdn_waf_evidence.append("httpx -cdn")
        for tech in j.get("tech", []) or []:
            name, _, ver = tech.partition(":")
            if not any(d.name.lower() == name.lower() for d in host.detections):
                host.detections.append(Detection(
                    name=name, category=_httpx_category(name),
                    version=ver or None, confidence="medium",
                    evidence=["httpx tech-detect"],
                ))
    Path(listfile).unlink(missing_ok=True)


_CATEGORY_HINTS = {
    "php": "language", "node.js": "language", "nodejs": "language", "java": "language",
    "asp.net": "language", "python": "language", "ruby": "language",
    "laravel": "backend", "express": "backend", "next.js": "backend", "nuxt.js": "backend",
    "django": "backend", "spring": "backend", "ruby on rails": "backend",
    "angular": "frontend", "react": "frontend", "vue.js": "frontend", "svelte": "frontend",
    "wordpress": "cms", "drupal": "cms", "joomla": "cms",
    "nginx": "server", "apache": "server", "apache http server": "server",
    "iis": "server", "microsoft-iis": "server", "litespeed": "server", "caddy": "server",
}


def _httpx_category(name: str) -> str:
    return _CATEGORY_HINTS.get(name.strip().lower(), "other")


def nuclei_detect(hosts: list[HostResult], timeout: int = 10) -> None:
    """Run nuclei DETECTION templates only (safe). Adds detections; no exploits."""
    bin_ = shutil.which("nuclei")
    if not bin_:
        return
    targets = [f"{h.scheme or 'https'}://{h.hostname}" for h in hosts
               if h.liveness in {"live", "live_error"}]
    if not targets:
        return
    by_name = {h.hostname: h for h in hosts}
    listfile = _write_list(targets)
    cmd = [
        bin_, "-l", listfile, "-jsonl", "-silent", "-no-color",
        # Detection only. Explicitly restrict to tech/detect tags; exclude intrusive.
        "-tags", "tech,detect,favicon,waf",
        "-severity", "info,low",
        "-exclude-tags", "intrusive,dos,fuzz,sqli,rce,lfi,xss",
        "-rate-limit", "100", "-timeout", str(timeout),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except (subprocess.TimeoutExpired, OSError):
        Path(listfile).unlink(missing_ok=True)
        return
    for line in proc.stdout.splitlines():
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        host_field = (j.get("host") or "").replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        host = by_name.get(host_field)
        if not host:
            continue
        info = j.get("info", {})
        name = info.get("name", j.get("template-id", "nuclei"))
        if not any(d.name.lower() == name.lower() for d in host.detections):
            host.detections.append(Detection(
                name=name, category="other", version=None,
                confidence="medium", evidence=[f"nuclei: {j.get('template-id','')}"],
            ))
    Path(listfile).unlink(missing_ok=True)

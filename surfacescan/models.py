"""Shared data structures."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Detection:
    """A single technology detected on a host, with evidence."""
    name: str                       # e.g. "PHP", "Node.js", "Angular"
    category: str                   # language | backend | frontend | cms | server | cdn_waf | analytics
    version: str | None = None      # only when observable
    confidence: str = "medium"      # low | medium | high
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HostResult:
    """Everything learned about one hostname."""
    hostname: str
    record_type: str = ""           # A | CNAME | (from input)
    record_target: str = ""         # as published in DNS input

    # DNS
    cname_chain: list[str] = field(default_factory=list)
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    caa: list[str] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    asn: str = ""
    asn_org: str = ""
    dns_notes: list[str] = field(default_factory=list)   # dangling, private-IP-in-public-dns, wildcard...

    # Edge
    cdn_waf: str = "unknown"        # provider name | none | unknown
    cdn_waf_confidence: str = "low"
    cdn_waf_evidence: list[str] = field(default_factory=list)
    classification: str = "unknown"  # own-infra | third-party-saas | suspicious | unknown

    # Liveness / HTTP
    liveness: str = "untested"      # live | live_error | waf_blocked | filtered | refused | dns_fail | dangling | untested
    open_ports: list[int] = field(default_factory=list)
    scheme: str = ""                # http | https (whichever answered)
    status_code: int | None = None
    final_url: str = ""
    title: str = ""
    response_ms: int | None = None
    server_header: str = ""

    # TLS
    tls_issuer: str = ""
    tls_not_after: str = ""
    tls_notes: list[str] = field(default_factory=list)

    # Fingerprint
    detections: list[Detection] = field(default_factory=list)

    # Advisory verdicts, keyed by advisory id -> {verdict, reason, action}
    advisories: dict[str, dict[str, str]] = field(default_factory=dict)

    error: str = ""

    def tech_by_category(self, category: str) -> list[Detection]:
        return [d for d in self.detections if d.category == category]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["detections"] = [x.to_dict() for x in self.detections]
        return d

"""Optional advisory matching.

An advisory is a YAML profile naming a technology and the affected version
ranges. Against the stored fingerprints it produces a verdict per host:

  affected       tech present AND version confirmed in an affected range
  likely         tech present, version unknown, and any exposure hint is met
  possible       tech present, version unknown
  not-detected   tech not detected and host answered normally
  unknown        host blocked by WAF / unreachable -> no conclusion

No exploitation. This is version/inventory correlation only. For memory-safety
bugs the honest default is "possible/likely -> confirm with the asset owner",
never an active vulnerability test.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from packaging.version import Version, InvalidVersion

from .models import HostResult


class Advisory:
    def __init__(self, spec: dict):
        self.id = spec["id"]
        self.name = spec.get("name", self.id)
        self.tech = spec["tech"]                       # must match a Detection.name
        self.affected = spec.get("affected", [])       # list of "op ver" specs joined
        self.exposure_hints = spec.get("exposure_hints", [])
        self.action = spec.get("action", "Patch / confirm with asset owner.")

    @classmethod
    def load(cls, path: str | Path) -> "Advisory":
        return cls(yaml.safe_load(Path(path).read_text()))

    @classmethod
    def load_dir(cls, directory: str | Path) -> dict[str, "Advisory"]:
        out = {}
        for f in Path(directory).glob("*.y*ml"):
            try:
                a = cls.load(f)
                out[a.id] = a
            except Exception:
                continue
        return out

    def _version_affected(self, version: str) -> bool | None:
        try:
            v = Version(version)
        except InvalidVersion:
            return None
        for rng in self.affected:
            if self._in_range(v, rng):
                return True
        return False

    @staticmethod
    def _in_range(v: Version, rng: str) -> bool:
        # rng like ">=22.0.0,<22.23.4" or "<8.2.35"
        for clause in rng.split(","):
            clause = clause.strip()
            for op in (">=", "<=", "==", "!=", ">", "<"):
                if clause.startswith(op):
                    bound = clause[len(op):].strip()
                    try:
                        b = Version(bound)
                    except InvalidVersion:
                        return False
                    if op == ">=" and not v >= b: return False
                    if op == "<=" and not v <= b: return False
                    if op == ">" and not v > b: return False
                    if op == "<" and not v < b: return False
                    if op == "==" and not v == b: return False
                    if op == "!=" and not v != b: return False
                    break
        return True

    def evaluate(self, host: HostResult) -> dict[str, str]:
        det = next((d for d in host.detections if d.name == self.tech), None)
        if det is None:
            if host.liveness in {"waf_blocked", "filtered", "refused", "untested"}:
                return {"verdict": "unknown",
                        "reason": f"{self.tech} not observed but host is {host.liveness}",
                        "action": "Confirm from an allowlisted scan or ask the owner."}
            return {"verdict": "not-detected",
                    "reason": f"{self.tech} not detected; host answered normally",
                    "action": "Low priority."}

        if det.version:
            hit = self._version_affected(det.version)
            if hit is True:
                return {"verdict": "affected",
                        "reason": f"{self.tech} {det.version} is in an affected range",
                        "action": self.action}
            if hit is False:
                return {"verdict": "not-detected",
                        "reason": f"{self.tech} {det.version} is not in an affected range",
                        "action": "Patched / not affected."}

        # tech present, version unknown
        if self.exposure_hints:
            met = [h for h in self.exposure_hints if h in getattr(host, "_exposure", set())]
            if met:
                return {"verdict": "likely",
                        "reason": f"{self.tech} present (version unknown); exposure hint(s): {', '.join(met)}",
                        "action": self.action}
        return {"verdict": "possible",
                "reason": f"{self.tech} present; version not observable externally",
                "action": "Confirm the running version with the asset owner."}

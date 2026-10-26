"""SQLite history so runs can be diffed and advisories re-run offline
(--from-last-run) without sending any new traffic.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .models import HostResult, Detection


class Store:
    def __init__(self, path: str | Path = "output/history.sqlite"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at REAL,
                note TEXT
            )""")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS results (
                run_id INTEGER,
                hostname TEXT,
                data TEXT
            )""")
        self.conn.commit()

    def new_run(self, note: str = "") -> int:
        cur = self.conn.execute("INSERT INTO runs(started_at, note) VALUES (?,?)",
                                (time.time(), note))
        self.conn.commit()
        return cur.lastrowid

    def save(self, run_id: int, hosts: list[HostResult]):
        for h in hosts:
            self.conn.execute("INSERT INTO results(run_id, hostname, data) VALUES (?,?,?)",
                              (run_id, h.hostname, json.dumps(h.to_dict())))
        self.conn.commit()

    def last_run_id(self) -> int | None:
        row = self.conn.execute("SELECT MAX(run_id) FROM results").fetchone()
        return row[0] if row and row[0] is not None else None

    def load_run(self, run_id: int) -> list[HostResult]:
        rows = self.conn.execute("SELECT data FROM results WHERE run_id=?", (run_id,)).fetchall()
        out = []
        for (data,) in rows:
            d = json.loads(data)
            dets = [Detection(**x) for x in d.pop("detections", [])]
            h = HostResult(**{k: v for k, v in d.items() if k in HostResult.__dataclass_fields__})
            h.detections = dets
            out.append(h)
        return out

    def diff_previous(self, hosts: list[HostResult]) -> list[str]:
        """Return human-readable changes vs the previous run."""
        prev_id = None
        rows = self.conn.execute("SELECT DISTINCT run_id FROM results ORDER BY run_id DESC").fetchall()
        ids = [r[0] for r in rows]
        if len(ids) < 2:
            return []
        prev_id = ids[1]
        prev = {h.hostname: h for h in self.load_run(prev_id)}
        changes = []
        for h in hosts:
            p = prev.get(h.hostname)
            if not p:
                changes.append(f"NEW host: {h.hostname}")
                continue
            if p.liveness != h.liveness:
                changes.append(f"{h.hostname}: liveness {p.liveness} -> {h.liveness}")
            old_tech = {d.name for d in p.detections}
            new_tech = {d.name for d in h.detections}
            for t in new_tech - old_tech:
                changes.append(f"{h.hostname}: NEW tech {t}")
            for t in old_tech - new_tech:
                changes.append(f"{h.hostname}: tech gone {t}")
            if p.cdn_waf != h.cdn_waf:
                changes.append(f"{h.hostname}: CDN/WAF {p.cdn_waf} -> {h.cdn_waf}")
        cur_hosts = {h.hostname for h in hosts}
        for name in prev:
            if name not in cur_hosts:
                changes.append(f"GONE host: {name}")
        return changes

    def close(self):
        self.conn.close()

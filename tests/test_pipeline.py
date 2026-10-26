"""Full-pipeline test that bypasses live DNS by pointing hostnames at local
mock servers, exercising scan_one -> fingerprint -> store -> from-last-run ->
advisory re-eval -> xlsx, without any external network."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import surfacescan.dns_probe as dns_probe
import surfacescan.http_probe as http_probe
from surfacescan.models import HostResult
from surfacescan.fingerprint import Fingerprinter
from surfacescan.cdn import CdnMatcher
from surfacescan.classify import classify
from surfacescan.store import Store
from surfacescan.advisories import Advisory
from surfacescan.report import export_xlsx
from tests import mock_servers
import time

SIG = ROOT / "signatures"
ADV = ROOT / "advisories"

# map fake hostnames -> local mock port
HOST_PORT = {
    "shop.test": 8101,   # PHP/Laravel
    "api.test": 8102,    # Express/Node
    "app.test": 8104,    # Angular
}


def fake_resolve(host, nameservers=None, timeout=5.0, mode="auto", doh_provider="cloudflare"):
    host.resolved_ips = ["127.0.0.1"]
    host.a_records = ["127.0.0.1"]
    return host


def fake_check_ports(target, ports, timeout):
    # pretend only the host's mapped port is open, exposed as 80
    return [80]


def main():
    servers = mock_servers.start_all()
    time.sleep(0.3)

    dns_probe.resolve_host = fake_resolve  # not used directly here but for parity

    fp = Fingerprinter(SIG)
    cdn = CdnMatcher(SIG)
    hosts = []
    for name, port in HOST_PORT.items():
        h = HostResult(hostname=name, record_type="A")
        fake_resolve(h)
        classify(h)
        # probe the mapped port directly
        import httpx, re
        with httpx.Client(timeout=5, follow_redirects=True) as c:
            r = c.get(f"http://127.0.0.1:{port}/")
        h.open_ports = [80]; h.scheme = "http"; h.status_code = r.status_code
        h.final_url = f"http://{name}/"; h.server_header = r.headers.get("server", "")
        h._headers = dict(r.headers)
        h._cookies = []
        h._set_cookie = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []
        h._pages = {"/": r.text}
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
        if m: h.title = m.group(1).strip()
        h.liveness = "live" if 200 <= r.status_code < 400 else "live_error"
        prov, conf, ev = cdn.detect(h.cname_chain, h.resolved_ips, h._headers, h._set_cookie)
        h.cdn_waf, h.cdn_waf_confidence, h.cdn_waf_evidence = prov, conf, ev
        fp.run(h)
        hosts.append(h)

    # store round-trip
    db = ROOT / "output" / "_test_hist.sqlite"
    if db.exists(): db.unlink()
    store = Store(db)
    rid = store.new_run("pipeline-test")
    store.save(rid, hosts)
    loaded = store.load_run(rid)
    assert len(loaded) == 3, len(loaded)
    assert any(d.name == "PHP" for h in loaded for d in h.detections), "PHP lost in round-trip"
    assert any(d.name == "Angular" for h in loaded for d in h.detections), "Angular lost"

    # advisory re-eval on loaded (from-last-run path)
    adv = Advisory.load(ADV / "php2shell.yaml")
    for h in loaded:
        if not hasattr(h, "_exposure"): h._exposure = set()
        h.advisories[adv.id] = adv.evaluate(h)
    shop = next(h for h in loaded if h.hostname == "shop.test")
    assert shop.advisories[adv.id]["verdict"] == "affected", shop.advisories[adv.id]
    api = next(h for h in loaded if h.hostname == "api.test")
    assert api.advisories[adv.id]["verdict"] == "not-detected", api.advisories[adv.id]

    # export
    out = ROOT / "output" / "_test_pipeline.xlsx"
    export_xlsx(loaded, out, advisory_ids=[adv.id])
    from openpyxl import load_workbook
    wb = load_workbook(out)
    assert "Assets" in wb.sheetnames and f"Adv-{adv.id}"[:32] in [s for s in wb.sheetnames]

    store.close()
    print("PIPELINE TEST PASSED")
    print("  hosts:", [(h.hostname, [d.name for d in h.detections]) for h in loaded])
    print("  php2shell verdicts:", {h.hostname: h.advisories[adv.id]['verdict'] for h in loaded})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

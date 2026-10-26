"""End-to-end + unit tests. Run: python tests/test_e2e.py"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from surfacescan.models import HostResult
from surfacescan.http_probe import probe_http
from surfacescan.fingerprint import Fingerprinter
from surfacescan.cdn import CdnMatcher
from surfacescan.advisories import Advisory
from surfacescan.inputs import load_records
from surfacescan.classify import classify
from tests import mock_servers

SIG = ROOT / "signatures"
ADV = ROOT / "advisories"

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


def probe_localhost(port):
    h = HostResult(hostname="localhost")
    h.resolved_ips = ["127.0.0.1"]
    probe_http(h, timeout=5, user_agent="test", extra_ports=False, fetch_paths=False)
    # repoint URL host to 127.0.0.1:port isn't needed; but probe used port set.
    return h


def probe_port(port):
    """Probe a specific localhost port directly."""
    import httpx, re
    h = HostResult(hostname="127.0.0.1")
    h.resolved_ips = ["127.0.0.1"]
    url = f"http://127.0.0.1:{port}/"
    start = time.perf_counter()
    with httpx.Client(timeout=5, follow_redirects=True) as c:
        r = c.get(url)
    h.open_ports = [port]
    h.status_code = r.status_code
    h.scheme = "http"
    h.final_url = str(r.url)
    h.response_ms = int((time.perf_counter() - start) * 1000)
    h.server_header = r.headers.get("server", "")
    h._headers = dict(r.headers)
    h._cookies = [f"{k}={v}" for k, v in r.cookies.items()]
    h._set_cookie = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []
    m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
    if m:
        h.title = m.group(1).strip()
    h._pages = {"/": r.text}
    from surfacescan.http_probe import _looks_like_waf_block
    if _looks_like_waf_block(r, r.text):
        h.liveness = "waf_blocked"
    elif 200 <= r.status_code < 400:
        h.liveness = "live"
    else:
        h.liveness = "live_error"
    return h


def main():
    print("Starting mock servers...")
    servers = mock_servers.start_all()
    time.sleep(0.5)
    fp = Fingerprinter(SIG)
    cdn = CdnMatcher(SIG)

    def tech_names(h):
        return {d.name for d in h.detections}

    print("\n[1] PHP/Laravel on nginx (port 8101)")
    h = probe_port(8101); fp.run(h)
    names = tech_names(h)
    check("liveness live", h.liveness == "live", h.liveness)
    check("detects PHP", "PHP" in names, names)
    check("PHP version 8.3.11", any(d.name == "PHP" and d.version == "8.3.11" for d in h.detections),
          [(d.name, d.version) for d in h.detections])
    check("detects Laravel", "Laravel" in names, names)
    check("detects nginx", "nginx" in names, names)

    print("\n[2] Node/Express (port 8102)")
    h = probe_port(8102); fp.run(h)
    names = tech_names(h)
    check("detects Express", "Express" in names, names)
    check("Express implies Node.js", "Node.js" in names, names)

    print("\n[3] Next.js (port 8103)")
    h = probe_port(8103); fp.run(h)
    names = tech_names(h)
    check("detects Next.js", "Next.js" in names, names)
    check("Next implies Node.js", "Node.js" in names, names)
    check("Next implies React", "React" in names, names)

    print("\n[4] Angular on Apache (port 8104)")
    h = probe_port(8104); fp.run(h)
    names = tech_names(h)
    check("detects Angular", "Angular" in names, names)
    check("Angular version 17.3.2", any(d.name == "Angular" and d.version == "17.3.2" for d in h.detections),
          [(d.name, d.version) for d in h.detections])
    check("detects Apache", "Apache" in names, names)
    check("Angular is frontend category", any(d.name == "Angular" and d.category == "frontend" for d in h.detections))

    print("\n[5] WordPress (port 8105)")
    h = probe_port(8105); fp.run(h)
    names = tech_names(h)
    check("detects WordPress", "WordPress" in names, names)
    check("WP version 6.5.2", any(d.name == "WordPress" and d.version == "6.5.2" for d in h.detections),
          [(d.name, d.version) for d in h.detections])
    check("WP implies PHP", "PHP" in names, names)

    print("\n[6] Cloudflare WAF block (port 8106)")
    h = probe_port(8106)
    headers = h._headers; cookies = h._set_cookie
    prov, conf, ev = cdn.detect([], [], headers, cookies)
    check("liveness waf_blocked", h.liveness == "waf_blocked", h.liveness)
    check("CDN detected Cloudflare", prov == "Cloudflare", prov)

    print("\n[7] CDN by CNAME chain")
    prov = CdnMatcher.by_cname(["d123.cloudfront.net"])
    check("cloudfront via cname", prov == "Amazon CloudFront", prov)
    prov = CdnMatcher.by_cname(["x.akamaiedge.net"])
    check("akamai via cname", prov == "Akamai", prov)

    print("\n[8] CDN by IP range (Cloudflare 104.16.x)")
    check("cloudflare ip", cdn.by_ip("104.16.5.5") == "Cloudflare", cdn.by_ip("104.16.5.5"))

    print("\n[9] Advisory: PHP2Shell version matching")
    adv = Advisory.load(ADV / "php2shell.yaml")
    hv = HostResult(hostname="a")
    from surfacescan.models import Detection
    hv.detections = [Detection(name="PHP", category="language", version="8.3.11")]
    hv.liveness = "live"
    v = adv.evaluate(hv)
    check("PHP 8.3.11 affected", v["verdict"] == "affected", v)
    hv.detections = [Detection(name="PHP", category="language", version="8.3.36")]
    v = adv.evaluate(hv)
    check("PHP 8.3.36 not affected", v["verdict"] == "not-detected", v)
    hv.detections = [Detection(name="PHP", category="language", version=None)]
    v = adv.evaluate(hv)
    check("PHP no version -> possible", v["verdict"] == "possible", v)
    hv.detections = [Detection(name="PHP", category="language", version="8.1.9")]
    v = adv.evaluate(hv)
    check("PHP 8.1.9 (EOL) affected", v["verdict"] == "affected", v)

    print("\n[10] Advisory: Node waf_blocked -> unknown")
    adv2 = Advisory.load(ADV / "nodejs-brotli.yaml")
    hb = HostResult(hostname="b"); hb.liveness = "waf_blocked"
    v = adv2.evaluate(hb)
    check("node behind waf -> unknown", v["verdict"] == "unknown", v)

    print("\n[11] Input parsing (CSV with header)")
    tmp = ROOT / "output" / "_test_records.csv"
    tmp.write_text("hostname,type,target\nwww.example.com,A,1.2.3.4\napi.example.com,CNAME,x.cloudfront.net\n# comment\nwww.example.com,A,1.2.3.4\n")
    recs = load_records(tmp)
    check("parsed 2 unique rows", len(recs) == 2, len(recs))
    check("cname target captured", any(r.record_target == "x.cloudfront.net" for r in recs))
    tmp.unlink()

    print("\n[12] Classification: SaaS target")
    hs = HostResult(hostname="help.example.com")
    hs.cname_chain = ["example.zendesk.com"]; hs.resolved_ips = ["1.1.1.1"]
    classify(hs)
    check("zendesk -> third-party-saas", hs.classification == "third-party-saas", hs.classification)

    print("\n[13] CDN: F5 Distributed Cloud (ves.io) detected")
    prov = CdnMatcher.by_cname(["ves-io-abc123.ac.vh.ves.io"])
    check("ves.io -> F5 Distributed Cloud", prov == "F5 Distributed Cloud", prov)
    check("F5 XC anycast IP in range", cdn.by_ip("159.60.131.238") == "F5 Distributed Cloud",
          cdn.by_ip("159.60.131.238"))

    print("\n[14] Classification: more SaaS builders / status pages")
    for cname, label in [("usersites.strikinglydns.com", "strikingly"),
                         ("stats.uptimerobot.com", "uptimerobot"),
                         ("proxy.webflow.com", "webflow"),
                         ("shops.myshopify.com", "shopify")]:
        h = HostResult(hostname=f"x-{label}.example.com")
        h.cname_chain = [cname]; h.resolved_ips = ["1.1.1.1"]
        classify(h)
        check(f"{label} -> third-party-saas", h.classification == "third-party-saas", h.classification)

    print("\n[15] Deploy-your-code platforms are NOT skipped (own-infra)")
    for cname, label in [("cname.vercel-dns.com", "vercel"),
                         ("app.netlify.app", "netlify"),
                         ("x.herokudns.com", "heroku")]:
        h = HostResult(hostname=f"app-{label}.example.com")
        h.cname_chain = [cname]; h.resolved_ips = ["1.1.1.1"]
        classify(h)
        check(f"{label} -> own-infra (probed)", h.classification == "own-infra", h.classification)

    print("\n[16] Laravel does NOT fire on generic XSRF-TOKEN alone")
    hx = HostResult(hostname="rails.test"); hx.liveness = "live"
    hx._headers = {}; hx._cookies = []
    hx._set_cookie = ["XSRF-TOKEN=abc; path=/", "_bobcat_session=xyz; path=/"]
    hx._pages = {"/": "<html></html>"}
    fp.run(hx)
    names = {d.name for d in hx.detections}
    check("no false Laravel from XSRF-TOKEN", "Laravel" not in names, names)
    check("Rails still detected (_bobcat_session)", "Ruby on Rails" in names, names)

    print("\n[17] laravel_session still detects Laravel")
    hl = HostResult(hostname="laravel.test"); hl.liveness = "live"
    hl._headers = {"x-powered-by": "PHP/8.3.11"}; hl._cookies = []
    hl._set_cookie = ["laravel_session=abc; path=/"]
    hl._pages = {"/": "<html></html>"}
    fp.run(hl)
    names = {d.name for d in hl.detections}
    check("laravel_session -> Laravel", "Laravel" in names, names)
    check("PHP still detected", "PHP" in names, names)

    print(f"\n==== {PASS} passed, {FAIL} failed ====")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())

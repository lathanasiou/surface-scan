#!/usr/bin/env python3
"""
surface-scan — defensive external attack-surface inventory.

Reads a list of DNS records you own and reports, per host:
  - DNS (A/AAAA/CNAME chain/MX/TXT/NS/CAA + hygiene flags)
  - liveness (live / live_error / waf_blocked / filtered / refused / dangling / dns_fail)
  - CDN/WAF in front (auto-detected) and whether the app has none
  - technologies in use (language/runtime, backend, frontend, CMS, server) with
    version when externally visible
  - optional per-advisory verdict (version/inventory correlation only)

Inventory only. No exploitation, no WAF-bypass, no exploit probes.

AUTHORISED USE ONLY: run this against assets your organisation owns or is
explicitly authorised to assess, from an approved source IP, with your SOC
informed. You are responsible for staying within scope.

Examples:
  python scan.py --input records.csv
  python scan.py --input records.csv --tech nodejs,angular,php
  python scan.py --input records.csv --advisory php2shell --advisory nodejs-brotli
  python scan.py --from-last-run --advisory php2shell        # no new traffic
  python scan.py --input records.csv --use-external          # use dnsx/httpx if installed
"""
from __future__ import annotations

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from surfacescan import __version__
from surfacescan.inputs import load_records
from surfacescan.dns_probe import resolve_host
from surfacescan.http_probe import probe_http
from surfacescan.cdn import CdnMatcher
from surfacescan.classify import classify
from surfacescan.fingerprint import Fingerprinter
from surfacescan.advisories import Advisory
from surfacescan.store import Store
from surfacescan.report import export_xlsx, export_json
from surfacescan import externals

HERE = Path(__file__).parent
SIG_DIR = HERE / "signatures"
ADV_DIR = HERE / "advisories"

BANNER = r"""
   ___ _   _ _ __ / _| __ _  ___ ___        ___  ___ __ _ _ __
  / __| | | | '__| |_ / _` |/ __/ _ \ _____/ __|/ __/ _` | '_ \
  \__ \ |_| | |  |  _| (_| | (_|  __/|_____\__ \ (_| (_| | | | |
  |___/\__,_|_|  |_|  \__,_|\___\___|      |___/\___\__,_|_| |_|
"""

INPUT_HELP = """\
INPUT FILE FORMAT (CSV / XLSX / TXT)
------------------------------------
One DNS record per line. A header row is recommended. The only required
column is the hostname; `type` and `target` are optional (the tool resolves
DNS itself).

  hostname,type,target
  www.yourco.com,A,203.0.113.10
  api.yourco.com,CNAME,d123.cloudfront.net
  help.yourco.com,CNAME,yourco.zendesk.com

Minimal form (just hostnames, one per line) also works:

  hostname
  www.yourco.com
  api.yourco.com

Notes:
  * One hostname (FQDN) per row — each subdomain is its own line.
  * Column names are flexible: host/fqdn/name/domain (hostname),
    record_type/rtype (type), value/data/content/ip/cname (target).
  * No scheme needed (write www.yourco.com, not https://www.yourco.com/).
  * Blank lines and lines starting with # are ignored; duplicates removed.
  * A DNS-provider or crt.sh export usually works as-is.

EXAMPLES
  python scan.py --input records.csv
  python scan.py --input records.csv --tech nodejs,angular,php
  python scan.py --input records.csv --advisory php2shell --advisory nodejs-brotli
  python scan.py --from-last-run --advisory php2shell        # no new traffic
"""


def print_banner(args):
    if getattr(args, "no_banner", False):
        return
    # ANSI colour only when writing to a real terminal
    tty = sys.stderr.isatty()
    c = "\033[36m" if tty else ""      # cyan
    d = "\033[2m" if tty else ""       # dim
    r = "\033[0m" if tty else ""       # reset
    print(f"{c}{BANNER}{r}", file=sys.stderr)
    print(f"  {d}v{__version__}  ·  defensive external attack-surface inventory{r}", file=sys.stderr)
    print(f"  {d}inventory only — no exploitation · authorised assets only, SOC informed{r}", file=sys.stderr)
    print(file=sys.stderr)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Defensive external attack-surface inventory.",
        epilog=INPUT_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", "-i", help="record list (CSV / XLSX / TXT)")
    src.add_argument("--from-last-run", action="store_true",
                     help="re-evaluate the last stored run (no new traffic)")

    p.add_argument("--advisory", "-a", action="append", default=[],
                   help="advisory id or file (repeatable). Bare name resolves in advisories/")
    p.add_argument("--tech", help="comma-separated technologies to highlight in a filtered sheet")

    p.add_argument("--out", "-o", default="output/surface-scan",
                   help="output path prefix (a timestamp is appended to each file)")
    p.add_argument("--no-timestamp", action="store_true",
                   help="do not append a timestamp to output filenames")
    p.add_argument("--db", default="output/history.sqlite", help="sqlite history file")
    p.add_argument("--signatures-dir", default=str(SIG_DIR),
                   help="directory of signature YAML files (default: bundled)")
    p.add_argument("--advisories-dir", default=str(ADV_DIR),
                   help="directory of advisory YAML files (default: bundled)")

    p.add_argument("--threads", type=int, default=40, help="concurrent hosts (default 40)")
    p.add_argument("--timeout", type=float, default=8.0, help="per-request timeout seconds")
    p.add_argument("--rps", type=float, default=5.0, help="max requests/sec per host (politeness)")
    p.add_argument("--nameservers", help="comma-separated resolvers (default system)")
    p.add_argument("--dns-mode", choices=["auto", "udp", "doh"], default="auto",
                   help="auto=UDP then DoH fallback; udp=classic only; doh=DNS-over-HTTPS only")
    p.add_argument("--doh-provider", choices=["cloudflare", "google"], default="cloudflare")
    p.add_argument("--user-agent",
                   default=f"surface-scan/{__version__} (authorised asset inventory)")

    p.add_argument("--extra-ports", action="store_true",
                   help="also TCP-probe admin/DB ports on DIRECT hosts (not via CDN)")
    p.add_argument("--fetch-paths", action="store_true",
                   help="fetch a few benign framework paths to strengthen fingerprinting")
    p.add_argument("--skip-saas-probe", action="store_true", default=True,
                   help="do not HTTP/port probe third-party SaaS targets (default on)")

    p.add_argument("--use-external", action="store_true",
                   help="use dnsx/httpx if on PATH (speed + Wappalyzer rules)")
    p.add_argument("--use-nuclei", action="store_true",
                   help="run nuclei DETECTION templates only (safe tags) if on PATH")

    p.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    p.add_argument("--version", action="version", version=f"surface-scan {__version__}")
    return p.parse_args(argv)


def resolve_advisories(names: list[str], adv_dir: Path) -> dict[str, Advisory]:
    out: dict[str, Advisory] = {}
    for n in names:
        path = Path(n)
        if path.exists():
            a = Advisory.load(path)
            out[a.id] = a
            continue
        # try advisories/<name>.yaml
        for cand in (adv_dir / f"{n}.yaml", adv_dir / f"{n}.yml"):
            if cand.exists():
                a = Advisory.load(cand)
                out[a.id] = a
                break
        else:
            # maybe it's an advisory id already in the dir
            allf = Advisory.load_dir(adv_dir)
            if n in allf:
                out[n] = allf[n]
            else:
                print(f"[warn] advisory not found: {n}", file=sys.stderr)
    return out


def scan_one(host, cdn_matcher, fp, args, nameservers):
    delay = 1.0 / args.rps if args.rps > 0 else 0
    try:
        resolve_host(host, nameservers=nameservers, timeout=args.timeout,
                     mode=args.dns_mode, doh_provider=args.doh_provider)
        classify(host)

        skip = args.skip_saas_probe and host.classification == "third-party-saas"
        if not skip and host.liveness not in {"dns_fail", "dangling"}:
            probe_http(host, timeout=args.timeout, user_agent=args.user_agent,
                       extra_ports=args.extra_ports, fetch_paths=args.fetch_paths)
            # CDN/WAF detection using DNS + headers + IP ranges
            headers = getattr(host, "_headers", {})
            cookies = getattr(host, "_set_cookie", []) + getattr(host, "_cookies", [])
            prov, conf, ev = cdn_matcher.detect(host.cname_chain, host.resolved_ips, headers, cookies)
            host.cdn_waf, host.cdn_waf_confidence = prov, conf
            host.cdn_waf_evidence = ev
            # re-classify now that we know CDN (SaaS detection relies on CNAME, already done)
            fp.run(host)
        else:
            # still try CDN by CNAME/IP even without HTTP
            prov, conf, ev = cdn_matcher.detect(host.cname_chain, host.resolved_ips, {}, [])
            host.cdn_waf, host.cdn_waf_confidence, host.cdn_waf_evidence = prov, conf, ev
        time.sleep(delay)
    except Exception as e:  # never let one host kill the run
        host.error = f"{type(e).__name__}: {e}"
    return host


def main(argv=None):
    args = parse_args(argv)
    print_banner(args)
    nameservers = args.nameservers.split(",") if args.nameservers else None
    sig_dir = Path(args.signatures_dir)
    adv_dir = Path(args.advisories_dir)
    store = Store(args.db)
    advisories = resolve_advisories(args.advisory, adv_dir)

    if args.from_last_run:
        rid = store.last_run_id()
        if rid is None:
            print("No previous run stored.", file=sys.stderr)
            return 2
        hosts = store.load_run(rid)
        print(f"Loaded {len(hosts)} hosts from run {rid} (no new traffic).")
    else:
        try:
            hosts = load_records(args.input)
        except FileNotFoundError:
            print(f"Input file not found: {args.input}\n", file=sys.stderr)
            print("Run 'python scan.py --help' to see the expected CSV format.", file=sys.stderr)
            return 2
        if not hosts:
            print(f"No valid hostnames found in {args.input}.\n", file=sys.stderr)
            print("Expected one hostname per row. See the CSV format:\n", file=sys.stderr)
            print(INPUT_HELP, file=sys.stderr)
            return 2
        print(f"Loaded {len(hosts)} hosts. Scanning with {args.threads} threads "
              f"(timeout {args.timeout}s, {args.rps} rps/host)...")
        print("AUTHORISED USE ONLY — ensure these assets are in scope.\n")

        cdn_matcher = CdnMatcher(sig_dir)
        fp = Fingerprinter(sig_dir)

        done = 0
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = {ex.submit(scan_one, h, cdn_matcher, fp, args, nameservers): h for h in hosts}
            for fut in as_completed(futs):
                done += 1
                h = fut.result()
                if done % 10 == 0 or done == len(hosts):
                    print(f"  {done}/{len(hosts)} ...")

        # optional external enrichment
        avail = externals.available()
        if args.use_external and (avail["httpx"] or avail["dnsx"]):
            print("Enriching with external tools:",
                  ", ".join(k for k, v in avail.items() if v) or "none")
            if avail["httpx"]:
                externals.httpx_enrich(hosts, timeout=int(args.timeout))
        if args.use_nuclei and avail["nuclei"]:
            print("Running nuclei detection templates (safe tags only)...")
            externals.nuclei_detect(hosts, timeout=int(args.timeout))

        rid = store.new_run(note=args.input)
        store.save(rid, hosts)

    # advisory evaluation (also builds host._exposure placeholder set)
    for h in hosts:
        if not hasattr(h, "_exposure"):
            h._exposure = set()  # type: ignore[attr-defined]
    for aid, adv in advisories.items():
        for h in hosts:
            h.advisories[aid] = adv.evaluate(h)

    # outputs — timestamped filenames (local time) unless --no-timestamp
    if args.no_timestamp:
        prefix = args.out
    else:
        ts = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        prefix = f"{args.out}-{ts}"
    xlsx_path = f"{prefix}.xlsx"
    json_path = f"{prefix}.json"
    export_xlsx(hosts, xlsx_path, advisory_ids=list(advisories))
    export_json(hosts, json_path)

    # console summary
    from collections import Counter
    live = Counter(h.liveness for h in hosts)
    print("\n=== Summary ===")
    print("Liveness:", dict(live))
    print("CDN/WAF:", dict(Counter(h.cdn_waf for h in hosts)))
    langs = Counter()
    for h in hosts:
        for d in h.tech_by_category("language"):
            langs[d.name] += 1
    print("Languages/runtimes:", dict(langs))

    if args.tech:
        wanted = {t.strip().lower() for t in args.tech.split(",")}
        print(f"\nHosts matching {sorted(wanted)}:")
        for h in hosts:
            names = {d.name.lower() for d in h.detections}
            hit = wanted & names
            if hit:
                print(f"  {h.hostname}  ->  {', '.join(sorted(hit))}  [{h.liveness}, cdn={h.cdn_waf}]")

    for aid in advisories:
        verdicts = Counter(h.advisories.get(aid, {}).get("verdict", "n/a") for h in hosts)
        print(f"\nAdvisory {aid}: {dict(verdicts)}")
        for h in hosts:
            v = h.advisories.get(aid, {})
            if v.get("verdict") in {"affected", "likely"}:
                print(f"  [{v['verdict'].upper()}] {h.hostname} — {v['reason']}")

    changes = store.diff_previous(hosts) if not args.from_last_run else []
    if changes:
        print("\n=== Changes vs previous run ===")
        for c in changes[:50]:
            print("  " + c)

    print(f"\nWrote {xlsx_path} and {json_path}")
    store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

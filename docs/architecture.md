# Architecture & function reference

This document explains how surface-scan is put together, the data flow, and
every module and function.

## Data flow

```
                        ┌─────────────────────────────────────────────┐
  records.csv/xlsx/txt  │                 scan.py (CLI)                │
        │               │  orchestration · threads · summary · export │
        ▼               └─────────────────────────────────────────────┘
  inputs.load_records ─▶ [HostResult, ...]
        │
        ▼   (per host, in a thread pool)
  dns_probe.resolve_host ──(auto fallback)──▶ doh.DohResolver
        │   A/AAAA/CNAME chain/MX/TXT/NS/CAA + hygiene flags
        ▼
  classify.classify            own-infra / third-party-saas / suspicious
        │
        ▼
  http_probe.probe_http        TCP liveness · HTTP(S) · TLS · title · headers
        │
        ▼
  cdn.CdnMatcher.detect        CDN/WAF from CNAME + headers + IP ranges
        │
        ▼
  fingerprint.Fingerprinter.run    technologies (YAML signatures) + versions
        │
        ▼
  externals (optional)         httpx_enrich / nuclei_detect  (if --use-external/--use-nuclei)
        │
        ▼
  store.Store.save             SQLite history (enables --from-last-run + diff)
        │
        ▼
  advisories.Advisory.evaluate verdict per host (optional)
        │
        ▼
  report.export_xlsx / export_json      Excel (multi-sheet) + JSON
```

## Package layout

```
surface-scan/
├── scan.py                 # CLI entry point / orchestrator
├── surfacescan/            # library package
│   ├── models.py           # Detection, HostResult dataclasses
│   ├── inputs.py           # load CSV/XLSX/TXT -> HostResult list
│   ├── dns_probe.py        # DNS resolution (+ DoH fallback)
│   ├── doh.py              # DNS-over-HTTPS resolver
│   ├── http_probe.py       # TCP liveness, HTTP(S) probe, TLS
│   ├── cdn.py              # CDN/WAF detection
│   ├── classify.py         # own-infra / saas / suspicious
│   ├── fingerprint.py      # signature-driven tech detection
│   ├── advisories.py       # CVE advisory profiles + verdicts
│   ├── externals.py        # optional dnsx/httpx/nuclei integration
│   ├── store.py            # SQLite history + diffing
│   └── report.py           # Excel + JSON export
├── signatures/             # base.yaml (shipped) + custom.yaml (+ cdn_ranges.json)
├── advisories/             # one YAML per CVE profile
├── tests/                  # mock servers + unit/pipeline tests
└── docs/                   # this documentation
```

---

## Module & function reference

### `models.py`

Shared data structures.

- **`Detection`** (dataclass) — one technology found on a host.
  Fields: `name`, `category` (`language|backend|frontend|cms|server|cdn_waf|analytics`),
  `version`, `confidence` (`low|medium|high`), `evidence` (list).
  - `to_dict()` — JSON-serialisable form.
- **`HostResult`** (dataclass) — everything known about one hostname: the input
  record, all DNS data, edge/CDN info, liveness + HTTP fields, TLS, the list of
  `Detection`s, and per-advisory verdicts.
  - `tech_by_category(category)` — the detections in one category.
  - `to_dict()` — JSON-serialisable form (used by the store and JSON export).

### `inputs.py`

Load the record list from CSV / XLSX / TXT with flexible column names.

- **`load_records(path)`** — dispatch by extension → list of `HostResult`.
- `_read_csv / _read_xlsx / _read_txt` — format readers.
- `_rows_to_hosts(rows)` — header detection, column mapping, hostname validation
  and de-duplication.
- `_clean_host(h)` — strip scheme/path/port/trailing dot, lower-case.
- `_pick(headers, keys)` — find a column by a set of accepted names.

Accepted header names: hostname (`hostname/host/name/fqdn/domain/subdomain/record`),
type (`type/record_type/rtype`), target (`target/value/data/content/ip/cname/…`).

### `dns_probe.py`

DNS resolution with a DoH fallback.

- **`resolve_host(host, nameservers, timeout, mode, doh_provider)`** — main entry.
  `mode`:
  - `udp` — classic resolver only;
  - `doh` — DNS-over-HTTPS only;
  - `auto` (default) — try UDP, fall back to DoH when UDP yields nothing.
  Populates A/AAAA/CNAME chain/MX/TXT/NS/CAA and `resolved_ips`.
- `_mk_resolver(nameservers, timeout)` — build a dnspython resolver.
- `_query(resolver, name, rtype)` — a single record lookup, exceptions swallowed.
- `_follow_cname(resolver, host)` — walk the CNAME chain (UDP), detect dangling.
- `_resolve_doh / _doh_follow_cname` — same over DoH.
- `_finish_dns(host, chain, dangling)` — set hygiene flags: dangling CNAME
  (takeover risk), private/non-routable IP in public DNS, `dns_fail` when nothing
  resolves.

### `doh.py`

DNS-over-HTTPS resolver (RFC 8484 JSON form). Works where UDP/53 is blocked.

- **`DohResolver(provider, timeout)`** — `provider` is `cloudflare` or `google`.
  - `query(name, rtype)` — list of record values.
  - `has_cname(name)` — the CNAME target, if any.
  - `resolves(name)` — whether the name has A/AAAA.
  - `close()` — release the HTTP client.

### `http_probe.py`

Liveness, HTTP(S) probing, and TLS.

- **`probe_http(host, timeout, user_agent, extra_ports, fetch_paths)`** — main
  entry. TCP-checks the web ports (and admin/DB ports on direct hosts when
  `extra_ports`), then an HTTPS-first (HTTP fallback) GET capturing status,
  redirect chain, title, headers, cookies and timing; reads TLS on HTTPS; and
  optionally fetches a few benign framework paths when `fetch_paths`.
- `tcp_open(host, port, timeout)` — single TCP connect test.
- `check_ports(target, ports, timeout)` — which ports accept a connection.
- `_tls_info(host, port, timeout)` — certificate issuer + expiry, with
  near-expiry/expired notes.
- `_fetch_fingerprint_paths(...)` — GET the extra public paths for stronger
  fingerprinting (no payloads).
- `_looks_like_waf_block(resp, text)` — classify a 403/429/503 challenge/block
  page as `waf_blocked` rather than a real app error.

Port sets: `DEFAULT_WEB_PORTS` = 443, 80, 8443, 8080, 8000, 3000, 5000, 9000;
`EXTRA_PORTS` (opt-in, direct hosts only) = 22, 3389, 3306, 5432, 6379, 27017,
9200, 5601, 8081, 7001.

### `cdn.py`

Automatic CDN/WAF detection — the caller never has to say whether a host is
fronted.

- **`CdnMatcher(signatures_dir)`** — loads built-in IP ranges, optionally merged
  with `signatures/cdn_ranges.json`.
  - `by_ip(ip)` — provider by IP-range membership.
  - `by_cname(chain)` — provider by CNAME suffix (static method).
  - `by_headers(headers, cookies)` — provider by response header/cookie (static).
  - **`detect(chain, resolved_ips, headers, cookies)`** — combines all signals by
    weighted vote → `(provider | "none" | "unknown", confidence, evidence[])`.
    Conflicting signals are flagged, not silently guessed.
- `CNAME_SUFFIXES`, `HEADER_SIGNALS`, `_BUILTIN_RANGES` — the signal tables
  (Cloudflare, Akamai, Fastly, CloudFront, Azure Front Door, Imperva, Sucuri,
  F5, AWS ALB, …).

### `classify.py`

- **`classify(host)`** — set `host.classification`:
  - `suspicious` — dangling CNAME or private IP in public DNS;
  - `third-party-saas` — CNAME target matches a known SaaS suffix
    (`SAAS_SUFFIXES`: Zendesk, HubSpot, Netlify, Vercel, Shopify, GitHub Pages,
    Squarespace, Salesforce, Heroku, Firebase, …) — recorded, **not** probed;
  - `own-infra` — resolves to your own IPs/CDN;
  - `unknown` — nothing resolved.

### `fingerprint.py`

Signature-driven technology detection — data, not code.

- **`Fingerprinter(signatures_dir)`** — loads `base.yaml` then `custom.yaml`.
  - **`run(host)`** — evaluate every signature against the host's headers,
    cookies, body and probed paths; capture versions; apply `implies` (e.g.
    Laravel ⇒ PHP); sort detections by category.
- **`Signature(name, spec)`** — one compiled signature.
  - `match(host)` — returns a `Detection` with evidence, or `None`. Matches on
    `headers`, `server`, `cookies`, `html`, `paths` (path+status+body), and
    extracts `version` from a `(?P<version>…)` group when present.

### `advisories.py`

Optional CVE correlation — version/inventory logic only, never exploitation.

- **`Advisory(spec)`** — one profile (`id`, `name`, `tech`, `affected` ranges,
  `exposure_hints`, `action`).
  - `load(path)` / `load_dir(directory)` — load one or all profiles.
  - **`evaluate(host)`** → `{verdict, reason, action}`:
    - `affected` — tech present **and** version in an affected range;
    - `likely` — tech present, version unknown, an exposure hint is met;
    - `possible` — tech present, version not observable;
    - `not-detected` — tech not seen and host answered normally (or version is
      outside the affected range);
    - `unknown` — host blocked/unreachable, so no conclusion.
  - `_version_affected / _in_range` — semantic-version range checks (via
    `packaging`).

### `externals.py`

Optional integration with maintained tools; auto-detected on `PATH`.

- **`available()`** — which of `dnsx`/`httpx`/`nuclei` are installed.
- **`httpx_enrich(hosts, …)`** — run ProjectDiscovery `httpx` and merge
  status/title/web-server/CDN/tech (Wappalyzer rules) into results.
- **`nuclei_detect(hosts, …)`** — run `nuclei` **detection** templates only
  (tags restricted to `tech,detect,favicon,waf`; intrusive/exploit tags
  explicitly excluded). Adds detections; never runs exploits.
- `_httpx_category(name)` — map a tool's tech name to a category.

### `store.py`

SQLite history for diffing and offline re-evaluation.

- **`Store(path)`** — open/create the DB (tables `runs`, `results`).
  - `new_run(note)` / `save(run_id, hosts)` — persist a run.
  - `last_run_id()` / `load_run(run_id)` — reload (used by `--from-last-run`).
  - **`diff_previous(hosts)`** — human-readable changes vs the previous run: new
    or gone hosts, liveness changes, new/removed technologies, CDN changes.
  - `close()`.

### `report.py`

- **`export_xlsx(hosts, path, advisory_ids)`** — multi-sheet workbook: Summary,
  Assets, Tech, DNS, Flags, and one `Adv-<id>` sheet per advisory (verdicts
  colour-coded).
- **`export_json(hosts, path)`** — full results as JSON for automation.
- `_langs / _cat` — format a host's detections per category for the Assets sheet.

### `scan.py` (CLI)

- **`parse_args(argv)`** — all command-line options.
- **`resolve_advisories(names, adv_dir)`** — resolve `--advisory` values (file
  path, bare name, or id) to `Advisory` objects.
- **`scan_one(host, cdn_matcher, fp, args, nameservers)`** — the per-host
  pipeline (resolve → classify → probe → CDN → fingerprint), isolated so one bad
  host can't kill the run; honours per-host rate limiting.
- **`main(argv)`** — load input or last run, run the thread pool, optional
  external enrichment, store, evaluate advisories, export, print summary/diff.

---

## Concurrency, politeness, safety

- Hosts are processed in a `ThreadPoolExecutor` (`--threads`, default 20).
- `--rps` adds a per-host delay to stay polite behind CDNs and avoid rate limits.
- Exceptions in `scan_one` are captured on the `HostResult.error` field — a single
  failing host never aborts the run.
- Third-party SaaS targets are **recorded but not probed** by default.
- No exploitation, no WAF bypass, no exploit payloads anywhere in the codebase;
  `nuclei` is constrained to detection tags.

## Limits

- External detection is best-effort: WAFs and hardened configs hide signals.
- Most runtimes don't expose a version over HTTP (Node.js especially), so
  advisory verdicts are often `possible`/`likely`, not `affected`.
- IP-range CDN detection uses small built-in lists; supply
  `signatures/cdn_ranges.json` for authoritative coverage.
- Pair with an internal inventory (osquery, Trivy/Grype, dependency manifests)
  for authoritative versions.

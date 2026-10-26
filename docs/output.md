# Output format

Each run produces three things under your output prefix (default `output/`). The
`.xlsx` and `.json` filenames carry a per-run timestamp
(`surface-scan-YYYYMMDD-HHMMSS.xlsx`) so runs don't overwrite each other; disable
with `--no-timestamp`.

1. `<name>-<timestamp>.xlsx` — a multi-sheet workbook for humans (incl. an **All** sheet that mirrors the JSON, one row per host)
2. `<name>-<timestamp>.json` — full structured results for automation
3. `history.sqlite` — append-only run history for diffing and `--from-last-run` (single file, not timestamped)

## Excel workbook

### Summary
Headline counts: total hosts, liveness breakdown, CDN/WAF breakdown, and a
technology tally (languages and frontend frameworks).

### All
One row per host with **every** field from the JSON (all 32 keys), flattened to
flat cells — the complete record in spreadsheet form. Lists are comma-joined;
`detections` and `advisories` are rendered compactly. Use **Assets** for a
curated, readable view and **All** when you want everything.

### Assets (one row per host)
| Column | Meaning |
|---|---|
| hostname, record_type, classification | identity + own-infra/saas/suspicious |
| liveness | live / live_error / waf_blocked / filtered / refused / dangling / dns_fail |
| cdn_waf, cdn_waf_conf | detected provider (or none/unknown) + confidence |
| status, final_url, title, resp_ms | HTTP response summary |
| open_ports, resolved_ips, asn_org | network facts |
| language, backend, frontend, cms, server | detected stack (version appended when known) |
| tls_issuer, tls_expiry | certificate issuer + expiry date |
| dns_notes, tls_notes | hygiene / warning notes |

### Tech (one row per host × technology)
`hostname, category, technology, version, confidence, evidence` — the evidence
column shows *why* each detection fired (which header/cookie/body/path matched).

### DNS
Full records per host: record type/target, CNAME chain, A, AAAA, MX, NS, TXT,
CAA, and notes.

### Flags
Actionable items only: dangling CNAMEs (subdomain-takeover risk), internet-facing
apps with **no** CDN/WAF, and expiring/expired TLS. Highlighted for quick triage.

### Adv-\<id\> (one per advisory)
`hostname, verdict, reason, action` — verdicts colour-coded
(affected = red, likely = orange, possible = yellow, unknown = grey,
not-detected = green).

## JSON

An array of host objects, each the full `HostResult` (see
[architecture.md](architecture.md#modelspy)) including every `Detection` with its
evidence and any advisory verdicts. Use it to feed dashboards, ticketing, or your
SIEM.

```bash
# e.g. list hosts where PHP2Shell verdict is affected or likely
jq -r '.[] | select(.advisories["PHP2SHELL-2026"].verdict as $v | $v=="affected" or $v=="likely") | .hostname' output/surface-scan.json
```

## SQLite history

Tables:
- `runs(run_id, started_at, note)`
- `results(run_id, hostname, data)` — `data` is the JSON of each `HostResult`

Used for:
- `--from-last-run` — reload the most recent run and re-apply advisories with no
  new traffic.
- **Run-to-run diff** — at the end of a fresh scan the tool prints changes vs the
  previous run: new/gone hosts, liveness changes, new/removed technologies, and
  CDN changes.

## Console summary

Every run prints a compact summary: liveness counts, CDN/WAF counts,
language/runtime counts, any `--tech` matches, advisory verdict tallies (with
affected/likely hosts listed), and the diff vs the previous run.

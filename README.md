# surface-scan

> Defensive **external attack-surface inventory** — resolve your DNS records,
> see what's live, detect the CDN/WAF in front, and fingerprint the technology
> stack. Then answer *"which of our hosts run **X**?"* in seconds when the next
> critical advisory drops.

![CI](https://github.com/YOURORG/surface-scan/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-beta-orange)

---

surface-scan takes a list of DNS records you own and builds a living inventory of
your internet-facing assets: **DNS → liveness → CDN/WAF → technology stack**,
exported to Excel and JSON. It is built to be **future-proof**: detection is
driven by YAML signatures, and emergency triage is driven by YAML *advisory
profiles*. When a new critical bug lands — a PHP RCE, a Node.js memory-safety
flaw, a framework CVE — you drop in one small file and re-run against your stored
results, **without sending new traffic**.

It ships with example advisories for recent high-profile issues (PHP2Shell —
`CVE-2026-109618` / `CVE-2026-109619`; and the Node.js Brotli out-of-bounds write
— `CVE-2026-111497`) to show the pattern. **It is not a single-CVE tool** — those
are just examples of the workflow.

> ⚠️ **Authorised use only.** Inventory tooling, not an exploitation framework:
> no exploitation, no WAF bypass, no exploit payloads. Run only against assets you
> own or are authorised to assess, from an approved IP, with your SOC informed.
> See [SECURITY.md](SECURITY.md).

## Table of contents

- [Why](#why)
- [What it reports](#what-it-reports-per-host)
- [How it works](#how-it-works)
- [Install](#install)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Output](#output)
- [Extending it](#extending-it)
- [Documentation](#documentation)
- [Limitations](#limitations-read-this)
- [Contributing](#contributing)
- [License](#license)

## Why

When a critical vulnerability in a widely used technology is announced, the first
question every security team must answer is **"are we exposed, and where?"**
Answering it by hand across hundreds of hostnames is slow and error-prone.
surface-scan turns that into a repeatable query: inventory once, then correlate
any new advisory against what you already know.

Representative use cases:

- **Emergency triage** — a CVE drops in PHP / Node.js / nginx / WordPress; find
  affected or likely-affected hosts fast.
- **Continuous attack-surface management (EASM)** — scheduled runs with run-to-run
  diffing surface new hosts, new technologies, and dangling records.
- **Audit & hardening** — spot apps with **no** CDN/WAF, expiring TLS, and
  subdomain-takeover risks.

## What it reports (per host)

| Area | Details |
|---|---|
| **DNS** | A, AAAA, CNAME chain, MX, TXT, NS, CAA; flags dangling CNAMEs (takeover risk) and private IPs in public DNS |
| **Liveness** | `live`, `live_error`, `waf_blocked`, `filtered`, `refused`, `dangling`, `dns_fail` |
| **CDN / WAF** | Auto-detected (CNAME suffix + headers/cookies + IP ranges); flags apps with **none** in front |
| **Technology** | Language/runtime (PHP, Node.js, Java, .NET, Python, Ruby, Go), backend (Laravel, Express, Next.js, Django, Spring, Rails…), frontend (Angular, React, Vue, Svelte), CMS (WordPress, Drupal), web server (nginx, Apache, IIS, LiteSpeed) — with version when visible |
| **TLS** | Issuer and expiry, with near-expiry / expired flags |
| **Advisory verdict** | *(optional)* affected / likely / possible / not-detected / unknown |

## How it works

```
records.csv ─▶ DNS resolve ─▶ liveness/TCP ─▶ CDN/WAF detect ─▶ fingerprint ─▶ store ─▶ report
   (input)      dns_probe       http_probe        cdn            fingerprint     store     report
                + DoH fallback   + TLS            classify       (YAML sigs)     (sqlite)  (xlsx/json)
                                                                     │
                                            advisories (YAML) ───────┴─▶ verdicts per host
```

Design principles:

- **Presence first, version when visible.** The default question is *"is this
  technology in use here?"* — answered even when the version is hidden. Version is
  captured when the server exposes it and feeds advisory matching.
- **Data, not code.** Add a technology by editing YAML; add a CVE by dropping a
  file in `advisories/`. No code changes for the next emergency.
- **Frontend ≠ backend.** Angular/React/Vue run in the browser and say nothing
  about the server; they are reported in their own category so detections are not
  misread.
- **Honest verdicts.** For memory-safety bugs where the version isn't externally
  visible, the verdict is `possible` / `likely → confirm with owner` — never a
  fake yes/no.

## Install

Requires **Python 3.10+**. Using a virtual environment is recommended so the
dependencies don't touch your system Python.

**Quick setup (macOS / Linux):**

```bash
git clone https://github.com/YOURORG/surface-scan
cd surface-scan
./setup.sh                      # creates .venv and installs everything
source .venv/bin/activate       # activate it (prompt shows (.venv))
python scan.py --input records.csv
deactivate                      # when you're done
```

**Manual setup (any OS):**

```bash
git clone https://github.com/YOURORG/surface-scan
cd surface-scan
python3 -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
python scan.py --input records.csv
```

> On macOS use `python3` / `pip3` (plain `pip` is often not on PATH). Inside an
> activated venv, plain `python` and `pip` work.

Optional external tools (auto-detected on `PATH`, used only with `--use-external`
/ `--use-nuclei`; everything works without them):

```bash
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest   # detection templates only
```

## Quick start

```bash
# 1) inventory everything -> Excel + JSON in ./output/
python scan.py --input records.csv

# 2) a CVE drops -> triage against what you already scanned, no new traffic
python scan.py --from-last-run --advisory php2shell
```

Input is CSV / XLSX / TXT with flexible columns; minimum is a hostname column:

```csv
hostname,type,target
www.yourco.com,A,203.0.113.10
api.yourco.com,CNAME,d123.cloudfront.net
help.yourco.com,CNAME,yourco.zendesk.com
```

## Usage

```bash
# Highlight specific technologies in a filtered view
python scan.py --input records.csv --tech nodejs,angular,php

# Run one or more advisories during a fresh scan
python scan.py --input records.csv --advisory php2shell --advisory nodejs-brotli

# Use maintained external tools if installed (speed + Wappalyzer rules)
python scan.py --input records.csv --use-external

# Locked-down network / UDP:53 blocked -> resolve over HTTPS
python scan.py --input records.csv --dns-mode doh
```

Common options: `--threads`, `--timeout`, `--rps` (per-host politeness),
`--nameservers`, `--dns-mode {auto,udp,doh}`, `--extra-ports` (admin/DB ports on
**direct** hosts only), `--fetch-paths`, `--signatures-dir`, `--advisories-dir`,
`--out`, `--db`. Full reference: [docs/usage.md](docs/usage.md).

## Output

`output/<name>.xlsx` with sheets: **Summary**, **Assets**, **Tech** (one row per
host×technology with evidence), **DNS**, **Flags** (dangling CNAMEs, no-CDN apps,
expiring TLS), and one **Adv-\<id\>** sheet per advisory. Plus `output/<name>.json`
for automation and `output/history.sqlite` for run-to-run diffing. Details:
[docs/output.md](docs/output.md).

## Extending it

Add a technology — `signatures/custom.yaml`:

```yaml
"My Framework":
  category: backend
  confidence: high
  headers:
    X-Powered-By: "MyFramework"
  implies: ["Node.js"]
```

Add an advisory — `advisories/my-cve.yaml`:

```yaml
id: CVE-2026-XXXXX
name: "Some product RCE"
tech: nginx
affected: ["<1.27.3"]
action: "Upgrade and reload."
```

Then: `python scan.py --from-last-run --advisory my-cve`. See
[docs/signatures.md](docs/signatures.md) and
[docs/advisories.md](docs/advisories.md).

## Documentation

- [docs/architecture.md](docs/architecture.md) — modules, data flow, and every function
- [docs/usage.md](docs/usage.md) — full CLI reference and recipes
- [docs/signatures.md](docs/signatures.md) — signature schema and authoring guide
- [docs/advisories.md](docs/advisories.md) — advisory schema and verdict logic
- [docs/output.md](docs/output.md) — Excel/JSON/SQLite output format
- `presentation.html` — a self-contained slide deck for sharing with your team

## Limitations (read this)

External scanning cannot see everything. Behind a WAF, or with `expose_php=Off`,
a language can be undetectable. Most runtimes (Node.js especially) do **not**
reveal their version over HTTP, so advisory verdicts will often be
`possible`/`likely` rather than a definitive `affected`. Pair surface-scan with an
**internal** inventory (osquery, container image scanning with Trivy/Grype,
dependency manifests) for authoritative version data. See
[docs/architecture.md](docs/architecture.md#limits).

## Contributing

Signatures and advisories are the easiest and most valuable contributions — both
are plain YAML. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE) © 2026 Leonidas Athanasiou and contributors.

---

<sub>Keywords: external attack surface management (EASM), asset inventory,
reconnaissance, technology fingerprinting, Wappalyzer-style detection, DNS
enumeration, CDN/WAF detection, subdomain takeover, CVE triage, vulnerability
management, blue team, PHP2Shell CVE-2026-109618 CVE-2026-109619, Node.js Brotli
CVE-2026-111497.</sub>

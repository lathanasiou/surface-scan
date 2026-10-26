# Usage & CLI reference

```bash
python scan.py (--input FILE | --from-last-run) [options]
```

You must provide exactly one source: `--input` for a fresh scan, or
`--from-last-run` to re-evaluate the last stored run without sending traffic.

## Options

### Source
| Option | Default | Description |
|---|---|---|
| `--input`, `-i FILE` | — | Record list: CSV / XLSX / TXT |
| `--from-last-run` | — | Re-evaluate the last stored run (no new traffic) |

### Advisories & filtering
| Option | Default | Description |
|---|---|---|
| `--advisory`, `-a NAME` | — | Advisory id, file path, or bare name in `advisories/`. Repeatable |
| `--tech LIST` | — | Comma-separated technologies to highlight in console + report |

### Output
| Option | Default | Description |
|---|---|---|
| `--out`, `-o PREFIX` | `output/surface-scan` | Output path prefix; a `-YYYYMMDD-HHMMSS` timestamp is appended per run |
| `--no-timestamp` | off | Don't append a timestamp to output filenames |
| `--db PATH` | `output/history.sqlite` | SQLite history file |
| `--signatures-dir DIR` | bundled `signatures/` | Signature YAML directory |
| `--advisories-dir DIR` | bundled `advisories/` | Advisory YAML directory |

### Network behaviour
| Option | Default | Description |
|---|---|---|
| `--threads N` | 40 | Concurrent hosts (raise for speed, lower to be gentle) |
| `--timeout SECONDS` | 8.0 | Per-request timeout |
| `--rps FLOAT` | 5.0 | Max requests/sec per host (politeness) |
| `--nameservers LIST` | system | Comma-separated resolvers |
| `--dns-mode {auto,udp,doh}` | auto | `auto` = UDP then DoH fallback |
| `--doh-provider {cloudflare,google}` | cloudflare | DoH endpoint |
| `--user-agent STRING` | identifying UA | HTTP User-Agent |

### Probing scope
| Option | Default | Description |
|---|---|---|
| `--extra-ports` | off | Also TCP-probe admin/DB ports on **direct** (non-CDN) hosts |
| `--fetch-paths` | off | Fetch a few benign framework paths for stronger fingerprinting |
| `--skip-saas-probe` | on | Do not probe third-party SaaS targets |

### External tools
| Option | Default | Description |
|---|---|---|
| `--use-external` | off | Use `dnsx`/`httpx` if on `PATH` |
| `--use-nuclei` | off | Run `nuclei` **detection** templates only, if on `PATH` |

## Recipes

**First inventory**
```bash
python scan.py --input records.csv
```

**Emergency: a PHP CVE drops**
```bash
# if you already scanned recently:
python scan.py --from-last-run --advisory php2shell
# or a fresh scan with the advisory applied:
python scan.py --input records.csv --advisory php2shell
```

**Find every host running a given stack**
```bash
python scan.py --input records.csv --tech nodejs,angular,wordpress
```

**Deeper detection (slower, more requests)**
```bash
python scan.py --input records.csv --fetch-paths --use-external
```

**Restricted network (no UDP/53 egress)**
```bash
python scan.py --input records.csv --dns-mode doh --doh-provider cloudflare
```

**Gentle scan of a sensitive target**
```bash
python scan.py --input records.csv --threads 5 --rps 1 --timeout 15
```

**Custom signature/advisory directories**
```bash
python scan.py --input records.csv \
  --signatures-dir ./my-signatures \
  --advisories-dir ./my-advisories \
  --advisory CVE-2026-XXXXX
```

## Scheduling (continuous EASM)

Run on a schedule (cron, CI, a scheduled job) and the SQLite history gives you
run-to-run diffs automatically — new hosts, new technologies, dangling records,
CDN changes are printed at the end of each run. Example cron (weekly):

```cron
0 6 * * 1  cd /opt/surface-scan && /usr/bin/python3 scan.py --input records.csv --out output/weekly >> output/cron.log 2>&1
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed |
| 2 | No valid input / no previous run to load |

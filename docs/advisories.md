# Advisory schema & verdict logic

An advisory profile maps a CVE (or any "upgrade X" notice) to the technology and
version ranges it affects, so you can triage your inventory against it. Profiles
are plain YAML in `advisories/` (override the directory with `--advisories-dir`).

**Advisories never contain exploit logic.** They are version/inventory
correlation only.

## Fields

| Field | Required | Description |
|---|---|---|
| `id` | yes | Advisory id (CVE or your own id). Used as the sheet/key name |
| `name` | no | Human-readable title |
| `tech` | yes | The technology name it applies to — **must match a detectable signature** (e.g. `PHP`, `Node.js`, `nginx`) |
| `affected` | yes | List of version-range specs (see below) |
| `exposure_hints` | no | Conditions that raise "possible" to "likely" |
| `action` | no | Remediation text shown in the report |

### Version ranges

Each entry in `affected` is a comma-joined set of clauses using
`>=`, `>`, `<=`, `<`, `==`, `!=`, compared semantically (via `packaging`):

```yaml
affected:
  - ">=8.3.0,<8.3.36"     # 8.3 branch below the fix
  - "<8.2.0"              # everything older
```

A host is in range if it satisfies **any** entry (and all clauses within that
entry).

## Verdicts

`Advisory.evaluate(host)` returns one of:

| Verdict | When | Suggested action |
|---|---|---|
| **affected** | tech present **and** version in an affected range | Patch now |
| **likely** | tech present, version unknown, an `exposure_hint` is met | Patch now, confirm with owner |
| **possible** | tech present, version not observable externally | Owner confirms the running version |
| **not-detected** | tech not seen and host answered normally, **or** version is outside the affected range | Low priority / not affected |
| **unknown** | host blocked by WAF or unreachable | Confirm via allowlisted scan or owner |

This honesty is deliberate: for memory-safety bugs where the version isn't
exposed over HTTP, the tool will not claim a definitive yes/no. Most Node.js
hosts, for example, land on `possible`.

## Examples

**PHP2Shell** (`advisories/php2shell.yaml`):
```yaml
id: PHP2SHELL-2026
name: "PHP2Shell (CVE-2026-109618 / CVE-2026-109619)"
tech: PHP
affected:
  - ">=8.5.0,<8.5.12"
  - ">=8.4.0,<8.4.27"
  - ">=8.3.0,<8.3.36"
  - ">=8.2.0,<8.2.35"
  - "<8.2.0"
action: "Upgrade PHP to a fixed release and RESTART Apache/PHP-FPM/workers."
```

**Node.js Brotli OOB write** (`advisories/nodejs-brotli.yaml`):
```yaml
id: CVE-2026-111497
name: "Node.js Brotli decoder OOB write (CVE-2026-111497)"
tech: "Node.js"
affected:
  - ">=22.0.0,<22.23.4"
  - ">=24.0.0,<24.22.1"
  - ">=26.0.0,<26.12.1"
exposure_hints:
  - accepts_brotli_request_body
action: "Upgrade Node.js and redeploy. Version is not externally observable — confirm on the host."
```

## Writing your own

1. Create `advisories/<name>.yaml` with the fields above.
2. Make sure `tech` matches a name a signature detects (add a signature first if
   needed — see [signatures.md](signatures.md)).
3. Run it:
   ```bash
   python scan.py --from-last-run --advisory <name>
   ```
   `<name>` can be the file stem, the full path, or the `id`.

## Exposure hints

`exposure_hints` are labels that, when present in a host's computed exposure set,
upgrade a version-unknown `possible` to `likely`. The current build ships the
hint names but leaves the exposure set empty by default (populating it safely for
a given bug — e.g. confirming an endpoint accepts a particular input — is a
deliberate, opt-in extension). Treat `likely` as "prioritise and confirm",
`possible` as "confirm the version".

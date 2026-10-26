# Signature schema & authoring guide

Signatures teach surface-scan to recognise a technology. They are plain YAML —
**no code changes** needed to add detection for a new stack.

Loaded from, in order:
1. `signatures/base.yaml` — the shipped set
2. `signatures/custom.yaml` — your additions/overrides

Each top-level key is a technology name; its value is the spec.

## Fields

| Field | Type | Description |
|---|---|---|
| `category` | string | `language` · `backend` · `frontend` · `cms` · `server` · `analytics` |
| `confidence` | string | `low` · `medium` · `high` — base confidence when matched |
| `headers` | map | `{Header-Name: regex}` matched against that response header's value |
| `server` | regex | matched against the `Server` header |
| `cookies` | list | regexes matched against `Set-Cookie` / cookie names |
| `html` | list | regexes matched against the root page body |
| `paths` | list | `[{path: /x, status: 200, body: regex}]` — matched against probed paths |
| `version` | regex | with a `(?P<version>...)` group; captures version when present |
| `implies` | list | other technologies to also record (e.g. `["PHP"]`) |

A signature matches if **any** of its signals match. `version` is extracted from
header values or the root body when the regex hits. All regexes are
case-insensitive.

> `paths` rules only apply when the path was actually fetched. Root (`/`) is
> always fetched; the extra paths require `--fetch-paths`.

## Examples

**Language via header + cookie, with version:**
```yaml
PHP:
  category: language
  confidence: high
  headers:
    X-Powered-By: "PHP"
  cookies: ["^PHPSESSID="]
  version: "PHP/(?P<version>\\d+\\.\\d+\\.\\d+)"
```

**Backend framework that implies a runtime:**
```yaml
Express:
  category: backend
  confidence: high
  headers:
    X-Powered-By: "Express"
  implies: ["Node.js"]
```

**Frontend framework with version from markup:**
```yaml
Angular:
  category: frontend
  confidence: high
  html: ["ng-version=\"(?P<version>[\\d.]+)\"", "_nghost", "_ngcontent"]
  version: "ng-version=\"(?P<version>[\\d.]+)\""
```

**CMS via generator meta + path:**
```yaml
WordPress:
  category: cms
  confidence: high
  html: ["/wp-content/", "<meta name=\"generator\" content=\"WordPress (?P<version>[\\d.]+)"]
  paths:
    - {path: "/wp-login.php", status: 200}
  version: "WordPress (?P<version>[\\d.]+)"
  implies: ["PHP"]
```

## Authoring tips

- **Prefer the most specific signal.** A dedicated header or cookie beats a
  generic HTML string. Unanchored substrings cause false positives (e.g. a loose
  `_session=` also matches `laravel_session=`).
- **Anchor cookie regexes** with `^` where possible.
- **Set the right category.** Frontend frameworks must be `frontend` so they are
  not misread as server-side.
- **Only add `version`** when the value is genuinely exposed; a wrong version
  silently skews advisory verdicts.
- **Add a test.** Extend `tests/mock_servers.py` with a profile and assert on it
  in `tests/test_e2e.py`.

## Overriding a shipped signature

Define a key in `custom.yaml` with the same name as one in `base.yaml`; the
custom entry is loaded in addition and takes precedence at lookup. This lets you
tighten or extend a shipped signature without editing `base.yaml`.

## Coverage & how to extend it

The shipped `base.yaml` covers 80+ technologies; `cdn.py` recognises 80+ CDN/WAF
CNAME patterns plus header/cookie signals; `classify.py` knows 140+ third-party
SaaS suffixes. These lists are meant to grow — most real-world gaps are a one-
line addition:

- **New technology** → add a signature (here or in `custom.yaml`).
- **New CDN/WAF** → add a CNAME suffix and/or header signal in `cdn.py`
  (`CNAME_SUFFIXES`, `HEADER_SIGNALS`), or drop IP ranges into
  `signatures/cdn_ranges.json`.
- **New SaaS product** → add its CNAME suffix to `SAAS_SUFFIXES` in
  `classify.py`. Note: platforms where you deploy your *own* code (Vercel,
  Netlify, Heroku, Render, Fly, Firebase, Pages) are deliberately *not* in that
  list — they host your app and should be probed; they're labelled as the edge
  instead.

PRs that add coverage are the most welcome kind — see
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Relationship to external tools

With `--use-external`, ProjectDiscovery `httpx` adds its Wappalyzer-based
detections on top of these signatures. Your YAML signatures always run; the
external tool only adds to the result set.

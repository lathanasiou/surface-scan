# Contributing to surface-scan

Thanks for helping improve surface-scan. The most valuable contributions are
usually **new technology signatures** and **new advisory profiles** — both are
plain YAML, so you don't need to touch Python.

## Ways to contribute

1. **Add a technology signature** — teach the tool to detect another stack.
2. **Add an advisory profile** — map a CVE to the technology and versions it
   affects, so the community can triage it with `--from-last-run`.
3. **Improve detection** — reduce false positives/negatives in `signatures/`.
4. **Core code** — DNS, probing, reporting, external-tool integration.
5. **Docs** — clarify usage, add examples.

## Dev setup

```bash
git clone https://github.com/YOURORG/surface-scan
cd surface-scan
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e ".[dev]"      # optional: editable install + pytest/ruff
```

## Running tests

```bash
python tests/test_e2e.py        # unit + mock-server detection tests
python tests/test_pipeline.py   # full pipeline incl. store + advisory re-eval
# or, with pytest:
pytest
```

All tests must pass before a PR is merged. CI runs them on every push and PR.

## Adding a signature

Edit `signatures/base.yaml` (shipped set) or add to `signatures/custom.yaml`.
See [docs/signatures.md](docs/signatures.md) for the full schema. A good
signature:

- uses the **most specific** signal available (a dedicated header or cookie beats
  a generic HTML string);
- sets `category` correctly (`language` / `backend` / `frontend` / `cms` /
  `server` / `analytics`);
- sets a realistic `confidence`;
- adds a `version` regex with a `(?P<version>...)` group **only** when the value
  is genuinely exposed;
- **adds a test** in `tests/` (extend `mock_servers.py` with a profile and assert
  on it in `test_e2e.py`).

Please avoid broad, unanchored regexes — they cause false positives on unrelated
hosts.

## Adding an advisory

Add a file under `advisories/`. See [docs/advisories.md](docs/advisories.md).
Advisories must reference a `tech` name that a signature can actually detect, and
must use version ranges, not exploit logic. Advisories never contain exploit
code.

## Coding standards

- Python 3.10+, standard library first.
- Keep the pure-Python path working even when optional external tools are absent.
- No network calls in unit tests — use the local mock servers.
- Run `ruff check .` before submitting.

## Scope boundaries (important)

This project is **inventory and detection only**. Pull requests that add
exploitation, WAF-bypass payloads, credential attacks, or intrusive fuzzing will
be declined. Detection and version correlation are in scope; weaponisation is
not. See [SECURITY.md](SECURITY.md).

## Pull requests

- One logical change per PR.
- Describe what you changed and why; link any related issue.
- Confirm tests pass and (for signatures) that you added a test.

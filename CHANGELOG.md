# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added / Improved
- Greatly expanded **CDN/WAF detection** (84 CNAME suffixes, 27 header/cookie
  signal sets, more IP ranges): F5 Distributed Cloud (ves.io), Google Cloud,
  Vercel, Netlify, BunnyCDN, KeyCDN, Gcore, CacheFly, Edgio, Section, Alibaba,
  Tencent, Qrator, DDoS-Guard, Reblaze, Barracuda, Wallarm, Fortinet, Citrix,
  Varnish, and more.
- Greatly expanded **SaaS classification** (145 suffixes) across site builders,
  e-commerce, status pages, helpdesk/chat, marketing/forms, docs/KB, community,
  email and media. Deploy-your-own-code platforms (Vercel, Netlify, Heroku,
  Render, Fly, Firebase, Pages) are intentionally probed as own-infra, not
  skipped as SaaS.
- Expanded **technology signatures** to 84: more frameworks (NestJS, FastAPI,
  Flask, Phoenix, Remix, SvelteKit, Astro, Gatsby, Ember, ASP.NET Core, …),
  servers (OpenResty, Tengine, Tomcat, Jetty, Gunicorn, Kestrel, Traefik, …),
  CMS (Ghost, Magento, TYPO3, Craft, Sitecore, AEM, Shopify, Wix, Squarespace),
  and analytics tags (GTM, Segment, Matomo, Plausible, Hotjar, Sentry, …).

### Fixed
- **Laravel false positives**: the signature no longer fires on the generic
  `XSRF-TOKEN` cookie (set by Axios/Angular and others); it now requires
  `laravel_session`. Genuine Laravel apps are still detected via PHP + cookie.
- DNS hygiene now also flags **non-globally-routable IPs** (e.g. 100.64.0.0/10
  CGNAT/shared space) in public DNS, not only RFC-1918 private ranges.

## [1.0.0] - 2026-10-25

### Added
- Initial public release.
- DNS resolution via dnspython with DNS-over-HTTPS (DoH) fallback
  (`--dns-mode {auto,udp,doh}`): A, AAAA, CNAME chain, MX, TXT, NS, CAA, plus
  hygiene flags (dangling CNAME / subdomain-takeover risk, private IPs in public
  DNS).
- Liveness classification: `live`, `live_error`, `waf_blocked`, `filtered`,
  `refused`, `dangling`, `dns_fail`.
- Automatic CDN/WAF detection from CNAME suffix, response headers/cookies, and
  IP-range membership (overridable via `signatures/cdn_ranges.json`).
- Signature-driven technology fingerprinting (data-driven YAML): language,
  backend, frontend, CMS, web server, with version capture when visible.
- Host classification: own-infra / third-party-saas / suspicious. SaaS targets
  are recorded, not probed.
- Optional advisory profiles (YAML) with verdicts: affected / likely / possible /
  not-detected / unknown. Example profiles for PHP2Shell
  (CVE-2026-109618 / CVE-2026-109619) and the Node.js Brotli OOB write
  (CVE-2026-111497).
- `--from-last-run` to re-evaluate a stored run against a new advisory with no
  new traffic.
- Optional integration with ProjectDiscovery `dnsx` / `httpx` (`--use-external`)
  and `nuclei` detection templates only (`--use-nuclei`).
- Excel (multi-sheet) + JSON export, and a SQLite history store with run-to-run
  diffing.
- Test suite: unit + mock-server detection tests and a full-pipeline test.
- `setup.sh` one-step virtual-environment setup; startup banner (suppress with
  `--no-banner`); input CSV format shown in `--help` and on input errors.

[1.0.0]: https://github.com/YOURORG/surface-scan/releases/tag/v1.0.0

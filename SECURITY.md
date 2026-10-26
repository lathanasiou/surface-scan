# Security Policy & Responsible Use

## Responsible use

surface-scan is **defensive inventory tooling**. It resolves DNS, checks
liveness, detects the CDN/WAF in front of a host, and fingerprints the
technologies in use. It performs **no exploitation**, **no WAF bypass**, and
sends **no exploit payloads**.

Even so, active network probing of systems you do not own or are not authorised
to assess may be unlawful in your jurisdiction and may violate acceptable-use
policies.

**Before you run it:**

- Only scan assets your organisation **owns** or is **explicitly authorised** to
  assess.
- Obtain written authorisation and define the scope.
- Notify your SOC / MSSP of the scanner source IP and the scan window, so your
  own monitoring does not treat it as an attack.
- Run from an approved source IP (ideally a dedicated cloud VM, not an office or
  VPN IP that may be allowlisted).
- Respect the rate limits (`--rps`, `--threads`) and the target's terms of
  service.
- Third-party SaaS CNAME targets (Zendesk, HubSpot, Netlify, …) are **not** your
  servers; the tool records but does not probe them, and neither should you.

You are solely responsible for how you use this software. See the warranty
disclaimer in [LICENSE](LICENSE).

## Reporting a vulnerability in surface-scan

If you find a security issue **in this tool itself** (for example, a way it could
be made to send traffic it should not, or a code-execution risk from a crafted
input file or signature), please report it privately:

1. Use GitHub's **"Report a vulnerability"** (Security Advisories) on the
   repository, **or**
2. Open a minimal issue asking a maintainer to contact you, without disclosing
   details publicly.

Please do not open a public issue with exploit details. We aim to acknowledge
reports within a few business days.

## Supported versions

The `main` branch and the latest tagged release receive fixes. Older tags are
best-effort.

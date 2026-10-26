"""surface-scan: defensive external attack-surface inventory.

Given a list of DNS records you own, it resolves DNS, checks whether each
target is live, detects which CDN/WAF (if any) fronts it, and fingerprints the
technologies in use (language/runtime, frameworks, web server, CMS). Optional
advisory profiles let you re-evaluate the stored results against a specific
CVE by version when the version is observable.

Inventory only — no exploitation, no WAF-bypass, no exploit probes.
"""

__version__ = "1.0.0"

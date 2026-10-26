---
name: New signature or advisory
about: Request/propose detection for a technology, or a CVE advisory profile
title: "[signature] " 
labels: enhancement, signatures
---

**Type**
- [ ] Technology signature (detect a stack)
- [ ] Advisory profile (map a CVE to a technology + versions)

**Technology / product name**
e.g. "FastAPI", "Tomcat", or the affected product for an advisory.

**For a signature — what gives it away?**
List any reliable signals you know of:
- Response header(s):
- Cookie name(s):
- HTML / body markers:
- Specific path + status:
- Is a version ever exposed? where?

**For an advisory — details**
- CVE id(s):
- Affected version ranges:
- Fixed version(s):
- `tech` name it maps to (must be detectable):
- Is the version observable externally? (if not, verdicts will be "possible")

**Links / references**
Advisory, vendor bulletin, docs.

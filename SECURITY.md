# Security policy

## Supported versions
| Version | Status |
|---------|--------|
| 0.3.x (TS `mcp-rbac`, Python `mcp-rbac`) | security fixes |
| 0.2.x | security fixes until 0.4.0 ships, then end of life (see docs/SUPPORT.md) |
| < 0.2 (`mcp-guard`) | unsupported |

## Reporting a vulnerability
Please report privately to the maintainers (security contact to be set before the first public release). Do not open
a public issue. Include the version, a minimal reproduction, and the impact. We aim to acknowledge reports within 3
business days, ship a fix or mitigation for high/critical issues within 30 days, and credit reporters who want it.

## Scope
In scope: any bypass of an allow/deny decision, scope/tenant/role escalation, approval or budget bypass, audit
tampering that verification fails to detect, token or secret disclosure through logs, results or errors, and
injection through the PDP or HTTP surfaces.
Out of scope: issues that need a compromised host, a malicious MCP server *implementation* that the guard wraps
(see docs/THREAT-MODEL.md, "what the guard cannot stop"), and denial of service from a client that is already authorized.

## Design documents
- docs/THREAT-MODEL.md: assets, actors, trust boundaries, and known bypass limits
- docs/DATA-FLOW.md: what personal data flows where (GDPR / PII)
- docs/SECURITY-REVIEW.md: the 0.3.0 self-review, its findings, and the fixes

# Security policy

## Supported versions
| Version | Status |
|---------|--------|
| 0.5.x (npm `mcp-rbac`, PyPI `mcp-rbac` + `mcp-rbac-core`, crates.io `mcp-rbac-core`) | security fixes |
| < 0.5 | never published to a registry; unsupported |

Features exported from `mcp-rbac/experimental` (and `mcp_rbac.experimental`) are covered by this policy, but their
API may change in a minor release (see docs/experimental/README.md).

## Reporting a vulnerability
<!-- TODO(Saarim, release blocker): set the security contact (address or GitHub private reporting) before the first
release; tools/release-dry-run.sh fails while this placeholder is here. -->
**Security contact: TODO, to be set before the first release.**

Please report privately through GitHub private vulnerability reporting on the repository (to be enabled when the
public repository is created; a security contact address will be listed here before the first release). Do not open
a public issue. Include the version, a minimal reproduction, and the impact. We aim to acknowledge reports within 3
business days, ship a fix or mitigation for high/critical issues within 30 days, and credit reporters who want it.

## Scope
In scope: any bypass of an allow/deny decision, scope/tenant/role escalation, approval or budget bypass, audit
tampering that verification fails to detect, token or secret disclosure through logs, results or errors, and
injection through the PDP or HTTP surfaces.
Out of scope: issues that need a compromised host, a malicious MCP server *implementation* that the guard wraps
(see docs/THREAT-MODEL.md, "what the guard cannot stop"), and denial of service from a client that is already authorized.
Unauthenticated callers: the guards decide on the identity your auth layer supplies; a caller with no identity is
denied (`unauthenticated`), so authentication itself (token validation, OAuth) is the host's job and in scope only
where mcp-rbac's own helpers (`mcp-rbac/remote`, the proxy's `--url` auth) do it.

## Design documents
- docs/THREAT-MODEL.md: assets, actors, trust boundaries, and known bypass limits
- docs/DATA-FLOW.md: what personal data flows where (GDPR / PII)
- docs/SECURITY-REVIEW.md: the 0.3.0 self-review, its findings, and the fixes

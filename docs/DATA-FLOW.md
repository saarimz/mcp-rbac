# Data flow and personal data (GDPR)

mcp-rbac is a library/proxy that runs inside the operator's infrastructure. It sends nothing to its authors or to
any third party. The operator is the controller; mcp-rbac is software the operator runs, not a processor.

## Flows
```
client/agent --(bearer token, tool args)--> [verify token] -> [authorize] -> tool handler --(result)--> [redact/label] --> client
                                                 |                |
                                                 v                v
                                          audit store       budget counters / approvals
                                   (memory|SQLite|Redis|PG)   (same store)        -> optional OTLP export / OTel spans
```

| Data | Where it goes | Personal data? | Retention |
|------|---------------|----------------|-----------|
| Bearer token | Verified in memory only. Never logged, audited, put in spans, or passed to tools. mcp-rbac grant tokens are stored only as SHA-256 hashes (upstream OAuth tokens of the remote proxy live in a 0600 file under the user's config dir). | credential | request lifetime |
| Subject id (`sub`), tenant, roles, actor chain | Audit events; OTel `mcp_rbac.*` decision attributes on the guard span | pseudonymous identifier | audit retention |
| Tool arguments | **TS**: stored as given unless you pass `redact(tool, args)` to the guard, which you should do for PII arguments. **Python**: scalars only, strings truncated at 200 chars, objects reduced to their type name, at most 50 keys. Approval records hold the same args. | possibly (e.g. an email argument) | audit / approval retention |
| Tool results | Pass through to the client after redaction. **Never stored** by mcp-rbac. | yes (profiles) | not retained |
| Counters | Keys contain tenant/user/client/agent ids, not content | pseudonymous | 2× the window (TTL) |
| MRTR `requestState` | Contains only a nonce, digests and expiry; sealed. Nonce kept as a counter until its TTL (default 15 min). | no | ≤ TTL |

## Controls for GDPR obligations
- **Minimisation**: output redaction rules per role; `export+pii` label rules; the guard `redact` hook for audited args (TS); truncation (Python).
- **Retention**: `auditRetentionMs` (TS) / `audit_retention_s` (Python) prune old events; counters expire by TTL.
- **Erasure (Art. 17)**: delete a subject's audit rows by `usr`/`user` (the SQL/Redis layouts are documented in the
  store sources). Deleting rows breaks the hash chain from that point; record the deletion and re-anchor by exporting the
  new head. This trade-off between erasure and integrity is deliberate; pseudonymise `sub` at the IdP if you need both.
- **Access (Art. 15)**: `mcp-rbac audit --user <id>` / `store.queryAudit({ user })` (TS); `await store.all_audit()` filtered on `user` (Python) lists a subject's events.
- **Security of processing (Art. 32)**: see docs/THREAT-MODEL.md.
- **International transfers**: none by mcp-rbac. Redis/Postgres/OTLP endpoints are chosen by the operator.

# Threat model (mcp-rbac 0.3.0)

## Assets
Tool side effects (sending campaigns, refunds, deletes), personal data in tool results (emails, phones), tenant
isolation between accounts, bearer tokens and upstream credentials, the integrity of the audit log, and budgets.

## Actors
- **Human user**, authenticated by the operator's IdP. Trusted to the extent of their roles.
- **Agent / LLM client** acting for the user. NOT trusted: it controls every tool argument, can be prompt-injected
  (for example by a review containing "ignore previous instructions"), and may replay or forge protocol fields.
- **Sub-agent / delegated actor** (RFC 8693 `act`). Trusted strictly less than its parent.
- **PEP talking to the PDP** (AuthZEN): a service. Trusted only if it holds the PDP token; never trusted for roles in directory mode.
- **Network attacker**: assumed to be stopped by TLS, which the operator terminates.

## Trust boundaries and how each is enforced
| Boundary | Enforcement |
|----------|-------------|
| Who the caller is | Only from a token the SDK or our verifier checked (JWT signature/iss/aud/exp, or introspection). Never from arguments, headers the client sets freely, or `_meta`. Malformed `act` means unauthenticated. Python `local_identity` is ignored for HTTP requests. |
| Which account a call touches | `scope.lookup` resolves the *record's* account server-side. A token-bound tenant is pinned (`cross_tenant`). Org roles expand to per-account assignments at request time. |
| What a token may do | Per-tool `requiredScopes` with a hierarchy. Missing scope: hidden from lists and refused with 403 `insufficient_scope` (step-up). |
| What a delegated agent may do | Actor policy ceilings (tools/scopes); unknown actors are denied by default; `narrow_identity` / token exchange only narrow (scopes and roles must be subsets, TTL ≤ parent `exp`, ≤ 300 s by default). |
| Human approval | MRTR: `requestState` is HMAC-sealed (TS) or AES-GCM-sealed by the SDK (Python), bound to principal, method, exact-argument digest and expiry, with a single-use nonce. Forged `inputResponses` without valid state cause a fresh prompt, never execution. Legacy: elicitation. No capability means deny. |
| Data leaving the server | Role-based field redaction; `export+pii` label rules; non-JSON text is withheld when a redaction rule applies; UGC is labelled, not executed. |
| Budgets | Atomic burst+steady counters (Lua / `FOR UPDATE` / SQLite transaction / single-thread memory), keyed per tenant, client, agent or user. |
| Audit integrity | SHA-256 hash chain (byte-identical in TS and Python). Appends are atomic across processes (Redis CAS, PG advisory lock, SQLite `BEGIN IMMEDIATE`). |
| PDP | Bearer token compared in constant time; directory mode ignores PEP-supplied roles; 1 MB body cap, 1000-item batch cap; deny on any engine error. |

## Known bypass limits (what the guard cannot stop)
1. **A wrapped server that lies.** The guard decides on the tool *name* and *arguments*. A tool whose implementation
   does more than its name says (e.g. `get_report` that also emails it) is out of reach. Mitigation: argument
   constraints, `scope.lookup` on the record the handler really touches, and code review.
2. **Approval trusts the client UI.** Elicitation / MRTR prove that *the client application* returned "approve", not
   that a human read it. A malicious client can auto-approve. Use the durable queue approver (`approval: "queue"` /
   `store_approver`) when a human must be out-of-band.
3. **Token theft.** A stolen bearer token is that user until it expires. Keep TTLs short (token exchange defaults to
   300 s), bind tokens with DPoP/mTLS at the IdP or gateway, and revoke grants (`mcp-rbac revoke`).
4. **Toolsets are not a security boundary.** They narrow lists and calls for usability; roles and scopes are the boundary.
5. **Redaction is field-based.** PII inside free text (a review body that contains an email) is not detected. When a
   redaction rule applies, non-JSON text is withheld, but PII in JSON fields that no rule lists passes through.
6. **Rate-limit windows are fixed windows.** Up to 2× the limit can pass at a window edge; the burst window limits the spike.
7. **Audit truncation.** A writer with database access can drop the newest events without breaking the chain.
   Export the head hash periodically (`audit-verify`, OTLP) to storage the writer can't modify.
8. **Multi-instance deployments** must share the store (Redis/Postgres) and the `requestStateKey` (TS) or
   `RequestStateSecurity(keys=...)` (Python). Otherwise nonces are per-instance and an approved state could be
   replayed once against each instance within its TTL.
9. **The PEP-trusting PDP mode** (no `directory`) accepts roles from the request. Use it only behind its token on a private network.
10. **Stdio has no token.** Roles for a stdio server come from the operator's configuration (the local user), not per request.
11. **Legacy SSE responses** don't carry RateLimit headers; limits are still enforced and reported in `_meta`.

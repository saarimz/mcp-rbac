# mcp-rbac for Python

`python/` is a typed (mypy strict, `py.typed`) package for servers built on the official Python MCP SDK
(`mcp>=2.3,<3`, `mcp.server.mcpserver.MCPServer`). It shares these with the TypeScript package, and tests check
each one across languages: the JSON policy format, canonical JSON and the audit hash chain (byte-identical), Redis keys and
Lua scripts, Postgres tables, budget keys, and the AuthZEN mapping and error strings.

```bash
pip install ./python[jwt]            # extras: jwt, redis, postgres, pdp, dev
```

## Guarding an MCPServer
```python
from mcp.server.mcpserver import MCPServer
from mcp_rbac import Role, Limit, ScopePolicy, OutputPolicy, LabelRule
from mcp_rbac.mcpserver import RBAC, JwtVerifier

rbac = RBAC({"owner": Role.everything(), "manager": Role.of("get_*", "send_*")},
            scopes=ScopePolicy(), output=OutputPolicy(label_rules=[LabelRule(["export", "pii"], allow_roles=["owner"])]),
            store=None)          # MemoryStore; RedisStore(redis.asyncio client) / await PostgresStore.open(dsn) for multi-instance
server = MCPServer("shop", token_verifier=JwtVerifier(KEY, issuer=ISS, audience=AUD), auth=...)

@server.tool()
@rbac.tool(allow=["manager"], scopes=["campaigns:write"], scope=lambda a: {"tenant": lookup_account(a["campaign_id"])},
           approve=True, limits=[Limit("*", max=5, window_s=86400, per="tenant", burst=(2, 60))])
def send_campaign(campaign_id: str) -> str: ...

rbac.install(server)          # deny-by-default middleware; tools/list filtered per caller
app = rbac.http_app(server)   # streamable HTTP + 403 insufficient_scope step-up in front
```

- **Identity** comes only from the SDK-verified `AccessToken` (`identity=` maps it; the default reads `roles`, scopes,
  `tenant`, `client_id` and the RFC 8693 `act` chain). A malformed `act` means unauthenticated. `local_identity` applies to
  stdio/in-process only, never to HTTP.
- **Scopes**: `ScopePolicy` hierarchy (write implies read). With `http_app`, a missing scope returns HTTP 403 with
  `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"` (JSON-RPC -32003), the same as the TS server.
- **Tenants / org roles / custom roles**: `OrgDirectory`, `OrgRole`, `org_assignments`, `custom_role(permission_sets, picks)`.
- **Output**: `redact=[paths]`, `redact_unless=[roles]`, `labels=[...]`, label rules; non-JSON text is withheld when a redaction rule applies.
- **Delegation**: `DelegationOptions(actors={"agent-x": ActorPolicy(tools=["get_*"], scopes=["campaigns:read"])})`; unknown actors are denied.
- **Approvals**: `approve=True`. 2026-07-28 clients get an MRTR `input_required` result (the SDK seals `requestState`,
  bound to principal, tool and args digest, with a single-use nonce through the store); older clients get form
  elicitation; no capability means deny. `approvals="queue"` uses durable store approvals decided out of band (also from TS).
  Multi-instance: pass `RequestStateSecurity(keys=...)` to the SDK and a shared store.
- **Audit**: hash-chained events in the store; `audit_retention_s`; `to_jsonl`, `verify_audit_chain`;
  `python -m mcp_rbac audit-verify export.jsonl` (exit 2 when broken).
- **OTel**: an internal span `mcp-rbac authorize {tool}` with `mcp_rbac.*` decision attributes under the SDK's `tools/call` span.
- **AuthZEN**: `AuthZenEngine(AuthZenClient(url, token=...))` (fails closed); `python -m mcp_rbac pdp --policy p.json [--users u.json] [--token-env VAR]`.

## Example and tests
`examples/klaviyo-style/server.py` (mock data). Tests: `cd python && .venv/bin/python -m pytest` (48 tests, including
Redis/Postgres and TS↔Python cross-language checks when `redis-server` / `pg_ctl` are on PATH; skipped otherwise).

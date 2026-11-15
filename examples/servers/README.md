# Three realistic MCP servers behind the mcp-rbac core

Real servers, not mocks. Each has its own SQLite database, a domain-specific tool set, a policy, stdio and Streamable
HTTP transports, JWT bearer auth, human approvals, an audit table and an admin CLI. They exist to prove the guard against
servers shaped like production ones. The red team (`redteam/`) and the Inspector e2e (`test/servers-inspector.e2e.test.ts`)
drive them.

| Server | Language / SDK | Guard | Policy | Tools | Roles | Domain |
|---|---|---|---|---|---|---|
| `venue/` | TypeScript, MCP TS SDK 1.32 | `protectWithCore` (WASM) | `examples/policies/venue.yaml` | 19 | owner, project_manager, door_staff, vendor | events, tickets, refunds, guest lists, vendors |
| `marketing/` | Python, MCP Python SDK 2.3 (MCPServer) | `CoreGuard` (PyO3) | `examples/policies/marketing.yaml` | 25 | account_admin, marketer, analyst, support, viewer | multi-tenant profiles, lists, campaigns, flows, exports |
| `../../go/examples/devops/` | Go, go-sdk 1.8 | `Engine.Protect` (wazero) | `examples/policies/devops.yaml` | 21 | sre, oncall, developer, release_manager, auditor, ci_bot | deploys, builds, secrets, incidents, services, logs, flags |

## Run

```sh
# stdio: identity comes from the environment (a local, trusted launch)
MCP_RBAC_IDENTITY='{"id":"sam","tenant":"acme","roles":["sre"]}' go run ./go/examples/devops --db /tmp/devops.db
MCP_RBAC_IDENTITY='{"id":"ana","tenant":"acme","roles":["account_admin"]}' python/.venv/bin/python examples/servers/marketing/server.py --db /tmp/m.db
MCP_RBAC_IDENTITY='{"id":"olu","roles":["owner"]}' npx tsx examples/servers/venue/server.ts --db /tmp/v.db

# Streamable HTTP on 127.0.0.1 (prints "listening on <url>"; --http 0 picks a free port): bearer tokens required
MCP_DEMO_JWT_SECRET=$(openssl rand -hex 32) npx tsx examples/servers/venue/server.ts --http 8080 --db /tmp/v.db

# admin CLI (the human side of approvals, revocation, audit)
npx tsx examples/servers/venue/server.ts admin pending --db /tmp/v.db     # shows tool + exact args
npx tsx examples/servers/venue/server.ts admin approve 3 --db /tmp/v.db
npx tsx examples/servers/venue/server.ts admin revoke <jti> --db /tmp/v.db
npx tsx examples/servers/venue/server.ts admin audit --db /tmp/v.db
```

## Token format (HTTP)

A compact JWS signed with **HS256** (the algorithm is pinned: anything else, `alg: none` or a `crit` header is rejected),
using the shared secret `MCP_DEMO_JWT_SECRET` (at least 32 bytes; the server refuses to start otherwise). Mint one with
`examples/servers/shared/auth.py` (`mint(secret, claims)`), `auth.ts`, or `go/examples/devops/auth.go`.

| Claim | Required | Meaning / check |
|---|---|---|
| `iss` | yes | must be `mcp-guard-demo-idp` |
| `aud` | yes | per server: `venue-mcp`, `marketing-mcp`, `devops-mcp` (a token for one server is rejected by the others) |
| `sub` | yes | user id → `identity.id`; an HTTP session is bound to it (another subject on that session id gets 403) |
| `iat`, `exp` | yes | 5 s leeway; `exp − iat` ≤ 1 hour; `iat` not in the future |
| `nbf` | no | not before (5 s leeway) |
| `jti` | yes | revocable: `admin revoke <jti>` blocks the token on its next request, including inside a live session |
| `roles` | no | → `identity.roles`: role names or `{role, scope}` objects |
| `rscope` | no | → `identity.scope` (e.g. `{venue: "bk"}`, `{org: "acme"}`) |
| `tenant` | no | → `identity.tenant` |
| `scope` | no | space-separated OAuth scopes → `identity.scopes` |
| `client_id` | no | → `identity.clientId` (keys `shared: client` rate limits) |
| `org_roles` | no | → `identity.orgRoles` |
| `act` | no | RFC 8693 actor chain (nested `{sub, act}`) → `identity.actors`, outermost first, at most 8 |

Errors: 401 with `WWW-Authenticate: Bearer error="invalid_token", error_description="<reason>"` (bad signature, alg, iss,
aud, expired, lifetime, revoked...); 413 above 1 MiB (with `Connection: close`). DNS-rebinding protection is on. The
format is a demo IdP's: in production, put your real OAuth 2.1 resource-server validation in its place (the guard only
needs the resulting identity object).

## Approvals

A `needs_approval` decision (for example a venue refund over $200, or devops `secrets.read` in prod) records a pending
request bound to **(subject, tool, canonical args)** and returns "Approval required". A human runs `admin pending`, which
shows the exact arguments, then `admin approve ID`. The next identical call by the same subject consumes the approval:
single use and atomic. 24 concurrent callers sharing one approval produce exactly one execution (tested on all three servers).
Changing any argument needs a new approval.

## Tests that drive them

- `test/servers-inspector.e2e.test.ts`: MCP Inspector 2.15 CLI over stdio and HTTP, `--strict` schema checks.
- `go/examples/devops/e2e_test.go`, `python/tests/test_servers_marketing.py`, `test/servers-venue*.test.ts`.
- `python -m redteam.run` (140 checks, report in `redteam/report.md`) and `python -m redteam.malformed` (hostile input + soak).

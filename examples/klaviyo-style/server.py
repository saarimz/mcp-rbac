"""Klaviyo-style multi-account marketing MCP server (Python, official SDK ``MCPServer``). MOCK DATA ONLY.

Same org, roles, matrix, scopes and data as server.ts (both read data.json):
  - Klaviyo's 8 roles + a custom role built from permission sets
  - org roles: Super Admin (Owner on all accounts), "All accounts", "By group", "Specific accounts"
  - API scopes per tool (write implies read), toolsets
  - PII redaction unless Owner/Admin/Support; PII export only for Owner/Admin
  - send_campaign: human approval (MRTR for 2026-07-28 clients, elicitation for older) + per-account budget

    python examples/klaviyo-style/server.py [--port 3341]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Literal

from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer

from mcp_rbac import Identity, LabelRule, Limit, OrgDirectory, OrgRole, OutputPolicy, Role, ScopePolicy, Toolsets, custom_role, org_assignments
from mcp_rbac.mcpserver import RBAC

DATA: dict[str, Any] = json.loads((Path(__file__).parent / "data.json").read_text())
KRole = Literal["Owner", "Admin", "Manager", "Analyst", "Campaign Coordinator", "Content Creator", "Support", "Social Media Manager"]
M: dict[str, list[KRole]] = DATA["matrix"]
S: dict[str, list[str]] = DATA["scopes"]
ORG = OrgDirectory(DATA["org"]["accounts"], DATA["org"]["groups"])


class MockTokens:
    """TokenVerifier for the mock bearer tokens in data.json (a real deployment uses JwtVerifier / introspection)."""

    async def verify_token(self, token: str) -> AccessToken | None:
        u = DATA["users"].get(token)
        if not u:
            return None
        return AccessToken(token=token, client_id="klaviyo-style-demo", scopes=u.get("scopes", DATA["allScopes"]), subject=u["id"],
                           claims={"sub": u["id"], "org_roles": u["orgRoles"]})


def identity(tok: AccessToken) -> Identity[Any] | None:
    """Org roles -> per-account assignments, resolved on every request."""
    roles = [OrgRole(r["role"], r["access"]) for r in (tok.claims or {}).get("org_roles", [])]
    return Identity(id=tok.subject or tok.client_id, assignments=org_assignments(ORG, roles), scopes=frozenset(tok.scopes), client_id=tok.client_id)


def account(args: Any) -> dict[str, str]:
    a = args.get("account_id")
    if a not in ORG.accounts:
        raise LookupError("unknown account")
    return {"tenant": a}


def record(table: str, key: str) -> Any:
    def lookup(args: Any) -> dict[str, str]:
        return {"tenant": DATA[table][args[key]]["account"]}
    return lookup


def build(state: dict[str, list[str]] | None = None, *, port: int = 3341, **rbac_kw: Any) -> tuple[MCPServer, RBAC[Any]]:
    state = state if state is not None else {"sent": []}
    roles: dict[str, Role] = {r: Role() for r in DATA["roles"]}
    for name, picks in DATA["customRoles"].items():
        roles[name] = custom_role(DATA["permissionSets"], picks)
    rbac: RBAC[Any] = RBAC(roles, identity=identity, scopes=ScopePolicy(), toolsets=Toolsets(DATA["toolsets"]),
                           output=OutputPolicy(label_rules=[LabelRule(["export", "pii"], allow_roles=["Owner", "Admin"])]), **rbac_kw)
    server = MCPServer("klaviyo-style-mock", instructions="Mock Klaviyo-style marketing server (mock data).", token_verifier=MockTokens(),
                       auth=AuthSettings(issuer_url="https://auth.example.invalid", resource_server_url=f"http://127.0.0.1:{port}/mcp", validate_token_resource=False))

    @server.tool()
    @rbac.tool(allow=M["list_campaigns"], scopes=S["list_campaigns"], scope=account)
    def list_campaigns(account_id: str) -> dict[str, Any]:
        return {"campaigns": [{"id": k, "name": c["name"], "recipients": c["recipients"]} for k, c in DATA["campaigns"].items() if c["account"] == account_id]}

    @server.tool()
    @rbac.tool(allow=M["create_campaign"], scopes=S["create_campaign"], scope=account)
    def create_campaign(account_id: str, name: str) -> str:
        return f'created draft "{name[:120]}" (mock)'

    @server.tool()
    @rbac.tool(allow=M["send_campaign"], scopes=S["send_campaign"], scope=record("campaigns", "campaign_id"), approve=True,
               limits=[Limit("*", max=5, window_s=86400, per="tenant", burst=(2, 60), name="sends")])
    def send_campaign(campaign_id: str) -> str:
        state["sent"].append(campaign_id)
        return f"sent {campaign_id} (mock)"

    @server.tool()
    @rbac.tool(allow=M["get_profiles"], scopes=S["get_profiles"], scope=account, labels=["pii"],
               redact=["profiles.*.email", "profiles.*.phone_number"], redact_unless=["Owner", "Admin", "Support"])
    def get_profiles(account_id: str) -> dict[str, Any]:
        return {"profiles": [{"id": k, "first_name": p["first_name"], "email": p["email"], "phone_number": p["phone_number"]}
                             for k, p in DATA["profiles"].items() if p["account"] == account_id]}

    @server.tool()
    @rbac.tool(allow=M["export_profiles"], scopes=S["export_profiles"], scope=account, labels=["pii", "export"])
    def export_profiles(account_id: str) -> dict[str, str]:
        return {"export": f"export of {account_id} queued (mock)"}

    @server.tool()
    @rbac.tool(allow=M["update_profile"], scopes=S["update_profile"], scope=record("profiles", "profile_id"))
    def update_profile(profile_id: str, first_name: str) -> str:
        return f"updated {profile_id} (mock)"

    @server.tool()
    @rbac.tool(allow=M["get_metrics"], scopes=S["get_metrics"], scope=account)
    def get_metrics(account_id: str) -> dict[str, Any]:
        return {"account_id": account_id, "opens": 1234, "clicks": 210, "revenue": 5400.5}

    @server.tool()
    @rbac.tool(allow=M["create_template"], scopes=S["create_template"], scope=account)
    def create_template(account_id: str, name: str) -> str:
        return f'template "{name[:120]}" created (mock)'

    @server.tool()
    @rbac.tool(allow=M["get_reviews"], scopes=S["get_reviews"], scope=account, labels=["userGeneratedContent"])
    def get_reviews(account_id: str) -> dict[str, Any]:
        return {"reviews": [{"id": k, "rating": r["rating"], "body": r["body"]} for k, r in DATA["reviews"].items() if r["account"] == account_id]}

    @server.tool()
    @rbac.tool(allow=M["reply_review"], scopes=S["reply_review"], scope=record("reviews", "review_id"))
    def reply_review(review_id: str, text: str) -> str:
        return f"replied to {review_id} (mock)"

    rbac.install(server)
    return server, rbac


if __name__ == "__main__":
    import uvicorn

    port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 3341
    srv, rbac = build(port=port)
    uvicorn.run(rbac.http_app(srv), host="127.0.0.1", port=port, log_level="warning")  # http_app adds the 403 scope step-up

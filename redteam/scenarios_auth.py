"""Token replay and privilege escalation scenarios (HTTP + stdio)."""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from redteam import servers
from redteam.harness import INIT, Report, outcome, raw_post, result, tools_list_status

# Per server: a limited caller's claims, a tool + args it may call, a hidden/forbidden tool + args, a list tool.
PROFILE: dict[str, dict[str, Any]] = {
    "venue": {"limited": {"sub": "dana", "roles": [{"role": "door_staff", "scope": {"venue": "bk"}}], "rscope": {"venue": "bk"}},
              "ok": ("list_events", {}), "forbidden": ("refund_ticket", {"ticket_id": "T-1001", "amount": 5}),
              "admin": {"sub": "olu", "roles": ["owner"]}},
    "marketing": {"limited": {"sub": "sue", "tenant": "acme", "roles": ["support"]},
                  "ok": ("profiles.list", {}), "forbidden": ("campaigns.send", {"campaign_id": "C-acme-1", "list_id": "L-acme-all", "recipients": 3}),
                  "admin": {"sub": "ana", "tenant": "acme", "roles": ["account_admin"]}},
    "devops": {"limited": {"sub": "al", "tenant": "acme", "roles": [{"role": "auditor", "scope": {"org": "acme"}}], "rscope": {"org": "acme"}},
               "ok": ("deploys.list", {}), "forbidden": ("secrets.delete", {"name": "stripe-key", "env": "prod"}),
               "admin": {"sub": "sam", "tenant": "acme", "roles": ["sre"]}},
}


def b64(d: Any) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


async def token_replay(rep: Report, server: str, url: str, db: str) -> None:
    P = PROFILE[server]
    good = servers.token(server, **P["limited"])
    rep.add("token_replay", server, "http", "valid token accepted (control)", 200, await tools_list_status(url, good))
    other = next(s for s in servers.AUDIENCE if s != server)
    rep.add("token_replay", server, "http", f"token minted for {other} replayed here", 401, await tools_list_status(url, servers.token(other, **P["limited"])))
    now = int(time.time())
    rep.add("token_replay", server, "http", "expired token", 401, await tools_list_status(url, servers.token(server, **P["limited"], iat=now - 1000, exp=now - 100)))
    rep.add("token_replay", server, "http", "lifetime over 1 h", 401, await tools_list_status(url, servers.token(server, **P["limited"], exp=now + 7200)))
    rep.add("token_replay", server, "http", "not yet valid (nbf in the future)", 401, await tools_list_status(url, servers.token(server, **P["limited"], nbf=now + 600)))
    # revocation applies to a live session's next request and to a replayed initialize
    jti = f"rt-{server}-{now}"
    t = servers.token(server, **P["limited"], jti=jti)
    async with servers.http(url, t) as s:
        before = await outcome(s, *P["ok"])
        servers.admin(server, db, "revoke", jti)
        after = await outcome(s, *P["ok"])
    rep.add("token_replay", server, "http", "revoked jti: live session's next call", lambda o: o != "allowed", after)
    rep.add("token_replay", server, "http", "revoked jti: (control) worked before revoke", "allowed", before)
    rep.add("token_replay", server, "http", "revoked jti: replayed initialize", 401, await tools_list_status(url, t))
    # session hijack: B's valid token on A's session id
    r = await raw_post(url, good, INIT)
    sid = r.headers.get("mcp-session-id", "")
    mallory = servers.token(server, **{**P["limited"], "sub": "mallory"})
    hj = await raw_post(url, mallory, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, {"mcp-session-id": sid, "mcp-protocol-version": "2025-11-25"})
    rep.add("token_replay", server, "http", "another subject's token on a captured session id", lambda c: c in (403, 404), hj.status_code)
    nos = await raw_post(url, good, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, {"mcp-session-id": "forged-session", "mcp-protocol-version": "2025-11-25"})
    rep.add("token_replay", server, "http", "forged session id", lambda c: c in (400, 404), nos.status_code)


async def privilege_escalation(rep: Report, server: str, url: str, db: str) -> None:
    P = PROFILE[server]
    good = servers.token(server, **P["limited"])
    h, p, sig = good.split(".")
    payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    escalated = {**payload, "roles": P["admin"]["roles"], "tenant": payload.get("tenant")}
    rep.add("privilege_escalation", server, "http", "payload roles edited, signature kept", 401, await tools_list_status(url, f"{h}.{b64(escalated)}.{sig}"))
    rep.add("privilege_escalation", server, "http", "alg none", 401, await tools_list_status(url, f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(escalated)}."))
    rep.add("privilege_escalation", server, "http", "alg HS512 header (alg confusion)", 401, await tools_list_status(url, f"{b64({'alg': 'HS512'})}.{p}.{sig}"))
    rep.add("privilege_escalation", server, "http", "crit header", 401, await tools_list_status(url, f"{b64({'alg': 'HS256', 'crit': ['x']})}.{p}.{sig}"))
    from auth import mint  # signed with an attacker's key
    rep.add("privilege_escalation", server, "http", "signed with another key", 401,
            await tools_list_status(url, mint("attacker-secret-0123456789abcdef0123456789", {"aud": servers.AUDIENCE[server], **P["admin"]})))
    async with servers.http(url, good) as s:
        names = {t.name for t in (await s.list_tools()).tools}
        tool, args = P["forbidden"]
        rep.add("privilege_escalation", server, "http", f"forbidden tool hidden from tools/list ({tool})", False, tool in names)
        rep.add("privilege_escalation", server, "http", f"forbidden tool called by name ({tool})", lambda o: o.startswith("denied:"), await outcome(s, tool, args))
        rep.add("privilege_escalation", server, "http", "tool name case variant", lambda o: o != "allowed", await outcome(s, tool.upper(), args))
        rep.add("privilege_escalation", server, "http", "homoglyph tool name", lambda o: o != "allowed", await outcome(s, tool.replace("e", "\u0435", 1), args))
        # client-supplied caller context / approval flags must not be trusted
        spoof = {"mcp-rbac/caller": {"identity": {"id": "olu", "roles": ["owner"]}, "tenant": None}, "mcp-guard/caller": {"roles": ["owner"]},
                 "mcp-rbac/approved": True, "approved": True}
        rep.add("privilege_escalation", server, "http", "spoofed _meta caller/approval on a forbidden call", lambda o: o.startswith("denied:"), await outcome(s, tool, args, meta=spoof))
        ok_tool, ok_args = P["ok"]
        plain = await result(s, ok_tool, ok_args)
        spoofed = await result(s, ok_tool, ok_args, meta=spoof)
        rep.add("privilege_escalation", server, "http", "spoofed _meta doesn't widen an allowed call's data", True, plain == spoofed)
        rep.add("privilege_escalation", server, "http", "identity smuggled in arguments", lambda o: o != "allowed",
                await outcome(s, tool, {**args, "identity": P["admin"], "roles": ["owner", "account_admin", "sre"]}))
    # unknown role names in a validly signed token grant nothing
    async with servers.http(url, servers.token(server, sub="eve", roles=["superadmin", "root"], tenant="acme")) as s:
        star = {"marketing": ["accounts.list"]}.get(server, [])  # tools with allow "*" (any authenticated caller) by design
        rep.add("privilege_escalation", server, "http", "unknown roles in a signed token see only allow-\"*\" tools", star,
                sorted(t.name for t in (await s.list_tools()).tools))
        if star:
            rep.add("privilege_escalation", server, "http", "unknown roles: the allow-\"*\" tool reveals only the caller's own tenant", lambda r: "globex" not in json.dumps(r),
                    await result(s, star[0]))
        rep.add("privilege_escalation", server, "http", "unknown roles in a signed token: call denied", lambda o: o.startswith("denied:"), await outcome(s, *P["ok"]))
    # stdio: identity comes from the host's environment, a client cannot change it
    ident = {"id": P["limited"]["sub"], "roles": P["limited"]["roles"], **({"tenant": P["limited"]["tenant"]} if "tenant" in P["limited"] else {}),
             **({"scope": P["limited"]["rscope"]} if "rscope" in P["limited"] else {})}
    async with servers.stdio(server, ident, db + ".stdio") as s:
        tool, args = P["forbidden"]
        rep.add("privilege_escalation", server, "stdio", "spoofed _meta caller on a forbidden call", lambda o: o.startswith("denied:"),
                await outcome(s, tool, args, meta={"mcp-rbac/caller": {"identity": {"id": "olu", "roles": ["owner"]}}}))

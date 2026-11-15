"""Klaviyo-style marketing MCP server: 25 tools over SQLite behind the Rust core (PyO3), stdio or Streamable HTTP.

    python server.py [--db FILE]                      stdio; identity from MCP_RBAC_IDENTITY (JSON)
    python server.py --http PORT [--db FILE]          Streamable HTTP on 127.0.0.1; bearer tokens (MCP_DEMO_JWT_SECRET)
    python server.py admin pending|approve ID|revoke JTI|audit --db FILE

Accounts are tenants. Every record-addressed call is authorized against the account that owns the record (resource
resolver); every query is scoped to that account. Approvals are human and out of band, bound to (subject, tool, exact
arguments), single use.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import os
import pathlib
import socket
import sqlite3
import sys
from collections.abc import Callable
from typing import Any, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(ROOT / "python/src"), str(HERE.parent / "shared"), str(HERE)]

from auth import BearerFront, bearer, identity_of, verify  # noqa: E402
from db import SerializedDB, open_db  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402
from mcp.server.mcpserver.exceptions import ToolError  # noqa: E402
from mcp.server.transport_security import TransportSecuritySettings  # noqa: E402

from mcp_rbac.core_guard import CoreGuard, current_caller  # noqa: E402
from mcp_rbac.audit_sink import SqliteAuditSink, audit_record_from_decision  # noqa: E402

AUDIENCE = "marketing-mcp"
POLICY = (ROOT / "examples/policies/marketing.yaml").read_text()
GROUPS = {"agency_clients": ["acme", "globex"]}
ALL_ACCOUNTS = ["acme", "globex", "initech", "umbrella"]


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def args_hash(tool: str, args: Any) -> str:
    return hashlib.sha256(f"{tool}\0{json.dumps(args, sort_keys=True, separators=(',', ':'))}".encode()).hexdigest()


class Denied(ToolError):
    """A business-rule failure, reported to the caller as a tool error (isError)."""


def resolve_resource(db: SerializedDB, tool: str, a: dict[str, Any]) -> dict[str, str] | None:
    """The account that owns the record a call touches (never trusted from arguments)."""
    def owner(table: str, key: str) -> dict[str, str]:
        v = a.get(key)
        row = db.execute(f"SELECT account FROM {table} WHERE id = ?", (v,)).fetchone() if isinstance(v, str) else None  # noqa: S608
        return {"account": row["account"]} if row else {}
    by_record = {"profiles.get": ("profiles", "profile_id"), "profiles.update": ("profiles", "profile_id"), "profiles.delete": ("profiles", "profile_id"),
                 "data_privacy.delete_profile": ("profiles", "profile_id"), "lists.add_profiles": ("lists", "list_id"),
                 "campaigns.get": ("campaigns", "campaign_id"), "campaigns.update": ("campaigns", "campaign_id"),
                 "campaigns.send": ("campaigns", "campaign_id"), "flows.update_status": ("flows", "flow_id")}
    if tool in by_record:
        return owner(*by_record[tool])
    acct = a.get("account")
    return {"account": acct} if isinstance(acct, str) else None  # explicit target account, else the caller's own


def build(db: SerializedDB, identity_fn: Any, sink: SqliteAuditSink | None = None) -> MCPServer:
    s = MCPServer("marketing-platform", version="0.4.0")

    def acct_of() -> str:
        c = current_caller()
        if c is None:
            raise Denied("no caller context: tools must run behind the guard")
        acct = (c.get("resource") or {}).get("account") or c.get("tenant")
        if not acct:
            raise Denied("pass `account` (you have access to several)")
        return str(acct)

    def rows(sql: str, *p: Any) -> list[dict[str, Any]]:
        return [dict(r) for r in db.execute(sql, p).fetchall()]

    def one(sql: str, *p: Any) -> dict[str, Any] | None:
        r = db.execute(sql, p).fetchone()
        return dict(r) if r else None

    def profile_out(p: dict[str, Any]) -> dict[str, Any]:
        return {"id": p["id"], "account": p["account"], "email": p["email"], "phone_number": p["phone_number"], "first_name": p["first_name"],
                "last_name": p["last_name"], "location": {"city": p["city"], "country": p["country"]}}

    def owned(table: str, rid: str) -> dict[str, Any]:
        r = one(f"SELECT * FROM {table} WHERE id = ?", rid)  # noqa: S608
        if r is None or r["account"] != acct_of() or r.get("deleted"):
            raise Denied(f"No {table[:-1]} {rid}")
        return r

    def tool(name: str, description: str) -> Callable[[F], F]:
        return s.tool(name=name, description=description, structured_output=True)

    @tool("accounts.list", "Accounts you can work in")
    def accounts_list() -> dict[str, Any]:
        c = current_caller() or {}
        ident = c.get("identity") or {}
        if ident.get("tenant"):
            return {"accounts": [ident["tenant"]]}
        seen: list[str] = []
        for r in ident.get("orgRoles") or []:
            acc = r.get("access")
            names: list[str] = []
            if acc == "all":
                names = ALL_ACCOUNTS
            elif isinstance(acc, dict) and isinstance(acc.get("group"), str):
                names = GROUPS.get(acc["group"], [])
            elif isinstance(acc, dict) and isinstance(acc.get("accounts"), list):
                names = acc["accounts"]
            seen += [n for n in names if n in ALL_ACCOUNTS and n not in seen]
        return {"accounts": seen}

    @tool("profiles.get", "One profile")
    def profiles_get(profile_id: str) -> dict[str, Any]:
        return profile_out(owned("profiles", profile_id))

    @tool("profiles.list", "Profiles in the account")
    def profiles_list(account: str | None = None, page_size: int = 50) -> dict[str, Any]:
        acct = acct_of()
        return {"profiles": [profile_out(p) for p in rows("SELECT * FROM profiles WHERE account = ? AND deleted = 0 ORDER BY id LIMIT ?", acct, page_size)]}

    @tool("profiles.create", "Create a profile")
    def profiles_create(email: str, first_name: str = "", last_name: str = "", account: str | None = None) -> dict[str, Any]:
        acct = acct_of()
        pid = f"P-{acct}-{abs(hash((email, now()))) % 10**8}"
        db.execute("INSERT INTO profiles (id, account, email, first_name, last_name) VALUES (?, ?, ?, ?, ?)", (pid, acct, email, first_name, last_name))
        return profile_out(owned("profiles", pid))

    @tool("profiles.update", "Update a profile's name or location")
    def profiles_update(profile_id: str, first_name: str | None = None, last_name: str | None = None, city: str | None = None) -> dict[str, Any]:
        p = owned("profiles", profile_id)
        db.execute("UPDATE profiles SET first_name = ?, last_name = ?, city = ? WHERE id = ?",
                   (first_name or p["first_name"], last_name or p["last_name"], city or p["city"], profile_id))
        return profile_out(owned("profiles", profile_id))

    @tool("profiles.delete", "Delete a profile (needs approval)")
    def profiles_delete(profile_id: str) -> dict[str, Any]:
        owned("profiles", profile_id)
        db.execute("UPDATE profiles SET deleted = 1 WHERE id = ?", (profile_id,))
        return {"deleted": profile_id}

    @tool("profiles.export", "Export profiles with contact details (account admins)")
    def profiles_export(format: str, account: str | None = None) -> dict[str, Any]:  # noqa: A002 - API argument name
        acct = acct_of()
        ps = rows("SELECT id, email, phone_number, first_name, last_name FROM profiles WHERE account = ? AND deleted = 0", acct)
        c = current_caller() or {}
        db.execute("INSERT INTO exports (account, by_sub, format, rows, at) VALUES (?, ?, ?, ?, ?)", (acct, (c.get("identity") or {}).get("id"), format, len(ps), now()))
        return {"format": format, "rows": len(ps), "profiles": ps}

    @tool("data_privacy.delete_profile", "GDPR erasure of a profile (needs approval)")
    def privacy_delete(profile_id: str) -> dict[str, Any]:
        owned("profiles", profile_id)
        c = current_caller() or {}
        db.execute("UPDATE profiles SET email = 'erased', phone_number = NULL, first_name = NULL, last_name = NULL, city = NULL, deleted = 1 WHERE id = ?", (profile_id,))
        db.execute("INSERT INTO privacy_requests (account, profile_id, by_sub, at) VALUES (?, ?, ?, ?)", (acct_of(), profile_id, (c.get("identity") or {}).get("id"), now()))
        return {"erased": profile_id}

    @tool("lists.list", "Lists in the account")
    def lists_list(account: str | None = None) -> dict[str, Any]:
        return {"lists": rows("SELECT l.id, l.name, count(m.profile_id) AS size FROM lists l LEFT JOIN list_members m ON m.list_id = l.id WHERE l.account = ? GROUP BY l.id", acct_of())}

    @tool("lists.create", "Create a list")
    def lists_create(name: str, account: str | None = None) -> dict[str, Any]:
        acct = acct_of()
        lid = f"L-{acct}-{abs(hash((name, now()))) % 10**8}"
        db.execute("INSERT INTO lists VALUES (?, ?, ?)", (lid, acct, name))
        return {"id": lid, "name": name}

    @tool("lists.add_profiles", "Add profiles to a list")
    def lists_add(list_id: str, profile_ids: list[str], count: int) -> dict[str, Any]:
        lst = owned("lists", list_id)
        if count != len(profile_ids):
            raise Denied(f"count must equal the number of profile_ids ({len(profile_ids)})")
        for pid in profile_ids:  # every profile must belong to the list's account: no cross-account smuggling
            p = one("SELECT account FROM profiles WHERE id = ? AND deleted = 0", pid)
            if p is None or p["account"] != lst["account"]:
                raise Denied(f"No profile {pid}")
        db.executemany("INSERT OR IGNORE INTO list_members VALUES (?, ?)", [(list_id, pid) for pid in profile_ids])
        return {"list_id": list_id, "added": len(profile_ids)}

    @tool("segments.list", "Segments in the account")
    def segments_list(account: str | None = None) -> dict[str, Any]:
        return {"segments": rows("SELECT * FROM segments WHERE account = ?", acct_of())}

    @tool("segments.create", "Create a segment")
    def segments_create(name: str, definition: str, account: str | None = None) -> dict[str, Any]:
        acct = acct_of()
        sid = f"S-{acct}-{abs(hash((name, now()))) % 10**8}"
        db.execute("INSERT INTO segments VALUES (?, ?, ?, ?)", (sid, acct, name, definition))
        return {"id": sid}

    @tool("campaigns.list", "Campaigns in the account")
    def campaigns_list(account: str | None = None) -> dict[str, Any]:
        return {"campaigns": rows("SELECT id, name, channel, status, sent_to FROM campaigns WHERE account = ?", acct_of())}

    @tool("campaigns.get", "One campaign, with its internal notes")
    def campaigns_get(campaign_id: str) -> dict[str, Any]:
        return owned("campaigns", campaign_id)

    @tool("campaigns.create", "Create a draft campaign")
    def campaigns_create(name: str, channel: str, list_id: str | None = None, account: str | None = None) -> dict[str, Any]:
        acct = acct_of()
        if list_id is not None:
            owned("lists", list_id)
        cid = f"C-{acct}-{abs(hash((name, now()))) % 10**8}"
        db.execute("INSERT INTO campaigns (id, account, name, channel, list_id) VALUES (?, ?, ?, ?, ?)", (cid, acct, name, channel, list_id))
        return {"id": cid, "status": "draft"}

    @tool("campaigns.update", "Rename a campaign or change its list/template")
    def campaigns_update(campaign_id: str, name: str | None = None, list_id: str | None = None, template_id: str | None = None) -> dict[str, Any]:
        c = owned("campaigns", campaign_id)
        if list_id is not None:
            owned("lists", list_id)
        if template_id is not None:
            owned("templates", template_id)
        db.execute("UPDATE campaigns SET name = ?, list_id = ?, template_id = ? WHERE id = ?",
                   (name or c["name"], list_id or c["list_id"], template_id or c["template_id"], campaign_id))
        return owned("campaigns", campaign_id)

    @tool("campaigns.send", "Send a campaign to a list (approval at 10,000+ recipients)")
    def campaigns_send(campaign_id: str, list_id: str, recipients: int) -> dict[str, Any]:
        c = owned("campaigns", campaign_id)
        lst = owned("lists", list_id)  # same account as the campaign (owned() checks the caller's account)
        size = one("SELECT count(*) AS n FROM list_members m JOIN profiles p ON p.id = m.profile_id WHERE m.list_id = ? AND p.deleted = 0", lst["id"])["n"]  # type: ignore[index]
        if recipients != size:  # the policy's approval threshold and budget use `recipients`: it must be the truth
            raise Denied(f"recipients must equal the list size ({size})")
        if c["status"] == "sent":
            raise Denied(f"Campaign {campaign_id} was already sent")
        db.execute("UPDATE campaigns SET status = 'sent', list_id = ?, sent_to = ? WHERE id = ?", (list_id, size, campaign_id))
        return {"sent": campaign_id, "recipients": size}

    @tool("flows.list", "Automation flows")
    def flows_list(account: str | None = None) -> dict[str, Any]:
        return {"flows": rows("SELECT * FROM flows WHERE account = ?", acct_of())}

    @tool("flows.create", "Create a draft flow")
    def flows_create(name: str, account: str | None = None) -> dict[str, Any]:
        acct = acct_of()
        fid = f"F-{acct}-{abs(hash((name, now()))) % 10**8}"
        db.execute("INSERT INTO flows VALUES (?, ?, ?, 'draft')", (fid, acct, name))
        return {"id": fid, "status": "draft"}

    @tool("flows.update_status", "Set a flow to draft, manual or live (live needs approval)")
    def flows_status(flow_id: str, status: str) -> dict[str, Any]:
        owned("flows", flow_id)
        db.execute("UPDATE flows SET status = ? WHERE id = ?", (status, flow_id))
        return {"id": flow_id, "status": status}

    @tool("templates.list", "Email templates")
    def templates_list(account: str | None = None) -> dict[str, Any]:
        return {"templates": rows("SELECT id, name FROM templates WHERE account = ?", acct_of())}

    @tool("templates.create", "Create an email template")
    def templates_create(name: str, html: str, account: str | None = None) -> dict[str, Any]:
        acct = acct_of()
        tid = f"TPL-{acct}-{abs(hash((name, now()))) % 10**8}"
        db.execute("INSERT INTO templates VALUES (?, ?, ?, ?)", (tid, acct, name, html))
        return {"id": tid}

    @tool("metrics.query", "Aggregate a metric over the last N days")
    def metrics_query(metric: str, days: int, account: str | None = None) -> dict[str, Any]:
        since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
        r = one("SELECT count(*) AS count, coalesce(sum(value), 0) AS total FROM events WHERE account = ? AND metric = ? AND at >= ?", acct_of(), metric, since)
        return {"metric": metric, "days": days, **(r or {})}

    @tool("events.track", "Record an event for a profile")
    def events_track(metric: str, profile_id: str | None = None, value: float = 0, account: str | None = None) -> dict[str, Any]:
        acct = acct_of()
        if profile_id is not None:
            owned("profiles", profile_id)
        db.execute("INSERT INTO events (account, profile_id, metric, value, at) VALUES (?, ?, ?, ?, ?)", (acct, profile_id, metric, value, now()))
        return {"tracked": metric}

    # authz-begin (mcp-rbac wiring: approval store, audit sink, guard; counted by bench/competitors/loc.py)
    def approve(call: dict[str, Any], d: dict[str, Any]) -> bool:
        sub = (call.get("identity") or {}).get("id")
        h = args_hash(call["tool"], call["args"])
        row = db.execute("SELECT id FROM approvals WHERE sub = ? AND tool = ? AND args_hash = ? AND status = 'approved' AND used_at IS NULL ORDER BY id LIMIT 1",
                         (sub, call["tool"], h)).fetchone()
        if row:
            return db.execute("UPDATE approvals SET used_at = ? WHERE id = ? AND used_at IS NULL", (now(), row["id"])).rowcount == 1
        if not db.execute("SELECT 1 FROM approvals WHERE sub = ? AND tool = ? AND args_hash = ? AND status = 'pending'", (sub, call["tool"], h)).fetchone():
            db.execute("INSERT INTO approvals (sub, tool, args_hash, args, created_at) VALUES (?, ?, ?, ?, ?)",
                       (sub, call["tool"], h, json.dumps(call["args"], sort_keys=True, separators=(",", ":")), now()))
        return False

    # Hash-chained decision audit; batched group commit by default (MCP_RBAC_AUDIT_MODE=sync commits before the call proceeds).
    sink = sink or SqliteAuditSink(db.path, mode=os.environ.get("MCP_RBAC_AUDIT_MODE", "batched"))

    def audit(e: dict[str, Any]) -> None:
        sink.write(audit_record_from_decision(e))

    s.middleware.append(CoreGuard(POLICY, identity=identity_fn, approve=approve, on_decision=audit,
                                  resource=lambda tool, args, ident, ctx: resolve_resource(db, tool, args)))
    # authz-end
    return s


def http_identity(secret: str, db: SerializedDB) -> Any:
    def ident(ctx: Any) -> dict[str, Any] | None:
        req = getattr(ctx, "request", None)
        tok = bearer(getattr(req, "headers", None))
        if tok is None:
            return None
        claims, _ = verify(tok, secret, AUDIENCE, lambda j: db.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (j,)).fetchone() is not None)
        return identity_of(claims) if claims else None
    return ident


def admin(db: SerializedDB, cmd: str, arg: str | None) -> None:
    if cmd == "pending":
        # the approver sees the exact arguments they are approving (an injected call shows its injected arguments)
        out: Any = [{**dict(r), "args": json.loads(r["args"])} for r in db.execute("SELECT id, sub, tool, args, created_at FROM approvals WHERE status = 'pending'")]
    elif cmd == "approve":
        out = {"approved": db.execute("UPDATE approvals SET status = 'approved' WHERE id = ? AND status = 'pending'", (int(arg or 0),)).rowcount}
    elif cmd == "revoke":
        out = {"revoked": db.execute("INSERT OR IGNORE INTO revoked_tokens VALUES (?)", (arg,)).rowcount}
    elif cmd == "audit":
        out = [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id")]
    else:
        sys.exit("usage: admin pending|approve ID|revoke JTI|audit --db FILE")
    print(json.dumps(out, indent=2))


def main() -> None:
    argv = sys.argv[1:]

    def flag(name: str) -> str | None:
        return argv[argv.index(name) + 1] if name in argv else None
    db = open_db(flag("--db") or ":memory:")
    if argv and argv[0] == "admin":
        if db.path != ":memory:":
            SqliteAuditSink(db.path, shutdown_hooks=False).close()  # creates the audit table if no server ran yet
        return admin(db, argv[1], argv[2] if len(argv) > 2 and not argv[2].startswith("--") else None)
    port = flag("--http")
    if port is None:
        ident = json.loads(os.environ["MCP_RBAC_IDENTITY"]) if os.environ.get("MCP_RBAC_IDENTITY") else None
        build(db, lambda ctx: ident).run("stdio")
        return
    import uvicorn
    secret = os.environ.get("MCP_DEMO_JWT_SECRET", "")
    sock = socket.socket()
    sock.bind(("127.0.0.1", int(port)))
    sock.listen(128)  # listen before announcing, so a client never races the bind
    real = sock.getsockname()[1]
    server = build(db, http_identity(secret, db))
    app = server.streamable_http_app(transport_security=TransportSecuritySettings(allowed_hosts=[f"127.0.0.1:{real}", f"localhost:{real}"]))
    front = BearerFront(app, secret=secret, audience=AUDIENCE,
                        revoked=lambda j: db.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (j,)).fetchone() is not None)
    print(f"marketing-platform listening on http://127.0.0.1:{real}/mcp", flush=True)
    asyncio.run(uvicorn.Server(uvicorn.Config(front, log_level="warning", lifespan="on")).serve(sockets=[sock]))


if __name__ == "__main__":
    main()

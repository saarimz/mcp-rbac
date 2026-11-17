"""P13 review fixes in the Python CoreGuard: unguarded methods refused, class rules on a cold start (or fail closed),
async identity, the audit option (shared sink, failures surface, fail-closed), uniform denials, shared engines."""
from __future__ import annotations

import sqlite3
from typing import Any

import pytest

pytest.importorskip("mcp_rbac_core")
from mcp import Client  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402
from mcp.shared.exceptions import MCPError  # noqa: E402
from mcp.types import ToolAnnotations  # noqa: E402

from mcp_rbac.audit_sink import SqliteAuditSink, shared_audit_sink, verify_audit_table  # noqa: E402
from mcp_rbac.core_guard import CoreGuard, protect_with_core, shared_engine  # noqa: E402

pytestmark = pytest.mark.anyio

POLICY = """version: 1
roles:
  owner: {includes: [staff], tools: [refund]}
  staff: {tools: [list_events, checkin]}
tools:
  refund: {limits: {amount: {min: 0, max: 500}}}
limits:
  - {tool: checkin, max: 3, per: minute}
"""
SEM = """version: 1
roles:
  staff: {tools: [list_events, wipe]}
semantics:
  grants: {staff: [read]}
  rules:
    - {classes: [destructive], denyRoles: [staff]}
"""
STAFF = {"id": "dana", "roles": ["staff"]}


def text(r: Any) -> str:
    return r.content[0].text


def build(policy: str = POLICY, **kw: Any) -> tuple[MCPServer, CoreGuard]:
    s = MCPServer("venue")

    @s.tool()
    def list_events() -> str:
        return "Friday"

    @s.tool()
    def checkin(ticketId: str) -> str:  # noqa: N803
        return f"checked in {ticketId}"

    @s.tool(annotations=ToolAnnotations(destructiveHint=True))
    def wipe() -> str:
        return "wiped"

    @s.resource("mem://secret")
    def secret() -> str:
        return "the secret"

    @s.prompt()
    def hello() -> str:
        return "hi"

    kw.setdefault("identity", lambda ctx: STAFF)
    g = protect_with_core(s, policy, **kw)
    return s, g


async def test_resources_prompts_completion_refused_for_everyone() -> None:
    for ident in (STAFF, None):
        s, _ = build(identity=lambda ctx, i=ident: i)
        async with Client(s) as c:
            for fn in (c.list_resources, c.list_prompts, lambda: c.read_resource("mem://secret"), lambda: c.get_prompt("hello")):
                with pytest.raises(MCPError) as e:
                    await fn()
                assert e.value.code == -32601
            assert text(await c.call_tool("list_events", {})) == ("Friday" if ident else "Denied: unauthenticated")


async def test_class_rules_apply_on_a_cold_start() -> None:
    s, _ = build(SEM)
    async with Client(s) as c:  # no tools/list first: the guard reads the server's own list
        assert text(await c.call_tool("wipe", {})) == "Denied: class_denied:destructive"
        assert text(await c.call_tool("list_events", {})) == "Friday"


async def test_metadata_unreadable_fails_closed() -> None:
    s, g = build(SEM)

    async def broken_list(ctx: Any, call_next: Any) -> Any:
        if ctx.method == "tools/list":
            raise RuntimeError("upstream down")
        return await call_next(ctx)

    s.middleware.append(broken_list)  # inner to the guard: the guard's own tools/list read fails
    async with Client(s) as c:
        assert text(await c.call_tool("wipe", {})) == "Denied: tool_meta_unavailable"
    assert g._meta == {}


async def test_async_identity() -> None:
    async def who(ctx: Any) -> dict[str, Any]:
        return STAFF

    s, _ = build(identity=who)
    async with Client(s) as c:
        assert sorted(t.name for t in (await c.list_tools()).tools) == ["checkin", "list_events"]
        assert text(await c.call_tool("list_events", {})) == "Friday"


async def test_uniform_denials_hide_the_reason_from_the_agent_only() -> None:
    seen: list[str] = []
    s, _ = build(denials="uniform", share_engine=False, on_decision=lambda e: seen.append(e["decision"]["reason"]))
    async with Client(s) as c:
        r = await c.call_tool("refund", {"amount": 5})
        assert text(r) == "Denied" and r.meta == {"mcp-rbac/denial": {"decision": "deny"}}
    assert seen == ["user:no_matching_permission"]
    with pytest.raises(ValueError):
        CoreGuard(POLICY, identity=lambda c: None, denials="nope")


async def test_shared_engine_counters_across_guards() -> None:
    policy = POLICY + "# shared-py\n"
    assert shared_engine(policy) is shared_engine(policy)
    outs = []
    for _ in range(4):  # four guards (per-session style), one user
        s, _ = build(policy)
        async with Client(s) as c:
            outs.append(text(await c.call_tool("checkin", {"ticketId": "x"})))
    assert outs[:3] == ["checked in x"] * 3 and outs[3].startswith("Denied: rate_limited")
    s, _ = build(policy, share_engine=False)
    async with Client(s) as c:
        assert text(await c.call_tool("checkin", {"ticketId": "y"})) == "checked in y"


async def test_audit_option_one_chain_per_file(tmp_path: Any) -> None:
    db = str(tmp_path / "audit.db")
    guards = [build(audit={"path": db, "mode": "sync", "shutdown_hooks": False}) for _ in range(3)]
    for s, _ in guards:
        async with Client(s) as c:
            await c.call_tool("list_events", {})
            await c.call_tool("refund", {"amount": 1})
    for _, g in guards:
        g.close()
    v = verify_audit_table(db)
    assert v["ok"] and v["count"] == 6


async def test_audit_failures_surface_and_can_fail_closed() -> None:
    class Flaky:
        ok = True

        def write(self, r: Any) -> None:
            if not self.ok:
                raise OSError("disk full")

        def healthy(self) -> bool:
            return self.ok

    w = Flaky()
    errs: list[BaseException] = []
    s1, _ = build(audit=w, audit_fail_closed=True, on_audit_error=errs.append)
    s2, _ = build(audit=w, on_audit_error=errs.append)
    async with Client(s1) as c1, Client(s2) as c2:
        assert text(await c1.call_tool("list_events", {})) == "Friday"
        w.ok = False
        assert text(await c1.call_tool("list_events", {})) == "Denied: audit_unavailable"
        assert text(await c2.call_tool("list_events", {})) == "Friday"
    assert len(errs) == 2
    with pytest.raises(TypeError):
        CoreGuard(POLICY, identity=lambda c: None, audit=object())


def test_sync_sink_raises_on_commit_failure_and_recovers(tmp_path: Any) -> None:
    db = str(tmp_path / "a.db")
    errs: list[BaseException] = []
    s = SqliteAuditSink(db, mode="sync", shutdown_hooks=False, on_error=errs.append)
    rec = {"at": "t", "tool": "x", "decision": "allow", "reason": "ok"}
    s.write(rec)
    other = sqlite3.connect(db)
    other.execute("CREATE TRIGGER no_insert BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'disk says no'); END;")
    other.commit()
    with pytest.raises(RuntimeError, match="not committed"):
        s.write(rec)
    assert not s.healthy() and s.stats()["dropped"] == 1 and len(errs) == 1
    other.execute("DROP TRIGGER no_insert")
    other.commit()
    other.close()
    s.write(rec)
    assert s.healthy()
    s.close()
    assert verify_audit_table(db)["count"] == 2


def test_batched_sink_dead_writer_is_not_silent(tmp_path: Any) -> None:
    s = SqliteAuditSink(str(tmp_path / "b.db"), shutdown_hooks=False)
    s._q.put(None)  # stop the writer thread (what a crash in it looks like from outside)
    assert s._thread is not None
    s._thread.join(5)
    assert not s.healthy()
    with pytest.raises(RuntimeError, match="writer thread"):
        s.write({"at": "t", "tool": "x", "decision": "allow", "reason": "ok"})
    s.close()


def test_shared_audit_sink_refcount(tmp_path: Any) -> None:
    db = str(tmp_path / "c.db")
    a = shared_audit_sink(db, mode="sync", shutdown_hooks=False)
    b = shared_audit_sink(db)
    assert a.sink is b.sink
    a.write({"at": "t", "tool": "x", "decision": "allow", "reason": "ok"})
    a.close()
    a.close()
    b.write({"at": "t", "tool": "y", "decision": "deny", "reason": "r"})
    assert b.healthy()
    b.close()
    assert not b.healthy()
    assert verify_audit_table(db)["count"] == 2


def test_python_narrow_identity_keeps_scope_and_never_widens() -> None:
    from mcp_rbac.roles import Assignment, Identity, narrow_identity

    base: Identity[str] = Identity.of("maya", [Assignment("manager", {"venue": "bk"}), Assignment("door", {"venue": "qn"})], scopes={"a", "b"})
    sub = narrow_identity(base, roles=["door"], scopes=["a"])
    assert sub.assignments == (Assignment("door", {"venue": "qn"}),)  # the kept role keeps ITS scope, nothing broader
    assert sub.roles_at({"venue": "qn"}) == ["door"] and sub.roles_at({"venue": "bk"}) == []
    assert sub.scopes == frozenset({"a"})
    with pytest.raises(ValueError):
        narrow_identity(sub, scopes=["a", "b"])  # token scopes intersect only
    with pytest.raises(ValueError):
        narrow_identity(sub, roles=["manager"])  # a role dropped earlier cannot come back


def test_redaction_top_level_array_is_records() -> None:
    import json as _json

    import mcp_rbac_core

    from mcp_rbac.output import redact_fields

    assert redact_fields([{"email": "a", "p": 1}, {"email": "b"}], ["email", "0.p"]) == [{"email": "[REDACTED]", "p": "[REDACTED]"}, {"email": "[REDACTED]"}]
    assert redact_fields({"email": "a", "l": [{"email": "b"}]}, ["email"]) == {"email": "[REDACTED]", "l": [{"email": "b"}]}
    e = mcp_rbac_core.Engine("version: 1\nroles:\n  r: {tools: [people]}\ntools:\n  people:\n    redact: {fields: [email]}\n")
    d = e.decide(_json.dumps({"tool": "people", "identity": {"id": "u", "roles": ["r"]}}))
    out = _json.loads(e.redact(_json.dumps({"content": [{"type": "text", "text": '[{"email":"a@x"},{"email":"b@x"}]'}]}), d))
    assert out["content"][0]["text"] == '[{"email":"[REDACTED]"},{"email":"[REDACTED]"}]'

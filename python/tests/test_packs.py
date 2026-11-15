"""Policy packs (mcp_rbac.packs) + tool semantics through CoreGuard: annotations, packs, class grants, class approvals
and post-call spend accounting, end to end over the official Python SDK (same scenario as test/packs.test.ts)."""
from __future__ import annotations

import json
import pathlib
from typing import Any

import anyio
import pytest

core = pytest.importorskip("mcp_rbac_core")
from mcp_rbac import load_policy_with_packs, resolve_packs, validate_pack  # noqa: E402
from mcp_rbac.portable import decide, load_policy_json  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "examples/core-servers/semantics.yaml"
COUNTS = {"klaviyo": 309, "stripe": 15, "github": 133}


@pytest.mark.parametrize("name", sorted(COUNTS))
def test_builtin_pack_compiles_and_classes_gate(name):
    doc = json.loads((ROOT / f"packs/{name}/pack.json").read_text())
    validate_pack(doc)
    assert len(doc["tools"]) == COUNTS[name]
    ids = {s["id"] for s in doc["sources"]}
    assert all(t["source"] in ids and t["confidence"] in ("high", "medium", "low") for t in doc["tools"].values())
    policy = resolve_packs(f"version: 1\nroles:\n  r: {{}}\nsemantics:\n  packs: [{name}]\n  grants: {{r: [read]}}\n")
    p = load_policy_json(policy)
    e = core.Engine(policy)
    for t, sem in doc["tools"].items():
        req = {"tool": t, "identity": {"id": "u", "roles": ["r"]}}
        want = "allow" if all(c == "read" for c in sem["classes"]) else "deny"
        assert decide(p, req)["decision"] == want, t
        assert json.loads(e.decide(json.dumps(req)))["decision"] == want, t


def test_resolution_order_prefix_and_errors():
    pk = lambda tools: {"pack": "p", "tools": tools}  # noqa: E731
    out = json.loads(resolve_packs(
        "version: 1\nroles: {r: {}}\nsemantics:\n  tools:\n    a: {classes: [read]}\n  packs: [one, {name: two, prefix: x_}, two]\n",
        packs={"one": pk({"a": {"classes": ["write"]}, "b": {"classes": ["send"]}}), "two": pk({"b": {"classes": ["read"]}, "c": {"classes": ["spend"]}})}))
    assert "packs" not in out["semantics"]
    assert list(out["semantics"]["tools"].items()) == [("a", {"classes": ["read"]}), ("b", {"classes": ["send"]}), ("x_b", {"classes": ["read"]}),
                                                     ("x_c", {"classes": ["spend"]}), ("c", {"classes": ["spend"]})]
    y = "version: 1\nroles: {r: {}}\n"
    assert resolve_packs(y) == y
    with pytest.raises(ValueError, match='pack "nope-nope" not found'):
        resolve_packs("version: 1\nroles: {r: {}}\nsemantics: {packs: [nope-nope]}\n")
    with pytest.raises(ValueError, match="exactly one of name"):
        resolve_packs("version: 1\nroles: {r: {}}\nsemantics: {packs: [{name: a, path: b}]}\n")
    with pytest.raises(ValueError, match="invalid pack name"):
        resolve_packs("version: 1\nroles: {r: {}}\nsemantics: {packs: ['..']}\n")
    with pytest.raises(ValueError, match="packs"):
        core.Engine("version: 1\nroles: {r: {}}\nsemantics: {packs: [klaviyo]}\n")
    assert list(json.loads(load_policy_with_packs(SCENARIO))["semantics"]["tools"]) == ["generate", "boost"]


def _server(identity, costs: list, upstream: list):
    from mcp.server.mcpserver import MCPServer
    from mcp.types import ToolAnnotations

    from mcp_rbac.core_guard import protect_with_core

    s = MCPServer("sem", version="0")

    @s.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def list_items() -> str:
        upstream.append("list_items")
        return "items"

    @s.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
    def wipe() -> str:
        upstream.append("wipe")
        return "wiped"

    @s.tool()
    def boost(cents: float) -> str:
        upstream.append("boost")
        return f"boosted {cents:g}"

    @s.tool(structured_output=True)
    def generate() -> dict[str, Any]:
        upstream.append("generate")
        return {"usage": {"cost": 0.6}}

    @s.tool()
    def mystery() -> str:
        upstream.append("mystery")
        return "?"

    protect_with_core(s, load_policy_with_packs(SCENARIO), identity=lambda ctx: identity, on_cost=lambda e: costs.append(e["cost"]))
    return s


def _t(r) -> str:
    return r.content[0].text


def test_semantics_through_core_guard():
    from mcp import Client

    async def go():
        up: list = []
        async with Client(_server({"id": "s", "roles": ["staff"]}, [], up)) as c:
            assert [t.name for t in (await c.list_tools()).tools] == ["list_items"]
            assert _t(await c.call_tool("list_items", {})) == "items"
            assert _t(await c.call_tool("wipe", {})) == "Denied: user:no_matching_permission"
            assert _t(await c.call_tool("mystery", {})) == "Denied: user:no_matching_permission"
        assert up == ["list_items"]

        up = []
        async with Client(_server({"id": "o", "roles": ["owner"]}, [], up)) as c:
            assert sorted(t.name for t in (await c.list_tools()).tools) == ["boost", "generate", "list_items", "wipe"]
            assert _t(await c.call_tool("wipe", {})) == "Approval required for wipe"
            assert _t(await c.call_tool("mystery", {})) == "Denied: user:no_matching_permission"
            assert _t(await c.call_tool("boost", {"cents": 60})) == "boosted 60"
            assert _t(await c.call_tool("boost", {"cents": 50})) == "Denied: rate_limited:0"
        assert up == ["boost"]

        up, costs = [], []
        async with Client(_server({"id": "o2", "roles": ["owner"]}, costs, up)) as c:
            await c.list_tools()
            assert not (await c.call_tool("generate", {})).is_error
            assert not (await c.call_tool("generate", {})).is_error
            assert _t(await c.call_tool("generate", {})) == "Denied: rate_limited:0"
        assert [x["cost"] for x in costs] == [{"amount": 0.6, "currency": "USD"}] * 2
        assert costs[1]["charged"][0]["used"] == pytest.approx(1.2)
        assert up == ["generate", "generate"]

    anyio.run(go)

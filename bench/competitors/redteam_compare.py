"""Run the repo's red-team scenarios (redteam/) against each competitor configuration on the venue (TS) and marketing
(Python) servers, and classify every check: pass | fail | cannot_express | shared_auth | n/a.

    python -m bench.competitors.redteam_compare [target ...]     (from the repo root, python/.venv)

Grading: the scenario code is unchanged. Two adaptations, both recorded in the output:
  * lenient denial matching for competitors: a check expecting "denied:<mcp-rbac reason>" passes on any denial
    (competitors have their own reason strings); mcp-rbac itself is graded strictly;
  * competitor-specific denial shapes are normalized (mcp-policy-guard JSON errors, agentgateway's JSON-RPC
    "unknown resource" error) before grading.
Checks on the devops server are not part of this comparison (it runs mcp-rbac in every round and is dropped).
"""
from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import pathlib
import sys
import tempfile
import time
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(ROOT), str(HERE), str(ROOT / "examples/servers/shared")]

import auth  # noqa: E402
import services  # noqa: E402
import tokens  # noqa: E402
from redteam import agent, harness, scenarios_auth, scenarios_data, servers  # noqa: E402
from redteam.harness import Report  # noqa: E402

AUTHN = {"payload roles edited, signature kept", "alg none", "alg HS512 header (alg confusion)", "crit header", "signed with another key"}
APPROVAL = lambda c: c["category"] == "approval_bypass"  # noqa: E731
BUDGET = lambda c: c["category"] == "budget_exhaustion"  # noqa: E731
JWT_TAMPER = {"payload roles edited, signature kept", "alg none", "alg HS512 header (alg confusion)", "crit header", "signed with another key"}
ARG_SCOPE = {"list_events for venue qn", "list profiles naming account globex"}
RECORD_OWNER = {"check_in a qn ticket, claiming venue bk in args", "refund a qn ticket from a bk manager", "read a qn ticket",
                "read a globex profile", "update a globex profile"}

# target -> how its servers start, and which checks it cannot express (with the reason shown in the report)
TARGETS: dict[str, dict[str, Any]] = {
    "mcp-rbac": {"label": "mcp-rbac 0.4 (in-process core)", "strict": True, "front": "shared"},
    "baseline": {"label": "No guard (same app code + JWT front)", "authz": "none", "front": "shared"},
    "cerbos": {"label": "Cerbos 0.57.0 PDP", "authz": "cerbos", "front": "shared",
               "cannot": [(APPROVAL, "no approval primitive (stateless PDP; workflow is custom code)"),
                          (BUDGET, "no counters/rate limits (stateless PDP)")]},
    "openfga": {"label": "OpenFGA 1.22.1", "authz": "openfga", "front": "shared",
                "cannot": [(APPROVAL, "no approval primitive (ReBAC check API; workflow is custom code)"),
                           (BUDGET, "no counters/rate limits")]},
    "policy-guard": {"label": "mcp-policy-guard 0.2.0", "authz": "policy-guard", "front": "shared", "servers": ["venue"],
                     "cannot": [(lambda c: c["name"].startswith("30 concurrent $200 refunds"), "no sum-of-argument budget (call counts only)"),
                               (lambda c: c["name"].startswith("12 concurrent booth"), "limiter state lives in each guarded server instance (one per HTTP session; no shared/injectable store) and overrides are keyed per tool, not per identity")]},
    "agentgateway": {"label": "agentgateway 1.7.0", "authz": "none", "front": "gateway",
                     "cannot": [(APPROVAL, "no approval primitive"),
                                (BUDGET, "local rate limits count HTTP requests per key, not tool calls; docs: not for long windows"),
                                (lambda c: c["name"] in RECORD_OWNER, "needs the record's owner (DB lookup); gateway sees only token + arguments"),
                                (lambda c: c["name"] == "lifetime over 1 h", "no maximum-token-lifetime setting in jwtAuth"),
                                (lambda c: c["name"].startswith("revoked jti") and "control" not in c["name"], "no jti revocation list")]},
    "pomerium": {"label": "Pomerium 0.34.1 (MCP route)", "authz": "none", "front": "gateway", "oauth": True,
                 "na": [(lambda c: c["name"] in JWT_TAMPER, "clients hold Pomerium-issued opaque MCP tokens (OAuth 2.1 via Pomerium), never a JWT they could tamper with")],
                 "cannot": [(APPROVAL, "no approval primitive"),
                            (BUDGET, "no per-tool-call counters (PPL has no rate limits)"),
                            (lambda c: c["name"] in RECORD_OWNER, "needs the record's owner (DB lookup); PPL sees only claims + tool name"),
                            (lambda c: c["name"] in ARG_SCOPE or c["category"] == "prompt_injection", "PPL cannot read tool arguments (mcp_tool matches the tool name only): no argument limits or argument-level scope"),
                            (lambda c: c["name"].startswith("door staff's list_events only shows"), "no result filtering (PPL decides per request; records in the response are not visible)"),
                            (lambda c: "tools/list" in c["name"] or "see only allow" in c["name"], "no tools/list filtering"),
                            (lambda c: c["name"] == "lifetime over 1 h", "no maximum IdP-token-lifetime setting"),
                            (lambda c: c["name"].startswith("revoked jti") and "control" not in c["name"], "IdP jti revocation is not visible to Pomerium (it has its own token revocation endpoint)")]},
}


ORIG = {"start_http": servers.start_http, "stdio": servers.stdio, "mint": servers.mint, "auth_mint": auth.mint,
        "h_classify": harness.classify, "a_classify": agent.classify, "outcome": harness.outcome,
        "sa_outcome": scenarios_auth.outcome, "sd_outcome": scenarios_data.outcome, "agent_run": agent.run,
        "priv_esc": scenarios_auth.privilege_escalation, "http": servers.http}


def restore() -> None:
    servers.start_http, servers.stdio, servers.mint, auth.mint = ORIG["start_http"], ORIG["stdio"], ORIG["mint"], ORIG["auth_mint"]  # type: ignore[assignment]
    harness.classify, agent.classify = ORIG["h_classify"], ORIG["a_classify"]  # type: ignore[assignment]
    harness.outcome, scenarios_auth.outcome, scenarios_data.outcome = ORIG["outcome"], ORIG["sa_outcome"], ORIG["sd_outcome"]  # type: ignore[assignment]
    agent.run = ORIG["agent_run"]  # type: ignore[assignment]
    scenarios_auth.privilege_escalation = ORIG["priv_esc"]  # type: ignore[attr-defined]
    servers.http = ORIG["http"]  # type: ignore[assignment]


def _messages(e: BaseException) -> list[str]:
    if isinstance(e, BaseExceptionGroup):
        return [m for x in e.exceptions for m in _messages(x)]
    return [str(e)]


class RefusedSession:
    """Pomerium refuses the whole MCP session (403 at initialize) when no allow rule matches, e.g. unknown roles:
    the caller sees no tools and every call is denied."""

    async def list_tools(self) -> Any:
        from mcp import types
        return types.ListToolsResult(tools=[])

    async def call_tool(self, *_a: Any, **_k: Any) -> Any:
        from mcp import types
        return types.CallToolResult(content=[types.TextContent(type="text", text="Denied: gateway_session_refused")], isError=True)


@contextlib.asynccontextmanager
async def http_refusable(url: str, token: str) -> Any:
    entered = False
    try:
        async with ORIG["http"](url, token) as s:
            entered = True
            yield s
    except BaseException as e:  # noqa: BLE001
        if entered or not any("access denied" in m for m in _messages(e)):
            raise
        yield RefusedSession()


class GatewaySession:
    """agentgateway rejects an unauthorized tool with a JSON-RPC error ("unknown resource"), not a tool
    result; map it to the same denied outcome `outcome()` uses so the scripted agent keeps going."""

    def __init__(self, s: Any) -> None:
        self._s = s

    def __getattr__(self, k: str) -> Any:
        return getattr(self._s, k)

    async def call_tool(self, tool: str, args: Any = None, *a: Any, **k: Any) -> Any:
        from mcp import types
        try:
            return await self._s.call_tool(tool, args, *a, **k)
        except Exception as e:  # noqa: BLE001
            if "unknown resource" not in str(e) and "access denied" not in str(e):
                raise
            return types.CallToolResult(content=[types.TextContent(type="text", text="Denied: gateway_unknown_resource")], isError=True)


class NotApplicable(Exception):
    pass


class LenientReport(Report):
    def __init__(self, strict: bool) -> None:
        super().__init__()
        self.strict = strict

    def add(self, category: str, server: str, transport: str, name: str, expected: Any, observed: Any) -> bool:
        ok = super().add(category, server, transport, name, expected, observed)
        if not ok and not self.strict and isinstance(expected, str) and expected.startswith("denied:") and str(observed).startswith("denied:"):
            self.checks[-1].ok = ok = True
        return ok


def normalizer(target: str) -> Any:
    base = ORIG["a_classify"]

    def classify(is_error: bool, text: str) -> str:
        if is_error and text.startswith("{"):
            try:  # mcp-policy-guard: JSON-in-text guard errors
                j = json.loads(text)
                code = str(j.get("code") or j.get("error") or "")
                if "rate" in code:
                    return "denied:rate_limited"
                if "confirm" in code:
                    return "approval_required"
                if code in ("denied", "policy_denied", "forbidden", "unauthorized"):
                    return "denied:" + code
            except (ValueError, AttributeError):
                pass
        return base(is_error, text)
    return classify


def patch(target: str) -> None:
    t = TARGETS[target]
    real_start = ORIG["start_http"]
    if target != "mcp-rbac":
        cls = normalizer(target)
        harness.classify = cls  # type: ignore[assignment]
        agent.classify = cls  # type: ignore[assignment]
        orig = ORIG["outcome"]

        async def outcome(s: Any, tool: str, args: dict[str, Any] | None = None, meta: dict[str, Any] | None = None) -> str:
            o = await orig(s, tool, args, meta)
            if t["front"] == "gateway" and o.startswith("protocol_error:") and ("unknown resource" in o or "access denied" in o):
                return "denied:gateway_unknown_resource"
            return o
        for m in (harness, scenarios_auth, scenarios_data):
            m.outcome = outcome  # type: ignore[attr-defined]

        if t["front"] == "gateway":
            async def run(session: Any, *a: Any, **k: Any) -> Any:
                return await ORIG["agent_run"](GatewaySession(session), *a, **k)
            agent.run = run  # type: ignore[assignment]

        def stdio(*_a: Any, **_k: Any) -> Any:
            raise NotApplicable("stdio transport not part of the competitor run")
        servers.stdio = stdio  # type: ignore[assignment]

    if t.get("oauth"):  # Pomerium: a "token" is a Pomerium MCP access token obtained by signing in with these claims
        import pomerium_login
        by_aud = {servers.AUDIENCE[n]: n for n in t.get("servers", ["venue", "marketing"])}

        def pom_mint(secret: Any, claims: dict[str, Any], *a: Any) -> Any:
            name = by_aud.get(claims.get("aud"))
            if name is None:
                return ORIG["mint"](secret, claims, *a)
            try:
                return pomerium_login.login(services.POMERIUM_ROUTES[name], services.start_mock_idp(), claims, services.pomerium_tls()[2])
            except Exception as e:  # noqa: BLE001  the IdP token was rejected at sign-in (expired, not yet valid, ...)
                return "sign-in-rejected." + type(e).__name__
        servers.mint = pom_mint  # type: ignore[assignment]
        servers.http = http_refusable  # type: ignore[assignment]
        src = inspect.getsource(ORIG["priv_esc"])
        a, b = src.index('    h, p, sig = good.split(".")'), src.index("    async with servers.http(url, good) as s:")
        ns: dict[str, Any] = {}
        exec(compile(src[:a] + src[b:], "privilege_escalation(no JWT tamper)", "exec"), vars(scenarios_auth), ns)
        scenarios_auth.privilege_escalation = ns["privilege_escalation"]  # type: ignore[attr-defined]
    elif t["front"] == "gateway":
        gw_aud = {servers.AUDIENCE[n] for n in t.get("servers", ["venue", "marketing"])}  # devops stays the real HS256 server

        def gw_mint(secret: Any, claims: dict[str, Any], *a: Any, key: str = "idp", orig: Any = ORIG["mint"]) -> Any:
            return tokens.mint_rs256(claims, key=key) if claims.get("aud") in gw_aud else orig(secret, claims, *a)
        servers.mint = gw_mint  # type: ignore[assignment]
        auth.mint = lambda secret, claims, now=None: gw_mint(secret, claims, key="attacker", orig=ORIG["auth_mint"])  # type: ignore[assignment]

    pom: dict[str, Any] = {}

    def start_http(name: str, db: str) -> tuple[str, Any]:
        if target == "mcp-rbac" or name == "devops" or name not in t.get("servers", ["venue", "marketing"]):
            url, p = real_start(name, db)  # devops / not-applicable servers: real mcp-rbac, checks dropped below
        elif t.get("oauth"):  # one Pomerium per round with both routes (venue starts first; marketing's port is reserved)
            env = {"TRUST_ASSERTION_HEADER": "x-pomerium-jwt-assertion"}
            if name == "venue":
                mport = services.free_port()
                up, p1 = services.start_alt(name, db, "none", trust=True, env=env)
                pom["urls"], p2 = services.start_pomerium({"venue": up, "marketing": f"http://127.0.0.1:{mport}/mcp"})
                pom["mport"] = mport
                url, p = pom["urls"]["venue"], services.Group(p2, p1)
            else:
                _, p = services.start_alt(name, db, "none", trust=True, port=pom["mport"], env=env)
                url = pom["urls"]["marketing"]
        elif t["front"] == "gateway":
            up, p1 = services.start_alt(name, db, "none", trust=True)
            url, p2 = services.start_agentgateway(name, up)
            p = services.Group(p2, p1)
        else:
            url, p = services.start_alt(name, db, t["authz"])
        return url, p
    servers.start_http = start_http  # type: ignore[assignment]


async def run_target(target: str) -> dict[str, Any]:
    t = TARGETS[target]
    rep = LenientReport(strict=bool(t.get("strict")))
    notes: list[str] = []
    t0 = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        patch(target)
        live: list[Any] = []
        try:
            def fresh(tag: str) -> tuple[dict[str, str], dict[str, str]]:
                urls, dbs = {}, {}
                for name in ("venue", "marketing", "devops"):
                    db = f"{tmp}/{name}-{tag}.db"
                    url, p = servers.start_http(name, db)
                    live.append(p)
                    urls[name], dbs[name] = url, db
                return urls, dbs
            urls, dbs = fresh("auth")
            for name in ("venue", "marketing"):
                await scenarios_auth.token_replay(rep, name, urls[name], dbs[name])
                try:
                    await scenarios_auth.privilege_escalation(rep, name, urls[name], dbs[name])
                except NotApplicable as e:
                    notes.append(f"{name}: {e}")
            urls, dbs = fresh("data")
            await scenarios_data.confused_deputy(rep, urls)
            await scenarios_data.cross_tenant(rep, urls)
            await scenarios_data.prompt_injection(rep, urls)
            urls, dbs = fresh("budget")
            await scenarios_data.budget_exhaustion(rep, urls)
            urls, dbs = fresh("approval")
            await scenarios_data.approval_bypass(rep, urls, dbs)
        finally:
            for p in live:
                p.terminate()
            for p in live:
                p.wait(10)
            restore()
    checks = []
    for c in rep.checks:
        d = {"category": c.category, "server": c.server, "transport": c.transport, "name": c.name, "expected": c.expected, "observed": c.observed, "ok": c.ok}
        if c.server == "devops":
            continue
        authn = c.category == "token_replay" or c.name in AUTHN
        na = next((w for f, w in t.get("na", []) if f(d)), None)
        if na:
            d["status"], d["why"] = "n/a", na
        elif c.server not in t.get("servers", ["venue", "marketing"]):
            d["status"], d["why"] = "n/a", "library is TypeScript-only; the marketing server is Python"
        elif authn and t["front"] == "shared":
            d["status"], d["why"] = "shared_auth", "checked by the shared demo JWT front, not by this product"
        else:
            why = next((w for f, w in t.get("cannot", []) if f(d)), None)
            d["status"], d["why"] = ("cannot_express", why) if why else ("pass" if c.ok else "fail", "")
        checks.append(d)
    canon = HERE / "results" / "redteam-mcp-rbac.json"
    if target != "mcp-rbac" and canon.exists():  # same denominator for every target: checks a scenario skipped count too
        seen = {(c["server"], c["category"], c["transport"], c["name"]) for c in checks}
        for c in json.loads(canon.read_text())["checks"]:
            k = (c["server"], c["category"], c["transport"], c["name"])
            if k in seen:
                continue
            if c["transport"] == "stdio":
                checks.append({**{f: c[f] for f in ("category", "server", "transport", "name", "expected")}, "observed": "", "ok": False,
                               "status": "n/a", "why": "stdio transport not part of the competitor run"})
                continue
            d = {**{f: c[f] for f in ("category", "server", "transport", "name", "expected")}, "observed": "not reached: an earlier step of this scenario failed", "ok": False}
            na = next((w for f, w in t.get("na", []) if f(d)), None)
            if na:
                d["status"], d["why"] = "n/a", na
            elif c["server"] not in t.get("servers", ["venue", "marketing"]):
                d["status"], d["why"] = "n/a", "library is TypeScript-only; the marketing server is Python"
            else:
                why = next((w for f, w in t.get("cannot", []) if f(d)), None)
                d["status"], d["why"] = ("cannot_express", why) if why else ("fail", "not reached")
            checks.append(d)
    if target != "mcp-rbac":
        for name in ("venue", "marketing"):
            if name in t.get("servers", ["venue", "marketing"]):
                checks.append({"category": "privilege_escalation", "server": name, "transport": "stdio", "name": "spoofed _meta caller on a forbidden call",
                               "expected": "denied:*", "observed": "", "ok": False, "status": "n/a", "why": "stdio transport not part of the competitor run"})
    return {"target": target, "label": t["label"], "seconds": round(time.time() - t0, 1), "notes": notes, "checks": checks, "summary": summarize(checks)}


def summarize(checks: list[dict[str, Any]]) -> dict[str, Any]:
    authz = [c for c in checks if c["status"] != "shared_auth" and not (c["category"] == "token_replay" or c["name"] in AUTHN)]
    authn = [c for c in checks if c["category"] == "token_replay" or c["name"] in AUTHN]
    app = [c for c in authz if c["status"] != "n/a"]
    expr = [c for c in app if c["status"] in ("pass", "fail")]
    return {
        "authz_total": len(authz), "authz_applicable": len(app), "authz_expressible": len(expr),
        "authz_pass_expressible": sum(c["status"] == "pass" for c in expr),
        "authz_pass_raw": sum(bool(c["ok"]) for c in app),  # what you actually get, including checks it cannot express
        "cannot_express": sum(c["status"] == "cannot_express" for c in app),
        "authn_total": len(authn), "authn_scored_by_product": sum(c["status"] in ("pass", "fail", "cannot_express") for c in authn),
        "authn_pass": sum(c["status"] == "pass" for c in authn), "authn_cannot_express": sum(c["status"] == "cannot_express" for c in authn),
        "authn_shared_pass": sum(bool(c["ok"]) for c in authn if c["status"] == "shared_auth"),
    }


async def main(names: list[str]) -> None:
    out = HERE / "results"
    out.mkdir(exist_ok=True)
    cerbos = fga = None
    if "cerbos" in names:
        cerbos = services.start_cerbos()
    if "openfga" in names:
        fga, _ = services.start_openfga()
    try:
        for n in names:
            r = await run_target(n)
            (out / f"redteam-{n}.json").write_text(json.dumps(r, indent=1) + "\n")
            s = r["summary"]
            print(f"{n:14s} authz {s['authz_pass_expressible']}/{s['authz_expressible']} expressible, raw {s['authz_pass_raw']}/{s['authz_applicable']}, "
                  f"cannot_express {s['cannot_express']}; authn product {s['authn_pass']}/{s['authn_scored_by_product']} ({r['seconds']} s)", flush=True)
            for c in r["checks"]:
                if c["status"] == "fail":
                    print(f"   FAIL {c['server']}/{c['category']}: {c['name']} -> {c['observed'][:110]}")
    finally:
        for p in (cerbos, fga):
            if p is not None:
                p.terminate()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:] or list(TARGETS)))

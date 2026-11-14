"""OpenID AuthZEN Authorization API 1.0: a client (PEP side), a Guard engine backed by any AuthZEN PDP, and a
Python PDP (Starlette) speaking the same mapping as ``mcp-rbac pdp`` in the TS package."""
from __future__ import annotations

import hmac
import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal

import httpx

from .roles import Assignment, BuiltinEngine, DecisionInput, EngineDecision, Identity, Kind, Role, load_policy, scope_allows

AZ_ACTION: dict[str, str] = {"tool": "tools/call", "resource": "resources/read", "prompt": "prompts/get"}
_KIND_OF = {v: k for k, v in AZ_ACTION.items()}
Semantic = Literal["execute_all", "deny_on_first_deny", "permit_on_first_permit"]


class PdpError(Exception):
    pass


def to_authzen(i: DecisionInput, *, list_mode: bool = False) -> dict[str, Any]:
    ident = i.identity
    roles = sorted({str(a.role) for a in ident.assignments if scope_allows(a.scope, i.resource)})
    props: dict[str, Any] = {"assignments": [{"role": str(a.role), "scope": dict(a.scope)} for a in ident.assignments], "roles": roles}
    if ident.attr:
        props["attr"] = dict(ident.attr)
    ctx: dict[str, Any] = {"agent": i.agent}
    if ident.tenant:
        ctx["tenant"] = ident.tenant
    if list_mode:
        ctx["mcp_rbac"] = {"list": True}
    return {"subject": {"type": "user", "id": ident.id, "properties": props}, "action": {"name": AZ_ACTION[i.kind]},
            "resource": {"type": i.kind, "id": i.name, "properties": {"scope": dict(i.resource), "arguments": dict(i.args)}}, "context": ctx}


class AuthZenClient:
    """Async AuthZEN client. ``token`` is sent as a Bearer token and never logged."""

    def __init__(self, url: str, *, token: str | None = None, timeout_s: float = 2.0, client: httpx.AsyncClient | None = None) -> None:
        self.url = url.rstrip("/")
        self._headers = {"content-type": "application/json", **({"authorization": f"Bearer {token}"} if token else {})}
        self._client = client or httpx.AsyncClient(timeout=timeout_s)
        self._own = client is None

    async def configuration(self) -> dict[str, Any]:
        r = await self._client.get(f"{self.url}/.well-known/authzen-configuration")
        r.raise_for_status()
        out: dict[str, Any] = r.json()
        return out

    async def evaluate(self, subject: Mapping[str, Any], action: Mapping[str, Any], resource: Mapping[str, Any],
                       context: Mapping[str, Any] | None = None, *, request_id: str | None = None) -> dict[str, Any]:
        body = {"subject": subject, "action": action, "resource": resource, **({"context": context} if context else {})}
        return await self._post("/access/v1/evaluation", body, request_id)

    async def evaluations(self, evaluations: Sequence[Mapping[str, Any]], *, defaults: Mapping[str, Any] | None = None,
                          semantic: Semantic | None = None, request_id: str | None = None) -> list[dict[str, Any]]:
        body: dict[str, Any] = {"evaluations": list(evaluations), **(defaults or {})}
        if semantic:
            body["options"] = {"evaluations_semantic": semantic}
        r = await self._post("/access/v1/evaluations", body, request_id)
        ev = r.get("evaluations")
        if not isinstance(ev, list):
            raise PdpError("pdp_malformed")
        return ev

    async def _post(self, path: str, body: Mapping[str, Any], rid: str | None) -> dict[str, Any]:
        try:
            r = await self._client.post(self.url + path, content=json.dumps(body), headers={**self._headers, **({"x-request-id": rid} if rid else {})})
        except httpx.HTTPError as e:
            raise PdpError("pdp_unavailable") from e
        if r.status_code != 200:
            raise PdpError(f"pdp_status_{r.status_code}")
        try:
            out = r.json()
        except ValueError as e:
            raise PdpError("pdp_malformed") from e
        if not isinstance(out, dict):
            raise PdpError("pdp_malformed")
        return out

    async def aclose(self) -> None:
        if self._own:
            await self._client.aclose()


class AuthZenEngine:
    """Guard engine that asks an external AuthZEN PDP. Fails CLOSED on any error or malformed answer."""

    name = "authzen"

    def __init__(self, client: AuthZenClient) -> None:
        self.client = client

    async def decide(self, i: DecisionInput) -> EngineDecision:
        try:
            ev = to_authzen(i)
            r = await self.client.evaluate(ev["subject"], ev["action"], ev["resource"], ev["context"])
        except PdpError as e:
            return EngineDecision(False, str(e))
        if not isinstance(r.get("decision"), bool):
            return EngineDecision(False, "pdp_malformed")
        raw_ctx = r.get("context")
        ctx: dict[str, Any] = raw_ctx if isinstance(raw_ctx, dict) else {}
        if r["decision"]:
            return EngineDecision(True, "ok", f"authzen:{ctx.get('rule', 'permit')}")
        return EngineDecision(False, f"authzen:{ctx.get('reason', 'deny')}")


# --- PDP server ---------------------------------------------------------------------------------------------
def _is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def _is_entity(v: Any) -> bool:
    return _is_obj(v) and isinstance(v.get("type"), str) and bool(v["type"]) and isinstance(v.get("id"), str) and bool(v["id"]) \
        and (v.get("properties") is None or _is_obj(v["properties"]))


def validate_evaluation(e: Any) -> str | None:
    if not _is_obj(e):
        return "request body must be an object"
    if not _is_entity(e.get("subject")):
        return "subject with string type and id is required"
    a = e.get("action")
    if not _is_obj(a) or not isinstance(a.get("name"), str) or not a["name"]:
        return "action with string name is required"
    if not _is_entity(e.get("resource")):
        return "resource with string type and id is required"
    if e.get("context") is not None and not _is_obj(e["context"]):
        return "context must be an object"
    return None


def _subject_identity(s: Mapping[str, Any]) -> Identity[Any] | None:
    p = s.get("properties") or {}
    raw = p.get("assignments") if isinstance(p.get("assignments"), list) else (
        [{"role": r, "scope": p.get("scope") or {}} for r in p["roles"]] if isinstance(p.get("roles"), list) else None)
    if raw is None:
        return None
    out: list[Assignment[Any]] = []
    for a in raw:
        if not isinstance(a, dict) or not isinstance(a.get("role"), str):
            return None
        try:
            out.append(Assignment(a["role"], dict(a.get("scope") or {})))
        except (ValueError, TypeError):
            return None
    attr = p.get("attr")
    return Identity(id=s["id"], assignments=tuple(out), attr=attr if isinstance(attr, dict) else {})


def pdp_app(*, roles: Mapping[str, Role] | None = None, policy: Any = None, engine: Any = None,
            directory: Callable[[str], Identity[Any] | None] | None = None, token: str | None = None,
            expose_reasons: bool = True, base_url: str = "") -> Any:
    """Starlette app: GET /.well-known/authzen-configuration, POST /access/v1/evaluation[s]. With ``directory``,
    roles sent by the PEP are ignored (a PEP can't grant itself roles)."""
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    if engine is None:
        if roles is None and policy is None:
            raise TypeError("pdp_app needs engine, roles or policy")
        engine = BuiltinEngine(roles if roles is not None else load_policy(policy)[0])

    def send(status: int, body: Any, rid: str | None) -> JSONResponse:
        return JSONResponse(body, status_code=status, headers={"x-request-id": rid} if rid else None)

    async def evaluate(e: Mapping[str, Any]) -> dict[str, Any]:
        act = e["action"]["name"]
        kind: Kind | None = _KIND_OF.get(act) or (e["resource"]["type"] if e["resource"]["type"] in AZ_ACTION else None)  # type: ignore[assignment]
        if kind is None:
            return {"decision": False, **({"context": {"reason": f'unsupported action "{act}"'}} if expose_reasons else {})}
        ident = directory(e["subject"]["id"]) if directory else _subject_identity(e["subject"])
        if ident is None:
            return {"decision": False, **({"context": {"reason": "unknown_subject"}} if expose_reasons else {})}
        p = e["resource"].get("properties") or {}
        scope = {k: v for k, v in (p.get("scope") or {}).items() if isinstance(v, str) and v} if _is_obj(p.get("scope")) else {}
        ctx = e.get("context") or {}
        list_mode = isinstance(ctx.get("mcp_rbac"), dict) and ctx["mcp_rbac"].get("list") is True
        if list_mode:
            vis = getattr(engine, "visible", None)
            ok = bool(await vis(ident, kind, e["resource"]["id"])) if vis else True
            return {"decision": ok, **({"context": {"reason": "visible" if ok else "not_visible"}} if expose_reasons else {})}
        try:
            raw_args = p.get("arguments")
            args: dict[str, Any] = raw_args if isinstance(raw_args, dict) else {}
            agent = ctx.get("agent")
            d = await engine.decide(DecisionInput(ident, kind, e["resource"]["id"], args, scope, agent if isinstance(agent, str) else "pep"))
        except Exception:
            return {"decision": False, **({"context": {"reason": "engine_error"}} if expose_reasons else {})}
        c = {"reason": d.reason, **({"rule": d.rule} if d.rule else {})}
        return {"decision": d.allow, **({"context": c} if expose_reasons else {})}

    def authed(req: Request) -> bool:
        if not token:
            return True
        h = req.headers.get("authorization", "")
        return h.startswith("Bearer ") and hmac.compare_digest(h[7:].encode(), token.encode())

    async def config(req: Request) -> JSONResponse:
        b = base_url or str(req.base_url).rstrip("/")
        return JSONResponse({"policy_decision_point": b, "access_evaluation_endpoint": f"{b}/access/v1/evaluation",
                             "access_evaluations_endpoint": f"{b}/access/v1/evaluations"})

    async def body(req: Request) -> Any:
        raw = await req.body()
        if len(raw) > 1_000_000:
            raise ValueError("request too large")
        return json.loads(raw)

    async def one(req: Request) -> JSONResponse:
        rid = (req.headers.get("x-request-id") or "")[:200] or None
        if not authed(req):
            return JSONResponse("unauthorized", status_code=401, headers={"www-authenticate": 'Bearer realm="pdp"', **({"x-request-id": rid} if rid else {})})
        try:
            e = await body(req)
        except ValueError:
            return send(400, "invalid JSON", rid)
        err = validate_evaluation(e)
        if err:
            return send(400, err, rid)
        return send(200, await evaluate(e), rid)

    async def many(req: Request) -> JSONResponse:
        rid = (req.headers.get("x-request-id") or "")[:200] or None
        if not authed(req):
            return JSONResponse("unauthorized", status_code=401, headers={"www-authenticate": 'Bearer realm="pdp"', **({"x-request-id": rid} if rid else {})})
        try:
            b = await body(req)
        except ValueError:
            return send(400, "invalid JSON", rid)
        if not _is_obj(b):
            return send(400, "request body must be an object", rid)
        evs = b.get("evaluations") if isinstance(b.get("evaluations"), list) else None
        sem = (b.get("options") or {}).get("evaluations_semantic") if _is_obj(b.get("options")) else None
        sem = sem or "execute_all"
        if sem not in ("execute_all", "deny_on_first_deny", "permit_on_first_permit"):
            return send(400, "unsupported evaluations_semantic", rid)
        if not evs:
            err = validate_evaluation(b)
            return send(400, err, rid) if err else send(200, await evaluate(b), rid)
        if len(evs) > 1000:
            return send(400, "too many evaluations", rid)
        merged = []
        for it in evs:
            it = it if _is_obj(it) else {}
            m = {k: it.get(k) if it.get(k) is not None else b.get(k) for k in ("subject", "action", "resource", "context")}
            if m["context"] is None:
                del m["context"]
            err = validate_evaluation(m)
            if err:
                return send(400, err, rid)
            merged.append(m)
        out: list[dict[str, Any]] = []
        for m in merged:
            r = await evaluate(m)
            out.append(r)
            if sem == "deny_on_first_deny" and not r["decision"]:
                break
            if sem == "permit_on_first_permit" and r["decision"]:
                break
        return send(200, {"evaluations": out}, rid)

    return Starlette(routes=[Route("/.well-known/authzen-configuration", config, methods=["GET"]),
                             Route("/access/v1/evaluation", one, methods=["POST"]),
                             Route("/access/v1/evaluations", many, methods=["POST"])])

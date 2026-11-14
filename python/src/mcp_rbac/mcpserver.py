"""Integration with the official Python MCP SDK (``mcp>=2.3``: ``mcp.server.mcpserver.MCPServer``).

    server = MCPServer("shop", token_verifier=JwtVerifier(...), auth=AuthSettings(...))
    rbac = RBAC[Role](roles=ROLES)

    @server.tool()
    @rbac.tool(allow=["manager"], scopes=["campaigns:write"], approve=True)
    async def send_campaign(campaign_id: str) -> str: ...

    rbac.install(server)          # enforces tools/list + tools/call for EVERY tool (deny by default)

Identity comes only from the SDK's verified ``AccessToken`` (``get_access_token()``), never from arguments.
Approvals: MCP 2026-07-28 clients get an ``input_required`` result (MRTR; the SDK seals ``requestState`` and binds
it to the principal and the exact arguments; we add a single-use nonce). Older clients with the elicitation
capability get ``elicitation/create``. Clients with neither are denied.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Generic, Literal, TypeVar

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from pydantic import BaseModel

from .constraints import Constraint
from .delegation import DelegationError, actors_from_claims
from .guard import ApprovalRequest, Approver, Decision, Guard, Limit, ToolRule
from .roles import Assignment, Identity, Role
from .scopes import parse_toolsets
from .stores import ConsumeItem

R = TypeVar("R", bound=str)
MODERN = "2026-07-28"
APPROVAL_INPUT_KEY = "mcp-rbac/approval"
DENIAL_META_KEY = "mcp-rbac/denial"
RATELIMIT_META_KEY = "mcp-rbac/ratelimit"
TOOLSETS_HEADER = "mcp-rbac-toolsets"
_APPROVAL_SCHEMA = {"type": "object", "properties": {"approve": {"type": "boolean", "title": "Approve this call?"}}, "required": ["approve"]}


def identity_from_token(token: AccessToken, *, roles_claim: str = "roles", tenant_claim: str = "tenant") -> Identity[Any] | None:
    """Default resolver: ``sub`` (or client id), ``roles`` claim (strings or {role, scope}), ``tenant`` claim,
    token scopes, client id, and the RFC 8693 ``act`` chain. A malformed ``act`` makes the caller unauthenticated."""
    claims = token.claims or {}
    sub = token.subject or claims.get("sub") or token.client_id
    if not isinstance(sub, str) or not sub:
        return None
    try:
        act = actors_from_claims(claims)
    except DelegationError:
        return None
    raw = claims.get(roles_claim, [])
    assignments: list[Assignment[Any]] = []
    for r in raw if isinstance(raw, list) else []:
        if isinstance(r, str):
            assignments.append(Assignment(r))
        elif isinstance(r, Mapping) and isinstance(r.get("role"), str):
            try:
                assignments.append(Assignment(r["role"], dict(r.get("scope") or {})))
            except ValueError:
                return None
    tenant = claims.get(tenant_claim)
    return Identity(id=sub, assignments=tuple(assignments), tenant=tenant if isinstance(tenant, str) and tenant else None,
                    scopes=frozenset(token.scopes), client_id=token.client_id, act=act)


class JwtVerifier:
    """``TokenVerifier`` for JWT access tokens (PyJWT). Checks signature, ``exp``, ``iss``, ``aud``; keeps claims."""

    def __init__(self, key: Any, *, issuer: str | None = None, audience: str | None = None, algorithms: Sequence[str] = ("HS256",),
                 leeway: float = 30) -> None:
        self.key, self.issuer, self.audience, self.algorithms, self.leeway = key, issuer, audience, list(algorithms), leeway

    async def verify_token(self, token: str) -> AccessToken | None:
        import jwt

        try:
            c = jwt.decode(token, self.key, algorithms=self.algorithms, issuer=self.issuer, audience=self.audience, leeway=self.leeway,
                           options={"require": ["exp", "sub"]})
        except jwt.PyJWTError:
            return None
        scope = c.get("scope", "")
        return AccessToken(token=token, client_id=str(c.get("client_id") or c.get("azp") or c["sub"]),
                           scopes=scope.split() if isinstance(scope, str) else [], expires_at=int(c["exp"]),
                           resource=self.audience, subject=str(c["sub"]), claims=c)


def store_approver(guard: Guard[Any], *, ttl_s: float = 600, poll_s: float = 0.5,
                   on_pending: Callable[[dict[str, Any]], None] | None = None) -> Approver:
    """Durable approval queue in the guard's store (Redis/Postgres for multi-process). A human decides it with
    ``decide_approval`` (or the TS ``mcp-rbac approve`` CLI on a shared store)."""

    async def ask(req: ApprovalRequest) -> str:
        now = int(time.time() * 1000)
        a: dict[str, Any] = {"ref": req.ref, "tool": req.tool, "args": dict(req.args), "user": req.identity.id, "agent": req.identity.agent,
             "createdAt": now, "expiresAt": now + int(ttl_s * 1000), "status": "pending"}
        if req.tenant:
            a["tenant"] = req.tenant
        await guard.store.put_approval(a)
        if on_pending:
            on_pending(a)
        while time.time() * 1000 < a["expiresAt"]:
            cur = await guard.store.get_approval(req.ref)
            if cur and cur["status"] != "pending":
                return "allow" if cur["status"] == "allow" else "deny"
            await asyncio.sleep(poll_s)
        return "deny"

    return ask


@dataclass
class _CallCtx:
    ctx: ServerRequestContext[Any, Any]
    modern: bool
    can_elicit: bool


class RBAC(Generic[R]):
    """Typed roles + colocated per-tool rules for an MCPServer."""

    def __init__(self, roles: Mapping[R, Role], *, identity: Callable[[AccessToken], Identity[R] | None] = identity_from_token,
                 local_identity: Identity[R] | None = None, approvals: Literal["auto", "queue", "deny"] | Approver = "auto",
                 approval_message: Callable[[ApprovalRequest], str] | None = None, nonce_ttl_s: float = 900, **guard_kw: Any) -> None:
        self.guard: Guard[R] = Guard(roles, **guard_kw)
        self.resolve = identity
        self.local_identity = local_identity
        self.approvals = approvals
        self.approval_message = approval_message or (lambda r: f"Approve {r.tool}({json.dumps(dict(r.args), default=str)[:300]}) for {r.identity.id}?")
        self.nonce_ttl_s = nonce_ttl_s

    # -- declaration -------------------------------------------------------------------------------------------
    def tool(self, allow: Sequence[R] = (), *, name: str | None = None, scopes: Sequence[str] = (),
             constraints: Mapping[str, Constraint] | None = None, scope: Callable[[Mapping[str, Any]], Any] | None = None,
             approve: bool | Callable[[Mapping[str, Any]], bool] = False, labels: Sequence[str] = (), redact: Sequence[str] = (),
             redact_unless: Sequence[R] = (), toolset: str | None = None, limits: Sequence[Limit] = ()) -> Callable[[Any], Any]:
        """Record rules for a tool. Put it UNDER ``@server.tool()`` (it returns the function unchanged)."""

        def deco(fn: Any) -> Any:
            self.guard.add_rule(name or fn.__name__, ToolRule(allow=tuple(allow), constraints=dict(constraints or {}), scopes=tuple(scopes),
                                                              scope=scope, approve=approve, labels=tuple(labels), redact=tuple(redact),
                                                              redact_unless=tuple(redact_unless), toolset=toolset, limits=tuple(limits)))
            return fn

        return deco

    def step_up(self, app: Any, verifier: Any, *, max_body: int = 4_000_000) -> Any:
        """ASGI wrapper: answer ``tools/call`` with HTTP 403 + ``WWW-Authenticate: Bearer error="insufficient_scope",
        scope="..."`` (RFC 6750 / RFC 9470 step-up) when the verified token lacks a scope the tool requires.
        Same status, JSON-RPC error (-32003) and challenge as the TS server. Everything else passes through
        unchanged (the request body is replayed to the app)."""
        from .scopes import insufficient_scope_challenge

        async def wrapped(scope: dict[str, Any], receive: Any, send: Any) -> None:
            if scope.get("type") != "http" or scope.get("method") != "POST" or not self.guard.scopes:
                await app(scope, receive, send)
                return
            msgs: list[dict[str, Any]] = []
            body = b""
            while True:
                m = await receive()
                msgs.append(m)
                body += m.get("body", b"")
                if not m.get("more_body") or len(body) > max_body:
                    break
            replay = list(msgs)

            async def again() -> dict[str, Any]:
                return replay.pop(0) if replay else await receive()

            need: list[str] = []
            rid: Any = None
            try:
                msg = json.loads(body) if len(body) <= max_body else None
            except ValueError:
                msg = None
            if isinstance(msg, dict) and msg.get("method") == "tools/call" and isinstance((msg.get("params") or {}).get("name"), str):
                rid = msg.get("id")
                auth = dict(scope.get("headers") or []).get(b"authorization", b"").decode("latin-1")
                if auth[:7].lower() == "bearer ":
                    at = await verifier.verify_token(auth[7:].strip())
                    ident = self.resolve(at) if at is not None else None
                    if ident is not None and ident.scopes is not None:
                        need = self.guard.scopes.missing(msg["params"]["name"], ident.scopes)
            if not need:
                await app(scope, again, send)
                return
            host = dict(scope.get("headers") or []).get(b"host", b"localhost").decode("latin-1")
            meta = f"{scope.get('scheme', 'http')}://{host}/.well-known/oauth-protected-resource{scope.get('path', '')}"
            payload = json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32003, "message": "insufficient_scope", "data": {"scopes": need}}}).encode()
            await send({"type": "http.response.start", "status": 403, "headers": [
                (b"content-type", b"application/json"), (b"www-authenticate", insufficient_scope_challenge(need, meta).encode())]})
            await send({"type": "http.response.body", "body": payload})

        return wrapped

    def http_app(self, server: Any, verifier: Any | None = None, **kw: Any) -> Any:
        """``server.streamable_http_app(**kw)`` with the 403 step-up pre-check in front."""
        v = verifier or getattr(server, "_token_verifier", None)
        app = server.streamable_http_app(**kw)
        return self.step_up(app, v) if v is not None else app

    def install(self, server: Any) -> None:
        """Append the enforcement middleware (runs inside the SDK's OTel + requestState boundary)."""
        server.middleware.append(self.middleware)

    # -- identity ----------------------------------------------------------------------------------------------
    def current_identity(self, ctx: ServerRequestContext[Any, Any] | None = None) -> Identity[R] | None:
        """Identity from the SDK-verified access token. ``local_identity`` (stdio / in-process) is NEVER used for
        an HTTP request: an HTTP request without a verified token is unauthenticated."""
        tok = get_access_token()
        if tok is None:
            return None if (ctx is not None and ctx.request is not None) else self.local_identity
        try:
            return self.resolve(tok)
        except Exception:
            return None

    @staticmethod
    def _toolsets(ctx: ServerRequestContext[Any, Any]) -> list[str] | None:
        req = ctx.request
        headers = getattr(req, "headers", None)
        if headers is not None:
            v = headers.get(TOOLSETS_HEADER)
            if v:
                return parse_toolsets(v)
        tok = get_access_token()
        if tok and tok.claims and "toolsets" in tok.claims:
            return parse_toolsets(tok.claims["toolsets"])
        return None

    # -- middleware --------------------------------------------------------------------------------------------
    async def middleware(self, ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        if ctx.method == "tools/list":
            return await self._list(ctx, call_next)
        if ctx.method == "tools/call":
            return await self._call(ctx, call_next)
        out: HandlerResult = await call_next(ctx)
        return out

    async def _list(self, ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        result = await call_next(ctx)
        ident = self.current_identity(ctx)
        sets = self._toolsets(ctx)
        d = _dump(result)
        tools = [t for t in d.get("tools", []) if await self.guard.visible(ident, t.get("name", ""), sets)]
        d["tools"] = tools
        d["cacheScope"] = "private"  # the list depends on who is asking (2026-07-28 cache hint; dropped for older versions)
        d.pop("resultType", None)
        return _model("ListToolsResult", d)

    def _approver(self, cc: _CallCtx, params: Mapping[str, Any]) -> Approver | None:
        mode = self.approvals
        if callable(mode):
            return mode
        if mode == "deny":
            return None
        if mode == "queue":
            return store_approver(self.guard)

        async def auto(req: ApprovalRequest) -> str:
            if cc.modern:
                resp = (params.get("inputResponses") or {}).get(APPROVAL_INPUT_KEY)
                state = params.get("requestState")
                if resp is not None and isinstance(state, str):
                    # requestState was unsealed by the SDK boundary (AES-GCM, bound to principal + tool + args digest).
                    try:
                        nonce = json.loads(state).get("n")
                    except (ValueError, AttributeError):
                        return "deny"
                    if not isinstance(nonce, str) or len(nonce) < 16:
                        return "deny"
                    once = await self.guard.store.consume_many([ConsumeItem(f"mrtr-nonce|{nonce}", 1, 1, int(self.nonce_ttl_s * 1000))], int(time.time() * 1000))
                    if not once.ok:
                        return "deny"  # replay
                    ok = isinstance(resp, Mapping) and resp.get("action") == "accept" and (resp.get("content") or {}).get("approve") is True
                    return "allow" if ok else "deny"
                return "input_required" if cc.can_elicit else "deny"
            if not cc.can_elicit:
                return "deny"
            r = await cc.ctx.session.elicit_form(self.approval_message(req), _APPROVAL_SCHEMA, related_request_id=cc.ctx.request_id)
            return "allow" if r.action == "accept" and (r.content or {}).get("approve") is True else "deny"

        return auto

    async def _call(self, ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        params = ctx.params or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(args, Mapping):
            return _model("CallToolResult", _denied("invalid", "invalid request", None))
        caps = ctx.session.client_capabilities
        cc = _CallCtx(ctx, ctx.protocol_version >= MODERN, bool(caps and caps.elicitation))
        ident = self.current_identity(ctx)
        d = await self.guard.authorize(ident, name, args, toolsets=self._toolsets(ctx), approver=self._approver(cc, params))
        if d.reason == "input_required":
            return _input_required(self.approval_message(ApprovalRequest(d.ref, name, args, ident, d.tenant)) if ident else "Approve?")
        if not d.allow:
            return _model("CallToolResult", _denied(d.ref, d.explanation, d))
        result = _dump(await call_next(ctx))
        result = self.guard.filter_output(d, result)
        if d.rate_limit:
            meta = dict(result.get("_meta") or {})
            rl = d.rate_limit
            meta[RATELIMIT_META_KEY] = {"name": rl.name, "limit": rl.limit, "remaining": rl.remaining, "windowSec": rl.window_s, "resetSec": rl.reset_s}
            result["_meta"] = meta
        return _model("CallToolResult", result)


def _model(kind: str, d: dict[str, Any]) -> BaseModel:
    import mcp_types as t

    d = {k: v for k, v in d.items() if k != "resultType"}
    model: type[BaseModel] = getattr(t, kind)
    return model.model_validate(d)


def _dump(r: Any) -> dict[str, Any]:
    if isinstance(r, BaseModel):
        return r.model_dump(by_alias=True, exclude_none=True, mode="json")
    return dict(r or {})


def _denied(ref: str, explanation: str, d: Decision | None) -> dict[str, Any]:
    meta: dict[str, Any] = {"ref": ref}
    if d and d.missing_scopes:
        meta["scopes"] = list(d.missing_scopes)
    if d and d.rate_limit:
        meta["rateLimit"] = {"name": d.rate_limit.name, "limit": d.rate_limit.limit, "remaining": 0, "resetSec": d.rate_limit.reset_s}
    return {"content": [{"type": "text", "text": f"Denied by policy: {explanation} (ref {ref})"}], "isError": True, "_meta": {DENIAL_META_KEY: meta}}


def _input_required(message: str) -> BaseModel:
    import mcp_types as t

    return t.InputRequiredResult(
        input_requests={APPROVAL_INPUT_KEY: t.ElicitRequest(params=t.ElicitRequestFormParams(message=message, requested_schema=_APPROVAL_SCHEMA))},
        request_state=json.dumps({"n": secrets.token_urlsafe(18)}),
    )



"""Drive every language's real mini server (stdio) with the official Python MCP client while each exports OTLP to a real
otelcol-contrib, then assert on the collector's OTLP-JSON file output and on Jaeger's query API.

Usage (see tools/otel-e2e.sh, which starts the collector and Jaeger): drive.py OUT.jsonl SUMMARY.json
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import secrets
import sys
import time
import urllib.request
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = pathlib.Path(sys.argv[1])
SUMMARY = pathlib.Path(sys.argv[2])
CANARY_ID = "CANARYid" + secrets.token_hex(4)
CANARY_ARG = "CANARYarg" + secrets.token_hex(4)
CANARY_BAG = "CANARYbag" + secrets.token_hex(4)
POLICY = str(ROOT / "examples/core-servers/mini.yaml")
BIN = pathlib.Path(os.environ["OTEL_E2E_BIN"])
SERVERS: dict[str, tuple[str, list[str], str]] = {
    "ts": ("npx", ["tsx", "examples/core-servers/ts/server.ts"], "mini-venue-ts"),
    "py": (str(ROOT / "python/.venv/bin/python"), ["examples/core-servers/python/server.py"], "mini-venue-py"),
    "go": (str(BIN / "otlp-mini-go"), ["-policy", POLICY], "mini-venue-go"),
    "rust": (str(ROOT / "core/target/debug/mini-server"), [POLICY], "mini-venue-rust"),
}
ENDPOINT = "http://127.0.0.1:14318"
# Contract attributes a binding cannot record, with the reason; reported in the summary instead of silently passing.
KNOWN_GAPS = {("go", "jsonrpc.request.id"): "go-sdk 1.8 keeps the request ID behind an unexported context key"}


def tp() -> tuple[str, str, str]:
    trace_id, parent = secrets.token_hex(16), secrets.token_hex(8)
    return trace_id, parent, f"00-{trace_id}-{parent}-01"


async def session(lang: str, identity: dict[str, Any], steps: list[tuple[str, dict[str, Any], str | None]]) -> list[Any]:
    cmd, args, _ = SERVERS[lang]
    env = {**os.environ, "MCP_RBAC_IDENTITY": json.dumps(identity), "OTEL_EXPORTER_OTLP_ENDPOINT": ENDPOINT,
           "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf"}
    out: list[Any] = []
    async with stdio_client(StdioServerParameters(command=cmd, args=args, env=env, cwd=str(ROOT))) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            out.append(sorted(t.name for t in (await s.list_tools()).tools))
            for tool, a, traceparent in steps:
                meta: dict[str, Any] = {"baggage": f"user={CANARY_BAG}"}
                if traceparent:
                    meta["traceparent"] = traceparent
                    meta["tracestate"] = "e2e=1"
                res = await s.call_tool(tool, a, meta=meta)  # type: ignore[arg-type]
                out.append({"isError": res.is_error, "text": res.content[0].text if res.content else None})  # type: ignore[union-attr]
    return out


def av(v: dict[str, Any]) -> Any:
    for k in ("stringValue", "boolValue", "intValue", "doubleValue"):
        if k in v:
            return v[k]
    return v


def attrs(xs: list[dict[str, Any]] | None) -> dict[str, Any]:
    return {a["key"]: av(a["value"]) for a in xs or []}


def load() -> tuple[list[dict], list[dict], list[dict]]:
    spans, points, logs = [], [], []
    for line in OUT.read_text().splitlines():
        if not line.strip():
            continue
        doc = json.loads(line)
        for rs in doc.get("resourceSpans", []):
            svc = attrs(rs["resource"].get("attributes")).get("service.name")
            for ss in rs.get("scopeSpans", []):
                for sp in ss.get("spans", []):
                    spans.append({**sp, "service": svc, "scope": ss.get("scope", {}).get("name"), "attrs": attrs(sp.get("attributes"))})
        for rm in doc.get("resourceMetrics", []):
            svc = attrs(rm["resource"].get("attributes")).get("service.name")
            for sm in rm.get("scopeMetrics", []):
                for m in sm.get("metrics", []):
                    for kind in ("sum", "histogram", "gauge"):
                        for dp in (m.get(kind) or {}).get("dataPoints", []):
                            points.append({"service": svc, "name": m["name"], "kind": kind, "attrs": attrs(dp.get("attributes")),
                                           "value": float(dp.get("asInt", dp.get("asDouble", 0))), "count": int(dp.get("count", 0)),
                                           "sum": float(dp.get("sum", 0))})
        for rl in doc.get("resourceLogs", []):
            svc = attrs(rl["resource"].get("attributes")).get("service.name")
            for sl in rl.get("scopeLogs", []):
                for lr in sl.get("logRecords", []):
                    logs.append({**lr, "service": svc, "attrs": attrs(lr.get("attributes"))})
    return spans, points, logs


def main() -> int:
    ids: dict[str, dict[str, tuple[str, str, str]]] = {}
    results: dict[str, Any] = {}
    t0 = time.time()
    for lang in SERVERS:
        ids[lang] = {k: tp() for k in ("allow", "deny", "rl", "appr", "red")}
        i = ids[lang]
        door = asyncio.run(session(lang, {"id": CANARY_ID, "roles": ["door"], "name": CANARY_ID}, [
            ("checkin", {"ticketId": CANARY_ARG}, i["allow"][2]),
            ("refund", {"ticketId": "t1", "amount": 5}, i["deny"][2]),
            ("checkin", {"ticketId": "t2"}, None),
            ("checkin", {"ticketId": "t3"}, None),
            ("checkin", {"ticketId": "t4"}, i["rl"][2]),
        ]))
        owner = asyncio.run(session(lang, {"id": "olu", "roles": ["owner"]}, [("refund", {"ticketId": "t1", "amount": 150}, i["appr"][2])]))
        support = asyncio.run(session(lang, {"id": "sam", "roles": ["support"]}, [("get_guest", {"guestId": "g1"}, i["red"][2])]))
        results[lang] = {"client": {"door": door, "owner": owner, "support": support}}
    drive_s = time.time() - t0
    time.sleep(3)  # collector file exporter + Jaeger ingestion
    spans, points, logs = load()
    raw = OUT.read_text()
    failures: list[str] = []

    def check(lang: str, name: str, ok: bool, detail: Any = None) -> None:
        results[lang].setdefault("checks", {})[name] = ok
        if not ok:
            failures.append(f"{lang}: {name}: {detail}")

    for lang, (_, _, svc) in SERVERS.items():
        i = ids[lang]
        c = results[lang]["client"]
        check(lang, "client: door sees 2 tools", c["door"][0] == ["checkin", "list_events"], c["door"][0])
        check(lang, "client: deny/rate-limit texts", c["door"][2]["text"] == "Denied: user:no_matching_permission"
              and c["door"][5]["text"] == "Denied: rate_limited:0", c["door"])
        check(lang, "client: redacted", "[REDACTED]" in (c["support"][1]["text"] or ""), c["support"])

        def in_trace(key: str) -> list[dict]:
            return [s for s in spans if s["traceId"] == i[key][0]]

        def server_span(key: str) -> dict | None:
            ss = [s for s in in_trace(key) if s.get("kind") == 2]
            return ss[0] if len(ss) == 1 else None

        srv = server_span("allow")
        auth = [s for s in in_trace("allow") if s["name"] == "mcp_rbac.authorize checkin"]
        check(lang, "trace: one SERVER span parented on client traceparent", srv is not None and srv.get("parentSpanId") == i["allow"][1]
              and srv["service"] == svc, [(s["name"], s.get("kind"), s.get("parentSpanId")) for s in in_trace("allow")])
        if srv:
            results[lang]["server_span_name"] = srv["name"]
            a = srv["attrs"]
            need_id = (lang, "jsonrpc.request.id") not in KNOWN_GAPS
            check(lang, "trace: server span semconv attrs", a.get("mcp.method.name") == "tools/call" and a.get("gen_ai.tool.name") == "checkin"
                  and a.get("gen_ai.operation.name") == "execute_tool" and (not need_id or "jsonrpc.request.id" in a)
                  and bool(a.get("mcp.protocol.version")) and a.get("mcp_rbac.decision") == "allow", a)
            gaps = {k: why for (lg, k), why in KNOWN_GAPS.items() if lg == lang and k not in a}
            if gaps:
                results[lang]["known_gaps"] = gaps
            results[lang]["protocol_version"] = a.get("mcp.protocol.version")
            check(lang, "trace: tracestate propagated", srv.get("traceState") == "e2e=1", srv.get("traceState"))
        check(lang, "trace: INTERNAL authorize child", len(auth) == 1 and auth[0].get("kind") == 1 and srv is not None
              and auth[0].get("parentSpanId") == srv["spanId"] and auth[0]["attrs"].get("mcp_rbac.reason") == "ok", auth)
        d = server_span("deny")
        check(lang, "trace: denial = error.type tool_error + ERROR status", d is not None and d["attrs"].get("error.type") == "tool_error"
              and d.get("status", {}).get("code") == 2 and d["attrs"].get("mcp_rbac.reason") == "user:no_matching_permission", d and d["attrs"])
        rl = server_span("rl")
        check(lang, "trace: rate limit reason", rl is not None and rl["attrs"].get("mcp_rbac.reason") == "rate_limited:0", rl and rl["attrs"])
        ap = server_span("appr")
        check(lang, "trace: approval unavailable", ap is not None and ap["attrs"].get("mcp_rbac.approval") == "unavailable"
              and ap["attrs"].get("mcp_rbac.decision") == "needs_approval", ap and ap["attrs"])
        rd = server_span("red")
        check(lang, "trace: redacted flag", rd is not None and rd["attrs"].get("mcp_rbac.redacted") is True, rd and rd["attrs"])

        mine = [p for p in points if p["service"] == svc]
        dec = {(p["attrs"].get("mcp_rbac.decision"), p["attrs"].get("gen_ai.tool.name")): p["value"] for p in mine if p["name"] == "mcp_rbac.decisions"}
        dsum: dict[tuple, float] = {}
        for p in mine:
            if p["name"] == "mcp_rbac.decisions":
                k = (p["attrs"].get("mcp_rbac.decision"), p["attrs"].get("gen_ai.tool.name"))
                dsum[k] = dsum.get(k, 0) + p["value"]
        check(lang, "metrics: decisions counter", dsum.get(("allow", "checkin")) == 3 and dsum.get(("deny", "checkin")) == 1
              and dsum.get(("deny", "refund")) == 1 and dsum.get(("needs_approval", "refund")) == 1 and dsum.get(("allow", "get_guest")) == 1, dsum or dec)
        hist = sum(p["count"] for p in mine if p["name"] == "mcp_rbac.authorize.duration")
        check(lang, "metrics: authorize.duration histogram (7 calls)", hist == 7, hist)
        appr = sum(p["value"] for p in mine if p["name"] == "mcp_rbac.approvals" and p["attrs"].get("mcp_rbac.approval.outcome") == "unavailable")
        check(lang, "metrics: approvals{unavailable}", appr == 1, appr)
        util = [p for p in mine if p["name"] == "mcp_rbac.budget.utilization"]
        check(lang, "metrics: budget.utilization 1/3+2/3+3/3", sum(p["count"] for p in util) == 3 and abs(sum(p["sum"] for p in util) - 2.0) < 1e-6,
              [(p["count"], p["sum"]) for p in util])
        results[lang]["operation_duration_points"] = sum(p["count"] for p in mine if p["name"] == "mcp.server.operation.duration")

        ml = [lg for lg in logs if lg["service"] == svc and "mcp_rbac.decision" in json.dumps(lg.get("body", {})) + str(lg.get("eventName"))]
        results[lang]["decision_logs"] = len(ml)
        check(lang, "logs: 7 decision records via OTLP", len(ml) == 7, len(ml))
        la = [lg for lg in ml if lg.get("traceId") == i["allow"][0]]
        check(lang, "logs: allow record correlated to authorize span, INFO", len(la) == 1 and bool(auth) and la[0].get("spanId") == auth[0]["spanId"]
              and la[0].get("severityText") == "INFO", la)
        ld = [lg for lg in ml if lg.get("traceId") == i["deny"][0]]
        check(lang, "logs: deny record WARN", len(ld) == 1 and ld[0].get("severityText") in ("WARN", "WARNING"), ld)

        jd: Any = None
        for _ in range(20):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:16686/api/traces/{i['allow'][0]}", timeout=5) as resp:
                    jd = json.load(resp)
                if jd.get("data"):
                    break
            except Exception as e:  # noqa: BLE001 - retry until Jaeger has indexed the trace
                jd = {"error": str(e)}
            time.sleep(0.5)
        jt = (jd or {}).get("data") or []
        ops = sorted(s["operationName"] for s in jt[0]["spans"]) if jt else []
        svcs = sorted({p["serviceName"] for p in jt[0]["processes"].values()}) if jt else []
        results[lang]["jaeger"] = {"operations": ops, "services": svcs}
        check(lang, "jaeger: trace queryable with server + authorize spans", "mcp_rbac.authorize checkin" in ops and svc in svcs and len(ops) >= 2, jd)

    for canary in (CANARY_ID, CANARY_ARG, CANARY_BAG):
        if canary in raw:
            failures.append(f"canary {canary[:9]} leaked into collector output")
    summary = {"date": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "drive_seconds": round(drive_s, 1), "collector_lines": len(raw.splitlines()),
               "spans": len(spans), "metric_points": len(points), "log_records": len(logs), "canaries_absent": not any(
                   c in raw for c in (CANARY_ID, CANARY_ARG, CANARY_BAG)), "failures": failures,
               "languages": {k: {kk: vv for kk, vv in v.items() if kk != "client"} for k, v in results.items()}}
    SUMMARY.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

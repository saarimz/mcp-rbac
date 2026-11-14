/**
 * Language-neutral Policy Decision Point: OpenID AuthZEN Authorization API 1.0 over HTTP.
 *   GET  /.well-known/authzen-configuration
 *   POST /access/v1/evaluation
 *   POST /access/v1/evaluations   (execute_all | deny_on_first_deny | permit_on_first_permit)
 * Any AuthZEN PEP (Python, Go, Java, a gateway...) can ask it; mcp-rbac's own AuthZenEngine and the
 * Python `mcp_rbac` package do.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import type { AddressInfo } from "node:net";
import { BuiltinEngine, type DecisionEngine } from "./engine.js";
import { loadPolicy } from "./policy.js";
import { fromAuthZen, validateEvaluation, type AzEntity, type AzEvaluation, type EvaluationsSemantic } from "./authzen.js";
import type { Role } from "./role.js";
import type { User } from "./types.js";

export interface PdpOptions {
  engine?: DecisionEngine;
  roles?: Record<string, Role<any>>;
  /** JSON policy (same format as `mcp-rbac init --format json`). */
  policy?: unknown;
  /**
   * PDP-owned directory: role assignments by subject id. When set, roles in the request's
   * subject.properties are IGNORED (a PEP can't grant itself roles). Without it the PEP is trusted
   * to send subject.properties.assignments.
   */
  directory?: (subjectId: string, subject: AzEntity) => User | undefined;
  /** Require `Authorization: Bearer <token>` from PEPs. */
  token?: string;
  /** Include reason/rule in the decision context (server-to-server). Default true. */
  exposeReasons?: boolean;
  baseUrl?: string;
  maxBodyBytes?: number;
}

function subjectUser(s: AzEntity): User | undefined {
  const p = s.properties ?? {};
  const raw = Array.isArray(p.assignments) ? p.assignments : Array.isArray(p.roles) ? (p.roles as unknown[]).map((r) => ({ role: r, scope: p.scope ?? {} })) : undefined;
  if (!raw) return undefined;
  const assignments: User["assignments"][number][] = [];
  for (const a of raw as any[]) {
    if (!a || typeof a.role !== "string") return undefined;
    const scope: Record<string, string> = {};
    if (a.scope && typeof a.scope === "object") for (const [k, v] of Object.entries(a.scope)) { if (typeof v !== "string" || !v) return undefined; scope[k] = v; }
    assignments.push({ role: a.role, scope });
  }
  return { id: s.id, assignments, ...(p.attr && typeof p.attr === "object" ? { attr: p.attr as Record<string, unknown> } : {}) };
}

export function createPdpHandler(o: PdpOptions) {
  const engine: DecisionEngine = o.engine ?? new BuiltinEngine(o.roles ?? (o.policy !== undefined ? loadPolicy(o.policy).roles : (() => { throw new TypeError("PDP needs engine, roles or policy"); })()));
  const userOf = (s: AzEntity) => (o.directory ? o.directory(s.id, s) : subjectUser(s));
  const expose = o.exposeReasons !== false;
  const send = (res: ServerResponse, status: number, body: unknown, rid?: string) => {
    res.writeHead(status, { "content-type": "application/json", ...(rid ? { "x-request-id": rid } : {}) });
    res.end(typeof body === "string" ? JSON.stringify(body) : JSON.stringify(body));
  };
  const evaluate = async (e: AzEvaluation) => {
    const m = fromAuthZen(e, userOf);
    if (!m.input) return { decision: false, ...(expose ? { context: { reason: m.error ?? "invalid" } } : {}) };
    try {
      if (m.list) {
        const ok = engine.visible ? (await engine.visible(m.input.user, m.input.kind, m.input.name)) === true : true;
        return { decision: ok, ...(expose ? { context: { reason: ok ? "visible" : "not_visible" } } : {}) };
      }
      const d = await engine.decide(m.input);
      return { decision: d?.allow === true, ...(expose ? { context: { reason: d?.reason ?? "engine_denied", ...(d?.rule ? { rule: d.rule } : {}) } } : {}) };
    } catch {
      return { decision: false, ...(expose ? { context: { reason: "engine_error" } } : {}) };
    }
  };
  const authOk = (req: IncomingMessage) => {
    if (!o.token) return true;
    const h = req.headers.authorization ?? "";
    const got = Buffer.from(h.replace(/^Bearer\s+/i, ""));
    const want = Buffer.from(o.token);
    return /^Bearer\s+/i.test(h) && got.length === want.length && timingSafeEqual(got, want);
  };
  return async (req: IncomingMessage, res: ServerResponse) => {
    const rid = typeof req.headers["x-request-id"] === "string" ? req.headers["x-request-id"].slice(0, 200) : undefined;
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const base = o.baseUrl ?? `http://${req.headers.host ?? "localhost"}`;
      if (req.method === "GET" && url.pathname === "/.well-known/authzen-configuration") {
        return send(res, 200, { policy_decision_point: base, access_evaluation_endpoint: `${base}/access/v1/evaluation`, access_evaluations_endpoint: `${base}/access/v1/evaluations` }, rid);
      }
      if (url.pathname !== "/access/v1/evaluation" && url.pathname !== "/access/v1/evaluations") return send(res, 404, "not found", rid);
      if (req.method !== "POST") return send(res, 405, "method not allowed", rid);
      if (!authOk(req)) { res.setHeader("www-authenticate", 'Bearer realm="pdp"'); return send(res, 401, "unauthorized", rid); }
      const chunks: Buffer[] = [];
      let n = 0;
      for await (const c of req) { n += (c as Buffer).length; if (n > (o.maxBodyBytes ?? 1_000_000)) return send(res, 400, "request too large", rid); chunks.push(c as Buffer); }
      let body: any;
      try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return send(res, 400, "invalid JSON", rid); }
      if (url.pathname === "/access/v1/evaluation") {
        const err = validateEvaluation(body);
        if (err) return send(res, 400, err, rid);
        return send(res, 200, await evaluate(body), rid);
      }
      // evaluations: top-level subject/action/resource/context are defaults for each item
      if (!body || typeof body !== "object") return send(res, 400, "request body must be an object", rid);
      const items: unknown[] | undefined = Array.isArray(body.evaluations) ? body.evaluations : undefined;
      const sem: EvaluationsSemantic = body.options?.evaluations_semantic ?? "execute_all";
      if (!["execute_all", "deny_on_first_deny", "permit_on_first_permit"].includes(sem)) return send(res, 400, "unsupported evaluations_semantic", rid);
      if (!items || items.length === 0) {
        const err = validateEvaluation(body);
        if (err) return send(res, 400, err, rid);
        return send(res, 200, await evaluate(body), rid); // spec: no evaluations array => behaves like a single evaluation
      }
      if (items.length > 1000) return send(res, 400, "too many evaluations", rid);
      const merged = items.map((it: any) => ({ subject: it?.subject ?? body.subject, action: it?.action ?? body.action, resource: it?.resource ?? body.resource, context: it?.context ?? body.context }));
      for (const m of merged) { const err = validateEvaluation(m); if (err) return send(res, 400, err, rid); }
      const out: unknown[] = [];
      if (sem === "execute_all") out.push(...(await Promise.all(merged.map((m) => evaluate(m as AzEvaluation)))));
      else {
        for (const m of merged) {
          const d = await evaluate(m as AzEvaluation);
          out.push(d);
          if (sem === "deny_on_first_deny" && !d.decision) break;
          if (sem === "permit_on_first_permit" && d.decision) break;
        }
      }
      return send(res, 200, { evaluations: out }, rid);
    } catch {
      if (!res.headersSent) send(res, 500, "internal error", rid);
    }
  };
}

export async function servePdp(o: PdpOptions & { port?: number; host?: string }) {
  const h = createPdpHandler(o);
  const srv = createServer((req, res) => { void h(req, res); });
  await new Promise<void>((r) => srv.listen(o.port ?? 0, o.host ?? "127.0.0.1", r));
  const { port } = srv.address() as AddressInfo;
  return { url: `http://${o.host ?? "127.0.0.1"}:${port}`, port, close: () => new Promise<void>((r) => { srv.closeAllConnections?.(); srv.close(() => r()); }) };
}

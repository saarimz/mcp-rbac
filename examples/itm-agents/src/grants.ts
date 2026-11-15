/**
 * Agent connection grants for ITM, enforced with mcp-rbac's portable engine.
 *
 *  - A human (AdminUserBrand OWNER/ADMIN/AGENT) creates named agent connections ("booking-bot", ...).
 *  - Each grant = OAuth scopes + optional tool allowlist + per-tool argument limits + budgets + extra approvals,
 *    pinned to ONE brand (and one moment for moment-scoped staff), expiring, revocable, epoched.
 *  - Creation is rejected unless the grant is <= the grantor's own rights (no escalation).
 *  - Every call is decided twice with mcp-rbac: base policy AS THE HUMAN (current role, grant scopes as token
 *    scopes) AND the grant's generated overlay policy. Both must allow. Budgets from both are enforced, so all
 *    of one human's agents together stay inside the human's own budget.
 *  - Tokens are opaque, hashed at rest, bound to the grant epoch and to the agent's DPoP key.
 *  - Every decision lands in a hash-chained AgentActionLog row with the act chain human -> agent.
 */
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { stringify } from "yaml";
import { canonical, decidePortable, expandScopes, loadPortablePolicy, requiredScopes, visiblePortable, type CompiledPolicy, type PortableDecision, type Rule } from "../../../src/portable.ts";
import { verifyProof } from "./dpop.ts";

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
export const MAX_GRANT_SECONDS = 90 * 24 * 3600; // ITM partner connections: 90-day absolute limit
const ACCESS_TOKEN_SECONDS = 3600;

export type Constraint = Partial<Pick<Rule, "min" | "max" | "maxLength" | "in" | "eq" | "pattern">> & { integer?: boolean; optional?: boolean };
export interface GrantRequest {
  grantorAdminUserId: number;
  brandUid: string;
  name: string;
  scopes: string[];
  /** Optional narrower allowlist inside what the scopes give. */
  tools?: string[];
  /** Per-tool argument limits, e.g. { send_email: { recipientCount: { max: 3 } } } */
  limits?: Record<string, Record<string, Constraint>>;
  /** Spend budget (sum of `sumArg`) per window, per agent. */
  budgets?: { tool: string; sum?: string; max: number; per: "minute" | "hour" | "day"; name: string }[];
  /** Tools that need a human approval for this agent even if the base policy doesn't require one. */
  approve?: string[];
  expiresInSec: number;
  /** For moment-scoped staff; must equal their assignment. */
  momentUid?: string;
}
export interface GrantRow { id: number; uid: string; brandId: number; grantorAdminUserId: number; grantorRoleAtGrant: string; grantorAuthorizationVersion: number; name: string; momentUid: string | null; scopes: string; tools: string; overlay: string; status: string; epoch: number; dpopJkt: string | null; createdAt: string; expiresAt: string; revokedAt: string | null }
export class EscalationError extends Error { constructor(public reasons: string[]) { super(`grant rejected: ${reasons.join(", ")}`); } }
export class AuthError extends Error { constructor(public code: string, public status = 401) { super(code); } }

export interface CallContext {
  grant: GrantRow; brandUid: string; human: { id: number; uid: string; email: string }; role: "OWNER" | "ADMIN" | "AGENT";
  membershipMomentUid: string | null; overlay: CompiledPolicy; scopes: string[];
}
export interface Decision { decision: "allow" | "deny" | "needs_approval"; reason: string; approvalUid?: string; base?: PortableDecision; overlay?: PortableDecision; auditSeq: number }

export class GrantStore {
  private overlayCache = new Map<string, CompiledPolicy>();
  /**
   * @param opts.momentPinning  OFF by default (Saarim 2026-11-15: AGENT staff stay brand-wide, matching today's
   *   BrandMemberGuard). When ON, an AGENT member with AdminUserBrand.momentUid set is limited to that moment, and so
   *   are the agents they create (optional/future knob, see ADOPTION.md).
   * @param opts.spendBudgets  OFF by default (Saarim 2026-11-15: v1 is about ACTIONS - tools, argument limits,
   *   approvals; spend needs per-partner cost extraction, so it is Phase 2). When OFF: the Phase-2 scope
   *   itm:bookings:spend can't be granted, grants can't carry spend budgets (budgets with `sum`), and spend limits
   *   in the base policy / overlays are not enforced. Call-count limits (no `sum`) still work.
   */
  constructor(readonly db: DatabaseSync, readonly base: CompiledPolicy, readonly toolNames: string[], readonly now: () => number = () => Date.now(), readonly opts: { momentPinning?: boolean; spendBudgets?: boolean } = {}) {}
  static readonly PHASE2_SCOPES = ["itm:bookings:spend"];
  /** The moment an AGENT member is pinned to, or null (always null unless the momentPinning knob is on). */
  pinnedMoment(m: { role: string; momentUid?: string | null }): string | null { return this.opts.momentPinning && m.role === "AGENT" && m.momentUid ? m.momentUid : null; }
  private iso(offsetMs = 0) { return new Date(this.now() + offsetMs).toISOString(); }

  // ----------------------------------------------------------------- lookups
  brandByUid(uid: string) { return this.db.prepare("SELECT id, uid, name FROM Brand WHERE uid = ?").get(uid) as { id: number; uid: string; name: string } | undefined; }
  membership(adminUserId: number, brandId: number) {
    return this.db.prepare("SELECT m.*, a.uid AS adminUid, a.email, a.revokedAt AS adminRevokedAt FROM AdminUserBrand m JOIN AdminUser a ON a.id = m.adminUserId WHERE m.adminUserId = ? AND m.brandId = ?").get(adminUserId, brandId) as any;
  }
  private activeMembership(adminUserId: number, brandId: number): { m: any } | { error: string } {
    const m = this.membership(adminUserId, brandId);
    if (!m) return { error: "no_membership" };
    if (m.adminRevokedAt) return { error: "admin_revoked" };
    if (m.revokedAt) return { error: "membership_revoked" };
    if (m.scheduledDeactivationAt && Date.parse(m.scheduledDeactivationAt) <= this.now()) return { error: "membership_deactivated" };
    return { m };
  }
  humanIdentity(m: any, brandUid: string, scopes?: string[], clientId?: string) {
    // Real ITM: AGENT passes BrandMemberGuard brand-wide (itm-backend src/auth/auth.decorators.ts). That is the default
    // here too; per-moment pinning is the optional, off-by-default knob (opts.momentPinning).
    const pin = this.pinnedMoment(m);
    const scope: Record<string, string> = pin ? { brand: brandUid, moment: pin } : { brand: brandUid };
    return { id: m.adminUid as string, roles: [{ role: String(m.role).toLowerCase(), scope }], tenant: brandUid, ...(scopes ? { scopes } : {}), ...(clientId ? { clientId } : {}) };
  }
  overlayIdentity(g: GrantRow, brandUid: string) {
    const scope: Record<string, string> = g.momentUid ? { brand: brandUid, moment: g.momentUid } : { brand: brandUid };
    return { id: g.uid, roles: [{ role: "grant", scope }], tenant: brandUid, clientId: g.uid };
  }
  overlayOf(g: GrantRow): CompiledPolicy {
    const k = `${g.uid}#${g.epoch}`;
    let p = this.overlayCache.get(k);
    if (!p) { p = loadPortablePolicy(g.overlay); this.overlayCache.set(k, p); }
    return p;
  }

  /** Tools a set of scopes unlocks in the base policy (tools with no required scope only if explicitly free, e.g. get_connection). */
  toolsForScopes(scopes: string[]): string[] {
    const exp = expandScopes(this.base, scopes);
    return this.toolNames.filter((t) => requiredScopes(this.base, t).every((s) => exp.has(s) || exp.has("*")));
  }
  /** The human's effective constraints on a tool (role permission constraints + tool-wide limits). */
  private humanConstraints(role: string, tool: string): Map<string, Rule> {
    const out = new Map<string, Rule>();
    const add = (c?: [string, Rule][]) => { for (const [k, r] of c ?? []) if (!out.has(k)) out.set(k, r); };
    for (const pm of this.base.roles.get(role) ?? []) if (pm.kind === "tool" && (pm.pattern === tool || pm.pattern === "*" || pm.pattern === "**")) add(pm.constraints);
    add(this.base.toolBase.get(tool));
    return out;
  }

  // ----------------------------------------------------------------- create (no escalation)
  createGrant(req: GrantRequest): GrantRow {
    const reasons: string[] = [];
    const brand = this.brandByUid(req.brandUid);
    if (!brand) throw new EscalationError(["unknown_brand"]);
    const am = this.activeMembership(req.grantorAdminUserId, brand.id);
    if ("error" in am) throw new EscalationError([`grantor_${am.error}`]);
    const m = am.m;
    if (!/^[a-z0-9][a-z0-9-]{1,40}$/.test(req.name)) reasons.push("bad_name");
    if (!(req.expiresInSec > 0 && req.expiresInSec <= MAX_GRANT_SECONDS)) reasons.push("bad_expiry");
    let momentUid: string | null = null;
    const pin = this.pinnedMoment(m);
    if (pin) {
      if (req.momentUid && req.momentUid !== pin) reasons.push("moment_outside_grantor_assignment");
      momentUid = pin;
    } else if (req.momentUid) { // anyone may voluntarily narrow a grant to one moment of their brand
      const mo = this.db.prepare("SELECT 1 FROM Moment WHERE uid = ? AND brandId = ?").get(req.momentUid, brand.id);
      if (!mo) reasons.push("moment_not_in_brand"); else momentUid = req.momentUid;
    }
    const resource: Record<string, string> = momentUid ? { brand: brand.uid, moment: momentUid } : { brand: brand.uid };
    const humanId = this.humanIdentity(m, brand.uid);
    const holds = (tool: string) => {
      const d = decidePortable(this.base, { identity: humanId, tool, args: {}, resource });
      // A permission exists if the only failures are argument-level or budget-level.
      return d.decision !== "deny" || d.reason.startsWith("user:constraint:") || d.reason.startsWith("limit_");
    };
    const known = new Set(this.toolNames);
    for (const s of req.scopes) {
      if (!/^itm:[a-z]+:[a-z]+$/.test(s)) { reasons.push(`bad_scope:${s}`); continue; }
      if (!this.opts.spendBudgets && GrantStore.PHASE2_SCOPES.includes(s)) { reasons.push(`phase2_scope_disabled:${s}`); continue; }
      const ts = this.toolsForScopes([s]).filter((t) => requiredScopes(this.base, t).length > 0);
      if (!ts.length) reasons.push(`unknown_scope:${s}`);
      for (const t of ts) if (requiredScopes(this.base, t).some((x) => expandScopes(this.base, [s]).has(x)) && !holds(t)) reasons.push(`scope_exceeds_grantor:${s}(${t})`);
    }
    const scopeTools = this.toolsForScopes(req.scopes);
    let tools = scopeTools;
    if (req.tools) {
      for (const t of req.tools) {
        if (!known.has(t)) reasons.push(`unknown_tool:${t}`);
        else if (!scopeTools.includes(t)) reasons.push(`tool_outside_scopes:${t}`);
      }
      tools = scopeTools.filter((t) => req.tools!.includes(t));
    }
    for (const t of tools) if (!holds(t)) reasons.push(`tool_exceeds_grantor:${t}`);
    for (const [t, cs] of Object.entries(req.limits ?? {})) {
      if (!tools.includes(t)) { reasons.push(`limit_on_ungranted_tool:${t}`); continue; }
      const hc = this.humanConstraints(String(m.role).toLowerCase(), t);
      for (const [arg, c] of Object.entries(cs)) {
        const h = hc.get(arg);
        if (!h) continue;
        if (h.max !== undefined && (c.max === undefined || c.max > h.max)) reasons.push(`limit_wider_than_grantor:${t}.${arg}.max`);
        if (h.min !== undefined && c.min !== undefined && c.min < h.min) reasons.push(`limit_wider_than_grantor:${t}.${arg}.min`);
        if (h.maxLength !== undefined && (c.maxLength === undefined || c.maxLength > h.maxLength)) reasons.push(`limit_wider_than_grantor:${t}.${arg}.maxLength`);
        if (h.in && c.in && !c.in.every((x) => h.in!.includes(x))) reasons.push(`limit_wider_than_grantor:${t}.${arg}.in`);
      }
    }
    for (const b of req.budgets ?? []) {
      if (b.sum !== undefined && !this.opts.spendBudgets) { reasons.push(`spend_budgets_disabled:${b.name}`); continue; }
      if (!tools.includes(b.tool)) { reasons.push(`budget_on_ungranted_tool:${b.tool}`); continue; }
      if (!(b.max > 0)) reasons.push(`bad_budget:${b.name}`);
      for (const l of this.base.limits) {
        if (l.pattern !== b.tool || l.sum === undefined || l.sum !== b.sum || l.shared !== "user") continue;
        // An agent budget may never exceed the grantor's own cap for the same spend (the grantor cap is also
        // enforced at runtime across ALL of the grantor's agents, so smaller windows can't add up past it).
        if (b.max > l.max) reasons.push(`budget_exceeds_grantor:${b.name}>${l.name ?? "limit"}`);
      }
    }
    for (const t of req.approve ?? []) if (!tools.includes(t)) reasons.push(`approval_on_ungranted_tool:${t}`);
    if (!tools.length) reasons.push("empty_grant");
    if (this.db.prepare("SELECT 1 FROM AgentGrant WHERE brandId = ? AND grantorAdminUserId = ? AND name = ? AND status != 'REVOKED'").get(brand.id, req.grantorAdminUserId, req.name)) reasons.push("name_taken");
    if (reasons.length) throw new EscalationError([...new Set(reasons)]);

    const uid = `grant_${randomUUID()}`;
    const overlay = this.renderOverlay(uid, req, tools);
    loadPortablePolicy(overlay); // must compile
    this.db.prepare("DELETE FROM AgentGrant WHERE brandId = ? AND grantorAdminUserId = ? AND name = ? AND status = 'REVOKED'").run(brand.id, req.grantorAdminUserId, req.name);
    this.db.prepare(`INSERT INTO AgentGrant (uid, brandId, grantorAdminUserId, grantorRoleAtGrant, grantorAuthorizationVersion, name, momentUid, scopes, tools, overlay, createdAt, expiresAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(uid, brand.id, req.grantorAdminUserId, m.role, m.authorizationVersion, req.name, momentUid, JSON.stringify(req.scopes), JSON.stringify(tools), overlay, this.iso(), this.iso(req.expiresInSec * 1000));
    return this.grant(uid)!;
  }

  renderOverlay(uid: string, req: GrantRequest, tools: string[]): string {
    const doc: Record<string, unknown> = {
      version: 1,
      name: uid,
      description: `Agent connection "${req.name}" (generated; do not edit)`,
      tenantKey: "brand",
      roles: { grant: { tools: tools.map((t) => (req.limits?.[t] ? { name: t, limits: req.limits[t] } : t)) } },
    };
    if (req.approve?.length) doc.approvals = req.approve.map((t) => ({ tool: t }));
    if (req.budgets?.length) doc.limits = req.budgets.map((b) => ({ name: b.name, tool: b.tool, max: b.max, per: b.per, shared: "user", ...(b.sum ? { sum: b.sum } : {}) }));
    return `# mcp-rbac per-grant overlay for ${req.name}\n${stringify(doc, { lineWidth: 0 })}`;
  }

  grant(uid: string) { return this.db.prepare("SELECT * FROM AgentGrant WHERE uid = ?").get(uid) as unknown as GrantRow | undefined; }
  grantsFor(adminUserId: number) { return this.db.prepare("SELECT g.*, b.uid AS brandUid, b.name AS brandName FROM AgentGrant g JOIN Brand b ON b.id = g.brandId WHERE grantorAdminUserId = ? ORDER BY g.id").all(adminUserId) as any[]; }

  /** Grantor, or an OWNER/ADMIN of the same brand, may revoke. Bumps the epoch (kills every token). */
  revoke(uid: string, byAdminUserId: number) {
    const g = this.grant(uid);
    if (!g) throw new AuthError("unknown_grant", 404);
    if (g.grantorAdminUserId !== byAdminUserId) {
      const am = this.activeMembership(byAdminUserId, g.brandId);
      if ("error" in am || am.m.role === "AGENT") throw new AuthError("forbidden", 403);
    }
    this.db.prepare("UPDATE AgentGrant SET status = 'REVOKED', epoch = epoch + 1, revokedAt = ?, revokedByAdminUserId = ? WHERE uid = ?").run(this.iso(), byAdminUserId, uid);
    this.db.prepare("UPDATE AgentGrantToken SET revokedAt = ? WHERE grantId = ? AND revokedAt IS NULL").run(this.iso(), g.id);
  }
  setStatus(uid: string, status: "ACTIVE" | "PAUSED") { this.db.prepare("UPDATE AgentGrant SET status = ? WHERE uid = ? AND status != 'REVOKED'").run(status, uid); }

  // ----------------------------------------------------------------- OAuth-style code + token
  issueCode(grantUid: string, codeChallenge: string, redirectUri: string, dpopJkt: string): string {
    const g = this.grant(grantUid)!;
    const code = randomBytes(24).toString("base64url");
    this.db.prepare("INSERT INTO AgentGrantAuthCode (codeHash, grantId, codeChallenge, redirectUri, dpopJkt, expiresAt) VALUES (?, ?, ?, ?, ?, ?)").run(sha256(code), g.id, codeChallenge, redirectUri, dpopJkt, this.iso(60_000));
    this.db.prepare("UPDATE AgentGrant SET dpopJkt = ? WHERE id = ?").run(dpopJkt, g.id);
    return code;
  }
  exchangeCode(code: string, verifier: string, redirectUri: string, proofJwt: string | undefined, htu: string): { access_token: string; token_type: "DPoP"; expires_in: number; grant: string } {
    const row = this.db.prepare("SELECT * FROM AgentGrantAuthCode WHERE codeHash = ?").get(sha256(code)) as any;
    if (!row) throw new AuthError("invalid_grant", 400);
    if (row.consumedAt) { // replay: kill the grant family, per OAuth BCP
      const g = this.db.prepare("SELECT uid FROM AgentGrant WHERE id = ?").get(row.grantId) as any;
      if (g) this.db.prepare("UPDATE AgentGrant SET epoch = epoch + 1 WHERE id = ?").run(row.grantId);
      throw new AuthError("invalid_grant_replayed", 400);
    }
    this.db.prepare("UPDATE AgentGrantAuthCode SET consumedAt = ? WHERE codeHash = ?").run(this.iso(), row.codeHash);
    if (Date.parse(row.expiresAt) <= this.now()) throw new AuthError("invalid_grant_expired", 400);
    if (row.redirectUri !== redirectUri) throw new AuthError("invalid_grant_redirect", 400);
    if (createHash("sha256").update(verifier).digest("base64url") !== row.codeChallenge) throw new AuthError("invalid_grant_pkce", 400);
    const p = verifyProof(proofJwt, "POST", htu, { seenJti: (j, i) => this.seenJti(j, i) });
    if (p.jkt !== row.dpopJkt) throw new AuthError("dpop_key_mismatch", 400);
    const g = this.db.prepare("SELECT * FROM AgentGrant WHERE id = ?").get(row.grantId) as unknown as GrantRow;
    return { ...this.mintToken(g.uid, p.jkt), token_type: "DPoP", grant: g.uid };
  }
  /** Mint a DPoP-bound access token (used by the code exchange; also by the staging proxy demo). */
  mintToken(grantUid: string, jkt: string): { access_token: string; expires_in: number } {
    const g = this.grant(grantUid)!;
    if (g.status !== "ACTIVE") throw new AuthError("grant_not_active", 400);
    const token = `itmag_${randomBytes(32).toString("base64url")}`;
    const exp = Math.min(this.now() + ACCESS_TOKEN_SECONDS * 1000, Date.parse(g.expiresAt));
    this.db.prepare("INSERT INTO AgentGrantToken (tokenHash, grantId, grantEpoch, jkt, expiresAt) VALUES (?, ?, ?, ?, ?)").run(sha256(token), g.id, g.epoch, jkt, new Date(exp).toISOString());
    this.db.prepare("UPDATE AgentGrant SET dpopJkt = ? WHERE id = ?").run(jkt, g.id);
    return { access_token: token, expires_in: Math.floor((exp - this.now()) / 1000) };
  }
  seenJti(jti: string, iat: number): boolean {
    this.db.prepare("DELETE FROM DpopJti WHERE iat < ?").run(Math.floor(Date.now() / 1000) - 300);
    try { this.db.prepare("INSERT INTO DpopJti (jti, iat) VALUES (?, ?)").run(jti, iat); return true; } catch { return false; }
  }

  // ----------------------------------------------------------------- authenticate every request (no caching)
  authenticate(authorization: string | undefined, dpop: string | undefined, method: string, htu: string): CallContext {
    if (!authorization) throw new AuthError("missing_token");
    const [scheme, token] = authorization.split(" ", 2);
    if (scheme?.toLowerCase() !== "dpop" || !token) throw new AuthError("token_requires_dpop");
    const t = this.db.prepare("SELECT * FROM AgentGrantToken WHERE tokenHash = ?").get(sha256(token)) as any;
    if (!t) throw new AuthError("invalid_token");
    const g = this.db.prepare("SELECT * FROM AgentGrant WHERE id = ?").get(t.grantId) as unknown as GrantRow;
    if (g.status === "REVOKED" || t.revokedAt) throw new AuthError("grant_revoked");
    if (g.status === "PAUSED") throw new AuthError("grant_paused", 403);
    if (t.grantEpoch !== g.epoch) throw new AuthError("grant_epoch_stale");
    if (Date.parse(g.expiresAt) <= this.now()) throw new AuthError("grant_expired");
    if (Date.parse(t.expiresAt) <= this.now()) throw new AuthError("token_expired");
    const p = verifyProof(dpop, method, htu, { accessToken: token, seenJti: (j, i) => this.seenJti(j, i) });
    if (p.jkt !== t.jkt) throw new AuthError("dpop_key_mismatch");
    const brand = this.db.prepare("SELECT uid FROM Brand WHERE id = ?").get(g.brandId) as { uid: string };
    const am = this.activeMembership(g.grantorAdminUserId, g.brandId);
    if ("error" in am) throw new AuthError(`grantor_${am.error}`, 403);
    if (am.m.authorizationVersion !== g.grantorAuthorizationVersion) throw new AuthError("grantor_authorization_changed", 403);
    return { grant: g, brandUid: brand.uid, human: { id: g.grantorAdminUserId, uid: am.m.adminUid, email: am.m.email }, role: am.m.role, membershipMomentUid: this.pinnedMoment(am.m), overlay: this.overlayOf(g), scopes: JSON.parse(g.scopes) };
  }

  /** tools/list for this connection: visible in the base policy as the human AND in the overlay. */
  visibleTools(ctx: CallContext, names: string[]): string[] {
    const m = this.membership(ctx.human.id, ctx.grant.brandId);
    const b = visiblePortable(this.base, this.humanIdentity(m, ctx.brandUid, ctx.scopes, ctx.grant.uid), names);
    const o = new Set(visiblePortable(ctx.overlay, this.overlayIdentity(ctx.grant, ctx.brandUid), names));
    return b.filter((n) => o.has(n));
  }

  // ----------------------------------------------------------------- authorize one call
  authorize(ctx: CallContext, tool: string, args: Record<string, unknown>, resource: Record<string, string> | null, validate?: () => string | null): Decision {
    const inputHash = sha256(canonical({ tool, args }));
    const audit = (decision: Decision["decision"], reason: string, b?: PortableDecision, o?: PortableDecision) =>
      this.audit({ brandUid: ctx.brandUid, adminUserUid: ctx.human.uid, grantUid: ctx.grant.uid, agentName: ctx.grant.name, tool, inputHash, decision, reason, baseRule: b?.rule ?? null, overlayRule: o?.rule ?? null, role: ctx.role });
    if (resource === null) { const seq = audit("deny", "resource_not_found"); return { decision: "deny", reason: "resource_not_found", auditSeq: seq }; }
    const m = this.membership(ctx.human.id, ctx.grant.brandId);
    const b = decidePortable(this.base, { identity: this.humanIdentity(m, ctx.brandUid, ctx.scopes, ctx.grant.uid), tool, args, resource, agent: ctx.grant.name });
    const o = decidePortable(ctx.overlay, { identity: this.overlayIdentity(ctx.grant, ctx.brandUid), tool, args, resource, agent: ctx.grant.name });
    if (b.decision === "deny") { const r = `base:${b.reason}`; return { decision: "deny", reason: r, base: b, overlay: o, auditSeq: audit("deny", r, b, o) }; }
    if (o.decision === "deny") { const r = `grant:${o.reason}`; return { decision: "deny", reason: r, base: b, overlay: o, auditSeq: audit("deny", r, b, o) }; }
    // Host checks that need an authorized caller first (so they can't be used as an oracle across brands).
    const v = validate?.();
    if (v) return { decision: "deny", reason: v, base: b, overlay: o, auditSeq: audit("deny", v, b, o) };
    // Spend limits (limits with a `sum` argument) are Phase 2: skipped unless the spendBudgets knob is on.
    const isSpend = (p: CompiledPolicy, i: number) => p.limits[i]?.sum !== undefined;
    const keep = (p: CompiledPolicy) => (l: { index: number }) => this.opts.spendBudgets || !isSpend(p, l.index);
    const limits = [...b.limits.filter(keep(this.base)).map((l) => ({ ...l, key: `base|${l.key}` })), ...o.limits.filter(keep(ctx.overlay)).map((l) => ({ ...l, key: `grant|${l.key}` }))];
    const at = this.now();
    for (const l of limits) {
      const used = (this.db.prepare("SELECT COALESCE(SUM(amount), 0) AS s FROM BudgetEvent WHERE key = ? AND at > ?").get(l.key, at - l.windowMs) as { s: number }).s;
      if (used + l.amount > l.max) { const r = `budget:${l.key.startsWith("base|") ? "grantor" : "agent"}:${l.name} (used ${used} + ${l.amount} > ${l.max})`; return { decision: "deny", reason: r, base: b, overlay: o, auditSeq: audit("deny", r, b, o) }; }
    }
    if (b.decision === "needs_approval" || o.decision === "needs_approval") {
      const ok = this.db.prepare("SELECT uid FROM AgentGrantApproval WHERE grantId = ? AND tool = ? AND inputHash = ? AND status = 'APPROVED' AND expiresAt > ? ORDER BY requestedAt LIMIT 1").get(ctx.grant.id, tool, inputHash, this.iso()) as any;
      if (!ok) {
        const pending = this.db.prepare("SELECT uid FROM AgentGrantApproval WHERE grantId = ? AND tool = ? AND inputHash = ? AND status = 'PENDING' AND expiresAt > ?").get(ctx.grant.id, tool, inputHash, this.iso()) as any;
        const uid = pending?.uid ?? `appr_${randomUUID()}`;
        if (!pending) this.db.prepare("INSERT INTO AgentGrantApproval (uid, grantId, tool, inputHash, summary, status, requestedAt, expiresAt) VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?)").run(uid, ctx.grant.id, tool, inputHash, JSON.stringify(args).slice(0, 500), this.iso(), this.iso(15 * 60_000));
        return { decision: "needs_approval", reason: "approval_required", approvalUid: uid, base: b, overlay: o, auditSeq: audit("needs_approval", `approval_required:${uid}`, b, o) };
      }
      this.db.prepare("UPDATE AgentGrantApproval SET status = 'CONSUMED' WHERE uid = ?").run(ok.uid);
    }
    for (const l of limits) this.db.prepare("INSERT INTO BudgetEvent (key, at, amount) VALUES (?, ?, ?)").run(l.key, at, l.amount);
    return { decision: "allow", reason: "ok", base: b, overlay: o, auditSeq: audit("allow", "ok", b, o) };
  }

  /** Approvals are decided by a human who could have made the call directly (grantor, or OWNER/ADMIN of the brand). */
  decideApproval(uid: string, byAdminUserId: number, approve: boolean) {
    const a = this.db.prepare("SELECT a.*, g.brandId, g.grantorAdminUserId FROM AgentGrantApproval a JOIN AgentGrant g ON g.id = a.grantId WHERE a.uid = ?").get(uid) as any;
    if (!a || a.status !== "PENDING") throw new AuthError("no_pending_approval", 404);
    const am = this.activeMembership(byAdminUserId, a.brandId);
    if ("error" in am || (am.m.role === "AGENT" && byAdminUserId !== a.grantorAdminUserId)) throw new AuthError("forbidden", 403);
    this.db.prepare("UPDATE AgentGrantApproval SET status = ?, decidedAt = ?, decidedByAdminUserId = ? WHERE uid = ?").run(approve ? "APPROVED" : "DENIED", this.iso(), byAdminUserId, uid);
  }
  pendingApprovals(adminUserId: number) {
    return this.db.prepare(`SELECT a.uid, a.tool, a.summary, a.requestedAt, g.name AS agent, g.uid AS grantUid FROM AgentGrantApproval a JOIN AgentGrant g ON g.id = a.grantId
      JOIN AdminUserBrand m ON m.brandId = g.brandId AND m.adminUserId = ? WHERE a.status = 'PENDING' AND (m.role != 'AGENT' OR g.grantorAdminUserId = ?)`).all(adminUserId, adminUserId) as any[];
  }

  // ----------------------------------------------------------------- audit (hash chain)
  audit(e: { brandUid: string; adminUserUid: string; grantUid: string; agentName: string; tool: string; inputHash: string; decision: string; reason: string; baseRule: string | null; overlayRule: string | null; role: string }): number {
    const prev = (this.db.prepare("SELECT hash FROM AgentActionLog ORDER BY seq DESC LIMIT 1").get() as any)?.hash ?? "0".repeat(64);
    const actChain = JSON.stringify([`admin_user:${e.adminUserUid}(${e.role})`, `agent:${e.agentName}#${e.grantUid}`]);
    const at = this.iso();
    const body = canonical({ at, brandUid: e.brandUid, adminUserUid: e.adminUserUid, grantUid: e.grantUid, agentName: e.agentName, actChain, tool: e.tool, inputHash: e.inputHash, decision: e.decision, reason: e.reason, baseRule: e.baseRule, overlayRule: e.overlayRule });
    const hash = sha256(prev + body);
    const r = this.db.prepare("INSERT INTO AgentActionLog (at, brandUid, adminUserUid, grantUid, agentName, actChain, tool, inputHash, decision, reason, baseRule, overlayRule, prevHash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(at, e.brandUid, e.adminUserUid, e.grantUid, e.agentName, actChain, e.tool, e.inputHash, e.decision, e.reason, e.baseRule, e.overlayRule, prev, hash);
    return Number(r.lastInsertRowid);
  }
  verifyAudit(): { ok: boolean; rows: number; brokenAt?: number } {
    let prev = "0".repeat(64); let n = 0;
    for (const r of this.db.prepare("SELECT * FROM AgentActionLog ORDER BY seq").all() as any[]) {
      const body = canonical({ at: r.at, brandUid: r.brandUid, adminUserUid: r.adminUserUid, grantUid: r.grantUid, agentName: r.agentName, actChain: r.actChain, tool: r.tool, inputHash: r.inputHash, decision: r.decision, reason: r.reason, baseRule: r.baseRule, overlayRule: r.overlayRule });
      if (r.prevHash !== prev || sha256(prev + body) !== r.hash) return { ok: false, rows: n, brokenAt: r.seq };
      prev = r.hash; n++;
    }
    return { ok: true, rows: n };
  }
}

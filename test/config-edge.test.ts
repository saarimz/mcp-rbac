import { describe, expect, it } from "vitest";
import { Guard } from "../src/index.js";
import { createStore, itmGuardOptions } from "../examples/itm.js";

const mk = (assignments: any[]) => {
  const store = createStore();
  return new Guard(itmGuardOptions(store, {
    resolveUser: (t) => (t === "u" ? ({ id: "u", assignments } as any) : undefined),
    loadUser: (id) => (id === "u" ? ({ id: "u", assignments } as any) : undefined),
  }));
};

describe("misconfiguration fails closed", () => {
  it("a scope key that is present but undefined/null/empty does NOT mean 'everywhere'", async () => {
    for (const venue of [undefined, null, "", 0, ["elsewhere"]]) {
      const g = mk([{ role: "manager", scope: { venue } }]);
      expect((await g.check("u", "tickets.list", { eventId: "echo-1120" })).allowed, String(venue)).toBe(false);
      expect((await g.check("u", "tickets.list", { eventId: "elsewhere-1114" })).allowed, String(venue)).toBe(false);
    }
  });

  it("role names that collide with Object.prototype don't resolve", async () => {
    for (const r of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
      const g = mk([{ role: r, scope: {} }]);
      expect((await g.check("u", "tickets.list", { eventId: "elsewhere-1114" })).allowed).toBe(false);
    }
  });

  it("garbage user records are denied, not crashed through", async () => {
    for (const a of [null, "owner", [{ role: "owner" }], [{ role: "owner", scope: null }]]) {
      const g = mk(a as any);
      const r = await g.check("u", "tickets.list", { eventId: "elsewhere-1114" }).catch(() => ({ allowed: false }));
      expect(r.allowed).toBe(false);
    }
  });

  it("multi-role user: delegation picks the assignment that actually covers the request", async () => {
    const g = mk([{ role: "door", scope: { venue: "elsewhere" } }, { role: "manager", scope: { venue: "knockdown" } }]);
    const a = await g.grant("u", { agent: "a", can: ["tickets.list"] });
    expect((await g.getGrant(a.id))!.scope).toEqual({ venue: "knockdown" });
    const b = await g.grant("u", { agent: "b", can: ["checkin"] });
    expect((await g.getGrant(b.id))!.scope).toEqual({ venue: "elsewhere" }); // first covering assignment
    const c = await g.grant("u", { agent: "c", can: ["checkin"], scope: { venue: "knockdown" } });
    expect((await g.getGrant(c.id))!.scope).toEqual({ venue: "knockdown" });
    await expect(g.grant("u", { agent: "d", can: ["tickets.list"], scope: { venue: "elsewhere" } })).rejects.toThrow();
  });

  it("a role object that isn't built with role() is refused at construction", () => {
    expect(() => new Guard({ roles: { evil: { permissions: [{ tool: "*" }] } as any }, resolveUser: () => undefined })).toThrow();
  });
});

describe("grant spec footguns from the original sketch", () => {
  it("rejects unknown keys like `until` and top-level `event` instead of silently widening the grant", async () => {
    const g = new Guard(itmGuardOptions(createStore()));
    await expect(g.grant("tok-maya", { agent: "a", can: ["checkin"], until: "2am" } as any)).rejects.toThrow(/Unknown grant option/);
    await expect(g.grant("tok-maya", { agent: "a", can: ["checkin"], event: "elsewhere-1114" } as any)).rejects.toThrow(/Unknown grant option/);
    await expect(g.grant("tok-maya", { agent: "a", can: ["checkin"], expiresAt: new Date("2am") })).rejects.toThrow(/Invalid expiry/);
  });
});

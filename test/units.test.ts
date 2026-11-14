import { describe, expect, it } from "vitest";
import { covers, isValidToolName, matches, overlaps } from "../src/patterns.js";
import { checkConstraints, narrow, validateConstraints } from "../src/constraints.js";
import { role } from "../src/index.js";

describe("tool names and patterns", () => {
  it("rejects tool-name tricks", () => {
    for (const n of ["Refund ", " refund", "refund\u200b", "ｒｅｆｕｎｄ", "tickets.*", "tickets.**", "*", "refund.", ".refund",
      "tickets..list", "tickets/list", "refund\n", "", "a".repeat(129), "rеfund" /* cyrillic e */]) {
      expect(isValidToolName(n), JSON.stringify(n)).toBe(false);
    }
    expect(isValidToolName("tickets.list")).toBe(true);
    expect(isValidToolName("Refund")).toBe(true); // valid name, but a different tool than "refund"
  });

  it("matching is exact, case-sensitive and segment-aware", () => {
    expect(matches("refund", "refund")).toBe(true);
    expect(matches("refund", "Refund")).toBe(false);
    expect(matches("tickets.*", "tickets.list")).toBe(true);
    expect(matches("tickets.*", "tickets")).toBe(false);
    expect(matches("tickets.*", "tickets.batch.create")).toBe(false);
    expect(matches("tickets.**", "tickets.batch.create")).toBe(true);
    expect(matches("tickets.*", "ticketsXlist")).toBe(false);
    expect(matches("*", "anything.at.all")).toBe(true);
    expect(matches("*.delete", "event.delete")).toBe(true);
    expect(matches("*.delete", "event.deleted")).toBe(false);
    expect(matches("tickets.*", "tickets.*")).toBe(false); // literal "*" is not a valid name
  });

  it("covers() is a sound subset check", () => {
    expect(covers("*", "tickets.*")).toBe(true);
    expect(covers("tickets.*", "tickets.list")).toBe(true);
    expect(covers("tickets.*", "tickets.*")).toBe(true);
    expect(covers("tickets.*", "*")).toBe(false);
    expect(covers("tickets.*", "tickets.**")).toBe(false);
    expect(covers("tickets.**", "tickets.*")).toBe(true);
    expect(covers("refund", "refund")).toBe(true);
    expect(covers("refund", "Refund")).toBe(false);
    expect(covers("tickets.list", "tickets.*")).toBe(false);
    expect(covers("*.delete", "event.delete")).toBe(true);
    expect(covers("event.delete", "*.delete")).toBe(false);
  });

  it("overlaps() finds shared names", () => {
    expect(overlaps("tickets.*", "*.delete")).toBe(true);
    expect(overlaps("checkin", "*.delete")).toBe(false);
    expect(overlaps("*", "refund")).toBe(true);
  });

  it("rejects bad patterns at role-build time", () => {
    expect(() => role().can("refund ")).toThrow();
    expect(() => role().can("tick*ets")).toThrow();
    expect(() => role().can("")).toThrow();
  });
});

describe("argument constraints", () => {
  const c = validateConstraints({ amount: { min: 0.01, max: 200 } });
  const deny = (v: unknown) => expect(checkConstraints(c, { amount: v }), String(v)).not.toBeNull();
  it("blocks type and range bypasses", () => {
    for (const v of ["500", "50", "0x10", 500, 200.0000001, -50, 0, -0, NaN, Infinity, -Infinity, 1e308, Number.MAX_VALUE,
      null, true, [50], { valueOf: () => 50 }, 50n]) deny(v);
    expect(checkConstraints(c, { amount: 200 })).toBeNull();
    expect(checkConstraints(c, { amount: 0.01 })).toBeNull();
  });
  it("missing or undefined fields are denied; optional allows absence", () => {
    expect(checkConstraints(c, {})).toMatch(/missing/);
    expect(checkConstraints(c, { amount: undefined })).toMatch(/missing/);
    const inherited = Object.create({ amount: 50 });
    expect(checkConstraints(c, inherited)).toMatch(/missing/); // prototype values don't count
    expect(checkConstraints(validateConstraints({ note: { maxLength: 5, optional: true } }), {})).toBeNull();
  });
  it("enum checks are strict (no case folding)", () => {
    const t = validateConstraints({ tier: { in: ["GA", "VIP"] } });
    expect(checkConstraints(t, { tier: "VIP" })).toBeNull();
    expect(checkConstraints(t, { tier: "vip" })).not.toBeNull();
    expect(checkConstraints(t, { tier: "VIP " })).not.toBeNull();
  });
  it("rejects typos and nonsense in constraint definitions", () => {
    expect(() => validateConstraints({ amount: { maxx: 200 } })).toThrow(/Unknown constraint/);
    expect(() => validateConstraints({ amount: { max: "200" } })).toThrow();
    expect(() => validateConstraints({ amount: { max: NaN } })).toThrow();
    expect(() => validateConstraints({ amount: { min: 5, max: 1 } })).toThrow();
    expect(() => validateConstraints({ amount: { in: [] } })).toThrow();
    expect(() => validateConstraints(JSON.parse('{"__proto__": {"max": 1}}'))).toThrow();
  });
  it("narrow() only tightens", () => {
    const p = validateConstraints({ amount: { min: 0.01, max: 200 } });
    expect(narrow(p, validateConstraints({ amount: { min: 0.01, max: 100 } }))).not.toBeNull();
    expect(narrow(p, validateConstraints({ amount: { max: 500 } }))).toBeNull();
    expect(narrow(p, validateConstraints({ amount: { max: 100 } }))).toBeNull(); // dropped min => looser
    expect(narrow(p, validateConstraints({ amount: { in: [10, 20] } }))).not.toBeNull();
    expect(narrow(p, validateConstraints({ amount: { in: [10, 500] } }))).toBeNull();
    expect(narrow(p, validateConstraints({ amount: { in: ["10"] } }))).toBeNull();
    expect(narrow(p, validateConstraints({ amount: { min: 0.01, max: 100, optional: true } }))).toBeNull();
    expect(narrow(p, undefined)).toEqual(p); // inherit
  });
});

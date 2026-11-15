import { describe, expect, it } from "vitest";
import { MemoryStore } from "../src/store.js";

// Regression (P8c): past 50k buckets, MemoryStore used to clear *every* counter, which reset live budgets.
describe("MemoryStore counter eviction", () => {
  const DAY = 86_400_000;
  it("a live budget survives a flood of other counters", () => {
    const s = new MemoryStore();
    const t0 = 1.7e12;
    for (let i = 0; i < 5; i++) expect(s.consume("victim|daily-spend", 1, 5, DAY, t0).ok).toBe(true);
    expect(s.consume("victim|daily-spend", 1, 5, DAY, t0).ok).toBe(false);
    for (let i = 0; i < 60_000; i++) s.consume(`caller-${i}|daily-spend`, 1, 5, DAY, t0 + i);
    expect(s.consume("victim|daily-spend", 1, 5, DAY, t0 + 60_001).ok).toBe(false); // still exhausted
    expect(s.peek("victim|daily-spend", DAY, t0 + 60_001)).toBe(5);
  });
  it("memory stays bounded when windows roll over (expired buckets are evicted)", () => {
    const s = new MemoryStore();
    let peak = 0;
    for (let i = 0; i < 300_000; i++) {
      s.consume(`caller-${i}`, 1, 10, 1_000, 1.7e12 + i * 10); // 100 new callers per 1 s window
      peak = Math.max(peak, s.counterCount());
    }
    expect(peak).toBeLessThanOrEqual(50_001);
    expect(s.counterCount()).toBeLessThan(50_001);
  });
});

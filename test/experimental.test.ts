// v0.5 scope cut: experimental features are reachable only from mcp-rbac/experimental, and `check` flags them.
import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as main from "../src/index.js";
import * as exp from "../src/experimental.js";
import { experimentalFeatures } from "../src/experimental-features.js";

const MOVED = ["orgAssignments", "permissionSets", "customRole", "actorsFromClaims", "identityChain", "mayAct", "tokenExchange",
  "TOKEN_EXCHANGE_GRANT", "toAuthZen", "fromAuthZen", "AZ_ACTION", "AuthZenEngine", "OpenFgaEngine", "CerbosEngine", "CasbinEngine", "PermitEngine"];

describe("v0.5 scope cut", () => {
  it("the default entry point does not export experimental features; mcp-rbac/experimental does", () => {
    for (const n of MOVED) {
      expect(n in main, n).toBe(false);
      expect(n in exp, n).toBe(true);
    }
    for (const n of ["loadPortablePolicy", "resolvePacks", "verifyAuditChain", "buildPreset", "protect", "Guard"]) expect(n in main, n).toBe(true);
  });
  it("experimentalFeatures names experimental policy keys and ignores stable ones", () => {
    expect(experimentalFeatures("version: 1\nroles: {a: {tools: [x]}}\nlimits:\n  - {tool: x, max: 1, per: minute}\n")).toEqual([]);
    expect(experimentalFeatures("version: 1\nroles: {}\nsemantics:\n  budgets:\n    - {class: x-merge, max: 5, per: day}\n")).toEqual([]);
    expect(experimentalFeatures("version: 1\nroles: {}\ndelegation: {unknownActors: deny}\ntenants: {accounts: {a: {}}}\n"))
      .toEqual(["tenants (org directory)", "delegation (RFC 8693 actors)"]);
    expect(experimentalFeatures('{"version":1,"roles":{},"semantics":{"budgets":[{"class":"spend","max":5,"per":"day","currency":"USD"}],"tools":{"t":{"spend":{"arg":"$.a","currency":"USD"}}}}}'))
      .toEqual(["spend budgets (semantics.budgets[].currency)", "spend declarations (semantics.tools.*.spend)"]);
  });
  it("`mcp-rbac check` prints a note for experimental keys (stderr) and still exits 0", () => {
    const d = mkdtempSync(join(tmpdir(), "exp-"));
    const f = join(d, "p.yaml");
    writeFileSync(f, "version: 1\nroles: {a: {tools: [x]}}\ndelegation: {unknownActors: deny}\n");
    const r = spawnSync("npx", ["tsx", "src/cli.ts", "check", f], { encoding: "utf8" });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("ok:");
    expect(r.stderr).toContain("note: uses experimental features (may change in a minor release): delegation (RFC 8693 actors)");
  });
});

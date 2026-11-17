import { describe, expect, it } from "vitest";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { PolicyError } from "../src/portable.js";
import { testPolicy, assertPolicy, parsePolicyTests, formatPolicyTestReport } from "../src/policy-test.js";

const VENUE = readFileSync("examples/policies/venue.yaml", "utf8");
const VENUE_TESTS = readFileSync("examples/policies/venue.test.yaml", "utf8");
const QUICKSTART = readFileSync("docs/snippets/mcp-rbac.yaml", "utf8");
const QUICKSTART_TESTS = readFileSync("docs/snippets/mcp-rbac.test.yaml", "utf8");

const cli = (args: string[], input?: string) =>
  spawnSync(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], { encoding: "utf8", input });

describe("testPolicy", () => {
  it("passes the venue example fixtures", () => {
    const r = testPolicy(VENUE, VENUE_TESTS);
    expect(r.ok, formatPolicyTestReport(r)).toBe(true);
    expect(r.failed).toBe(0);
    expect(r.passed).toBe(30);
  });

  it("passes the quickstart example fixtures", () => {
    const r = testPolicy(QUICKSTART, QUICKSTART_TESTS);
    expect(r.ok, formatPolicyTestReport(r)).toBe(true);
    expect(r.passed).toBe(9);
  });

  it("reports a deny-reason mismatch and assertPolicy throws", () => {
    const tests = `tests:\n  - name: staff cannot refund\n    as: {roles: [staff]}\n    call: {tool: refund, args: {amount: 20}}\n    expect: allow\n`;
    const r = testPolicy(QUICKSTART, tests);
    expect(r.ok).toBe(false);
    expect(r.failed).toBe(1);
    expect(r.results[0]!.actual).toBe("deny");
    expect(r.results[0]!.reason).toBe("user:no_matching_permission");
    expect(formatPolicyTestReport(r)).toMatch(/FAIL {2}staff cannot refund/);
    expect(formatPolicyTestReport(r)).toMatch(/expected allow, got deny \(reason: user:no_matching_permission\)/);
    expect(() => assertPolicy(QUICKSTART, tests)).toThrow(PolicyError);
    expect(() => assertPolicy(QUICKSTART, tests)).toThrow(/expected allow, got deny/);
  });

  it("compares visible lists as sets and reports missing/unexpected tools", () => {
    const tests = `tests:\n  - as: {roles: [staff]}\n    visible: [list_events]\n`;
    const r = testPolicy(QUICKSTART, tests);
    expect(r.ok).toBe(false);
    expect(r.results[0]!.message).toBe("visible: unexpected checkin");
  });

  it("defaults a missing identity id and accepts needs_approval as approval", () => {
    const tests = `tests:\n  - as: {roles: [owner]}\n    call: {tool: refund, args: {amount: 250}}\n    expect: needs_approval\n`;
    const r = testPolicy(QUICKSTART, tests);
    expect(r.ok, formatPolicyTestReport(r)).toBe(true);
    expect(r.results[0]!.actual).toBe("approval");
  });

  it("rejects a malformed tests file", () => {
    expect(() => parsePolicyTests("tests: [1]\n")).toThrow(/tests\[0\]: must be a map/);
    expect(() => parsePolicyTests("version: 1\n")).toThrow(/unknown key "version"/);
    expect(() => parsePolicyTests("tests:\n  - as: {roles: [staff]}\n    call: {tool: refund}\n")).toThrow(/call needs expect/);
  });
});

describe("CLI: test", () => {
  it("runs the venue fixtures and exits 0", () => {
    const r = cli(["test", "examples/policies/venue.yaml", "examples/policies/venue.test.yaml"]);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/30 passed, 0 failed\n$/);
    expect(r.stdout).toMatch(/^ok {4}door_staff can check in/m);
  });

  it("runs the quickstart fixtures and exits 0", () => {
    const r = cli(["test", "docs/snippets/mcp-rbac.yaml", "docs/snippets/mcp-rbac.test.yaml"]);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/9 passed, 0 failed\n$/);
  });

  it("exits 1 on a failure, prints the reason, and --json includes it", () => {
    const dir = mkdtempSync(join(tmpdir(), "rbac-test-"));
    writeFileSync(join(dir, "t.yaml"), "tests:\n  - name: staff cannot refund\n    as: {roles: [staff]}\n    call: {tool: refund, args: {amount: 20}}\n    expect: allow\n");
    const r = cli(["test", "docs/snippets/mcp-rbac.yaml", join(dir, "t.yaml")]);
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/FAIL {2}staff cannot refund/);
    expect(r.stdout).toMatch(/expected allow, got deny \(reason: user:no_matching_permission\)/);
    const j = cli(["test", "docs/snippets/mcp-rbac.yaml", join(dir, "t.yaml"), "--json"]);
    expect(j.status).toBe(1);
    const report = JSON.parse(j.stdout);
    expect(report.ok).toBe(false);
    expect(report.failed).toBe(1);
    expect(report.results[0].reason).toBe("user:no_matching_permission");
    expect(report.results[0].actual).toBe("deny");
  });

  it("exits 1 when usage or the policy is missing", () => {
    const r = cli(["test", "examples/policies/venue.yaml"]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/test needs <policy.yaml> <tests.yaml>/);
    const missing = cli(["test", "no-such-policy.yaml", "examples/policies/venue.test.yaml"]);
    expect(missing.status).toBe(1);
    expect(missing.stderr).toMatch(/ENOENT|no such file/i);
  });
});

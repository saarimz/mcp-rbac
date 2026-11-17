/** P13 review fixes in the grant layer: scope-less tools, the approver's argument summary. */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { loadPortablePolicy } from "../../../src/portable.ts";
import { GrantStore, approvalSummary } from "../src/grants.ts";

const BASE = loadPortablePolicy(`version: 1
roles:
  admin: {tools: ['*']}
scopes:
  required:
    list_events: [itm:events:read]
`);

describe("scope-less tools do not join every grant", () => {
  const names = ["list_events", "get_connection", "delete_brand"]; // delete_brand: no scope entry (e.g. added by mistake)
  test("only free tools (get_connection by default) ride along with a scope", () => {
    const s = new GrantStore(null as any, BASE, names);
    assert.deepEqual(s.toolsForScopes(["itm:events:read"]).sort(), ["get_connection", "list_events"]);
    assert.deepEqual(s.toolsForScopes([]), ["get_connection"]);
    assert.ok(!s.toolsForScopes(["*"]).includes("delete_brand"));
  });
  test("freeTools is configurable, and empty means nothing scope-less", () => {
    assert.deepEqual(new GrantStore(null as any, BASE, names, undefined, { freeTools: [] }).toolsForScopes(["itm:events:read"]), ["list_events"]);
  });
});

describe("the approver sees every argument", () => {
  test("padding first cannot push the meaningful values out of view", () => {
    const s = approvalSummary("send_email", { aaa_padding: "x".repeat(5000), to: "everyone@example.com", body: "Hi" });
    assert.match(s, /to="everyone@example.com"/);
    assert.match(s, /body="Hi"/);
    assert.match(s, /aaa_padding="x{100,}…\[\+\d+ chars\]/);
  });
  test("canonical key order: the same arguments always read the same", () => {
    assert.equal(approvalSummary("t", { b: 1, a: { d: 2, c: [3, { f: 1, e: 0 }] } }), approvalSummary("t", { a: { c: [3, { e: 0, f: 1 }], d: 2 }, b: 1 }));
    assert.equal(approvalSummary("t", { b: 1, a: { d: 2, c: 3 } }), 't: a={"c":3,"d":2}, b=1');
  });
  test("past the argument cap the remaining names are listed, never dropped silently", () => {
    const args = Object.fromEntries(Array.from({ length: 60 }, (_, i) => [`k${String(i).padStart(2, "0")}`, i]));
    const s = approvalSummary("t", args);
    assert.match(s, /\+10 more: k50, k51, .*k59$/);
  });
});

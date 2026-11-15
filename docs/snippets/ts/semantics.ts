// docs/snippets/ts/semantics.ts: a policy with no tool names. Roles get side-effect classes; the built-in
// GitHub pack says which class each github-mcp-server tool is in (spec/tool-semantics.md).
import { createCoreEngine } from "mcp-rbac/core";
import { resolvePacks } from "mcp-rbac";

const policy = resolvePacks(`
version: 1
roles:
  owner: {includes: [maintainer]}
  maintainer: {includes: [reviewer]}
  reviewer: {}
semantics:
  packs: [github]
  grants:
    reviewer: [read]
    maintainer: [write, send, x-merge, x-code-change]   # comment, open PRs, push, merge
    owner: [destructive, x-admin]
  rules:
    - {classes: [destructive], approve: true}
  budgets:
    - {class: x-merge, max: 5, per: day, name: merges}
`);
const engine = createCoreEngine(policy);
for (const [role, tool] of [["reviewer", "get_file_contents"], ["reviewer", "add_issue_comment"], ["maintainer", "add_issue_comment"],
  ["maintainer", "merge_pull_request"], ["maintainer", "delete_file"], ["owner", "delete_file"], ["owner", "some_new_tool"]]) {
  const d = JSON.parse(engine.decide(JSON.stringify({ tool, identity: { id: "u", roles: [role] }, args: { owner: "acme", repo: "app" } })));
  console.log(`${role} ${tool}: ${d.decision} (${d.reason}) classes=${d.semantics.classes.join("+")}`);
}
engine.free();

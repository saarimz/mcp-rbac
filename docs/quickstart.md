# Quickstart

Pick the path that matches your situation. Every code block on this page is a real file under
[`docs/snippets/`](snippets/), and `tools/docs-check.sh` runs each one and compares its output with the
`.expected` file shown below it.

| you have… | use | time |
|---|---|---|
| a server you didn't write (filesystem, GitHub, any stdio server) | [proxy mode](#1-any-server-proxy-mode-no-code) | 1 min |
| your own server in TypeScript, Python or Go | [one policy file + the core guard](#2-your-own-server-one-policy-file-three-languages) | 5 min |
| a partner's server (Klaviyo, Stripe, GitHub) and you care about *what calls do* | [tool semantics + packs](#3-govern-by-what-tools-do-classes-and-packs) | 5 min |
| several AI agents acting for one human, each limited differently | [agent grants (ITM example)](#4-several-agents-per-human-itm) | read |

Requirements: Node ≥ 22.13. Python ≥ 3.11 for the Python guard, Go ≥ 1.27 for the Go guard. Not yet published:
run from this repository (`npm ci && npm run build`; `pip install -e python`).

## 1. Any server: proxy mode (no code)

Put `mcp-rbac proxy` in front of the server's command in your MCP client config:

```bash
mcp-rbac proxy --preset read-only -- npx tsx docs/snippets/ts/notes-server.ts
```

[`notes-server.ts`](snippets/ts/notes-server.ts) is an ordinary server with `read_note`, `write_note` and
`delete_note`. This check runs the command exactly as a client would:

<!-- snippet: docs/snippets/ts/proxy-check.ts -->
```ts
// docs/snippets/ts/proxy-check.ts: runs the README proxy command exactly as a client would and lists what the agent sees.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

for (const preset of ["read-only", "no-destructive"]) {
  const t = new StdioClientTransport({
    command: "node",
    args: ["dist/cli.js", "proxy", "--preset", preset, "--db", ":memory:", "--", "npx", "tsx", "docs/snippets/ts/notes-server.ts"],
    stderr: "ignore",
  });
  const c = new Client({ name: "check", version: "0" });
  await c.connect(t);
  const names = (await c.listTools()).tools.map((x) => x.name).sort();
  const r = (await c.callTool({ name: "write_note", arguments: { name: "a", text: "b" } })) as any;
  console.log(`${preset}: tools=[${names.join(", ")}]; write_note -> ${String(r.content[0].text).replace(/ \(ref \w+\)$/, "")}`);
  await c.close();
}
```

<!-- snippet: docs/snippets/ts/proxy-check.expected -->
```text
read-only: tools=[read_note]; write_note -> Forbidden
no-destructive: tools=[read_note, write_note]; write_note -> saved
```

Presets, path and repo scoping, approvals, hosted servers (`--url`) and client config snippets: [proxy.md](proxy.md).

## 2. Your own server: one policy file, three languages

One `mcp-rbac.yaml` ([format](policy-format.md), [JSON Schema](../spec/mcp-rbac.schema.json)):

<!-- snippet: docs/snippets/policy.yaml -->
```yaml
# docs/snippets/policy.yaml: the policy used by the quickstart snippets (TS, Python, Go).
version: 1
roles:
  owner: {includes: [staff], tools: [refund]}
  staff: {tools: [list_events, checkin]}
tools:
  refund: {limits: {amount: {min: 0, max: 500}}}
approvals:
  - {tool: refund, when: {amount: {min: 100}}}
limits:
  - {tool: checkin, max: 3, per: minute}
```

### TypeScript (official SDK)

<!-- snippet: docs/snippets/ts/quickstart.ts -->
```ts
// docs/snippets/ts/quickstart.ts: guard an MCP server written with the official TypeScript SDK.
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { z } from "zod";
import { protectWithCore } from "mcp-rbac/core";

const server = new McpServer({ name: "venue", version: "1.0.0" });
const ok = (text: string) => ({ content: [{ type: "text" as const, text }] });
server.registerTool("list_events", {}, async () => ok("Friday, Saturday"));
server.registerTool("checkin", { inputSchema: { ticketId: z.string() } }, async ({ ticketId }) => ok(`checked in ${ticketId}`));
server.registerTool("refund", { inputSchema: { ticketId: z.string(), amount: z.number() } }, async ({ ticketId, amount }) => ok(`refunded ${amount} on ${ticketId}`));

// identity(extra) returns who is calling: from your OAuth/JWT layer in production (extra.authInfo).
const who = { id: "dana", roles: ["staff"] };
const { server: guarded } = await protectWithCore(server, {
  policy: readFileSync(new URL("../policy.yaml", import.meta.url), "utf8"),
  identity: () => who,
});

// connect a client (in-memory here; Streamable HTTP or stdio in production)
const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
await guarded.connect(serverSide);
const client = new Client({ name: "agent", version: "1.0.0" });
await client.connect(clientSide);

const text = async (name: string, args: Record<string, unknown> = {}) => ((await client.callTool({ name, arguments: args })) as any).content[0].text;
console.log("tools:", (await client.listTools()).tools.map((t) => t.name).join(", "));
console.log(await text("checkin", { ticketId: "t1" }));
console.log(await text("refund", { ticketId: "t1", amount: 20 }));
who.roles = ["owner"];
console.log(await text("refund", { ticketId: "t1", amount: 20 }));
console.log(await text("refund", { ticketId: "t1", amount: 250 }));
await client.close();
```

<!-- snippet: docs/snippets/ts/quickstart.expected -->
```text
tools: list_events, checkin
checked in t1
Denied: user:no_matching_permission
refunded 20 on t1
Approval required for refund
```

### Python (official SDK)

<!-- snippet: docs/snippets/py/quickstart.py -->
```python
"""docs/snippets/py/quickstart.py: guard an MCP server written with the official Python SDK (same policy as TS/Go)."""
import pathlib

import anyio
from mcp import Client
from mcp.server.mcpserver import MCPServer

from mcp_rbac.core_guard import protect_with_core

server = MCPServer("venue", version="1.0.0")


@server.tool()
def list_events() -> str:
    return "Friday, Saturday"


@server.tool()
def checkin(ticketId: str) -> str:  # noqa: N803 - MCP argument name
    return f"checked in {ticketId}"


@server.tool()
def refund(ticketId: str, amount: float) -> str:  # noqa: N803
    return f"refunded {amount:g} on {ticketId}"


# identity(ctx) returns who is calling: from your OAuth/JWT layer in production.
who = {"id": "dana", "roles": ["staff"]}
policy = (pathlib.Path(__file__).resolve().parent.parent / "policy.yaml").read_text()
protect_with_core(server, policy, identity=lambda ctx: who)


async def main() -> None:
    async with Client(server) as client:  # in-memory here; stdio or Streamable HTTP in production
        text = lambda r: r.content[0].text  # noqa: E731
        print("tools:", ", ".join(t.name for t in (await client.list_tools()).tools))
        print(text(await client.call_tool("checkin", {"ticketId": "t1"})))
        print(text(await client.call_tool("refund", {"ticketId": "t1", "amount": 20})))
        who["roles"] = ["owner"]
        print(text(await client.call_tool("refund", {"ticketId": "t1", "amount": 20})))
        print(text(await client.call_tool("refund", {"ticketId": "t1", "amount": 250})))


anyio.run(main)
```

<!-- snippet: docs/snippets/py/quickstart.expected -->
```text
tools: list_events, checkin
checked in t1
Denied: user:no_matching_permission
refunded 20 on t1
Approval required for refund
```

### Go (official go-sdk)

<!-- snippet: docs/snippets/go/main.go -->
```go
// docs/snippets/go/main.go: guard an MCP server written with the official Go SDK (same policy as TS/Python).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	mcprbac "github.com/mcp-rbac/mcp-rbac-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ticket struct {
	TicketID string  `json:"ticketId"`
	Amount   float64 `json:"amount,omitempty"`
}

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func main() {
	ctx := context.Background()
	rt, err := mcprbac.NewRuntime(ctx) // the Rust core as WASM via wazero (no cgo)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)
	policy, err := os.ReadFile("../policy.yaml")
	if err != nil {
		log.Fatal(err)
	}
	engine, err := rt.NewEngine(ctx, string(policy))
	if err != nil {
		log.Fatal(err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "venue", Version: "1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "list_events"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return text("Friday, Saturday"), nil, nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "checkin"}, func(_ context.Context, _ *mcp.CallToolRequest, a ticket) (*mcp.CallToolResult, any, error) {
		return text("checked in " + a.TicketID), nil, nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "refund"}, func(_ context.Context, _ *mcp.CallToolRequest, a ticket) (*mcp.CallToolResult, any, error) {
		return text(fmt.Sprintf("refunded %g on %s", a.Amount, a.TicketID)), nil, nil
	})

	// Identity returns who is calling: from your OAuth/JWT layer in production.
	who := map[string]any{"id": "dana", "roles": []any{"staff"}}
	engine.Protect(server, mcprbac.GuardOptions{Identity: func(context.Context, mcp.Request) any { return who }})

	ct, st := mcp.NewInMemoryTransports() // stdio or Streamable HTTP in production
	if _, err := server.Connect(ctx, st, nil); err != nil {
		log.Fatal(err)
	}
	client, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "1.0.0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	call := func(name string, args map[string]any) string {
		r, err := client.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			log.Fatal(err)
		}
		return r.Content[0].(*mcp.TextContent).Text
	}
	tools, _ := client.ListTools(ctx, nil)
	var names []string
	for _, t := range tools.Tools {
		names = append(names, t.Name)
	}
	fmt.Println("tools:", strings.Join(names, ", "))
	fmt.Println(call("checkin", map[string]any{"ticketId": "t1"}))
	fmt.Println(call("refund", map[string]any{"ticketId": "t1", "amount": 20}))
	who["roles"] = []any{"owner"}
	fmt.Println(call("refund", map[string]any{"ticketId": "t1", "amount": 20}))
	fmt.Println(call("refund", map[string]any{"ticketId": "t1", "amount": 250}))
}
```

<!-- snippet: docs/snippets/go/quickstart.expected -->
```text
tools: checkin, list_events
checked in t1
Denied: user:no_matching_permission
refunded 20 on t1
Approval required for refund
```

All three use the same Rust core (WASM in Node, PyO3 in Python, wazero in Go), so the decisions are byte-identical
([polyglot.md](polyglot.md)). Go lists tools in name order; that's the go-sdk, not the guard. Rust servers on rmcp
use `Guarded` from `core/mcp-rbac-rmcp`.

Next: real identity from OAuth/JWT ([library.md](library.md)), tenants and record ownership (`resource`), audit
([AUDIT.md](AUDIT.md)), OpenTelemetry ([otel.md](otel.md)).

## 3. Govern by what tools do: classes and packs

Name-based rules break when a server adds tools. With a `semantics` block, roles are granted side-effect classes
(`read`, `write`, `send`, `spend`, `destructive`, `external-comm`, `x-…`). Classes come from built-in packs
(Klaviyo 309 tools, GitHub 133, Stripe 15, each with cited sources), from the server's MCP `ToolAnnotations`, or
from your own entries. Unclassified tools are `unknown`, and nobody is granted that.

<!-- snippet: docs/snippets/ts/semantics.ts -->
```ts
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
```

<!-- snippet: docs/snippets/ts/semantics.expected -->
```text
reviewer get_file_contents: allow (ok) classes=read
reviewer add_issue_comment: deny (user:no_matching_permission) classes=write+send
maintainer add_issue_comment: allow (ok) classes=write+send
maintainer merge_pull_request: allow (ok) classes=write+x-merge
maintainer delete_file: deny (user:no_matching_permission) classes=write+destructive+x-code-change
owner delete_file: needs_approval (ok) classes=write+destructive+x-code-change
owner some_new_tool: deny (user:no_matching_permission) classes=unknown
```

Precedence, the pack format, and the experimental spend budgets in currency:
[spec/tool-semantics.md](../spec/tool-semantics.md). A live run of a class-only policy against Klaviyo's official
server: [LIVE-RESULTS-CLASSES.md](../examples/klaviyo-e2e/LIVE-RESULTS-CLASSES.md).

## 4. Several agents per human (ITM)

[`examples/itm-agents`](../examples/itm-agents/README.md) uses ITM's real roles (brand OWNER, ADMIN, AGENT check-in
staff). An admin connects several AI agents, each with a narrower grant: its own tools, argument limits, budgets
shared with the human, approvals, expiry and instant revocation. Every grant is always at most the granting human.

- 30 adversarial tests over real HTTP and MCP (`cd examples/itm-agents && npm test`).
- A live read-only run through mcp-rbac against ITM's **staging** MCP server, on a sandbox brand: 15/15 checks.
  Production was never touched.
- [`ADOPTION.md`](../examples/itm-agents/ADOPTION.md): how ITM's backend would ship it.

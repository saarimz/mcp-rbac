/**
 * MOCKED Klaviyo MCP server. Registers the official catalog of 309 tools and
 * returns canned results labelled as mock. Never talks to Klaviyo.
 *
 * Source: catalog/klaviyo-tools.json from
 * https://developers.klaviyo.com/en/docs/klaviyo_mcp_server_available_tools
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { loadCatalog, type CatalogTool } from "./roles.ts";

export function mockResult(tool: CatalogTool, args: Record<string, unknown>) {
  return {
    mock: true,
    warning: "MOCKED — this is not a real Klaviyo API call",
    tool: tool.name,
    category: tool.category,
    readOnly: tool.readOnly,
    args,
    data: canned(tool),
  };
}

function canned(tool: CatalogTool): unknown {
  if (tool.name === "get_account_details") {
    return {
      testAccount: true,
      organization: "mcp-rbac test",
      publicSiteKey: "UGJTx2",
      note: "Canned fixture. Live account fields come from Klaviyo only when a private API key is supplied.",
    };
  }
  if (tool.readOnly && /s$/.test(tool.name.split("_").pop() ?? "")) {
    return { data: [], note: "empty mocked list" };
  }
  return { id: `mock-${tool.name}`, note: "canned mock object" };
}

export function createMockKlaviyoServer(): McpServer {
  const catalog = loadCatalog();
  const server = new McpServer(
    { name: "klaviyo-mcp-mock", version: "0.0.0-mock" },
    { instructions: "MOCKED Klaviyo MCP. Every result is canned and labelled mock:true. No network calls are made." },
  );
  for (const tool of catalog.tools) {
    server.registerTool(
      tool.name,
      { description: `[MOCK] ${tool.description}`, inputSchema: {}, annotations: { readOnlyHint: tool.readOnly } },
      async (args) => ({
        content: [{ type: "text", text: JSON.stringify(mockResult(tool, (args ?? {}) as Record<string, unknown>)) }],
        structuredContent: mockResult(tool, (args ?? {}) as Record<string, unknown>),
      }),
    );
  }
  return server;
}

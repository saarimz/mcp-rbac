/**
 * Guarded ITM server over stdio. Stdio has no per-request auth, so the
 * caller's credential is fixed per process via MCP_GUARD_TOKEN.
 * Approvals: MCP_GUARD_AUTO_APPROVE=1 auto-approves (demo only); default denies.
 * MCP_GUARD_DB=path.db uses the shared SQLite store.
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Guard } from "../src/index.js";
import { SqliteStore } from "../src/store-sqlite.js";
import { createItmServer, createStore, itmGuardOptions } from "./itm.js";

const store = createStore();
const guard = new Guard(itmGuardOptions(store, {
  credentialFrom: () => process.env.MCP_GUARD_TOKEN,
  approver: async () => process.env.MCP_GUARD_AUTO_APPROVE === "1",
  exposeDelegateTool: true,
  store: process.env.MCP_GUARD_DB ? new SqliteStore(process.env.MCP_GUARD_DB) : undefined,
  audit: (e) => process.stderr.write(`AUDIT ${JSON.stringify(e)}\n`),
}));
const server = await guard.wrap(createItmServer(store));
await server.connect(new StdioServerTransport());

/** The UNGUARDED ITM server over stdio, used to demo `mcp-guard init` introspection. */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createItmServer, createStore } from "./itm.js";
await createItmServer(createStore()).connect(new StdioServerTransport());

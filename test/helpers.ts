import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Guard, type GuardOptions } from "../src/index.js";
import { createItmServer, createStore, itmGuardOptions, roles, type Resource, type Store } from "../examples/itm.js";

export type ItmGuard = Guard<Resource, typeof roles>;

export function setup(extra: Partial<GuardOptions<Resource, typeof roles>> = {}) {
  const store = createStore();
  const guard = new Guard(itmGuardOptions(store, extra));
  const clients: Client[] = [];
  /** A real MCP client connected over the in-memory transport; every request carries `token` as authInfo (as HTTP bearer auth would). */
  const connect = async (token: string | undefined, clientId = "test-agent") => {
    const server = await guard.wrap(createItmServer(store));
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const send = ct.send.bind(ct);
    ct.send = (msg, opts) => send(msg, { ...opts, authInfo: token === undefined ? undefined : { token, clientId, scopes: [] } });
    await server.connect(st);
    const client = new Client({ name: clientId, version: "1.0.0" });
    await client.connect(ct);
    clients.push(client);
    return client;
  };
  const close = async () => { await Promise.all(clients.map((c) => c.close())); };
  return { store, guard, connect, close };
}

export async function call(client: Client, name: string, args: Record<string, unknown> = {}) {
  const r: any = await client.callTool({ name, arguments: args });
  const text: string = r.content?.[0]?.text ?? "";
  let data: any;
  try { data = JSON.parse(text); } catch { /* not json */ }
  return { ok: !r.isError, text, data };
}

export const allowAll = async () => "allow" as const;
export type { Store };

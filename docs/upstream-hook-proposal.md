# Proposal: a request middleware hook in the MCP TypeScript SDK

## Problem

Authorization layers (mcp-rbac, gateways, audit tools) need to see and veto every request: `tools/call`, `tools/list`, `resources/read`, `prompts/get`, and so on. They also need to rewrite list results. Today the public options are:

1. **Replace handlers** with `server.setRequestHandler(...)`. This collides with `McpServer`, which installs its own handlers lazily, and registration order then decides who wins.
2. **Proxy**: put an outer `Server` in front of the real one through an in-memory transport pair and a `Client`. mcp-rbac does this, using public APIs only. It works for any server and costs about 14 µs per call in-process, but every capability has to be re-declared and every notification forwarded by hand. New protocol features (tasks, sampling/elicitation from server to client) also need explicit plumbing before they pass through.

mcp-rbac v0.1 patched private fields instead; v0.2 removed that. Since 0.5 the default for `McpServer` (SDK v1) and every
SDK v2 server is to wrap the registered handlers **in place** through `Protocol`'s private `_requestHandlers` map,
because the hop was most of the guard's CPU per call (bench/perf/README.md). That is fast but depends on a private
field in both SDK versions; this hook would make it public.

## Proposal

```ts
type Middleware = (
  req: JSONRPCRequest,
  extra: RequestHandlerExtra,
  next: () => Promise<Result>,
) => Promise<Result>;

protocol.use(middleware: Middleware): () => void;   // returns an unsubscribe
```

- **Ordering.** Middlewares run in registration order, before handler lookup, for requests in both directions. A guard can therefore also see server→client `sampling/createMessage` and `elicitation/create`.
- **Denial.** Throwing an `McpError` short-circuits the request. A middleware can also return its own result, for example a filtered `tools/list`.
- **Context.** `extra` carries `authInfo`, `sessionId`, `requestId` and `signal`, as today.
- **Notifications.** An equivalent `useNotification` hook covers them.
- **Compatibility.** The change is additive; no existing behaviour changes.

## What it would let mcp-rbac drop

- The in-memory proxy hop, for in-process use. The stdio/HTTP proxy for third-party servers stays.
- Capability mirroring and manual notification forwarding.
- The "register all capability kinds before wrap" caveat.

## Status

Draft. Not filed upstream; anything shared outside needs the owner's approval first.

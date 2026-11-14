/**
 * Remote (hosted) MCP servers for `mcp-rbac proxy --url`: Streamable HTTP with legacy SSE fallback,
 * static headers from the environment, the MCP OAuth client flow (RFC 9728 discovery, PKCE,
 * dynamic client registration, loopback redirect, refresh) and reconnects.
 *
 * Secrets (header values, tokens, client secrets) live only in this process and in a 0600 file under
 * the state dir. They are never logged, never put in audit records and never sent to the MCP client.
 */
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer, type Server as HttpServer } from "node:http";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport, StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import {
  UnauthorizedError, discoverAuthorizationServerMetadata, discoverOAuthProtectedResourceMetadata,
  type OAuthClientProvider, type OAuthDiscoveryState,
} from "@modelcontextprotocol/sdk/client/auth.js";
import type { OAuthClientInformationMixed, OAuthClientMetadata, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

type Log = (s: string) => void;

// ------------------------------------------------------------------ headers

const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/**
 * Parse `--header 'Name: value'` specs. `$VAR` / `${VAR}` in values are expanded from `env`, so a
 * token can come from the environment instead of the command line. Errors never include values.
 */
export function parseHeaders(specs: readonly string[], env: Record<string, string | undefined> = process.env): Record<string, string> {
  const out: Record<string, string> = {};
  for (const spec of specs) {
    const i = spec.indexOf(":");
    if (i <= 0) throw new Error(`--header must look like "Name: value" (got a spec without a colon)`);
    const name = spec.slice(0, i).trim();
    if (!HEADER_NAME.test(name)) throw new Error(`--header: invalid header name "${name.slice(0, 40)}"`);
    const raw = spec.slice(i + 1).trim();
    const value = raw.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (_m, a: string | undefined, b: string | undefined) => {
      const v = env[(a ?? b)!];
      if (v === undefined || v === "") throw new Error(`--header ${name}: environment variable ${(a ?? b)!} is not set`);
      return v;
    });
    if (/[\r\n\0]/.test(value)) throw new Error(`--header ${name}: value contains a line break`);
    if (["host", "content-length", "mcp-session-id", "mcp-protocol-version"].includes(name.toLowerCase())) throw new Error(`--header ${name} is managed by the proxy`);
    out[name] = value;
  }
  return out;
}

/** For logs: header names only. */
export const describeHeaders = (h: Record<string, string>) => Object.keys(h).map((k) => `${k}: <redacted>`).join(", ");

// ------------------------------------------------------------------ OAuth

export interface OAuthOptions {
  /** Where credentials are stored (0700 dir, 0600 files). Default <state dir>/oauth. */
  dir: string;
  /** Loopback port for the redirect (default 33418). Must stay stable: it is part of the registered client. */
  port?: number;
  /** "browser" (default) opens the system browser; "none" only prints the URL; or a function (tests). */
  open?: "browser" | "none" | ((url: URL) => void | Promise<void>);
  scope?: string;
  /** Pre-registered client (for authorization servers without dynamic client registration). */
  clientId?: string;
  clientSecret?: string;
  /** How long to wait for the user to finish in the browser (default 5 min). */
  authTimeoutMs?: number;
  log?: Log;
}

interface StoredCreds {
  serverUrl: string;
  client?: OAuthClientInformationMixed;
  tokens?: OAuthTokens;
  discovery?: OAuthDiscoveryState;
  savedAt?: string;
}

export const DEFAULT_OAUTH_PORT = 33418;

export function credentialFile(dir: string, serverUrl: string) {
  return join(dir, `${createHash("sha256").update(new URL(serverUrl).href).digest("hex").slice(0, 24)}.json`);
}

/** Write a file only the current user can read, atomically. */
function writePrivate(file: string, data: string, dir: string) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { chmodSync(dir, 0o700); } catch { /* not ours */ }
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  writeFileSync(tmp, data, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, file);
}

export function openInBrowser(url: string) {
  const [cmd, args] = process.platform === "darwin" ? ["open", [url]] : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]] : ["xdg-open", [url]];
  try {
    const p = spawn(cmd, args as string[], { stdio: "ignore", detached: true });
    p.on("error", () => {});
    p.unref();
  } catch { /* printed URL is the fallback */ }
}

/**
 * File-backed OAuthClientProvider: the SDK does discovery, PKCE, registration, code exchange and
 * refresh; this class stores the results and runs the loopback redirect listener.
 */
export class FileOAuthProvider implements OAuthClientProvider {
  readonly file: string;
  private verifier?: string;
  private expectedState?: string;
  private listener?: HttpServer;
  private waiting?: { resolve: (code: string) => void; reject: (e: Error) => void; promise: Promise<string> };
  private readonly port: number;
  private readonly log: Log;

  constructor(readonly serverUrl: string, private readonly o: OAuthOptions) {
    this.file = credentialFile(o.dir, serverUrl);
    this.port = o.port ?? DEFAULT_OAUTH_PORT;
    this.log = o.log ?? (() => {});
  }

  get redirectUrl() { return `http://127.0.0.1:${this.port}/callback`; }

  get clientMetadata(): OAuthClientMetadata {
    return {
      client_name: "mcp-rbac proxy",
      redirect_uris: [this.redirectUrl],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: this.o.clientSecret ? "client_secret_post" : "none",
      ...(this.o.scope ? { scope: this.o.scope } : {}),
    };
  }

  private cache?: { mtime: number; data: StoredCreds };
  private read(): StoredCreds {
    const empty = { serverUrl: new URL(this.serverUrl).href };
    let mtime: number;
    try { mtime = statSync(this.file).mtimeMs; } catch { this.cache = undefined; return empty; }
    if (this.cache?.mtime === mtime) return this.cache.data;
    try {
      const s = JSON.parse(readFileSync(this.file, "utf8")) as StoredCreds;
      const data = s.serverUrl === empty.serverUrl ? s : empty;
      this.cache = { mtime, data };
      return data;
    } catch { return empty; }
  }
  private write(patch: Partial<StoredCreds>) {
    const next = { ...this.read(), ...patch, savedAt: new Date().toISOString() };
    for (const k of Object.keys(patch) as (keyof StoredCreds)[]) if (patch[k] === undefined) delete next[k];
    writePrivate(this.file, JSON.stringify(next, null, 2), this.o.dir);
    this.cache = undefined;
  }

  state() { this.expectedState = randomBytes(24).toString("base64url"); return this.expectedState; }

  clientInformation(): OAuthClientInformationMixed | undefined {
    if (this.o.clientId) return { client_id: this.o.clientId, ...(this.o.clientSecret ? { client_secret: this.o.clientSecret } : {}) };
    const c = this.read().client as (OAuthClientInformationMixed & { redirect_uris?: string[] }) | undefined;
    // Registered for a different redirect (port changed)? Register again.
    if (c && Array.isArray(c.redirect_uris) && !c.redirect_uris.includes(this.redirectUrl)) return undefined;
    return c;
  }
  get saveClientInformation() {
    // Pre-registered clients must not be replaced by dynamic registration.
    return this.o.clientId ? undefined : (info: OAuthClientInformationMixed) => this.write({ client: info });
  }
  tokens() { return this.read().tokens; }
  saveTokens(tokens: OAuthTokens) { this.write({ tokens }); }
  discoveryState() { return this.read().discovery; }
  saveDiscoveryState(s: OAuthDiscoveryState) { this.write({ discovery: s }); }
  saveCodeVerifier(v: string) { this.verifier = v; }
  codeVerifier() {
    if (!this.verifier) throw new Error("No PKCE verifier for this authorization");
    return this.verifier;
  }
  invalidateCredentials(scope: "all" | "client" | "tokens" | "verifier" | "discovery") {
    if (scope === "verifier") { this.verifier = undefined; return; }
    if (scope === "all") { this.write({ client: undefined, tokens: undefined, discovery: undefined }); return; }
    this.write({ [scope === "client" ? "client" : scope === "tokens" ? "tokens" : "discovery"]: undefined });
  }

  /** Current secret values (for scrubbing output); never logged. */
  secretValues(): string[] {
    const s = this.read();
    return [s.tokens?.access_token, s.tokens?.refresh_token, (s.client as { client_secret?: string } | undefined)?.client_secret, this.o.clientSecret].filter((x): x is string => typeof x === "string" && x.length >= 8);
  }

  /** True if there is anything stored for this server. */
  hasTokens() { return !!this.read().tokens; }
  logout() { rmSync(this.file, { force: true }); this.cache = undefined; }

  async redirectToAuthorization(url: URL) {
    await this.listen();
    this.log(`authorization needed for ${new URL(this.serverUrl).origin}. Open this URL to sign in:\n    ${url.href}`);
    const how = this.o.open ?? (process.env.MCP_RBAC_NO_BROWSER ? "none" : "browser");
    if (typeof how === "function") await how(url);
    else if (how === "browser") openInBrowser(url.href);
  }

  /** Resolves with the authorization code once the browser hits the loopback redirect. */
  waitForCode(): Promise<string> {
    if (!this.waiting) throw new Error("No authorization in progress");
    return this.waiting.promise;
  }

  private async listen() {
    if (this.listener) return;
    let resolve!: (c: string) => void, reject!: (e: Error) => void;
    const promise = new Promise<string>((a, b) => { resolve = a; reject = b; });
    promise.catch(() => {});
    this.waiting = { resolve, reject, promise };
    const timer = setTimeout(() => { reject(new Error("Timed out waiting for browser authorization")); void this.closeListener(true); }, this.o.authTimeoutMs ?? 300_000);
    timer.unref();
    const page = (title: string, body: string) => `<!doctype html><meta charset="utf-8"><title>${title}</title><body style="font:16px system-ui;margin:3em"><h2>${title}</h2><p>${body}</p></body>`;
    this.listener = createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://127.0.0.1");
      if (u.pathname !== "/callback") { res.writeHead(404).end(); return; }
      const code = u.searchParams.get("code"), state = u.searchParams.get("state"), error = u.searchParams.get("error");
      if (!this.expectedState || state !== this.expectedState) {
        res.writeHead(400, { "content-type": "text/html" }).end(page("mcp-rbac: authorization rejected", "State mismatch. Start again from the proxy."));
        return; // keep waiting: a forged callback must not end the flow
      }
      clearTimeout(timer);
      if (error || !code) {
        res.writeHead(400, { "content-type": "text/html", connection: "close" }).end(page("mcp-rbac: authorization failed", "The server did not grant access. You can close this tab."), () => void this.closeListener());
        reject(new Error(`Authorization failed: ${String(error ?? "no code").slice(0, 100)}`));
      } else {
        res.writeHead(200, { "content-type": "text/html", connection: "close" }).end(page("mcp-rbac: signed in", "You can close this tab and return to your MCP client."), () => void this.closeListener());
        resolve(code);
      }
    });
    await new Promise<void>((ok, fail) => {
      this.listener!.once("error", (e: NodeJS.ErrnoException) => fail(new Error(e.code === "EADDRINUSE" ? `OAuth callback port ${this.port} is in use (pick another with --oauth-port)` : e.message)));
      this.listener!.listen(this.port, "127.0.0.1", () => ok());
    });
  }

  private async closeListener(force = false) {
    const l = this.listener;
    this.listener = undefined;
    this.expectedState = undefined;
    if (l) await new Promise<void>((r) => { l.close(() => r()); if (force) l.closeAllConnections(); else l.closeIdleConnections(); });
  }

  async dispose() { this.waiting?.reject(new Error("closed")); await this.closeListener(true); }
}

/** Read-only discovery: what does this server say about its authorization? Never registers anything. */
export async function discoverAuth(serverUrl: string, fetchFn: typeof fetch = fetch) {
  const probe = await fetchFn(serverUrl, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "mcp-rbac-discovery", version: "0.3.0" } } }),
  });
  const status = probe.status;
  const wwwAuthenticate = probe.headers.get("www-authenticate") ?? undefined;
  await probe.body?.cancel().catch(() => {});
  let resource: Awaited<ReturnType<typeof discoverOAuthProtectedResourceMetadata>> | undefined;
  let resourceError: string | undefined;
  const rm = /resource_metadata="([^"]+)"/.exec(wwwAuthenticate ?? "")?.[1];
  try { resource = await discoverOAuthProtectedResourceMetadata(serverUrl, rm ? { resourceMetadataUrl: new URL(rm) } : undefined, fetchFn); } catch (e) { resourceError = (e as Error).message.slice(0, 200); }
  const asUrl = resource?.authorization_servers?.[0] ?? (status === 401 ? new URL("/", serverUrl).href : undefined);
  let authServer: Awaited<ReturnType<typeof discoverAuthorizationServerMetadata>> | undefined;
  if (asUrl) { try { authServer = await discoverAuthorizationServerMetadata(asUrl, { fetchFn }); } catch { /* none */ } }
  return {
    status, requiresAuth: status === 401 || status === 403, wwwAuthenticate, resourceMetadataUrl: rm, resource, resourceError,
    authorizationServer: asUrl,
    authServerMetadata: authServer && {
      issuer: authServer.issuer, authorization_endpoint: authServer.authorization_endpoint, token_endpoint: authServer.token_endpoint,
      registration_endpoint: authServer.registration_endpoint, code_challenge_methods_supported: authServer.code_challenge_methods_supported,
      scopes_supported: authServer.scopes_supported,
    },
  };
}

// ------------------------------------------------------------------ upstream connection

export interface RemoteOptions {
  url: string;
  headers?: Record<string, string>;
  /** auto (default): Streamable HTTP, falling back to legacy SSE if the endpoint rejects it. */
  transport?: "auto" | "http" | "sse";
  /** OAuth settings, or false to never attempt OAuth (a 401 then fails with discovery info). */
  oauth?: OAuthOptions | false;
  connectTimeoutMs?: number;
  /** Reconnect attempts after the upstream drops (default 8, exponential backoff up to 30 s). */
  maxReconnects?: number;
  log?: Log;
  /** For tests. */
  fetch?: typeof fetch;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Keeps one MCP Client connected to a hosted server across session expiry and drops. */
export class RemoteUpstream {
  readonly client = new Client({ name: "mcp-rbac-proxy", version: "0.3.0" });
  readonly provider?: FileOAuthProvider;
  kind: "http" | "sse" | undefined;
  private transport?: Transport;
  private stopped = false;
  private closingOnPurpose = false;
  /** True between a successful connect and the next drop: only then does a close mean "reconnect". */
  private live = false;
  private reconnecting?: Promise<void>;
  private readonly log: Log;
  /** Called after every successful reconnect (re-plan, notify the client). */
  onReconnect?: () => Promise<void> | void;
  /** Called when reconnecting gave up. */
  onGiveUp?: (e: Error) => void;

  constructor(private readonly o: RemoteOptions) {
    const u = new URL(o.url);
    if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("--url must be http(s)");
    if (u.protocol === "http:" && !["127.0.0.1", "localhost", "[::1]"].includes(u.hostname)) {
      (o.log ?? (() => {}))(`warning: ${u.origin} is plain http; credentials would travel unencrypted`);
    }
    this.log = o.log ?? (() => {});
    if (o.oauth) this.provider = new FileOAuthProvider(o.url, { ...o.oauth, log: o.oauth.log ?? this.log });
    // A 404 on a request that carried our session id means the server never processed it (the session
    // is gone), so retrying once on a fresh session is safe even for writes.
    const request = this.client.request.bind(this.client) as (...a: unknown[]) => Promise<unknown>;
    (this.client as unknown as { request: (...a: unknown[]) => Promise<unknown> }).request = async (...a: unknown[]) => {
      try { return await request(...a); } catch (e) {
        if (!(e instanceof StreamableHTTPError && e.code === 404) || this.stopped) throw e;
        await this.reconnect("session expired");
        return request(...a);
      }
    };
    this.client.onclose = () => {
      const wasLive = this.live;
      this.live = false;
      if (this.stopped || this.closingOnPurpose || !wasLive) return;
      void this.reconnect("connection closed");
    };
  }

  get sessionId() { return (this.transport as StreamableHTTPClientTransport | undefined)?.sessionId; }

  /** fetch wrapper: notices an expired session (404 on a request that carried a session id). */
  private fetchFn: typeof fetch = async (input, init) => {
    const res = await (this.o.fetch ?? fetch)(input, init);
    const h = new Headers(init?.headers);
    const sid = h.get("mcp-session-id");
    if (res.status === 404 && sid && !this.stopped && this.live) {
      // Requests are retried by the request wrapper; this catches 404s on notifications or the GET stream.
      setTimeout(() => { if (this.sessionId === sid && !this.reconnecting) void this.reconnect("session expired"); }, 250).unref();
    }
    return res;
  };

  private make(kind: "http" | "sse"): Transport {
    const requestInit: RequestInit = { headers: { ...(this.o.headers ?? {}) } };
    const authProvider = this.provider;
    if (kind === "http") return new StreamableHTTPClientTransport(new URL(this.o.url), { requestInit, authProvider, fetch: this.fetchFn });
    // Legacy SSE: headers go on both the event stream and POSTs.
    return new SSEClientTransport(new URL(this.o.url), {
      requestInit, authProvider, fetch: this.fetchFn,
      eventSourceInit: { fetch: (u, i) => this.fetchFn(u, { ...i, headers: { ...Object.fromEntries(new Headers(i?.headers)), ...(this.o.headers ?? {}) } }) },
    });
  }

  private async connectKind(kind: "http" | "sse", interactive: boolean) {
    this.live = false;
    const withTimeout = <T>(p: Promise<T>) => {
      const ms = this.o.connectTimeoutMs ?? 30_000;
      let t: NodeJS.Timeout;
      return Promise.race([p, new Promise<never>((_, rej) => { t = setTimeout(() => rej(new Error(`Timed out connecting to ${new URL(this.o.url).origin} after ${ms} ms`)), ms); })]).finally(() => clearTimeout(t));
    };
    let t = this.make(kind);
    try {
      await withTimeout(this.client.connect(t));
    } catch (e) {
      if (!(e instanceof UnauthorizedError) || !this.provider) throw e;
      if (!interactive) throw new Error("Upstream needs a new sign-in; run: mcp-rbac login --url " + this.o.url);
      const code = await this.provider.waitForCode();
      await (t as StreamableHTTPClientTransport | SSEClientTransport).finishAuth(code);
      this.log("signed in; credentials stored in " + this.provider.file);
      t = this.make(kind);
      await withTimeout(this.client.connect(t));
    }
    this.transport = t;
    this.kind = kind;
    this.live = true;
  }

  async connect(interactive = true) {
    const pref = this.o.transport ?? "auto";
    if (pref !== "auto") return this.connectKind(pref, interactive);
    try {
      await this.connectKind("http", interactive);
    } catch (e) {
      // Spec back-compat: a 4xx on the initialize POST (other than auth) means "try the old HTTP+SSE transport".
      const code = e instanceof StreamableHTTPError ? e.code : undefined;
      if (code === undefined || ![400, 404, 405].includes(code)) throw await this.explain(e as Error);
      this.log(`Streamable HTTP rejected (${code}); trying legacy SSE`);
      try { await this.connectKind("sse", interactive); } catch { throw await this.explain(e as Error); }
    }
  }

  /** Turn a bare 401 into something actionable, using read-only discovery. */
  private async explain(e: Error): Promise<Error> {
    const code = e instanceof StreamableHTTPError ? e.code : undefined;
    if (code !== 401 && code !== 403) return e;
    try {
      const d = await discoverAuth(this.o.url, this.o.fetch ?? fetch);
      const dcr = !!d.authServerMetadata?.registration_endpoint;
      const as = d.authorizationServer ? ` (authorization server ${d.authorizationServer}${dcr ? ", supports dynamic registration" : ", no dynamic registration"})` : "";
      const hint = this.provider
        ? "Sign-in did not complete."
        : dcr ? "Run without --no-oauth (or `mcp-rbac login --url ...`) to sign in, or pass --header 'Authorization: Bearer $TOKEN'."
          : "Pass --oauth-client-id/--oauth-client-secret for a client you registered with it, or --header 'Authorization: Bearer $TOKEN'.";
      return new Error(`${new URL(this.o.url).origin} requires authorization${as}. ${hint}`);
    } catch { return e; }
  }

  reconnect(reason: string): Promise<void> {
    if (this.stopped) return Promise.resolve();
    if (this.reconnecting) return this.reconnecting;
    this.reconnecting = (async () => {
      this.log(`upstream ${reason}; reconnecting`);
      this.closingOnPurpose = true;
      try { await this.client.close(); } catch { /* already closed */ }
      this.closingOnPurpose = false;
      const max = this.o.maxReconnects ?? 8;
      for (let i = 0; !this.stopped; i++) {
        try {
          await this.connect(true);
          this.log(`reconnected (${this.kind}${this.sessionId ? ", new session" : ""})`);
          try { await this.onReconnect?.(); } catch { /* best effort */ }
          return;
        } catch (e) {
          if (i + 1 >= max) { this.log(`giving up: ${(e as Error).message}`); this.onGiveUp?.(e as Error); return; }
          await sleep(Math.min(30_000, 250 * 2 ** i));
        }
      }
    })().finally(() => { this.reconnecting = undefined; });
    return this.reconnecting;
  }

  /** Every secret this upstream holds (header values, tokens), for scrubbing what reaches the agent. */
  secretValues(): string[] {
    const fromHeaders = Object.values(this.o.headers ?? {}).flatMap((v) => [v, v.replace(/^(Bearer|Basic|token)\s+/i, "")]);
    return [...new Set([...fromHeaders, ...(this.provider?.secretValues() ?? [])].filter((v) => v.length >= 8))];
  }

  async close() {
    this.stopped = true;
    try { await (this.transport as StreamableHTTPClientTransport | undefined)?.terminateSession?.(); } catch { /* optional */ }
    try { await this.client.close(); } catch { /* ignore */ }
    await this.provider?.dispose();
  }
}

/** `mcp-rbac login`: run the browser flow now so the proxy starts without blocking the MCP client. */
export async function login(o: RemoteOptions & { oauth: OAuthOptions }) {
  const up = new RemoteUpstream(o);
  try {
    await up.connect(true);
    const v = up.client.getServerVersion();
    return { server: v ? `${v.name}@${v.version}` : "unknown", file: up.provider!.file, authorized: up.provider!.hasTokens() };
  } finally { await up.close(); }
}

export const hasStoredCredentials = (dir: string, url: string) => existsSync(credentialFile(dir, url));

/**
 * Wrap the downstream (agent-facing) transport so no message can carry a credential we hold, even if a
 * hostile or buggy upstream echoes its Authorization header back in a tool result or error.
 */
export function scrubSecrets(t: Transport, secrets: () => string[]): Transport {
  const send = t.send.bind(t);
  t.send = (message, options) => {
    const list = secrets();
    if (!list.length) return send(message, options);
    let text = JSON.stringify(message);
    let hit = false;
    for (const s of list) {
      for (const form of [s, JSON.stringify(s).slice(1, -1)]) {
        if (text.includes(form)) { text = text.split(form).join("[redacted by mcp-rbac]"); hit = true; }
      }
    }
    return send(hit ? JSON.parse(text) : message, options);
  };
  return t;
}

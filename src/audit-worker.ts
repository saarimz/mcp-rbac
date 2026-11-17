/**
 * Off-thread decision audit (P11 perf): the same hash-chained SQLite sink as `SqliteAuditSink` (batched group commit),
 * but the chain hashing, canonical JSON and the SQLite commit run on a worker thread, so the request path only does
 * an array push. Records reach the worker in small batches (one postMessage per event-loop turn or per 256 records).
 *
 *   const sink = new WorkerAuditSink("audit.db");           // same table layout and chain as SqliteAuditSink
 *   protectWithCore(server, { ..., onDecision: (e) => sink.write(auditRecordFromDecision(e)) });
 *
 * Semantics vs `batched`: identical chain and table (verifyAuditTable / audit-verify work unchanged). On a hard crash
 * you can lose the records not yet committed by the worker (at most one batch interval plus one in-flight message).
 * `flush()` / `close()` / process exit / SIGINT / SIGTERM are synchronous: the caller blocks (Atomics.wait) until the
 * worker has committed everything sent so far.
 */
import { isMainThread, MessageChannel, receiveMessageOnPort, Worker, workerData, parentPort, type MessagePort } from "node:worker_threads";
import { resolve as resolvePath } from "node:path";
import { SqliteAuditSink, type AuditRecord, type AuditSinkOptions, type AuditSinkStats } from "./audit-sink.js";

type Msg = { t: "w"; rs: AuditRecord[] } | { t: "f" | "c"; sab: SharedArrayBuffer; port: MessagePort };
/** Worker -> main: a commit failed ({e}) or recovered ({ok}). */
type Note = { e: string } | { ok: true };
interface Reply { stats: AuditSinkStats; head: string }

export class WorkerAuditSink {
  private w: Worker;
  private buf: AuditRecord[] = [];
  private scheduled = false;
  private closed = false;
  private last: Reply = { stats: { written: 0, dropped: 0, queued: 0, batches: 0, maxQueued: 0, errors: 0 }, head: "" };
  private err: string | undefined;
  private dead = false;
  private readonly onError: (err: unknown) => void;
  private readonly onExit = () => { this.flush(); };
  private readonly onSignal = (sig: NodeJS.Signals) => {
    this.flush();
    process.off(sig, this.onSignal);
    if (process.listenerCount(sig) === 0) process.kill(process.pid, sig);
  };

  constructor(path: string, opts: Omit<AuditSinkOptions, "mode"> = {}) {
    const { shutdownHooks, onError, ...rest } = opts;
    this.onError = onError ?? ((e) => process.stderr.write(`mcp-rbac audit: ${String(e)}\n`));
    // the worker loads this same module; from TypeScript sources (tests, tsx) it registers tsx first
    const self = import.meta.url;
    // boot handshake: the worker sets ready[0] = 1 once the sink is open, 2 if it failed (bad path, no TS loader, ...)
    const ready = new SharedArrayBuffer(4);
    const boot = `const { workerData } = require("node:worker_threads");
const fail = (e) => { process.stderr.write("mcp-rbac audit worker failed to start: " + (e && e.stack || e) + "\\n");
  const a = new Int32Array(workerData.ready); Atomics.store(a, 0, 2); Atomics.notify(a, 0); process.exit(1); };
(async () => { if (workerData.self.endsWith(".ts")) (await import("tsx/esm/api")).register(); await import(workerData.self); })().catch(fail);`;
    this.w = new Worker(boot, { eval: true, workerData: { mcpRbacAuditWorker: true, self, path, ready, opts: { ...rest, mode: "batched", shutdownHooks: false } } });
    // a dead worker is never silent: writes throw, healthy() is false, onError hears about it
    this.w.on("exit", (code) => { if (!this.closed) this.die(`audit worker exited with code ${code}`); });
    this.w.on("error", (e) => this.die(`audit worker: ${String(e)}`));
    this.w.on("message", (n: Note) => {
      if ("e" in n) { this.err = n.e; this.onError(new Error(n.e)); } else this.err = undefined;
    });
    this.w.unref();
    process.on("exit", this.onExit);
    if (shutdownHooks ?? true) for (const sig of ["SIGINT", "SIGTERM"] as const) process.on(sig, this.onSignal);
    const st = Atomics.wait(new Int32Array(ready), 0, 0, 30_000);
    if (st === "timed-out" || Atomics.load(new Int32Array(ready), 0) !== 1) {
      this.closed = true;
      process.off("exit", this.onExit);
      for (const sig of ["SIGINT", "SIGTERM"] as const) process.off(sig, this.onSignal);
      void this.w.terminate();
      throw new Error(st === "timed-out" ? "mcp-rbac audit worker did not start within 30 s" : `mcp-rbac audit worker failed to start (${path})`);
    }
    this.sync("f"); // open + schema created before the first write returns (fail fast on a bad path)
  }

  private die(why: string): void {
    if (this.dead) return;
    this.dead = true;
    this.err = why;
    if (this.buf.length) { this.last.stats.dropped += this.buf.length; this.buf = []; }
    this.onError(new Error(`mcp-rbac ${why}; audit records are no longer written`));
  }

  /** False after a failed commit (until the next good one) or once the worker died. */
  healthy(): boolean { return !this.closed && !this.dead && this.err === undefined; }
  lastError(): string | undefined { return this.closed ? "closed" : this.err; }

  write(r: AuditRecord): void {
    if (this.closed) throw new Error("audit sink is closed");
    if (this.dead) { this.last.stats.dropped++; throw new Error(`mcp-rbac: ${this.err}`); }
    this.buf.push(r);
    if (this.buf.length >= 256) this.send();
    else if (!this.scheduled) { this.scheduled = true; setImmediate(() => this.send()); }
  }

  private send(): void {
    this.scheduled = false;
    if (!this.buf.length || this.dead) return;
    this.w.postMessage({ t: "w", rs: this.buf } satisfies Msg);
    this.buf = [];
  }

  private sync(t: "f" | "c"): Reply {
    if (this.dead) throw new Error(`mcp-rbac: ${this.err}`);
    this.send();
    const sab = new SharedArrayBuffer(4);
    const { port1, port2 } = new MessageChannel();
    this.w.postMessage({ t, sab, port: port2 } satisfies Msg, [port2]);
    if (Atomics.wait(new Int32Array(sab), 0, 0, 30_000) === "timed-out") throw new Error("mcp-rbac audit worker did not answer within 30 s");
    const m = receiveMessageOnPort(port1);
    port1.close();
    if (!m) throw new Error("mcp-rbac audit worker: no reply");
    if ((m.message as { error?: string }).error) throw new Error(`mcp-rbac audit worker: ${(m.message as { error: string }).error}`);
    this.last = m.message as Reply;
    return this.last;
  }

  /** Block until everything written so far is committed. */
  flush(): void { if (!this.closed && !this.dead) this.sync("f"); }
  /** Stats as of the last flush (call flush() first for current numbers). */
  stats(): AuditSinkStats { return { ...this.last.stats, queued: this.buf.length }; }
  headHash(): string { return this.sync("f").head; }

  close(): void {
    if (this.closed) return;
    if (!this.dead) this.sync("c");
    this.closed = true;
    process.off("exit", this.onExit);
    for (const sig of ["SIGINT", "SIGTERM"] as const) process.off(sig, this.onSignal);
    void this.w.terminate();
  }
}

if (!isMainThread && (workerData as { mcpRbacAuditWorker?: boolean } | null)?.mcpRbacAuditWorker) {
  const { path, opts, ready } = workerData as { path: string; opts: AuditSinkOptions; ready: SharedArrayBuffer };
  let failing = false;
  const sink = new SqliteAuditSink(path, { ...opts, onError: (e) => { failing = true; parentPort!.postMessage({ e: String(e) } satisfies Note); } });
  const recovered = () => { if (failing && sink.healthy()) { failing = false; parentPort!.postMessage({ ok: true } satisfies Note); } };
  { const a = new Int32Array(ready); Atomics.store(a, 0, 1); Atomics.notify(a, 0); }
  parentPort!.on("message", (m: Msg) => {
    if (m.t === "w") { for (const r of m.rs) sink.write(r); recovered(); return; }
    try {
      sink.flush();
      recovered();
      m.port.postMessage({ stats: sink.stats(), head: sink.headHash() } satisfies Reply);
      if (m.t === "c") sink.close();
    } catch (e) { m.port.postMessage({ error: String(e) }); }
    m.port.close();
    const a = new Int32Array(m.sab);
    Atomics.store(a, 0, 1);
    Atomics.notify(a, 0);
  });
}

/** An audit sink chosen by mode. */
export type AuditSinkMode = "worker" | "batched" | "sync";
/**
 * What protectWithCore needs from an audit sink: `write` per decision; `flush`/`close` for shutdown; `healthy` (when
 * present) is checked by `failClosed` guards before running an allowed call.
 */
export interface AuditWriter { write(r: AuditRecord): void; flush?(): void; close?(): void; healthy?(): boolean; lastError?(): string | undefined }

/**
 * Open the hash-chained SQLite decision audit (docs/AUDIT.md). `worker` (default): chain hashing and commits on a
 * worker thread; if a worker cannot start here (no worker_threads, a bundler that drops the module, ...) it falls back
 * to `batched` on the main thread and says so on stderr. `batched`: group commit on the main thread. `sync`: every
 * record committed before `write()` returns. Same table and chain in every mode (`mcp-rbac audit-verify`).
 * Open ONE sink per database and share it between per-session guards.
 */
export function openAuditSink(path: string, opts: Omit<AuditSinkOptions, "mode"> & { mode?: AuditSinkMode } = {}): AuditWriter {
  const { mode = "worker", ...rest } = opts;
  if (mode === "worker") {
    try { return new WorkerAuditSink(path, rest); } catch (e) {
      if (!/failed to start|did not start|Worker|worker_threads/i.test(String(e))) throw e;
      process.stderr.write(`mcp-rbac: audit worker unavailable (${(e as Error).message}); using batched audit on the main thread\n`);
    }
  }
  return new SqliteAuditSink(path, { ...rest, mode: mode === "sync" ? "sync" : "batched" });
}

/**
 * One sink per database file and table, shared by every guard in this process (P13): per-session guards that each say
 * `audit: "audit.db"` write ONE chain (one worker, one chain head) instead of several sinks racing on one table, which
 * broke chain verification. Reference-counted: `close()` on a handle only closes the sink when the last guard
 * releases it. The first opener's mode and options win for that file.
 */
const shared = new Map<string, { sink: AuditWriter; refs: number }>();
export function sharedAuditSink(path: string, opts: Omit<AuditSinkOptions, "mode"> & { mode?: AuditSinkMode } = {}): AuditWriter {
  const key = `${path === ":memory:" ? path : resolvePath(path)}\u0000${opts.table ?? "audit"}`;
  let e = shared.get(key);
  if (!e) { e = { sink: openAuditSink(path, opts), refs: 0 }; shared.set(key, e); }
  e.refs++;
  const entry = e;
  let released = false;
  return {
    write: (r) => entry.sink.write(r),
    flush: () => entry.sink.flush?.(),
    healthy: () => entry.sink.healthy?.() ?? true,
    lastError: () => entry.sink.lastError?.(),
    close: () => {
      if (released) return;
      released = true;
      if (--entry.refs === 0) { shared.delete(key); entry.sink.close?.(); } else entry.sink.flush?.();
    },
  };
}

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
import { SqliteAuditSink, type AuditRecord, type AuditSinkOptions, type AuditSinkStats } from "./audit-sink.js";

type Msg = { t: "w"; rs: AuditRecord[] } | { t: "f" | "c"; sab: SharedArrayBuffer; port: MessagePort };
interface Reply { stats: AuditSinkStats; head: string }

export class WorkerAuditSink {
  private w: Worker;
  private buf: AuditRecord[] = [];
  private scheduled = false;
  private closed = false;
  private last: Reply = { stats: { written: 0, dropped: 0, queued: 0, batches: 0, maxQueued: 0, errors: 0 }, head: "" };
  private readonly onExit = () => { this.flush(); };
  private readonly onSignal = (sig: NodeJS.Signals) => {
    this.flush();
    process.off(sig, this.onSignal);
    if (process.listenerCount(sig) === 0) process.kill(process.pid, sig);
  };

  constructor(path: string, opts: Omit<AuditSinkOptions, "mode" | "onError"> = {}) {
    const { shutdownHooks, ...rest } = opts;
    // the worker loads this same module; from TypeScript sources (tests, tsx) it registers tsx first
    const self = import.meta.url;
    const boot = `const { workerData } = require("node:worker_threads");
(async () => { if (workerData.self.endsWith(".ts")) (await import("tsx/esm/api")).register(); await import(workerData.self); })()
  .catch((e) => { process.stderr.write("mcp-rbac audit worker failed to start: " + (e && e.stack || e) + "\\n"); process.exit(1); });`;
    this.w = new Worker(boot, { eval: true, workerData: { mcpRbacAuditWorker: true, self, path, opts: { ...rest, mode: "batched", shutdownHooks: false } } });
    this.w.on("exit", (code) => { if (code !== 0 && !this.closed) process.stderr.write(`mcp-rbac audit worker exited with code ${code}\n`); });
    this.w.on("error", (e) => process.stderr.write(`mcp-rbac audit worker: ${String(e)}\n`));
    this.w.unref();
    process.on("exit", this.onExit);
    if (shutdownHooks ?? true) for (const sig of ["SIGINT", "SIGTERM"] as const) process.on(sig, this.onSignal);
    this.sync("f"); // open + schema created before the first write returns (fail fast on a bad path)
  }

  write(r: AuditRecord): void {
    if (this.closed) throw new Error("audit sink is closed");
    this.buf.push(r);
    if (this.buf.length >= 256) this.send();
    else if (!this.scheduled) { this.scheduled = true; setImmediate(() => this.send()); }
  }

  private send(): void {
    this.scheduled = false;
    if (!this.buf.length) return;
    this.w.postMessage({ t: "w", rs: this.buf } satisfies Msg);
    this.buf = [];
  }

  private sync(t: "f" | "c"): Reply {
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
  flush(): void { if (!this.closed) this.sync("f"); }
  /** Stats as of the last flush (call flush() first for current numbers). */
  stats(): AuditSinkStats { return { ...this.last.stats, queued: this.buf.length }; }
  headHash(): string { return this.sync("f").head; }

  close(): void {
    if (this.closed) return;
    this.sync("c");
    this.closed = true;
    process.off("exit", this.onExit);
    for (const sig of ["SIGINT", "SIGTERM"] as const) process.off(sig, this.onSignal);
    void this.w.terminate();
  }
}

if (!isMainThread && (workerData as { mcpRbacAuditWorker?: boolean } | null)?.mcpRbacAuditWorker) {
  const { path, opts } = workerData as { path: string; opts: AuditSinkOptions };
  let err: string | undefined;
  const sink = new SqliteAuditSink(path, { ...opts, onError: (e) => { err = String(e); process.stderr.write(`mcp-rbac audit: ${err}\n`); } });
  parentPort!.on("message", (m: Msg) => {
    if (m.t === "w") { for (const r of m.rs) sink.write(r); return; }
    try {
      sink.flush();
      m.port.postMessage({ stats: sink.stats(), head: sink.headHash() } satisfies Reply);
      if (m.t === "c") sink.close();
    } catch (e) { m.port.postMessage({ error: String(e) }); }
    m.port.close();
    const a = new Int32Array(m.sab);
    Atomics.store(a, 0, 1);
    Atomics.notify(a, 0);
  });
}

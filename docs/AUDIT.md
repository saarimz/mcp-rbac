# Decision audit: sync vs batched, crash safety

Every guarded `tools/call` decision (allow, deny, needs_approval) can be written to a hash-chained SQLite table by
`SqliteAuditSink`. The same sink exists in three languages with the same table, event and hash format:

| Language | API | Writer |
|---|---|---|
| TypeScript | `import { SqliteAuditSink, auditRecordFromDecision, verifyAuditTable } from "mcp-rbac/audit"` | timer on the event loop (`node:sqlite`) |
| Python | `from mcp_rbac import SqliteAuditSink, audit_record_from_decision, verify_audit_table` | background thread (`sqlite3`) |
| Go | `mcprbac.NewAuditSink(db, mcprbac.AuditSinkOptions{...})`, `mcprbac.VerifyAuditTable` | goroutine (`database/sql`, any SQLite driver) |
| Rust (`mcp-rbac-rmcp`) | not provided yet: use `GuardOptions::on_decision` with your own writer | — |

A table written by any of the three verifies in the other two. Tests in `go/examples/devops/audit_sink_test.go`
and `python/tests/test_audit_sink.py` write with one language, append with another, and verify with a third.

## Modes

| | `sync` | `batched` | `worker` (TypeScript default since 0.5) |
|---|---|---|---|
| When `write()` returns | after the record's own transaction commits | after the record is queued | after an array push |
| Commit | one transaction per record | group commit: up to `maxBatch` records (default 512) per transaction, after at most `flushInterval` (default 5 ms) | the `batched` sink, running on a worker thread (hashing, canonical JSON and the commit leave the event loop) |
| Request-path cost | INSERT + COMMIT | an array push / queue put + hashing on the event loop | an array push; one `postMessage` per event-loop turn |
| Use when | the audit record must exist before the tool runs (regulated workloads) | a worker thread is not available | throughput matters; a crash may lose the last few ms of records |

TypeScript: the simplest wiring is the core guard's `audit` option, which opens a `worker` sink:

```ts
const { server } = await protectWithCore(mcpServer, { policy, identity, audit: "audit.db" });  // or { path, mode }
```

For one HTTP server with a guard per session, open one sink and share it:
`const sink = openAuditSink("audit.db")` from `mcp-rbac/audit-worker`, then `audit: sink` in every guard.
`openAuditSink` falls back to `batched` (and says so on stderr) where a worker thread cannot start.

Pick the mode with `mode: "sync" | "batched" | "worker"` (Go and Python: `sync` / `batched`). The example servers
read `MCP_RBAC_AUDIT_MODE`.

**Sharing a file with your app's data.** In `worker` mode the audit commits come from a second SQLite connection on
another thread. If the audit table lives in the same database file as your own tables, give your own connection a
`PRAGMA busy_timeout` (the venue example uses 5000 ms) or use a separate audit file; otherwise a write of yours can
fail with `database is locked` while a batch commits. (Found by the 0.5 test run; the example server now sets it.)

## Crash-safety semantics

- **What can be lost (batched).** On a hard crash (SIGKILL, OOM kill, power loss), you lose records still in the
  queue: at most `maxBatch` records or `flushInterval` of traffic in TS, and at most `maxQueue` (default 10,000)
  plus the batch being written in Python and Go. Records already committed are not lost.
- **Durability of a commit.** The sink sets WAL and `synchronous=NORMAL`. A committed transaction survives a
  process crash. An OS crash or power loss can roll back the most recent commits. Set `durability: "full"`
  (TS/Python), or open the Go DB with `synchronous(FULL)`, to fsync every commit.
- **Flush on shutdown.**
  - TS flushes on `close()`, `flush()` and process `exit`, and on SIGINT/SIGTERM when `shutdownHooks` is on (the
    default). If no other handler exists, it re-raises the signal after flushing.
  - Python flushes on `close()`, `flush()` and `atexit`, and on SIGTERM when `shutdown_hooks` is on (main thread
    only). A framework that installs its own SIGTERM handler, such as uvicorn, exits normally, and then `atexit`
    flushes.
  - Go has no exit hooks: call `Close()` on shutdown. The devops example does this from its signal handler.
- **The hash chain stays valid.** Hashes are computed in queue order at commit time, and each batch commits in
  one transaction. A failed batch rolls back entirely and the head hash does not advance, so the table always holds
  a gap-free prefix of the chain. Lost records shorten the chain without breaking it. To detect truncation of the
  tail, export the head hash (`headHash()` / `head_hash()` / `Head()`) to storage the writer cannot modify. A restarted
  sink continues from the last stored hash.
- **Bounded queue.**
  - TS commits on the event loop, so its queue never exceeds `maxBatch`: reaching it commits inline.
  - Python and Go use a separate writer. With `overflow: "block"` (the default), `write()` waits when the queue is
    full (backpressure, nothing lost). With `"drop"`, the record is discarded and counted in `stats().dropped`.
    A dropped record is never chained, so the chain stays valid.
- **Write errors** (disk full, I/O errors, locked DB after `busy_timeout`) go to `onError` and are counted in
  `stats().errors`. The batch's records are counted in `stats().dropped`.

These behaviours are tested: SIGTERM loses nothing, and SIGKILL loses exactly the unflushed tail while the chain
still verifies (`test/audit-sink.test.ts`, `python/tests/test_audit_sink.py`).

## Table

`audit(id, at, sub, tool, decision, reason, tenant, rule, approved, duration_ms, event, prev, hash)`.
`event` is the canonical JSON (sorted keys, JS number rules) of the record's non-null fields, with `durationMs`
rounded to 3 decimals. `hash = sha256(prev + "\n" + canonicalJSON({...event, prev}))`. This is the same
construction as the in-memory chain in `src/audit-chain.ts`.

## Exporting to OpenTelemetry

Committed rows can also be exported as OTel log records (`mcp_rbac.audit`, with `id`/`hash`/`prev` and the hashed
event as the body) plus one `mcp_rbac.audit.commit` span per batch: `audit: { path, otel: true }` (TS),
`audit={"path": ..., "otel": True}` (Python), `AuditSinkOptions.OnCommit: NewAuditOtelExporter(...)` (Go). Export runs
after COMMIT and can never lose or delay a record. Details: [otel.md, "Audit export"](otel.md#audit-export-hash-chained-audit-as-otel-logs--spans);
example: `examples/audit-otel/audit-otel.ts`.

## Performance (venue server, one MCP session, loopback; bench/competitors)

| Audit | c=1 p50 / p99 ms | c=32 req/s |
|---|---|---|
| P9: `INSERT` per decision (statement prepared per call, autocommit) | 0.717 / 2.088 | 1,508 |
| P10 `sync` | 0.507 / 1.081 | 2,310 |
| P10 `batched` (default) | 0.431 / 0.996 | 2,882 |
| no audit (diagnostic) | 0.375 / 0.782 | 3,289 |
| no guard | 0.242 / 0.693 | 5,604 |

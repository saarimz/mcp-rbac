"""Hash-chained decision audit sink for SQLite, with ``sync`` and ``batched`` (group commit) modes.

Table layout, hashed event and chain are identical to the TypeScript ``SqliteAuditSink`` (src/audit-sink.ts) and
the Go ``AuditSink``, so a table written by any of them verifies in all three (``verify_audit_table``).

Modes:

- ``sync``: the record is chained and committed (own transaction) before ``write()`` returns.
- ``batched`` (default): ``write()`` puts the record on a bounded queue; a writer thread commits up to
  ``max_batch`` records per transaction, waiting at most ``flush_interval_s`` for a batch to fill.

Crash safety (docs/AUDIT.md): a hard crash (SIGKILL, OOM, power loss) in batched mode loses at most the queued
records (``max_queue``) and the batch being written. ``close()``, ``flush()``, interpreter exit (atexit) and, with
``shutdown_hooks`` (default on, main thread only), SIGTERM flush first. WAL with ``synchronous=NORMAL`` survives a
process crash once committed; ``durability="full"`` fsyncs each commit. Hashes are computed in queue order at commit
time inside one transaction, so the table always holds a gap-free prefix of the chain. Queue full: ``overflow="block"``
(default) makes ``write()`` wait (backpressure, nothing lost); ``"drop"`` drops and counts the record (never chained).
"""
from __future__ import annotations

import atexit
import hashlib
import json
import math
import queue
import re
import signal
import sqlite3
import sys
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

from .audit import GENESIS, canonical_json

_TABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
_FIELDS = ("at", "tool", "decision", "reason", "sub", "tenant", "rule", "approved", "durationMs")


def audit_event_of(r: Mapping[str, Any]) -> dict[str, Any]:
    """The hashed event: every non-null field, ``durationMs`` rounded to 3 decimals like JS ``Math.round``."""
    e: dict[str, Any] = {}
    for k in _FIELDS:
        v = r.get(k)
        if v is None:
            continue
        if k == "durationMs":
            v = math.floor(float(v) * 1000 + 0.5) / 1000
        e[k] = v
    return e


def chain_hash(prev: str, event: Mapping[str, Any]) -> str:
    return hashlib.sha256(f"{prev}\n{canonical_json({**event, 'prev': prev})}".encode()).hexdigest()


def audit_record_from_decision(e: Mapping[str, Any], at: str | None = None) -> dict[str, Any]:
    """Map a CoreGuard ``on_decision`` event to an audit record."""
    from datetime import datetime, timezone

    raw_ident = e.get("identity")
    ident: Mapping[str, Any] = raw_ident if isinstance(raw_ident, Mapping) else {}
    d = e["decision"]
    sub = ident.get("id")
    tenant = d.get("tenant") or (ident.get("tenant") if isinstance(ident.get("tenant"), str) else None)
    return {"at": at or datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "tool": e["tool"], "decision": d["decision"], "reason": d["reason"],
            "sub": sub if isinstance(sub, str) else None, "tenant": tenant, "rule": d.get("rule"),
            "approved": e.get("approved"), "durationMs": e.get("duration_ms")}


class SqliteAuditSink:
    def __init__(self, path: str, *, mode: str = "batched", table: str = "audit", max_queue: int = 10_000,
                 max_batch: int = 512, flush_interval_s: float = 0.005, overflow: str = "block",
                 durability: str = "normal", shutdown_hooks: bool = True,
                 on_error: Callable[[BaseException], None] | None = None,
                 on_commit: Callable[[list[dict[str, Any]]], None] | None = None) -> None:
        """``on_commit``: called after each successful commit with the committed rows in chain order
        (``{"table", "id", "event", "canonical", "prev", "hash", "trace"?}``; OTel audit export, docs/otel.md). It runs
        after COMMIT (on the writer thread in batched mode); an exception is reported to ``on_error`` and never
        affects the audit."""
        if mode not in ("sync", "batched"):
            raise ValueError(f"bad audit mode: {mode}")
        if not _TABLE.match(table):
            raise ValueError(f"bad audit table name: {table}")
        if overflow not in ("block", "drop"):
            raise ValueError(f"bad overflow: {overflow}")
        self.mode, self.table, self.overflow = mode, table, overflow
        self.max_batch = max(1, max_batch)
        self.flush_interval_s = max(0.0, flush_interval_s)
        self._on_error = on_error or (lambda err: print(f"mcp-rbac audit: {err}", file=sys.stderr))
        self._on_commit = on_commit
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=5.0)
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute(f"PRAGMA synchronous = {'FULL' if durability == 'full' else 'NORMAL'}")
        self._db.execute(f"""CREATE TABLE IF NOT EXISTS {table} (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, sub TEXT,
            tool TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, tenant TEXT, rule TEXT, approved INTEGER,
            duration_ms REAL, event TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL)""")
        row = self._db.execute(f"SELECT hash FROM {table} ORDER BY id DESC LIMIT 1").fetchone()
        self._head: str = row[0] if row else GENESIS
        self._sql = (f"INSERT INTO {table} (at, sub, tool, decision, reason, tenant, rule, approved, duration_ms, event, prev, hash)"
                     " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        self._lock = threading.Lock()  # serializes commits (writer thread, flush(), sync writes)
        self._stats_lock = threading.Lock()
        self._stats = {"written": 0, "dropped": 0, "batches": 0, "errors": 0, "max_queued": 0}
        self._closed = False
        self._err: BaseException | None = None  # last commit error, cleared by the next successful commit
        self._q: queue.Queue[Any] = queue.Queue(maxsize=max(1, max_queue))  # records, flush markers (Event), None = stop
        self._thread: threading.Thread | None = None
        if mode == "batched":
            self._thread = threading.Thread(target=self._run, name="mcp-rbac-audit", daemon=True)
            self._thread.start()
        atexit.register(self.close)
        self._prev_term: Any = None
        if shutdown_hooks and threading.current_thread() is threading.main_thread():
            try:
                self._prev_term = signal.signal(signal.SIGTERM, self._on_term)
            except ValueError:
                pass

    # -- public
    def write(self, r: Mapping[str, Any]) -> None:
        if self._closed:
            raise RuntimeError("audit sink is closed")
        rec = dict(r)
        if self.mode == "sync":
            with self._lock:
                ok = self._commit([rec])
            if not ok:
                raise RuntimeError(f"audit record not committed: {self._err}")
            return
        if self._thread is not None and not self._thread.is_alive():
            with self._stats_lock:
                self._stats["dropped"] += 1
            raise RuntimeError("audit writer thread is not running")
        if self.overflow == "drop":
            try:
                self._q.put_nowait(rec)
            except queue.Full:
                with self._stats_lock:
                    self._stats["dropped"] += 1
                return
        else:
            self._q.put(rec)
        n = self._q.qsize()
        if n > self._stats["max_queued"]:
            self._stats["max_queued"] = n

    def flush(self, timeout: float | None = 10.0) -> bool:
        """Commit everything written before this call, in order (blocks until done or timeout)."""
        if self.mode == "sync" or self._thread is None or self._closed or not self._thread.is_alive():
            return True
        done = threading.Event()
        self._q.put(done)
        return done.wait(timeout)

    def healthy(self) -> bool:
        """False after a failed commit (until the next one succeeds), or when the batched writer thread is gone."""
        if self._closed or self._err is not None:
            return False
        return self._thread is None or self._thread.is_alive()

    def last_error(self) -> BaseException | None:
        return self._err

    def stats(self) -> dict[str, int]:
        return {**self._stats, "queued": self._q.qsize()}

    def head_hash(self) -> str:
        return self._head

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._thread is not None:
            self._q.put(None)  # wake the writer; it drains and exits
            self._thread.join(10)
        with self._lock:
            self._drain_locked()
            self._db.close()
        try:
            atexit.unregister(self.close)
        except Exception:  # noqa: BLE001
            pass

    # -- internals
    def _on_term(self, signum: int, frame: Any) -> None:
        self.close()
        prev = self._prev_term
        signal.signal(signal.SIGTERM, prev if prev is not None else signal.SIG_DFL)
        if callable(prev):
            prev(signum, frame)
        else:
            raise SystemExit(128 + signum)

    def _drain_locked(self) -> None:
        while True:
            batch: list[dict[str, Any]] = []
            try:
                while len(batch) < self.max_batch:
                    x = self._q.get_nowait()
                    if isinstance(x, threading.Event):
                        x.set()
                    elif x is not None:
                        batch.append(x)
            except queue.Empty:
                pass
            if not batch:
                return
            self._commit(batch)

    def _run(self) -> None:
        stop = False
        while not stop:
            first = self._q.get()
            if first is None:
                return
            batch: list[dict[str, Any]] = []
            markers: list[threading.Event] = []
            (markers.append if isinstance(first, threading.Event) else batch.append)(first)
            deadline = time.monotonic() + self.flush_interval_s
            while len(batch) < self.max_batch and not markers:
                left = deadline - time.monotonic()
                try:
                    x = self._q.get(timeout=left) if left > 0 else self._q.get_nowait()
                except queue.Empty:
                    break
                if x is None:
                    stop = True
                    break
                (markers.append if isinstance(x, threading.Event) else batch.append)(x)
            if batch:
                with self._lock:
                    self._commit(batch)
            for m in markers:
                m.set()

    def _commit(self, batch: list[dict[str, Any]]) -> bool:
        head = self._head
        rows = []
        for r in batch:
            ev = audit_event_of(r)  # only the known fields: a record's "trace" is correlation metadata, never hashed
            h = chain_hash(head, ev)
            ap = r.get("approved")
            rows.append((r["at"], r.get("sub"), r["tool"], r["decision"], r["reason"], r.get("tenant"), r.get("rule"),
                         None if ap is None else int(bool(ap)), ev.get("durationMs"), canonical_json(ev), head, h))
            head = h
        last_id = 0
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.executemany(self._sql, rows)
            if self._on_commit is not None:  # ids are contiguous: one writer holds the lock for the whole batch
                last_id = int(self._db.execute("SELECT last_insert_rowid()").fetchone()[0])
            self._db.execute("COMMIT")
        except BaseException as err:  # noqa: BLE001
            try:
                self._db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            with self._stats_lock:
                self._stats["errors"] += 1
                self._stats["dropped"] += len(batch)
            self._err = err
            self._on_error(err)
            return False
        self._err = None
        self._head = head
        self._stats["written"] += len(batch)
        self._stats["batches"] += 1
        if self._on_commit is not None:
            first = last_id - len(rows) + 1
            committed = []
            for i, (r, row) in enumerate(zip(batch, rows)):
                c: dict[str, Any] = {"table": self.table, "id": first + i, "event": json.loads(row[9]), "canonical": row[9],
                                     "prev": row[10], "hash": row[11]}
                if r.get("trace"):
                    c["trace"] = r["trace"]
                committed.append(c)
            try:
                self._on_commit(committed)
            except Exception as err:  # noqa: BLE001 - the records are committed; export problems never affect the audit
                self._on_error(RuntimeError(f"audit on_commit callback failed (the records are committed): {err}"))
        return True


_SHARED: dict[tuple[str, str], list[Any]] = {}  # (resolved path, table) -> [sink, refcount]
_SHARED_LOCK = threading.Lock()


class SharedAuditHandle:
    """One reference to a process-wide sink (see :func:`shared_audit_sink`); ``close()`` releases this reference."""

    def __init__(self, key: tuple[str, str], sink: SqliteAuditSink) -> None:
        self._key, self.sink, self._closed = key, sink, False

    def write(self, r: Mapping[str, Any]) -> None:
        self.sink.write(r)

    def healthy(self) -> bool:
        return not self._closed and self.sink.healthy()

    def last_error(self) -> BaseException | None:
        return self.sink.last_error()

    def flush(self, timeout: float | None = 10.0) -> bool:
        return self.sink.flush(timeout)

    def stats(self) -> dict[str, int]:
        return self.sink.stats()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with _SHARED_LOCK:
            ent = _SHARED.get(self._key)
            if ent is None or ent[0] is not self.sink:
                return
            ent[1] -= 1
            if ent[1] > 0:
                return
            del _SHARED[self._key]
        self.sink.close()


def shared_audit_sink(path: str, **opts: Any) -> SharedAuditHandle:
    """The process-wide sink for ``path`` (and ``table``): every guard naming the same file shares one sink and one
    chain (two sinks on one file would each chain from their own head and break verification). Options apply when
    the sink is first opened. The sink closes when the last handle does."""
    import os

    key = (os.path.realpath(path), str(opts.get("table", "audit")))
    with _SHARED_LOCK:
        ent = _SHARED.get(key)
        if ent is None or ent[0]._closed:
            ent = [SqliteAuditSink(path, **opts), 0]
            _SHARED[key] = ent
        ent[1] += 1
        return SharedAuditHandle(key, ent[0])


def verify_audit_table(path: str, table: str = "audit") -> dict[str, Any]:
    """Verify a sink table's chain (oldest first); works on tables written by the TS, Python and Go sinks."""
    if not _TABLE.match(table):
        raise ValueError(f"bad audit table name: {table}")
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        prev: str | None = None
        n = 0
        for rid, event, p, h in db.execute(f"SELECT id, event, prev, hash FROM {table} ORDER BY id"):
            if prev is not None and p != prev:
                return {"ok": False, "id": rid, "reason": "prev_mismatch"}
            if chain_hash(p, json.loads(event)) != h:
                return {"ok": False, "id": rid, "reason": "hash_mismatch"}
            prev, n = h, n + 1
        return {"ok": True, "head": prev or GENESIS, "count": n}
    finally:
        db.close()
